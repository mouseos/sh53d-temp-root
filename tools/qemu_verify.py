#!/usr/bin/env python3
"""Boot a device's own kernel under QEMU and measure what the port depends on.

Two measurements, both on the real kernel binary rather than on inference:

  stack   -- the entry SP of futex_wait_requeue_pi and core_sys_select on one
             task, giving the waiter's word index inside stack_fds and hence
             PSELECT_WAITER_WORD_SHIFT / SLIDE_PSELECT_WORD_SHIFT. This is the
             "QEMU verified SP diff" the device table refers to.

  linear  -- whether memstart_addr equals the DRAM base across KASLR seeds,
             i.e. whether arm64's linear-map randomisation fires. If it does,
             data_addr()'s physmap alias is not a per-firmware constant and
             P0_KERNEL_PHYS_LOAD cannot be baked in at all.

Usage:
    python3 tools/qemu_verify.py boot.img               # both
    python3 tools/qemu_verify.py boot.img --mode stack
    python3 tools/qemu_verify.py boot.img --mode linear --runs 4

Requires: qemu-system-aarch64, gdb-multiarch, vmlinux-to-elf, and a C compiler
that can target aarch64 (clang + ld.lld). Pass --init to reuse a prebuilt
freestanding init instead of compiling one.
"""

import argparse
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from extract_device import load_kernel, load_symbols  # noqa: E402

# QEMU's arm64 loader places a bare Image here inside -M virt.
VIRT_DRAM_BASE = 0x40000000
VIRT_TEXT_PHYS = 0x40200000
KIMAGE_VADDR = 0xFFFFFFC080000000

INIT_C = r'''
typedef unsigned long ulong; typedef long slong;
static inline slong sys6(long n, ulong a, ulong b, ulong c, ulong d, ulong e, ulong f){
  register ulong x8 __asm__("x8")=(ulong)n, x0 __asm__("x0")=a, x1 __asm__("x1")=b;
  register ulong x2 __asm__("x2")=c, x3 __asm__("x3")=d, x4 __asm__("x4")=e, x5 __asm__("x5")=f;
  __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory","cc");
  return (slong)x0;
}
#define SYS_write 64
#define SYS_futex 98
#define SYS_pselect6 72
#define SYS_nanosleep 101
#define FUTEX_WAIT_REQUEUE_PI 11
#define NFDS 320
static ulong in_set[5], out_set[5], ex_set[5];
struct ts_ { slong s, ns; };
static volatile int f1, f2;
static void put(const char*s){ulong n=0; while(s[n])n++; sys6(SYS_write,1,(ulong)s,n,0,0,0);}
static void nap(long s){struct ts_ t={s,0}; sys6(SYS_nanosleep,(ulong)&t,0,0,0,0,0);}
int main(void){
  put("[init] alive\n[init] sleeping 10s for gdb\n");
  nap(10);
  struct ts_ tv={0,20*1000*1000};
  for(int r=0;r<200;r++){
    /* core_sys_select: reached through pselect6, arm64 has no __NR_select */
    for(int w=0;w<5;w++){in_set[w]=0;out_set[w]=0;ex_set[w]=0;}
    put("[init] pselect6\n");
    sys6(SYS_pselect6,NFDS,(ulong)in_set,(ulong)out_set,(ulong)ex_set,(ulong)&tv,0);
    /* futex_wait_requeue_pi: runs its prologue then times out */
    f1=0; put("[init] futex\n");
    sys6(SYS_futex,(ulong)&f1,FUTEX_WAIT_REQUEUE_PI,0,(ulong)&tv,(ulong)&f2,0);
    nap(2);
  }
  for(;;) nap(60);
}
__attribute__((naked, section(".text.start"))) void _start(void){
  __asm__ volatile("mov x29,#0\nmov x30,#0\nbl main\nmov x8,#93\nmov x0,#0\nsvc #0\n");
}
'''


def need(tool):
    p = shutil.which(tool)
    if not p:
        raise SystemExit(f'{tool} not found in PATH')
    return p


def build_init(workdir):
    cc = shutil.which('clang') or shutil.which('aarch64-linux-gnu-gcc')
    if not cc:
        raise SystemExit('no aarch64-capable compiler; pass --init <path>')
    src = os.path.join(workdir, 'init.c')
    out = os.path.join(workdir, 'init')
    open(src, 'w').write(INIT_C)
    if 'clang' in os.path.basename(cc):
        cmd = [cc, '--target=aarch64-linux-gnu', '-static', '-nostdlib', '-nostdinc',
               '-ffreestanding', '-fno-stack-protector', '-fno-builtin', '-O1',
               '-fuse-ld=lld', '-Wl,-e,_start', src, '-o', out]
    else:
        cmd = [cc, '-static', '-nostdlib', '-nostdinc', '-ffreestanding',
               '-fno-stack-protector', '-O1', '-Wl,-e,_start', src, '-o', out]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(f'init build failed:\n{r.stderr[-2000:]}\n'
                         f'(clang needs ld.lld; install lld or pass --init)')
    return out


def build_initramfs(workdir, init_path):
    root = os.path.join(workdir, 'root')
    os.makedirs(root, exist_ok=True)
    shutil.copy(init_path, os.path.join(root, 'init'))
    os.chmod(os.path.join(root, 'init'), 0o755)
    cpio = os.path.join(workdir, 'initramfs.cpio')
    with open(cpio, 'wb') as fh:
        find = subprocess.Popen(['find', '.'], cwd=root, stdout=subprocess.PIPE)
        subprocess.run(['cpio', '-o', '-H', 'newc', '--quiet'], cwd=root,
                       stdin=find.stdout, stdout=fh, check=True)
        find.wait()
    return cpio


class Vm:
    def __init__(self, kernel_path, initramfs, log, cpu='max', mem='2G',
                 kaslr=False, gdb_port=None, monitor_port=None):
        cmdline = 'console=ttyAMA0 rdinit=/init panic=-1 loglevel=4'
        if not kaslr:
            cmdline += ' nokaslr'
        argv = [need('qemu-system-aarch64'), '-M', 'virt', '-cpu', cpu,
                '-smp', '1', '-m', mem, '-kernel', kernel_path,
                '-initrd', initramfs, '-append', cmdline,
                '-nographic', '-no-reboot']
        if gdb_port:
            argv += ['-gdb', f'tcp::{gdb_port}']
        if monitor_port:
            argv += ['-monitor', f'tcp:127.0.0.1:{monitor_port},server,nowait']
        self.log = log
        self.fh = open(log, 'wb')
        self.p = subprocess.Popen(argv, stdout=self.fh, stderr=subprocess.STDOUT)

    def wait_for_init(self, timeout=120):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.p.poll() is not None:
                break
            if b'sleeping 10s' in open(self.log, 'rb').read():
                return True
            time.sleep(1)
        return False

    def kill(self):
        self.p.terminate()
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()
        self.fh.close()


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def measure_stack(kernel_path, kernel, syms, initramfs, workdir):
    """Break on both syscall entries and read SP."""
    for name in ('futex_wait_requeue_pi', 'core_sys_select', 'memstart_addr',
                 'kimage_voffset'):
        if name not in syms:
            raise SystemExit(f'{name} missing from kallsyms')
    sel = syms['core_sys_select']
    fut = syms['futex_wait_requeue_pi']

    # Frame sizes and variable slots come from the same static analysis the
    # offsets extraction uses; QEMU supplies the entry SPs it cannot infer.
    from extract_device import frame_size, find_waiter_offset, find_stack_fds_offset
    base = syms['_text']
    futex_frame = frame_size(kernel, base, syms, 'futex_wait_requeue_pi')
    select_frame = frame_size(kernel, base, syms, 'core_sys_select')
    waiter_off, _ = find_waiter_offset(kernel, base, syms)
    fds_off = find_stack_fds_offset(kernel, base, syms)

    script = os.path.join(workdir, 'measure.gdb')
    port = free_port()
    open(script, 'w').write(f'''set pagination off
set confirm off
set architecture aarch64
target remote :{port}
set $memstart = *(unsigned long *)0x{syms['memstart_addr']:x}
set $voff     = *(unsigned long *)0x{syms['kimage_voffset']:x}
printf "memstart_addr  = 0x%016lx\\n", $memstart
printf "kimage_voffset = 0x%016lx\\n", $voff
set $SEL = (unsigned long)0x{sel:x}
set $FUT = (unsigned long)0x{fut:x}
break *0x{sel:x}
break *0x{fut:x}
set $sel_sp=(unsigned long)0
set $fut_sp=(unsigned long)0
set $sel_stk=(unsigned long)1
set $fut_stk=(unsigned long)2
set $n = 0
while $n < 8
  continue
  set $cpc = (unsigned long)$pc
  set $csp = (unsigned long)$sp
  if $cpc == $SEL
    set $sel_sp = $csp
    set $sel_stk = $csp & ~(unsigned long)0x3fff
    printf "SEL_SP 0x%016lx caller 0x%lx\\n", $csp, (unsigned long)$x30
  end
  if $cpc == $FUT
    set $fut_sp = $csp
    set $fut_stk = $csp & ~(unsigned long)0x3fff
    printf "FUT_SP 0x%016lx caller 0x%lx\\n", $csp, (unsigned long)$x30
  end
  set $n = $n + 1
end
printf "SAME_STACK %d\\n", ($sel_stk == $fut_stk)
printf "DELTA_SP %ld\\n", (long)($fut_sp - $sel_sp)
detach
quit
''')

    log = os.path.join(workdir, 'stack.log')
    vm = Vm(kernel_path, initramfs, log, gdb_port=port)
    try:
        if not vm.wait_for_init():
            raise SystemExit(f'kernel did not reach init; see {log}')
        r = subprocess.run([need('gdb-multiarch'), '-batch', '-x', script],
                           capture_output=True, text=True, timeout=300)
        out = r.stdout + r.stderr
    finally:
        vm.kill()

    sel_sps = [int(x, 16) for x in re.findall(r'SEL_SP 0x([0-9a-f]+)', out)]
    fut_sps = [int(x, 16) for x in re.findall(r'FUT_SP 0x([0-9a-f]+)', out)]
    if not sel_sps or not fut_sps:
        print(out[-3000:])
        raise SystemExit('no breakpoint hits')
    same = re.search(r'SAME_STACK (\d)', out)
    delta_sp = int(re.search(r'DELTA_SP (-?\d+)', out).group(1))

    print(f'  core_sys_select        frame 0x{select_frame:x}, '
          f'stack_fds at sp+0x{fds_off:x}')
    print(f'  futex_wait_requeue_pi  frame 0x{futex_frame:x}, '
          f'rt_waiter at sp+0x{waiter_off:x}')
    print(f'  entry SP core_sys_select       = ' +
          ', '.join(hex(v) for v in sorted(set(sel_sps))))
    print(f'  entry SP futex_wait_requeue_pi = ' +
          ', '.join(hex(v) for v in sorted(set(fut_sps))))
    print(f'  same kernel stack              = {bool(int(same.group(1)))}')
    print(f'  measured entry-SP delta        = {delta_sp}')
    if len(set(sel_sps)) != 1 or len(set(fut_sps)) != 1:
        print('  [WARN] entry SP not stable across hits')

    waiter_abs = fut_sps[-1] - futex_frame + waiter_off
    fds_abs = sel_sps[-1] - select_frame + fds_off
    word = (waiter_abs - fds_abs) // 8
    print(f'  rt_waiter  = 0x{waiter_abs:016x}')
    print(f'  stack_fds  = 0x{fds_abs:016x}')
    print(f'  waiter word                    = {word}')
    print(f'  feasible (need -2 <= word <= 3)= {-2 <= word <= 3}')
    print(f'  PSELECT_WAITER_WORD_SHIFT      = {word - 2}')
    print(f'  SLIDE_PSELECT_WORD_SHIFT       = {word}')
    return word


def read_phys(port, addr, retries=3):
    for _ in range(retries):
        try:
            s = socket.create_connection(('127.0.0.1', port), timeout=10)
            time.sleep(0.4)
            s.recv(65536)
            s.sendall(f'xp/1gx 0x{addr:x}\n'.encode())
            time.sleep(0.5)
            out = s.recv(65536).decode(errors='replace')
            s.close()
            m = re.findall(r'0x([0-9a-f]{16})', out)
            if m:
                return int(m[-1], 16)
        except OSError:
            time.sleep(1)
    return None


def measure_linear(kernel_path, syms, initramfs, workdir, runs):
    """Is memstart_addr the DRAM base regardless of the KASLR seed?

    Read through *physical* memory so the answer needs no KASLR offset: the
    Image's physical placement is fixed by QEMU's loader, so the physical
    address of any image symbol is known even when its VA is randomised.
    """
    ms_off = syms['memstart_addr'] - syms['_text']
    vo_off = syms['kimage_voffset'] - syms['_text']
    configs = [('max', False, '2G'), ('max', True, '2G'), ('max', True, '8G'),
               ('cortex-a76', True, '4G'), ('cortex-a710', True, '12G')][:runs]
    ok = True
    for cpu, kaslr, mem in configs:
        port = free_port()
        log = os.path.join(workdir, f'linear-{cpu}-{kaslr}-{mem}.log')
        vm = Vm(kernel_path, initramfs, log, cpu=cpu, mem=mem, kaslr=kaslr,
                monitor_port=port)
        try:
            if not vm.wait_for_init():
                print(f'  cpu={cpu:<12} kaslr={str(kaslr):<5} mem={mem:<4} BOOT FAILED')
                ok = False
                continue
            ms = read_phys(port, VIRT_TEXT_PHYS + ms_off)
            vo = read_phys(port, VIRT_TEXT_PHYS + vo_off)
        finally:
            vm.kill()
        if ms is None or vo is None:
            print(f'  cpu={cpu:<12} kaslr={str(kaslr):<5} mem={mem:<4} READ FAILED')
            ok = False
            continue
        text_va = (VIRT_TEXT_PHYS + vo) & ((1 << 64) - 1)
        kaslr_off = (text_va - KIMAGE_VADDR) & ((1 << 64) - 1)
        randomized = ms != VIRT_DRAM_BASE
        ok &= not randomized
        print(f'  cpu={cpu:<12} kaslr={str(kaslr):<5} mem={mem:<4} '
              f'memstart=0x{ms:<10x} kaslr_off=0x{kaslr_off:<12x} '
              f'delta=0x{(VIRT_TEXT_PHYS - ms) & ((1 << 64) - 1):<8x} '
              f'randomized={"YES" if randomized else "no"}')
    print(f'\n  linear map stable across KASLR seeds: {ok}')
    if ok:
        print('  => P0_PHYS_OFFSET == DRAM base, and P0_KERNEL_PHYS_LOAD is a')
        print('     single per-firmware constant (still a device measurement).')
    else:
        print('  => memstart_addr moves; a baked-in P0_KERNEL_PHYS_LOAD cannot work.')
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('image', help='boot.img or a raw/compressed kernel')
    ap.add_argument('--mode', choices=('stack', 'linear', 'both'), default='both')
    ap.add_argument('--init', help='prebuilt freestanding aarch64 init')
    ap.add_argument('--runs', type=int, default=5, help='linear-mode configs (max 5)')
    ap.add_argument('--keep', action='store_true', help='keep the work directory')
    args = ap.parse_args()

    kernel = load_kernel(args.image)
    syms, base = load_symbols(kernel)
    syms['_text'] = base
    vpos = kernel.find(b'Linux version ')
    print('[*] ' + kernel[vpos:vpos + 90].split(b'\x00')[0].decode('ascii', 'replace'))

    workdir = tempfile.mkdtemp(prefix='ghostlock-qemu-')
    raw = os.path.join(workdir, 'Image')
    open(raw, 'wb').write(kernel)
    try:
        init = args.init or build_init(workdir)
        initramfs = build_initramfs(workdir, init)
        if args.mode in ('stack', 'both'):
            print('\n=== pselect stack overlay (measured) ===')
            measure_stack(raw, kernel, syms, initramfs, workdir)
        if args.mode in ('linear', 'both'):
            print('\n=== linear map stability ===')
            measure_linear(raw, syms, initramfs, workdir, args.runs)
    finally:
        if args.keep:
            print(f'\nwork dir: {workdir}')
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == '__main__':
    main()
