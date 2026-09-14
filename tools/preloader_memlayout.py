#!/usr/bin/env python3
"""Dump the static memory-layout table out of a MediaTek preloader.

The table is what `platform/<soc>/src/core/memory_layout.c` compiles down to: an
array of fixed DRAM reservations, one per named region.  `mb_kernel` is the one
that matters here — MediaTek lk asserts the physical address it loads the kernel
to is exactly `mb_kernel.start` ("kernel_addr (0x%p) is not taken from mb"), so
that entry *is* `P0_KERNEL_PHYS_LOAD`.

Two preloader builds for the same device (retail vs engineering, say) can be
compared with --diff; a byte-identical table means both boot the kernel to the
same physical address, so a target.h generated for one is valid for the other.

  python3 tools/preloader_memlayout.py <preloader.bin>
  python3 tools/preloader_memlayout.py <a.bin> --diff <b.bin>

The table is located by scanning, not by a hardcoded offset, so this works on
any MediaTek preloader that keeps the same record shape.
"""

import argparse
import struct
import sys

GFH_MAGIC = b"MMM\x01"

# One record: {const char *name; u64 start; u64 size; u64 align; u64 flags;}
REC_SIZE = 40
REC_FMT = "<5Q"

# Bounds a real record has to satisfy.  Deliberately loose — they only need to
# reject random data well enough that a run of consecutive hits is unambiguous.
MIN_RUN = 6
MAX_ALIGN = 0x1000000
MIN_ALIGN = 0x1000
MAX_START = 1 << 40
MAX_SIZE = 1 << 30
MAX_FLAGS = 1 << 40


class Preloader:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as fh:
            self.data = fh.read()
        if self.data[:4] != GFH_MAGIC:
            raise ValueError(f"{path}: not a GFH-headered preloader")
        (self.load_addr,) = struct.unpack_from("<I", self.data, 0x1C)
        (self.file_len,) = struct.unpack_from("<I", self.data, 0x20)
        (self.content_off,) = struct.unpack_from("<I", self.data, 0x28)
        (self.sig_len,) = struct.unpack_from("<I", self.data, 0x2C)
        self.code_end = self.file_len - self.sig_len

    def off(self, va):
        return va - self.load_addr

    def va(self, off):
        return off + self.load_addr

    def cstr(self, va, maxlen=48):
        """Return the NUL-terminated printable string at `va`, or None."""
        off = self.off(va)
        if not 0 <= off < self.code_end:
            return None
        end = self.data.find(b"\0", off, min(off + maxlen, self.code_end))
        if end < 0:
            return None
        raw = self.data[off:end]
        if len(raw) < 2 or not all(0x20 <= c < 0x7F for c in raw):
            return None
        return raw.decode()

    def _record(self, off):
        if off < 0 or off + REC_SIZE > self.code_end:
            return None
        name_ptr, start, size, align, flags = struct.unpack_from(REC_FMT, self.data, off)
        if not MIN_ALIGN <= align <= MAX_ALIGN or align & (align - 1):
            return None
        if not 0 < start < MAX_START or start % align:
            return None
        if not 0 < size <= MAX_SIZE or size % MIN_ALIGN:
            return None
        if flags > MAX_FLAGS:
            return None
        name = self.cstr(name_ptr)
        if name is None:
            return None
        return {"name": name, "start": start, "size": size, "align": align, "flags": flags}

    def memory_layout(self):
        """Locate the layout table and return (file_offset, [record, ...])."""
        best = None
        off = self.content_off
        while off + REC_SIZE <= self.code_end:
            if self._record(off) is None:
                off += 8
                continue
            run_start = off
            recs = []
            while True:
                rec = self._record(off)
                if rec is None:
                    break
                recs.append(rec)
                off += REC_SIZE
            if len(recs) >= MIN_RUN and (best is None or len(recs) > len(best[1])):
                best = (run_start, recs)
        if best is None:
            raise LookupError(f"{self.path}: no memory-layout table found")
        return best


def render(pre, table_off, records):
    lines = [
        f"{pre.path}",
        f"  load_addr=0x{pre.load_addr:08x} file_len=0x{pre.file_len:x} "
        f"sig_len=0x{pre.sig_len:x}",
        f"  memory layout table: file 0x{table_off:x} "
        f"(VA 0x{pre.va(table_off):08x}), {len(records)} entries",
        "",
        f"  {'region':<20} {'start':>12} {'size':>12} {'align':>9} {'flags':>12}",
    ]
    for r in records:
        lines.append(
            f"  {r['name']:<20} 0x{r['start']:010x} 0x{r['size']:010x} "
            f"0x{r['align']:07x} 0x{r['flags']:010x}"
        )
    return "\n".join(lines)


def key(records):
    return [(r["name"], r["start"], r["size"], r["align"], r["flags"]) for r in records]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("preloader", help="MediaTek preloader image (GFH-headered .bin)")
    ap.add_argument("--diff", metavar="OTHER",
                    help="second preloader to compare the table against")
    args = ap.parse_args()

    try:
        pre = Preloader(args.preloader)
        off, recs = pre.memory_layout()
        other = other_off = orecs = None
        if args.diff:
            other = Preloader(args.diff)
            other_off, orecs = other.memory_layout()
    except (OSError, ValueError, LookupError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(render(pre, off, recs))

    kernel = next((r for r in recs if r["name"] == "mb_kernel"), None)
    if kernel is None:
        print("\n  warning: no mb_kernel entry — cannot derive P0_KERNEL_PHYS_LOAD",
              file=sys.stderr)
    else:
        print(f"\n  P0_KERNEL_PHYS_LOAD = 0x{kernel['start']:x}  (mb_kernel.start)")

    if other is None:
        return 0

    print()
    print(render(other, other_off, orecs))
    okernel = next((r for r in orecs if r["name"] == "mb_kernel"), None)
    if okernel is not None:
        print(f"\n  P0_KERNEL_PHYS_LOAD = 0x{okernel['start']:x}  (mb_kernel.start)")

    print()
    if key(recs) == key(orecs):
        print("== memory layout tables are IDENTICAL "
              "(same regions, same start/size/align/flags)")
        print("   -> both builds load the kernel to the same physical address;")
        print("      one target.h is valid for both.")
        return 0

    print("== memory layout tables DIFFER")
    a = {r["name"]: r for r in recs}
    b = {r["name"]: r for r in orecs}
    for name in sorted(set(a) | set(b)):
        ra, rb = a.get(name), b.get(name)
        if ra == rb:
            continue
        fmt = lambda r: ("absent" if r is None else
                         f"start=0x{r['start']:x} size=0x{r['size']:x} "
                         f"align=0x{r['align']:x} flags=0x{r['flags']:x}")
        print(f"   {name}:")
        print(f"     {args.preloader}: {fmt(ra)}")
        print(f"     {args.diff}: {fmt(rb)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
