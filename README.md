# SH-53D temporary root — 38JP_3_330

Build-specific GhostLock (CVE-2026-43499) port for SHARP AQUOS wish3 SH-53D.
It obtains a temporary uid-0 shell and sets SELinux to permissive. It writes no
boot, system, or userdata partition. The daemon and permissive state disappear
on reboot.

## Supported build

- Fingerprint: `DOCOMO/SH-53D/SH-53D:15/AP3A.240905.015.A2/38JP_3_330:user/release-keys`
- Android 15, SPL 2026-07-05
- Kernel: `6.6.89-android15-8-gbe8d201b0d27-ab13762941-4k`
- SoC: MediaTek MT6833, 4 KiB pages

`run.sh` rejects every other fingerprint.

## Build and run

Use Android NDK r26d or newer:

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk-r26d
./build.sh
./run.sh
```

The runner does not reboot the device. After verification it opens an
interactive root shell whose prompt is `SH-53D:/ #`. When stdout is not a
terminal, it prints the command needed to open that shell.

The exploit is a kernel race. A run can miss or panic/reboot the device. The
first physical-device validation succeeded in 88.6 seconds: W1 on attempt 1,
W2 on round 4.

## Port evidence

The Google CI build 13762941 `vmlinux` yields a raw Image byte-for-byte equal
to the stock boot Image (36,461,056 bytes, SHA-256
`ae17031903b1f5cacd5c0e718680bf1eb8881048b46ae96ec61239b7ac6703e1`).
All symbol and BTF offsets in
`targets/sh53d-38JP_3_330/target.h` therefore describe the stock kernel.

The stock `remove_waiter()` retains the vulnerable current-task cleanup.
Exact disassembly places both the freed futex waiter and pselect fdset at
syscall-entry SP-0x200, giving waiter word 0 and `PSELECT_SHIFT=-2`.
The first run changed the expected SELinux enforcing byte through the
`0x40080000` Image linear-map alias, directly validating the physical-load
value before W2 succeeded.

See `VALIDATION.md` for the observed root and SELinux results.

## Provenance

This Android 15 implementation follows the 6.6 port and embedded temporary
`su` design from
[soralis0912/CVE-2026-43499-pmg110-root](https://github.com/soralis0912/CVE-2026-43499-pmg110-root).
The earlier Android 13 branch was derived from the projects listed in
`NOTICE`.
