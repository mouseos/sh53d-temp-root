# SH-53D temporary root

This is a build-specific proof of concept that obtains temporary root and
switches SELinux to permissive on the Japanese SHARP AQUOS wish3 SH-53D.
Nothing is installed to a boot or system partition. Root access, the daemon,
and permissive mode disappear after a normal reboot.

## Supported build

The runner refuses any fingerprint other than the one tested:

| Item | Tested value |
|---|---|
| Model | SHARP AQUOS wish3 SH-53D |
| Build | `38JP_1_30I` |
| Fingerprint | `DOCOMO/SH-53D/SH-53D:13/TP1A.220624.014/38JP_1_30I:user/release-keys` |
| Android | 13 |
| Security patch | 2023-12-05 |
| Kernel | Linux 4.19.191+, arm64 |
| SoC | MediaTek MT6833 |

It was verified on the physical device on 2026-09-12. Kernel addresses and
race parameters are specific to this build. Running it on another build can
panic the kernel or corrupt memory. Use it only on a device you own and can
recover.

## Build

Android NDK r26d with the API 31 aarch64 compiler is the tested toolchain.

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk-r26d
./build.sh
```

The four binaries and `SHA256SUMS` are written to `dist/`.

## Run

Enable USB debugging, connect exactly one SH-53D, and run:

```sh
./run.sh
```

The script checks the exact build fingerprint, performs a clean reboot,
uploads files only under `/data/local/tmp`, resolves the per-boot KASLR slide,
and runs up to 12 race attempts. A race miss is handled by the attempt
supervisor; a kernel panic requires another run after the device reboots.

After success:

```sh
adb shell -t /data/local/tmp/sh53d-root
adb shell /data/local/tmp/sh53d-root -c 'id; getenforce'
```

Reboot when finished:

```sh
adb reboot
```

## Exploit chain

The first payload samples the accessible tracefs
`sched_blocked_reason` raw event to resolve the randomized kernel base. The
second stage adapts GhostLock (CVE-2026-43499) to the vendor 4.19 kernel and
uses a per-file `file_operations` target. A two-stage splice first proves an
arbitrary read primitive, then changes `FMODE_CAN_WRITE` to obtain arbitrary
kernel read/write. The payload patches only the current process credentials,
locates `selinux_state` by validating its linked 4.19 `avc` and policy-state
objects, changes its enforcing byte to zero, and starts a root command daemon.
The exploited file's original operations pointer and flags are restored
before completion.

The code deliberately avoids vendor KDP-protected security pointer writes;
those writes panic this device. SELinux remains permissive only until reboot.

## Provenance and license

This port builds on the GhostLock proof of concept and later Linux 4.19 and
Samsung M53 adaptations listed in [NOTICE](NOTICE). It is released under the
Apache License 2.0; see [LICENSE](LICENSE).
