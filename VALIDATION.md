# SH-53D 38JP_3_330 physical-device validation

Validation date: 2026-09-14
Fingerprint: `DOCOMO/SH-53D/SH-53D:15/AP3A.240905.015.A2/38JP_3_330:user/release-keys`

The first successful fresh boot used boot ID
`7b71eebc-2d7f-48c0-a67d-18bf29aa1022`. It began in `uid=2000(shell)` and
SELinux `Enforcing`, and used the default target values with no timing or
address override.

- Kernel offsets matched the exact uname.
- KernelSnitch reported `futex_hashsize 2048 (8 possible CPUs)`.
- W1 accepted on attempt 1 and the kernel reported `SELinux DISABLED`.
- perf found the child task at `0xffffff80440ccb00`.
- W2 accepted on round 4; the child reported `uid=0`.
- Total exploit time was 88,628 ms.
- The embedded daemon was installed and answered from a separate ordinary ADB
  shell.

Independent command verification:

```text
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
Permissive
```

Interactive PTY verification:

```text
SH-53D:/ # id; getenforce; pwd
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
Permissive
/
SH-53D:/ #
```

Artifact:

```text
a3a41a6c29b53eec429cb20acfda3e56c50f6e921af3a9e40c86fb4dd87feb01  preload-sh53d-38JP_3_330.so
```

The same artifact was exercised again on boot ID
`4cac80d4-1fcd-47c7-b3a1-9ee2e41c65a0`. One complete invocation safely
missed all five W1 attempts; the next invocation accepted W1 on attempt 4 and
W2 on round 1, reaching root and permissive in 62,994 ms. This is the artifact
shipped by the branch.

Two trials of an intermediate artifact (SHA-256
`3113925c56ad3a2ccc477b68dcc2b58fc08eeb72a7f166487902537ff528d574`)
rebooted at the first W1 pselect call. That artifact is not shipped. The
one-source-line difference was only the physical-load alignment diagnostic,
so causality is unproven; the result is retained as evidence that race panic
remains possible.

The runner makes up to three complete invocations so a safe full-run miss does
not require manual re-execution. If the kernel reboots, it waits for Android,
reinstalls the same artifact, and continues without issuing a reboot command.
