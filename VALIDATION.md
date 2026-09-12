# SH-53D physical-device validation

Validation date: 2026-09-12  
Device build: `38JP_1_30I`  
Fingerprint: `DOCOMO/SH-53D/SH-53D:13/TP1A.220624.014/38JP_1_30I:user/release-keys`

The host prepared a fresh boot before each trial. The measured command was:

```sh
/usr/bin/time -p ./run.sh
```

`run.sh` itself does not reboot the device. Success requires its final daemon
marker, an uid-0 command shell, and SELinux permissive mode.

| Trial | Boot ID | Stage 1 accepted | Root accepted | Wall time |
|---|---|---:|---:|---:|
| 1 | `11e8a6ed-8c6d-4a81-8079-cebaf8aed0fe` | attempt 1 | attempt 3 | 155.96 s |
| 2 | `b3a1fac2-f289-40a8-87dc-493e28b755da` | attempt 1 | attempt 7 | 322.11 s |

Both trials ended with:

```text
root permissive daemon enforcing=0 ready=1
uid=0(root) gid=0(root) ... context=u:r:shell:s0
Permissive
```

Artifact SHA-256 values:

```text
6273e35af10a6c044c2f364334100ae15131b80444eedd2ba8f214b6fd300b78  sh53d-slide.so
c851e9c05b649d552b4eea12be47d18ccc6f694936b7ba4692e3ac58d53d38ac  sh53d-exploit.so
2a22c13c3414d74569b61650cf5370bcb2f6cdf126203cf70036b45681430f04  sh53d-root
91da4afcf606558b9e608e44e3dcb4f7b49310aec715ccde3cd2f2c2585fa1fa  sh53d-launcher.so
```

The timing reductions keep the exploit acceptance checks intact. They reduce
the boot-quiet floor from 120 to 60 seconds, wait one second after all
KernelSnitch waiter threads report ready, use 8/1 timing samples, and remove
the fixed five-second pause between safe misses. A 15-second futex route was
rejected after 0 oracle hits in 7 attempts; the device-validated 25-second
route remains in use.
