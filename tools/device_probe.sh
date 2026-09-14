#!/system/bin/sh
# Pre-flight for a GhostLock port. Run over adb shell as the shell user:
#
#     adb push tools/device_probe.sh /data/local/tmp/probe.sh
#     adb shell sh /data/local/tmp/probe.sh
#
# Reports (1) whether this build matches an offsets.h entry, (2) anything the
# device will tell an unprivileged caller about the physical memory layout,
# which is what P0_KERNEL_PHYS_LOAD needs, and (3) the preconditions the
# exploit assumes.

say() { echo "== $*"; }

say "build"
echo "  uname -r        : $(uname -r)"
echo "  fingerprint     : $(getprop ro.build.fingerprint)"
echo "  product         : $(getprop ro.product.name) / $(getprop ro.product.model)"
echo "  incremental     : $(getprop ro.build.version.incremental)"
echo "  security patch  : $(getprop ro.build.version.security_patch)"
echo "  ota version     : $(getprop ro.build.version.ota)"
echo
echo "  The uname -r string above must appear verbatim in src/devices/*/offsets.h."
echo "  If it does not, the offsets are for a different build and the exploit"
echo "  will refuse to run rather than misfire."

echo
say "physical memory layout (for P0_KERNEL_PHYS_LOAD)"
echo "  -- /proc/zoneinfo start_pfn (gives memstart_addr = P0_PHYS_OFFSET) --"
if [ -r /proc/zoneinfo ]; then
  grep -E "^Node|start_pfn" /proc/zoneinfo 2>/dev/null | head -8 | sed 's/^/  /'
  first=$(grep start_pfn /proc/zoneinfo 2>/dev/null | head -1 | tr -dc '0-9')
  if [ -n "$first" ]; then
    echo "  first start_pfn = $first  ->  phys 0x$(printf '%x' $((first * 4096)))"
  fi
else
  echo "  not readable"
fi

echo "  -- /proc/iomem (needs root; zeros or empty otherwise) --"
if [ -r /proc/iomem ]; then
  grep -iE "kernel code|kernel data|System RAM" /proc/iomem 2>/dev/null | head -8 | sed 's/^/  /'
  [ -z "$(grep -iE 'kernel code' /proc/iomem 2>/dev/null)" ] && echo "  no 'Kernel code' line visible"
else
  echo "  not readable"
fi

echo "  -- dmesg (needs dmesg_restrict=0 or root) --"
dmesg 2>/dev/null | grep -iE "Virtual kernel memory|Memory:|memstart" | head -6 | sed 's/^/  /' \
  || echo "  denied"

echo "  -- device tree memory node --"
for dt in /proc/device-tree /sys/firmware/devicetree/base; do
  if [ -d "$dt" ]; then
    for m in "$dt"/memory*; do
      [ -e "$m/reg" ] && echo "  $m/reg: $(od -An -tx1 "$m/reg" 2>/dev/null | tr -d ' \n')"
    done
  fi
done

echo
echo "  This section is a cross-check, not the primary route. On MediaTek the"
echo "  value is already in the firmware:"
echo "     python3 tools/preloader_memlayout.py preloader_raw.img   ->  mb_kernel.start"
echo "  Elsewhere it has to come from a single rooted read, or be found by"
echo "  trying candidates:"
echo "     GHOSTLOCK_PHYS_LOAD=0x... /data/local/tmp/a/e --write1"
echo "  A wrong value writes to an unrelated physical page: expect a reboot."

echo
say "restrictions"
echo "  kptr_restrict   : $(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)"
echo "  dmesg_restrict  : $(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)"
echo "  perf_event_paranoid: $(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)"
echo "  selinux         : $(getenforce 2>/dev/null)"
echo "  uid             : $(id -u) ($(id -un 2>/dev/null))"

echo
say "exploit preconditions"
for d in /dev/ashmem /dev/ashmem_ctrl; do
  [ -e "$d" ] && echo "  $d present  $(ls -l $d 2>/dev/null)" || echo "  $d MISSING"
done
echo "  configfs        : $(mount 2>/dev/null | grep -c configfs) mount(s)"
echo "  uptime          : $(cut -d' ' -f1 /proc/uptime 2>/dev/null)s"
echo "    (README: run the exploit within ~30s of boot for KernelSnitch timing)"
echo "  ksud            : $(ls /data/adb/ksud /data/adb/ksu/bin/ksud 2>/dev/null | tr '\n' ' ')"
echo "    (without ksud you get uid 0 but no persistent KernelSU)"
