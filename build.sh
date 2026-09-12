#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  echo "ANDROID_NDK_HOME must point to Android NDK r26d (tested)." >&2
  exit 1
fi

make clean all
