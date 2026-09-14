#!/usr/bin/env bash
set -euo pipefail

: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to Android NDK r26d or newer.}"
make clean
make -j"$(getconf _NPROCESSORS_ONLN)"
sha256sum out/preload-sh53d-38JP_3_330.so
