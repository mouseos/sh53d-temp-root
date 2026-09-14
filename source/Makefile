API ?= 34
OUTDIR ?= build/bin
EMBEDDIR ?= build/embed

# The staged per-device headers. Both come from ../targets/<device>/ and are
# gitignored here, so a build can never silently use the previous device's.
TARGET_HEADER  ?= src/target.h
DEVICE_OFFSETS ?= src/device_offsets.h

# su_daemon.c is built as a standalone aarch64 PIE and then pulled into the
# library's .rodata by su_blob.S (.incbin), so the su binary ships inside
# preload.so instead of being a second file to push. warhol-root's route.
EMBED_SU := $(EMBEDDIR)/su_daemon_aarch64_pie
PRELOAD := $(OUTDIR)/preload.so

CORE_SRCS := \
  src/main.c \
  src/util.c \
  src/slide.c \
  src/fops.c \
  src/pipe.c \
  src/root.c \
  src/miniadb.c
PRELOAD_SRCS := $(CORE_SRCS) src/preload.c src/su_install.c src/su_blob.S

.DEFAULT_GOAL := preload

# Toolchain selection is warhol-root's, plus $(HOME)/Android/Sdk/ndk/* — the
# Linux Android Studio location, which its Darwin-only wildcard misses.
DEFAULT_NDK_ROOT := $(HOME)/android-ndk-cache/android-ndk-r29
LINUX_SDK_NDK_ROOT := $(lastword $(sort $(wildcard $(HOME)/Android/Sdk/ndk/*)))
DARWIN_NDK_ROOT := $(lastword $(sort $(wildcard $(HOME)/Library/Android/sdk/ndk/*)))
NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT),$(wildcard $(DEFAULT_NDK_ROOT)),$(LINUX_SDK_NDK_ROOT),$(DARWIN_NDK_ROOT))
NDK_PREBUILT := $(if $(filter Darwin,$(shell uname -s)),darwin-x86_64,linux-x86_64)
NDK_TOOLCHAIN ?= $(if $(NDK_ROOT),$(NDK_ROOT)/toolchains/llvm/prebuilt/$(NDK_PREBUILT))
NDK_CC := $(NDK_TOOLCHAIN)/bin/aarch64-linux-android$(API)-clang
HOST_CLANG ?= clang
SYSROOT ?= $(if $(NDK_TOOLCHAIN),$(NDK_TOOLCHAIN)/sysroot)
RESOURCE_DIR ?= $(if $(NDK_TOOLCHAIN),$(NDK_TOOLCHAIN)/lib/clang/21)

HOST_TARGET_FLAGS := \
  --target=aarch64-linux-android$(API) \
  --sysroot=$(SYSROOT) \
  -resource-dir $(RESOURCE_DIR) \
  --rtlib=compiler-rt \
  --unwindlib=none
HOST_COMMON_LDFLAGS := \
  -fuse-ld=lld \
  -Wl,-rpath-link,$(SYSROOT)/usr/lib/aarch64-linux-android/$(API) \
  -L$(SYSROOT)/usr/lib/aarch64-linux-android/$(API) \
  -L$(SYSROOT)/usr/lib/aarch64-linux-android
HOST_PIE_LDFLAGS := \
  $(HOST_COMMON_LDFLAGS) \
  -Wl,-dynamic-linker,/system/bin/linker64

ifneq ($(origin CC),default)
  TARGET_CC := $(CC)
  TARGET_FLAGS :=
  TARGET_COMMON_LDFLAGS :=
  TARGET_PIE_LDFLAGS :=
else ifneq ($(wildcard $(NDK_CC)),)
  NDK_CC_WORKS := $(shell $(NDK_CC) --version >/dev/null 2>&1 && echo yes)
  ifeq ($(NDK_CC_WORKS),yes)
    TARGET_CC := $(NDK_CC)
    TARGET_FLAGS :=
    TARGET_COMMON_LDFLAGS :=
    TARGET_PIE_LDFLAGS :=
  else
    TARGET_CC := $(HOST_CLANG)
    TARGET_FLAGS := $(HOST_TARGET_FLAGS)
    TARGET_COMMON_LDFLAGS := $(HOST_COMMON_LDFLAGS)
    TARGET_PIE_LDFLAGS := $(HOST_PIE_LDFLAGS)
  endif
else
  TARGET_CC := $(HOST_CLANG)
  TARGET_FLAGS := $(HOST_TARGET_FLAGS)
  TARGET_COMMON_LDFLAGS := $(HOST_COMMON_LDFLAGS)
  TARGET_PIE_LDFLAGS := $(HOST_PIE_LDFLAGS)
endif

# -Wall without warhol-root's -Wextra: this is ghostlock's tree, which is three
# times the size and was never built under it, so -Wextra here is noise rather
# than signal.
COMMON_CFLAGS := -O2 -g0 -Wall -Isrc
PIE_CFLAGS := -fPIE -pie $(COMMON_CFLAGS)
SO_CFLAGS := -fPIC $(COMMON_CFLAGS)
WARN_CFLAGS := -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function
# An LD_PRELOAD library wins symbol lookup for the whole process, so it exports
# nothing: -fvisibility=hidden keeps it from shadowing a same-named symbol in
# the host binary or in libc. (su_blob.S marks its two symbols .hidden by hand —
# this flag governs C codegen only.)
TARGET_CFLAGS := -DTARGET_CONFIG_H=\"target.h\" -DGHOSTLOCK_PRELOAD \
  -fvisibility=hidden $(EXTRA_CFLAGS)

.PHONY: all preload clean info

all: preload

preload: $(TARGET_HEADER) $(DEVICE_OFFSETS) $(PRELOAD)

$(TARGET_HEADER) $(DEVICE_OFFSETS):
	@echo "missing $@ — run make from the top level so it gets staged" >&2
	@false

$(OUTDIR):
	mkdir -p $@

$(EMBEDDIR):
	mkdir -p $@

$(EMBED_SU): src/su_daemon.c | $(EMBEDDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(PIE_CFLAGS) \
	  $< $(TARGET_PIE_LDFLAGS) -o $@

$(PRELOAD): $(PRELOAD_SRCS) $(EMBED_SU) $(TARGET_HEADER) $(DEVICE_OFFSETS) \
            src/offset.h src/offsets.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(SO_CFLAGS) $(WARN_CFLAGS) $(TARGET_CFLAGS) \
	  $(PRELOAD_SRCS) $(TARGET_COMMON_LDFLAGS) \
	  -shared -o $@ -pthread
	sha256sum $@

info:
	@echo "TARGET_HEADER=$(TARGET_HEADER)"
	@echo "DEVICE_OFFSETS=$(DEVICE_OFFSETS)"
	@echo "TARGET_CC=$(TARGET_CC)"
	@echo "TARGET_FLAGS=$(TARGET_FLAGS)"
	@echo "TARGET_COMMON_LDFLAGS=$(TARGET_COMMON_LDFLAGS)"
	@echo "TARGET_PIE_LDFLAGS=$(TARGET_PIE_LDFLAGS)"
	@echo "PRELOAD=$(PRELOAD)"
	@echo "EMBED_SU=$(EMBED_SU)"
	@echo "CORE_SRCS=$(CORE_SRCS)"

clean:
	rm -rf build
