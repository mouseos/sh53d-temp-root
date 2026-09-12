API ?= 31
HOST_TAG ?= linux-x86_64
TARGET := sh53d-prewake-linearmap-auto-root-nomut
TARGET_HEADER := src/targets/$(TARGET)/target.h
TARGET_INCLUDE := targets/$(TARGET)/target.h
CC := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(HOST_TAG)/bin/aarch64-linux-android$(API)-clang
DIST := dist
COMMON_SRCS := src/main.c src/util.c src/fops.c src/pipe.c src/root_m53.c src/preload.c
COMMON_FLAGS := -O2 -g0 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Isrc -DTARGET_HEADER='"$(TARGET_INCLUDE)"'

ifeq ($(wildcard $(CC)),)
$(error Set ANDROID_NDK_HOME to an Android NDK containing $(CC))
endif

.PHONY: all clean checksums
all: $(DIST)/sh53d-slide.so $(DIST)/sh53d-exploit.so $(DIST)/sh53d-root $(DIST)/sh53d-launcher.so checksums

$(DIST):
	mkdir -p $@

$(DIST)/sh53d-slide.so: $(COMMON_SRCS) src/slide.c $(TARGET_HEADER) src/targets/sh53d-prewake-linearmap-auto-root/target.h src/targets/sh53d-prewake-linearmap-auto-sweep/target.h src/common.h src/offset.h src/kernelsnitch/*.h | $(DIST)
	$(CC) -fPIC $(COMMON_FLAGS) $(COMMON_SRCS) src/slide.c -shared -pthread -o $@

$(DIST)/sh53d-exploit.so: $(COMMON_SRCS) src/slide_app.c $(TARGET_HEADER) src/targets/sh53d-prewake-linearmap-auto-root/target.h src/targets/sh53d-prewake-linearmap-auto-sweep/target.h src/common.h src/offset.h src/kernelsnitch/*.h | $(DIST)
	$(CC) -DAPP_PAYLOAD=1 -fPIC $(COMMON_FLAGS) $(COMMON_SRCS) src/slide_app.c -shared -pthread -o $@

$(DIST)/sh53d-root: src/su_daemon.c $(TARGET_HEADER) src/targets/sh53d-prewake-linearmap-auto-root/target.h src/targets/sh53d-prewake-linearmap-auto-sweep/target.h | $(DIST)
	$(CC) -fPIE -pie -O2 -g0 -Wall -Wextra -Isrc -DTARGET_HEADER='"$(TARGET_INCLUDE)"' $< -ldl -o $@

$(DIST)/sh53d-launcher.so: tools/launch_old_filetarget.c | $(DIST)
	$(CC) -fPIC -shared -O2 -Wall -Wextra $< -o $@

checksums: $(DIST)/sh53d-slide.so $(DIST)/sh53d-exploit.so $(DIST)/sh53d-root $(DIST)/sh53d-launcher.so
	cd $(DIST) && sha256sum sh53d-slide.so sh53d-exploit.so sh53d-root sh53d-launcher.so > SHA256SUMS

clean:
	rm -rf $(DIST)
