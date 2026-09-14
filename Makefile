# pmg110-root — top-level wrapper around source/Makefile
#
# Same shape as warhol-root: a per-device directory under targets/ holds the
# compile-time headers, and they are staged into source/src/ for the build, so
# a build can never silently pick up headers generated for another device.
#
# Unlike warhol-root, the exploit core here is the ghostlock 6.6 tree rather
# than popsicle: PMG110 runs GKI 6.6/android15, and popsicle's layout is pinned
# to 6.12/android16. Everything around that core is warhol-root's, including the
# su route — su_daemon.c built as a PIE and embedded with .incbin, so root ends
# in a persistent su rather than in a bare "the writes landed".

DEVICE ?= sh53d-38JP_3_330

TARGET_SRC  := targets/$(DEVICE)/target.h
OFFSETS_SRC := targets/$(DEVICE)/device_offsets.h
TARGET_DST  := source/src/target.h
OFFSETS_DST := source/src/device_offsets.h
PRELOAD     := source/build/bin/preload.so

.PHONY: all preload target clean info devices FORCE

all: preload

# re-checked every build, so switching DEVICE cannot leave the previous
# device's headers staged
target: $(TARGET_DST) $(OFFSETS_DST)

$(TARGET_DST): $(TARGET_SRC) FORCE
	@cmp -s $< $@ 2>/dev/null || cp $< $@

$(OFFSETS_DST): $(OFFSETS_SRC) FORCE
	@cmp -s $< $@ 2>/dev/null || cp $< $@

FORCE:

$(TARGET_SRC) $(OFFSETS_SRC):
	@echo "missing $@" >&2
	@echo "generate it first — see tools/extract_device.py" >&2
	@false

preload: target
	$(MAKE) -C source preload
	@mkdir -p out
	cp $(PRELOAD) out/preload-$(DEVICE).so
	@echo "-> out/preload-$(DEVICE).so"

devices:
	@ls targets

info:
	@echo "DEVICE      = $(DEVICE)"
	@echo "TARGET_SRC  = $(TARGET_SRC)"
	@echo "OFFSETS_SRC = $(OFFSETS_SRC)"
	@echo "OUT         = out/preload-$(DEVICE).so"
	@$(MAKE) -C source info

clean:
	$(MAKE) -C source clean
	rm -f $(TARGET_DST) $(OFFSETS_DST)
