.section .rodata
.balign 16

/* .hidden, which warhol-root does not need: this build compiles with
 * -fvisibility=hidden so the LD_PRELOAD library exports nothing into the host
 * process, and that flag governs C codegen only -- an assembler .global stays
 * exported. Without these two lines the blob bounds would be the only symbols
 * the library still puts in the host's global lookup. */
.global embedded_su_start
.hidden embedded_su_start
.type embedded_su_start, %object
embedded_su_start:
.incbin "build/embed/su_daemon_aarch64_pie"

.global embedded_su_end
.hidden embedded_su_end
.type embedded_su_end, %object
embedded_su_end:
.byte 0
