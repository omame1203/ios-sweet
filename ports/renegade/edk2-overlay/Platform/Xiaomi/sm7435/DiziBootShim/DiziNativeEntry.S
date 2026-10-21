/*
 * Real native first-PC Linux ARM64 Image for Xiaomi dizi / Qualcomm SM7435.
 *
 * ABL enters at first instruction at kernel Image load PA; x0=physical FDT,
 * x1=x2=x3=0 per ARM64 Linux boot ABI. Preserving x0 is mandatory for
 * eventual QcomPkg/PrePi/_ModuleEntryPoint.
 *
 * IMPORTANT: This deliberately does NOT enter EDK2. The real Qcom PrePi
 * first unconditional write is [PcdDeviceTreeStore] = [0x90400000]; it also
 * changes vectors at 0x90401000 and clears stack at 0x90fc0000. Neither
 * those PAs nor the 0x90000000/4MiB FD have independent live dizi/Gunyah
 * ownership/XPU/EL2-stage2 attestation. A B/BR to PrePi would be unsafe.
 *
 * This image genuinely executes architectural checks as its first-PC code.
 * No stack, absolute address, FDT dereference, FD copy or cache ops.
 * Only privileged state write is architected PSTATE.DAIFSET to mask
 * asynchronous exceptions BEFORE any physical access; it writes NO RAM.
 * x0..x3 kept intact; x14=original DAIF, x15=SCTLR_EL1 (EL1 only), x17=CurrentEL,
 * x16=terminal reason code (see DiziNativeEntry.h). All exits park using
 * WFE and unconditional B (safe without any writable RAM).
 *
 * Do not call this image a UEFI bootable wrapper. Separate independent
 * live owner evidence and a reviewed relocatable SEC loader are required.
 */
#include "DiziNativeEntry.h"

.section .text.head, "ax", %progbits
.balign DIZI_NATIVE_PAGE_BYTES
.global dizi_native_image_header
.type dizi_native_image_header, %function
dizi_native_image_header:
    b       dizi_native_first_pc              // code0 (EXACT AArch64 entry)
    .long   0                                 // code1
    .quad   0                                 // text_offset: 0
    .quad   __dizi_native_image_end - dizi_native_image_header  // image_size
    .quad   DIZI_NATIVE_IMAGE_FLAGS           // LE, 4K pages, anywhere
    .quad   0                                 // reserved 2
    .quad   0                                 // reserved 3
    .quad   0                                 // reserved 4
    .ascii  "ARM\x64"                         // ARM64 Linux Image magic
    .long   0                                 // reserved 5 / no PE COFF
.size dizi_native_image_header, .-dizi_native_image_header

.section .text.native, "ax", %progbits
.balign 64
.global dizi_native_first_pc
.type dizi_native_first_pc, %function
dizi_native_first_pc:
    /* x0..x3 MUST NOT be clobbered: potential physical FDT still in x0.
       No SP, memory, secure MMIO, TLBI, cache maintenance or indirect BR. */
    mrs     x14, DAIF                         // observe ABL interrupt mask
    msr     DAIFSet, #0xf                     // mask IRQ/FIQ/SError/debug
    mov     x16, #DIZI_NATIVE_REASON_BAD_FDT_X0
    cbz     x0, dizi_native_park

    /* An ARM64 FDT physical address must be at least 8-byte aligned. */
    mov     x16, #DIZI_NATIVE_REASON_FDT_ALIGNMENT
    tst     x0, #7
    b.ne    dizi_native_park

    mov     x16, #DIZI_NATIVE_REASON_NONZERO_X1
    cbnz    x1, dizi_native_park
    mov     x16, #DIZI_NATIVE_REASON_NONZERO_X2
    cbnz    x2, dizi_native_park
    mov     x16, #DIZI_NATIVE_REASON_NONZERO_X3
    cbnz    x3, dizi_native_park

    /* The real captured dizi diagnostic ran as EL1. EL2 is supported by
       Linux's ABI but NOT verified as a dizi EDK2 SEC transfer target. */
    mov     x16, #DIZI_NATIVE_REASON_WRONG_EL
    mrs     x17, CurrentEL
    cmp     x17, #4  // CurrentEL == EL1 << 2
    b.ne    dizi_native_park

    /* Kernel.org arm64 boot protocol also requires interrupts masked
       ON ENTRY. DAIFSET above safely masks them, but never retroactively
       treats an incorrect incoming state as a valid PrePi handoff. */
    mov     x16, #DIZI_NATIVE_REASON_IRQ_UNMASKED
    tbz     x14, #7, dizi_native_park
    mov     x16, #DIZI_NATIVE_REASON_FIQ_UNMASKED
    tbz     x14, #6, dizi_native_park

    /* Reading SCTLR_EL1 does not change the MMU or translation regime.
       A previous dizi ABL diagnostic observed M=1 (possibly enabled).
       The port must not blindly turn it off or assume identity mapping. */
    mrs     x15, SCTLR_EL1
    mov     x16, #DIZI_NATIVE_REASON_EL1_MMU_ON
    tbnz    x15, #0, dizi_native_park
    mov     x16, #DIZI_NATIVE_REASON_EL1_DCACHE_ON
    tbnz    x15, #2, dizi_native_park
    mov     x16, #DIZI_NATIVE_REASON_EL1_ICACHE_ON
    tbnz    x15, #12, dizi_native_park

    /* All register checks passed. Still NO executable FD or memory grant. */
    mov     x16, #DIZI_NATIVE_REASON_NO_OWNER
    b       dizi_native_park

.global dizi_native_park
dizi_native_park:
    wfe
    b       dizi_native_park
.size dizi_native_first_pc, .-dizi_native_first_pc

.section .note.GNU-stack,"",%progbits
