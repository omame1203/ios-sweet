/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Real branch into TianoCore's AArch64 FV reset vector, compiled ONLY with
 * externally audited/linked EL2/XPU owner. x0 physical FDT, x1 FD PA.
 * Does not relocate the FV nor silently guess the donor SEC ABI.
 */
.section .text.dizi_sec_enter,"ax",%progbits
.p2align 4
.global DiziSecEnterPrePi
.type DiziSecEnterPrePi,%function
DiziSecEnterPrePi:
#if defined(DIZI_SEC_ENABLE) && DIZI_SEC_ENABLE == 1 && \
    defined(DIZI_SEC_TRUSTED_OWNER_IMPLEMENTED) && \
    DIZI_SEC_TRUSTED_OWNER_IMPLEMENTED == 1
    /* A verified external owner established identical physical addressing,
     * exclusive FD/FDT/vector/stack RAM and valid caches before this call. */
    msr daifset, #0xf
    mov x16, x1
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    dsb sy
    isb
    br x16
#endif
.Ldizi_sec_park:
    wfe
    b .Ldizi_sec_park
.size DiziSecEnterPrePi, .-DiziSecEnterPrePi
.section .note.GNU-stack,"",%progbits
