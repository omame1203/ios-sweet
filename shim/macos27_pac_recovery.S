/* Exception-site-isolated AArch64 ID-register reads. NEVER invoked by
 * default shim; gated identically to the C implementation. Test instruction
 * and label identity with the AArch64 disassembler before any integration.
 *
 * The exception hook only modifies ELR_EL1 to skip precisely the MRS; the
 * assembly reads trap_mask before it can use x10 or store the read result.
 * x10 may be UNDEFINED after trapped MRS; the branch prevents its use.
 */
#if defined(__aarch64__) && \
    defined(MAC27_PAC_RECOVERY_ENABLE) && MAC27_PAC_RECOVERY_ENABLE == 1 && \
    defined(MAC27_PAC_RECOVERY_HANDLER_WIRED) && MAC27_PAC_RECOVERY_HANDLER_WIRED == 1
    .text
    .balign 4
    .global mac27_pac_recovery_read_isar1
    .type mac27_pac_recovery_read_isar1, %function
mac27_pac_recovery_read_isar1:
    mov     w9, #1
    str     w9, [x0, #20]       /* p->stage = 1 */
    .global mac27_pac_recovery_mrs_isar1
mac27_pac_recovery_mrs_isar1:
    mrs     x10, ID_AA64ISAR1_EL1
    ldr     w11, [x0, #24]      /* p->trap_mask */
    tbnz    w11, #0, 1f         /* fault? DO NOT consume x10 */
    str     x10, [x0, #0]       /* valid, direct observation */
    ldr     w11, [x0, #28]
    orr     w11, w11, #1
    str     w11, [x0, #28]      /* p->observed_mask |= 1 */
    mov     w0, #0
    ret
1:
    mov     w0, #1
    ret
    .size mac27_pac_recovery_read_isar1, .-mac27_pac_recovery_read_isar1

    .balign 4
    .global mac27_pac_recovery_read_isar2
    .type mac27_pac_recovery_read_isar2, %function
mac27_pac_recovery_read_isar2:
    mov     w9, #2
    str     w9, [x0, #20]       /* p->stage = 2 */
    .global mac27_pac_recovery_mrs_isar2
mac27_pac_recovery_mrs_isar2:
    mrs     x10, ID_AA64ISAR2_EL1
    ldr     w11, [x0, #24]
    tbnz    w11, #1, 2f         /* fault? DO NOT consume x10 */
    str     x10, [x0, #8]
    ldr     w11, [x0, #28]
    orr     w11, w11, #2
    str     w11, [x0, #28]
    mov     w0, #0
    ret
2:
    mov     w0, #1
    ret
    .size mac27_pac_recovery_read_isar2, .-mac27_pac_recovery_read_isar2
#endif
