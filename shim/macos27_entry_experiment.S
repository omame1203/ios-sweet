/* Dedicated EL1 experiment; assembled only on explicit dual opt-in. C calls
 * this AFTER copying a pinned authentic KC and instrumenting its bootstrap
 * target with BRK. BR X1 reaches the ORIGINAL, unchanged Apple entry B;
 * that branch reaches BRK, which ERET returns here. No XNU OSLAR or HVC.
 */
#if defined(__aarch64__) && \
    defined(DIZI_MACOS27_XNU_ENTRY_EXPERIMENT) && DIZI_MACOS27_XNU_ENTRY_EXPERIMENT == 1 && \
    defined(MAC27_ENTRY_EXPERIMENT_HANDLER_WIRED) && MAC27_ENTRY_EXPERIMENT_HANDLER_WIRED == 1
    .text
    .balign 4
    .global mac27_entry_experiment_trampoline
    .type mac27_entry_experiment_trampoline, %function
mac27_entry_experiment_trampoline:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    /* x0=zero or preverified physical 1152-byte bootargs (not used by B)
     * x1=verified original B VA in physically owned, executable RAM. */
    br x1
    .global mac27_entry_experiment_resume
mac27_entry_experiment_resume:
    mov w0, #1
    ldp x29, x30, [sp], #16
    ret
    .size mac27_entry_experiment_trampoline, .-mac27_entry_experiment_trampoline
#endif
