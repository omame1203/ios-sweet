#include "macos27_pac_recovery.h"
#include <stddef.h>

#if defined(__aarch64__) && \
    defined(MAC27_PAC_RECOVERY_ENABLE) && MAC27_PAC_RECOVERY_ENABLE == 1 && \
    defined(MAC27_PAC_RECOVERY_HANDLER_WIRED) && MAC27_PAC_RECOVERY_HANDLER_WIRED == 1
#define REAL_EL1_ENABLED 1
#else
#define REAL_EL1_ENABLED 0
#endif

_Static_assert(offsetof(struct mac27_pac_recovery_state, isar1) == 0, "ISAR1 assembler offset");
_Static_assert(offsetof(struct mac27_pac_recovery_state, isar2) == 8, "ISAR2 assembler offset");
_Static_assert(offsetof(struct mac27_pac_recovery_state, armed) == 16, "arm assembler offset");
_Static_assert(offsetof(struct mac27_pac_recovery_state, stage) == 20, "stage assembler offset");
_Static_assert(offsetof(struct mac27_pac_recovery_state, trap_mask) == 24, "trap assembler offset");
_Static_assert(offsetof(struct mac27_pac_recovery_state, observed_mask) == 28, "observed assembler offset");

static void clear_state(struct mac27_pac_recovery_state *p)
{
    p->isar1 = p->isar2 = 0;
    p->armed = p->stage = p->trap_mask = p->observed_mask = 0;
    p->native_boot_ready = p->reserved = 0;
}

uint64_t mac27_pac_recovery_expected_esr(unsigned which)
{
    if (which != 1 && which != 2) return 0;
    /*
     * Linux arch/arm64/include/asm/esr.h ESR_ELx_SYS64_ISS_*:
     * EC[31:26] = 0x18, IL[25] = 1, SYS64 ISS op0[21:20],
     * op2[19:17], op1[16:14], CRn[13:10], Rt[9:5], CRm[4:1], DIR[0].
     * Dedicated assembly uses Rt=x10. bit[24:22] must be zero.
     */
    return (MAC27_PAC_RECOVERY_ESR_SYSREG_EC << 26) |
           MAC27_PAC_RECOVERY_ESR_IL |
           (UINT64_C(3) << 20) | ((uint64_t)which << 17) |
           (UINT64_C(10) << 5) | (UINT64_C(6) << 1) | UINT64_C(1);
}

int mac27_pac_recovery_plan(struct mac27_pac_recovery_state *p,
                            const struct mac27_pac_recovery_sites *sites,
                            uint64_t slot, uint64_t esr, uint64_t pc,
                            uint64_t *resume_pc)
{
    unsigned which;
    uint32_t bit;
    if (!p || !sites || !resume_pc ||
        slot != MAC27_PAC_RECOVERY_SLOT_EL1_SPX_SYNC ||
        p->armed != 1 || (p->stage != 1 && p->stage != 2) ||
        (pc & 3u) || pc > UINT64_MAX - 4 ||
        !sites->isar1_mrs_pc || !sites->isar2_mrs_pc ||
        (sites->isar1_mrs_pc & 3u) || (sites->isar2_mrs_pc & 3u) ||
        sites->isar1_mrs_pc == sites->isar2_mrs_pc)
        return 0;
    which = (unsigned)p->stage;
    bit = which == 1 ? MAC27_PAC_RECOVERY_TRAP_ISAR1 :
                       MAC27_PAC_RECOVERY_TRAP_ISAR2;
    if (pc != (which == 1 ? sites->isar1_mrs_pc : sites->isar2_mrs_pc) ||
        esr != mac27_pac_recovery_expected_esr(which) ||
        (p->trap_mask & bit) || (p->observed_mask & bit) ||
        (p->trap_mask | p->observed_mask) & ~MAC27_PAC_RECOVERY_COMPLETE ||
        p->native_boot_ready)
        return 0;
    /* This exact probe MRS is the only instruction allowed to be skipped.
     * The caller's existing vector must subsequently ERET (not branch).
     * EL2 traps never reach this EL1 handler. */
    p->trap_mask |= bit;
    *resume_pc = pc + 4;
    return 1;
}

#if REAL_EL1_ENABLED
/* Standalone opt-in assembly entry points and instruction labels. */
extern uint8_t mac27_pac_recovery_mrs_isar1[];
extern uint8_t mac27_pac_recovery_mrs_isar2[];
extern unsigned mac27_pac_recovery_read_isar1(struct mac27_pac_recovery_state *);
extern unsigned mac27_pac_recovery_read_isar2(struct mac27_pac_recovery_state *);
static struct mac27_pac_recovery_state *volatile active;
#endif

int mac27_pac_recovery_exc_handler(uint64_t slot, uint64_t *regs)
{
#if REAL_EL1_ENABLED
    struct mac27_pac_recovery_state *p = active;
    struct mac27_pac_recovery_sites sites;
    uint64_t esr, elr, resume = 0;
    if (!regs || !p || slot != MAC27_PAC_RECOVERY_SLOT_EL1_SPX_SYNC)
        return 0;
    __asm__ volatile ("mrs %0, ESR_EL1" : "=r"(esr));
    __asm__ volatile ("mrs %0, ELR_EL1" : "=r"(elr));
    sites.isar1_mrs_pc = (uint64_t)(uintptr_t)mac27_pac_recovery_mrs_isar1;
    sites.isar2_mrs_pc = (uint64_t)(uintptr_t)mac27_pac_recovery_mrs_isar2;
    if (!mac27_pac_recovery_plan(p, &sites, slot, esr, elr, &resume))
        return 0;
    /* ONLY accepted MRS site, with matching ESR, advances ELR_EL1.
     * Never set PAC keys/SCTLR/HCR, never authorize native XNU execution. */
    __asm__ volatile ("msr ELR_EL1, %0" : : "r"(resume) : "memory");
    return 1;
#else
    (void)slot;
    (void)regs;
    return 0;
#endif
}

enum mac27_pac_recovery_status mac27_pac_recovery_sample(
    struct mac27_pac_recovery_state *out, uint32_t request)
{
    if (!out) return MAC27_PAC_RECOVERY_BAD_ARGUMENT;
#if REAL_EL1_ENABLED
    /* A reentrant request must not zero or corrupt the active session,
     * even if it supplies the same pointer as the ongoing probe. */
    if (active) return MAC27_PAC_RECOVERY_BUSY;
#endif
    clear_state(out);
    if (request != 1) return MAC27_PAC_RECOVERY_DISABLED;
#if REAL_EL1_ENABLED
    uint64_t current_el;
    unsigned failed1, failed2;
    __asm__ volatile ("mrs %0, CurrentEL" : "=r"(current_el));
    if (current_el != UINT64_C(4)) return MAC27_PAC_RECOVERY_WRONG_EL;
    /* Global session is intentionally SINGLE-CORE and non-reentrant; a
     * caller must mask interrupts and prevent other PEs invoking this API.
     * No implicit DAIF writes, no EL1/EL2 vector changes are made. */
    out->armed = 1;
    active = out;
    failed1 = mac27_pac_recovery_read_isar1(out);
    failed2 = mac27_pac_recovery_read_isar2(out);
    active = NULL;
    out->stage = out->armed = 0;
    if (failed1 || failed2 || out->trap_mask) {
        /* Trap bits are diagnostic only, never synthetic feature values. */
        if (failed1) out->isar1 = 0;
        if (failed2) out->isar2 = 0;
        return MAC27_PAC_RECOVERY_TRAPPED;
    }
    return MAC27_PAC_RECOVERY_OK;
#else
    return MAC27_PAC_RECOVERY_DISABLED;
#endif
}
