#ifndef DIZI_MACOS27_PAC_RECOVERY_H
#define DIZI_MACOS27_PAC_RECOVERY_H

/*
 * OPTIONAL, EL1-only, READ-ONLY ID-register exception recovery prototype.
 * This does not initialize PAC keys, sign fixups, or jump to Apple XNU.
 *
 * Compile BOTH C and .S with:
 *   -DMAC27_PAC_RECOVERY_ENABLE=1
 *   -DMAC27_PAC_RECOVERY_HANDLER_WIRED=1
 * ONLY after exc_handler(slot, regs) actually calls the hook and a dedicated
 * exception/reentrancy policy has been reviewed. Any missing macro (or a
 * non-AArch64 target) leaves the probe hard-disabled.
 *
 * Existing shim/start.S saves GPRs to uint64_t regs[32], vector slot 4
 * identifies CURRENT EL / SPx / synchronous exception; slot 5 is IRQ.
 * AArch64 system-register traps from EL1 may instead be directed to EL2,
 * or a missing register can generate EC=UNKNOWN; neither is recoverable by
 * this hook. It must NOT be advertised as generally trap-safe on Gunyah.
 *
 * The C pure planner is for host testing only. Supplying fabricated PCs /
 * ESR / ISAR fields cannot attest real CPU capability.
 */
#include <stdint.h>

#define MAC27_PAC_RECOVERY_SLOT_EL1_SPX_SYNC UINT64_C(4)
#define MAC27_PAC_RECOVERY_ESR_SYSREG_EC UINT64_C(0x18)
#define MAC27_PAC_RECOVERY_ESR_IL UINT64_C(0x02000000)
#define MAC27_PAC_RECOVERY_TRAP_ISAR1 UINT32_C(1)
#define MAC27_PAC_RECOVERY_TRAP_ISAR2 UINT32_C(2)
#define MAC27_PAC_RECOVERY_COMPLETE UINT32_C(3)

enum mac27_pac_recovery_status {
    MAC27_PAC_RECOVERY_OK = 0,
    MAC27_PAC_RECOVERY_DISABLED = 1,
    MAC27_PAC_RECOVERY_TRAPPED = 2,
    MAC27_PAC_RECOVERY_BAD_ARGUMENT = 3,
    MAC27_PAC_RECOVERY_WRONG_EL = 4,
    MAC27_PAC_RECOVERY_BUSY = 5
};

/* Offsets 0,8 are used by the dedicated .S routines; keep in sync.
 * The probe's return status is NOT evidence that the EL2/EL3 PAC policy
 * permits actual authenticated Apple kernel pointers.
 */
struct mac27_pac_recovery_state {
    uint64_t isar1;           /* +0: written ONLY after successful mrs */
    uint64_t isar2;           /* +8: written ONLY after successful mrs */
    uint32_t armed;           /* +16: 1 only while the EL1 probe runs */
    uint32_t stage;           /* +20: exactly 1 or 2 for intended mrs */
    uint32_t trap_mask;       /* +24: bit n set by matching EL1 trap */
    uint32_t observed_mask;   /* +28: bit n set only on real read success */
    uint32_t native_boot_ready; /* +32: ALWAYS 0 */
    uint32_t reserved;        /* +36 */
};

struct mac27_pac_recovery_sites {
    uint64_t isar1_mrs_pc;  /* exact address of dedicated MRS instruction */
    uint64_t isar2_mrs_pc;
};

/*
 * ESR ISS for MRS Xt,ID_AA64ISAR{1,2}_EL1: EC=0x18, IL=1,
 * op0=3,op1=0,CRn=0,CRm=6,op2=1/2,Rt=10,direction=READ.
 * Mismatched ISS, wrong PC, wrong stage, wrong slot or duplicate traps MUST
 * return 0 without mutating state or *resume_pc. Never swallow other faults.
 */
uint64_t mac27_pac_recovery_expected_esr(unsigned which);
int mac27_pac_recovery_plan(struct mac27_pac_recovery_state *state,
                            const struct mac27_pac_recovery_sites *sites,
                            uint64_t slot, uint64_t esr, uint64_t fault_pc,
                            uint64_t *resume_pc);

/*
 * Integration API for EXISTING shim.c's exc_handler(slot, regs):
 *
 *     if (mac27_pac_recovery_exc_handler(slot, regs)) return;
 *
 * Place it BEFORE any general panic/IRQ logic. Hook returns 1 ONLY for its
 * own validated EL1/SPx synchronous MRS fault; it reads ESR_EL1/ELR_EL1,
 * marks trap_mask, and writes ELR_EL1 = exact fault-PC + 4. The assembly
 * function immediately tests trap_mask before consuming its MRS target x10.
 * On every unrelated fault the hook returns 0 and NEVER writes ELR_EL1.
 * No source/build/exception-vector integration is performed by this task.
 */
int mac27_pac_recovery_exc_handler(uint64_t slot, uint64_t *regs);

/*
 * Never called automatically. Caller must independently establish CPU0/EL1
 * single-PE ownership, stack/vector readiness, and no concurrent probe;
 * no software can promise to recover traps routed to EL2 on this hardware.
 * Returns DISABLED by default, ZEROES output on disabled/failure, returns
 * TRAPPED if either isolated MRS failed (trap bits retained for diagnostics).
 */
enum mac27_pac_recovery_status mac27_pac_recovery_sample(
    struct mac27_pac_recovery_state *out, uint32_t explicit_request);

#endif
