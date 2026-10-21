#ifndef DIZI_MACOS27_ENTRY_EXPERIMENT_H
#define DIZI_MACOS27_ENTRY_EXPERIMENT_H

/* A single original 26A434 ARM64 B instruction, ending at our BRK trap.
 * Nothing here permits continuing the native XNU bootstrap or booting macOS.
 * Default builds contain no KC writes, trampolines or executable XNU path.
 *
 * The live opt-in requires BOTH:
 *   DIZI_MACOS27_XNU_ENTRY_EXPERIMENT=1
 *   MAC27_ENTRY_EXPERIMENT_HANDLER_WIRED=1
 * The second macro is an integration assertion: shim.c's exc_handler MUST
 * call mac27_entry_experiment_exc_handler(slot, regs) before panic handling.
 * Existing start.S gives slot 4 for EL1 SPx synchronous exceptions, and ERET
 * from the shim vector on a handled exception. No vectors are installed here.
 *
 * Responsibility of the integrator: verify by real FDT/platform evidence
 * that the physical window is EXCLUSIVELY owned, writable AND executable;
 * physically reserved DTB, initrd, shim, ramoops, frame buffer and firmware
 * are disjoint; zero-address Linux Image relocation is valid; no EL2/Gunyah
 * trap routing intercepts BRK. These properties cannot be proven by C input
 * flags. A forged attestation is not an acceptable integration.
 */
#include <stddef.h>
#include <stdint.h>

#define MAC27_EXPERIMENT_KC_SIZE UINT32_C(81444864)
#define MAC27_EXPERIMENT_ENTRY_OFFSET UINT32_C(48956544)
#define MAC27_EXPERIMENT_TARGET_OFFSET UINT32_C(48971888)
#define MAC27_EXPERIMENT_BRANCH UINT32_C(0x14000efc)
#define MAC27_EXPERIMENT_ORIGINAL_TARGET UINT32_C(0xd510109f)
#define MAC27_EXPERIMENT_BRK_IMM UINT32_C(0x4e27)
#define MAC27_EXPERIMENT_BRK_WORD (UINT32_C(0xd4200000) | (MAC27_EXPERIMENT_BRK_IMM << 5))
#define MAC27_EXPERIMENT_ESR (UINT64_C(0xf2000000) | MAC27_EXPERIMENT_BRK_IMM)
#define MAC27_EXPERIMENT_DIZI_BASE UINT64_C(0x8c0000000)
#define MAC27_EXPERIMENT_DIZI_SIZE UINT64_C(0xb0000000)
#define MAC27_EXPERIMENT_PAGE UINT64_C(0x4000)

enum mac27_entry_experiment_status {
    MAC27_EXP_TRAPPED_ONE_B = 0,
    MAC27_EXP_DISABLED = 1,
    MAC27_EXP_BAD_INPUT = 2,
    MAC27_EXP_NOT_OWNED = 3,
    MAC27_EXP_WRONG_KC = 4,
    MAC27_EXP_BAD_EL1 = 5,
    MAC27_EXP_BUSY = 6,
    MAC27_EXP_TRAP_NOT_SEEN = 7
};

struct mac27_entry_experiment_request {
    const void *original_kc;   /* readable decompressed 26A434 raw MH_FILESET */
    size_t original_bytes;     /* must be EXACT size, SHA-256 pinned internally */
    void *copy;                /* physical identity-mapped writable/executable RAM */
    size_t copy_capacity;      /* must cover entire raw original KC */
    uint64_t copy_pa;          /* physical address of copy[0] */
    uint64_t owned_pa;         /* independently verified exclusive RAM extent */
    uint64_t owned_bytes;
    uint64_t boot_args_pa;     /* zero or valid 1152-byte owned physical buffer */
    const void *boot_args;     /* NULL when boot_args_pa==0 */
    size_t boot_args_bytes;
    uint32_t explicit_request; /* must be exactly 1 */
    uint32_t exclusive_ram_verified; /* FDT/reservations independently checked */
    uint32_t write_exec_verified;    /* PA and EL1 permission independently checked */
    uint32_t single_cpu_vectors_verified; /* VBAR/DAIF/EL1 ABI and SP ownership */
    uint32_t boot_args_verified;     /* required for nonzero x0 */
};

struct mac27_entry_experiment_trap {
    uint64_t entry_pc;  /* physical identity mapped instruction VA */
    uint64_t target_pc; /* entry_pc + 0x3bf0, BRK is installed here */
    uint64_t resume_pc; /* assembly resume label inside shim */
    uint32_t armed;     /* exactly 1 while trampoline is executing */
    uint32_t hit;       /* becomes 1 on EXACT EL1 synchronous BRK match */
};

/* Pure structural input check; no reads from the full image and NO memory
 * writes. Returning 1 never bypasses the full SHA-256 check in run(). */
int mac27_entry_experiment_validate(const struct mac27_entry_experiment_request *r);

/* Pure host-testable ESR, ELR and slot matcher. All mismatches leave the trap
 * and resume unchanged. Only an exact one-shot trap can set hit=1. */
int mac27_entry_experiment_match_brk(struct mac27_entry_experiment_trap *trap,
                                    uint64_t slot, uint64_t esr, uint64_t elr,
                                    uint64_t *resume_pc);

/* SHA-256 for the exact original raw source; available in disabled builds for
 * offline host verification. Run() pins digest to 26A434 independently. */
void mac27_entry_experiment_sha256(const void *bytes, size_t size, uint8_t out[32]);

/* Disabled unless both macros are 1 on AArch64. On enabled builds this is a
 * PRIVILEGED live experiment: copies the SHA256-pinned KC, replaces ONLY the
 * original first target word with BRK, synchronizes both instruction sites,
 * branches via dedicated trampoline, and returns only after matched EL1 BRK.
 * No caller-provided report can authorize a native XNU boot. */
enum mac27_entry_experiment_status mac27_entry_experiment_run(
    const struct mac27_entry_experiment_request *r);

/* Insert at TOP of existing shim.c exc_handler(slot, regs), compiled with
 * both macros. Returns 0 on unrelated exceptions, without touching ELR_EL1. */
int mac27_entry_experiment_exc_handler(uint64_t slot, uint64_t *regs);

#endif
