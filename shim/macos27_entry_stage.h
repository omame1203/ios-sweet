#ifndef DIZI_MACOS27_ENTRY_STAGE_H
#define DIZI_MACOS27_ENTRY_STAGE_H
#include "../ports/macos27/kc_loader.h"
#include "../ports/macos27/kc_fixups.h"
#include "../ports/macos27/boot_args.h"

#define M27_STAGE_BASE UINT64_C(0x8c0000000)
#define M27_STAGE_BYTES UINT64_C(0xb0000000)
#define M27_STAGE_VMAPPLE_BYTES UINT32_C(81444864)
#define M27_STAGE_MAX_EXCLUSIONS 32u
#define M27_STAGE_MAX_DTB UINT32_C(0x200000)
#define M27_STAGE_VMA2_ENTRY UINT64_C(0xfffffe0009eb4480)
#define M27_STAGE_VMA2_FIRST_TARGET UINT64_C(0xfffffe0009eb8070)

struct m27_stage_span { uint64_t pa, size; };

/* Every address/buffer relationship is an independent externally verified
 * precondition. Caller must physically map the input and output as claimed
 * and attest exclusive writable ownership including its page tables, stack,
 * live kernel/firmware reservations. This module cannot obtain that proof.
 *
 * FDT is the complete bounded original ABL FDT, with /chosen initrd-start/end,
 * /memory/reg, memreserve and /reserved-memory/reg. Exclusions must include
 * ALL further live users (shim, stacks, MMU, framebuffer and firmware).
 * For the initial single B instruction no boot args or ADT is required.
 *
 * Optional boot arguments require an externally verified genuine Apple ADT,
 * supplied unchanged; this module does NOT generate/validate a native ADT.
 * adt_verified merely asserts caller-side proof; it grants no XNU entry.
 */
struct m27_entry_stage_request {
    const void *initrd;
    size_t initrd_size;
    uint64_t initrd_pa;
    const void *fdt;
    size_t fdt_capacity;
    uint64_t fdt_pa;
    const struct m27_stage_span *excluded;
    uint32_t excluded_count;
    uint32_t exclusive_writable_ram; /* must be exactly 1 */
    /* Saved dizi FDT has dynamic /reserved-memory nodes without reg.
     * Exactly 1 only if external runtime allocation/ownership attestation
     * has resolved all of them, including CMA and firmware. */
    uint32_t dynamic_reservations_attested;
    uint32_t stage_boot_args;       /* 0 = B-only; 1 = ADT + boot args */
    const void *adt;
    size_t adt_size;
    uint32_t adt_verified;          /* must be exactly 1 when requested */
    const char *command_line;
    size_t command_line_size;
};

struct m27_entry_stage_plan {
    struct mac27_kc_plan kc;
    struct mac27_kc_fixup_report fixups;
    size_t initrd_kc_offset;
    uint64_t loaded_pa_end;
    uint64_t first_b_pa, first_b_target_pa;
    uint64_t adt_pa, boot_args_pa, stage_end_pa;
    uint32_t stage_boot_args;
    uint32_t native_entry_permitted; /* ALWAYS 0 */
    uint32_t authenticated_pointers_unresolved; /* ALWAYS 1 */
};

enum m27_entry_stage_error {
    M27_STAGE_OK = 0, M27_STAGE_ARGUMENT, M27_STAGE_FDT,
    M27_STAGE_RAM, M27_STAGE_OVERLAP, M27_STAGE_NO_KC,
    M27_STAGE_KC_TRUST, M27_STAGE_KC_ENTRY, M27_STAGE_BOOT_ARGS,
    M27_STAGE_CAPACITY, M27_STAGE_STALE
};

/* Pure preflight, no output mutation on failure. Searches for one exact
 * SHA256-matched genuine 26A434 vma2 MH_FILESET (not a decoy or IMG4).
 * Do not branch to first_b_pa without independent EL1/MMU/PAC/HVC proof.
 */
int m27_entry_stage_plan(const struct m27_entry_stage_request *request,
                         struct m27_entry_stage_plan *out);

/* Writes ONLY the caller-provided RAM window mapped to M27_STAGE_BASE.
 * No direct physical dereference, branch, patch, PAC fixup or permission
 * modification. Recomputes plan before copy; pointer/report disjoint.
 */
int m27_entry_stage_copy(const struct m27_entry_stage_request *request,
                         const struct m27_entry_stage_plan *plan,
                         void *owned_window, size_t window_capacity);
#endif
