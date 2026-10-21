#ifndef MAC27_EXECUTION_PLATFORM_GUARD_H
#define MAC27_EXECUTION_PLATFORM_GUARD_H

/*
 * READ-ONLY candidate first-instruction rehearsal for dizi/SM7435.
 * No PAC changes, BRK execution, cache maintenance, MMIO, page-table
 * writes, KC mutations, firmware calls or transfers to XNU.
 *
 * Grounding:
 * - backed-up Android live backup/dizi/fdt, boards/dizi.json:
 *   requested kernel_ram 0x8c0000000+0xb0000000 is within DDR, disjoint
 *   from fixed /reserved-memory. FDT contains /chosen initrd, splash,
 *   ramoops and additional DYNAMIC reserved-memory children lacking 'reg'.
 *   FDT proves a layout AT CAPTURE TIME, not today's ABL/Gunyah ownership.
 * - authentic 26A434 VMAPPLE first AArch64 instruction:
 *   VA 0xfffffe0009eb4480 B +0x3bf0 -> 0xfffffe0009eb8070.
 *   with KC linked VA base 0xfffffe0006000000, candidate PA entry is
 *   0x8c3eb4480; physical branch destination 0x8c3eb8070. The caller's
 *   PRIVATE COPY may contain a BRK #0x4e27 at that destination; ORIGINAL
 *   Apple KC must NEVER be instrumented or modified by this module.
 * - shim/mmu.c maps low 8GiB under its diagnostic 16KiB TTBR0, not these
 *   high physical KC addresses. With SCTLR.M=1, virtual instruction
 *   access and fetch permissions require separately verified page tables.
 * - Apple bootstrap later writes TTBR1, invokes VMAPPLE HVC #0 BEFORE
 *   writing SCTLR. A successful PC-relative B is not an XNU boot.
 *
 * Successful STRUCTURAL analysis always returns BLOCKED: no software
 * bits supplied here constitute attestation of EL2 stage-2, XPU fetch
 * permissions, RAM ownership, PAC or correct BRK exception routing.
 */
#include <stdint.h>
#include <stddef.h>

#define M27_XG_PHYS UINT64_C(0x8c0000000)
#define M27_XG_PHYS_SIZE UINT64_C(0xb0000000)
#define M27_XG_VIRT_BASE UINT64_C(0xfffffe0006000000)
#define M27_XG_ENTRY_VA UINT64_C(0xfffffe0009eb4480)
#define M27_XG_DEST_VA UINT64_C(0xfffffe0009eb8070)
#define M27_XG_ENTRY_PA UINT64_C(0x8c3eb4480)
#define M27_XG_DEST_PA UINT64_C(0x8c3eb8070)
#define M27_XG_BRANCH_WORD UINT32_C(0x14000efc)
#define M27_XG_BRK_WORD UINT32_C(0xd429c4e0) /* brk #0x4e27, experiment ABI */
#define M27_XG_PAGE_SIZE UINT64_C(16384)
#define M27_XG_MAX_FDT_BYTES UINT32_C(2097152)
#define M27_XG_MAX_FDT_REGIONS 256u
#define M27_XG_MAX_LIVE_REGIONS 32u

enum m27_xg_kind {
    M27_XG_INITRD = 1,
    M27_XG_DTB = 2,
    M27_XG_FRAMEBUFFER = 3,
    M27_XG_RAMOOPS = 4,
    M27_XG_SHIM = 5,
    M27_XG_STACK = 6,
    M27_XG_TTBR_TABLES = 7,
    M27_XG_OTHER = 8
};

struct m27_xg_range {
    uint64_t pa, bytes;
    enum m27_xg_kind kind;
};

enum m27_xg_blocker {
    M27_XG_B_FDT_INVALID           = 1u << 0,
    M27_XG_B_NOT_DDR               = 1u << 1,
    M27_XG_B_FIXED_RESERVATION     = 1u << 2,
    M27_XG_B_DYNAMIC_RESERVATION   = 1u << 3,
    M27_XG_B_LIVE_RANGE_MISSING    = 1u << 4,
    M27_XG_B_LIVE_OVERLAP          = 1u << 5,
    M27_XG_B_ALIAS_UNPROVEN        = 1u << 6,
    M27_XG_B_EL1_MMU_STATE         = 1u << 7,
    M27_XG_B_EXECUTE_UNATTESTED    = 1u << 8,
    M27_XG_B_RAM_OWNERSHIP_UNKNOWN = 1u << 9,
    M27_XG_B_BRK_EXCEPTION_UNKNOWN = 1u << 10,
    M27_XG_B_CODE_COPY            = 1u << 11,
    M27_XG_B_TARGET_MISMATCH       = 1u << 12,
    M27_XG_B_BRK_NOT_INSTRUMENTED  = 1u << 13,
    M27_XG_B_KC_PROVENANCE        = 1u << 14,
    M27_XG_B_REGISTERS_UNATTESTED  = 1u << 15
};

enum m27_xg_origin {
    M27_XG_ORIGIN_NONE = 0,
    M27_XG_ORIGIN_SAVED_LOG = 1,
    M27_XG_ORIGIN_DIRECT_EL1 = 2
};

struct m27_xg_el1_state {
    uint64_t current_el; /* exact 0x4 for EL1 */
    uint64_t sctlr_el1;  /* bit 0: stage 1 enabled; M=0 required here */
    uint64_t tcr_el1;
    uint64_t ttbr0_el1;
    uint64_t ttbr1_el1;
    uint64_t instruction_va; /* current fetch address for attempted B */
    enum m27_xg_origin origin;
};

struct m27_xg_request {
    const void *fdt; /* ORIGINAL bounded DTB snapshot; no writes */
    size_t fdt_capacity;
    uint64_t fdt_pa; /* captured runtime PA, not derivable from DTB alone */
    const struct m27_xg_range *live; /* caller's CURRENT live allocations */
    size_t live_count;
    uint64_t kernel_pa, kernel_bytes;
    const void *instrumented_copy; /* separate read-only buffer, never ORIGINAL */
    size_t instrumented_capacity;
    uint64_t copy_pa; /* PA of first instrumented byte (should equal entry) */
    uint64_t entry_pa, brk_target_pa;
    uint32_t source_26a434_manifest_matched; /* user assertion, not signature */
    uint32_t separate_mutable_copy;         /* user assertion, not ownership */
    struct m27_xg_el1_state el1;
};

struct m27_xg_report {
    uint32_t blockers;
    uint32_t valid_fdt;
    uint32_t ddr_regions, fixed_reservations;
    uint32_t dynamic_reserved_children;
    uint32_t live_ranges_checked;
    uint64_t captured_initrd_start, captured_initrd_end;
    uint64_t captured_splash_pa, captured_splash_bytes;
    uint64_t captured_ramoops_pa, captured_ramoops_bytes;
    uint64_t physical_entry, physical_brk_target;
    uint64_t observed_current_el, observed_sctlr_el1;
    uint64_t observed_tcr_el1, observed_ttbr0_el1, observed_ttbr1_el1;
    uint32_t branch_word, brk_word;
    uint32_t structurally_plausible;
    uint32_t native_entry_allowed; /* ALWAYS 0 */
};

enum m27_xg_status {
    M27_XG_BAD_ARGUMENT = -1,
    M27_XG_BLOCKED = 0
};

/* Portable/freestanding parser validates FDT bounds, DDR banks, all
 * /memreserve and fixed reserved-memory ranges (including splash/ramoops),
 * missing dynamically allocated reserved-memory children, exact /chosen
 * initrd interval, original DTB and supplied live shim/stacks/TTBR intervals.
 * It checks the copied B and BRK words, but NEVER patches or executes them.
 *
 * Even an entirely filled-in synthetic request still has execution blockers.
 * The FDT alone cannot grant RAM ownership or PA execution permission.
 */
enum m27_xg_status m27_xg_analyze(const struct m27_xg_request *request,
                                  struct m27_xg_report *out);

#endif
