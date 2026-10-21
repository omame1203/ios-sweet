/* SPDX-License-Identifier: MIT
 *
 * Source-constrained 26A434 VMAPPLE bootstrap handoff guard for Qualcomm dizi.
 * This is a READ-ONLY preflight, NOT a boot entrypoint or EL1 monitor.
 *
 * Grounded in the actual VMAPPLE entry at 0xfffffe0009eb4480, which branches
 * to 0xfffffe0009eb8070:
 *  - x0 is a PHYSICAL boot_args pointer; x20 <- x0;
 *  - loads x20+0x8, +0x10, +0x18, +0x470 before creating TTBR1;
 *  - constructs 16-KiB tables, writes TCR_EL1/TTBR1_EL1 (not TTBR0_EL1);
 *  - issues HVC #0 with x0=0xc1000000 *before* SCTLR_EL1;
 *  - uses arm64e PAC, actual KC has authenticated format-8 fixups.
 *
 * Neither an apparently matching register snapshot nor passed proof bits
 * can grant execution. The VMAPPLE HVC ABI, PAC signing/key regime,
 * DIZI providers, physical ownership, signature/trust and XNU27 startup
 * environment have no verified native implementation.
 *
 * Do not wire this code to an indirect branch or replace the legacy shim.
 */
#ifndef MACOS27_ENTRY_HANDOFF_GUARD_H
#define MACOS27_ENTRY_HANDOFF_GUARD_H
#include <stddef.h>
#include <stdint.h>

#define M27_ENTRY_VMA2_BYTES UINT32_C(81444864)
#define M27_ENTRY_VMA2_FILESETS UINT32_C(216)
#define M27_ENTRY_VMA2_SUBTYPE UINT32_C(0xc0000002)
#define M27_ENTRY_VMAPPLE_ENTRY_VA UINT64_C(0xfffffe0009eb4480)
#define M27_ENTRY_VMAPPLE_BOOT_VA UINT64_C(0xfffffe0009eb8070)
#define M27_ENTRY_BOOT_ARGS_BYTES UINT32_C(1152)
#define M27_ENTRY_BOOT_FLAGS_OFFSET UINT32_C(0x470)
#define M27_ENTRY_PAGE_SIZE UINT64_C(0x4000)
#define M27_ENTRY_DIZI_PHYS UINT64_C(0x8c0000000)
#define M27_ENTRY_DIZI_MEMORY UINT64_C(0xb0000000)
#define M27_ENTRY_VMAPPLE_HVC_X0 UINT64_C(0xc1000000)

enum m27_entry_status {
    M27_ENTRY_ANALYZED_BLOCKED = 0,
    M27_ENTRY_BAD_ARGUMENT = -1,
    M27_ENTRY_WRONG_KC = -2,
    M27_ENTRY_WRONG_MACHINE_CODE = -3,
    M27_ENTRY_BAD_BOOT_ARGS = -4,
    M27_ENTRY_BAD_MEMORY_LAYOUT = -5,
    M27_ENTRY_BAD_REGISTERS = -6
};

enum m27_entry_blocker {
    M27_ENTRY_B_KC_TRUST                 = 1u << 0,
    M27_ENTRY_B_UNRESOLVED_AUTH_FIXUPS   = 1u << 1,
    M27_ENTRY_B_ARM64E_PAC              = 1u << 2,
    M27_ENTRY_B_HVC_VMAPPLE             = 1u << 3,
    M27_ENTRY_B_BOARD_IOKIT_PLATFORM     = 1u << 4,
    M27_ENTRY_B_PHYSICAL_RAM_OWNERSHIP   = 1u << 5,
    M27_ENTRY_B_EARLY_ADDRESS_TRANSLATE  = 1u << 6,
    M27_ENTRY_B_TTBR0_LIFECYCLE         = 1u << 7,
    M27_ENTRY_B_EL1_STATE               = 1u << 8,
    M27_ENTRY_B_BOOT_ROOT_TRUST         = 1u << 9
};
#define M27_ENTRY_ALWAYS_BLOCKED (M27_ENTRY_B_KC_TRUST | \
    M27_ENTRY_B_UNRESOLVED_AUTH_FIXUPS | M27_ENTRY_B_ARM64E_PAC | \
    M27_ENTRY_B_HVC_VMAPPLE | M27_ENTRY_B_BOARD_IOKIT_PLATFORM | \
    M27_ENTRY_B_PHYSICAL_RAM_OWNERSHIP | M27_ENTRY_B_EARLY_ADDRESS_TRANSLATE | \
    M27_ENTRY_B_TTBR0_LIFECYCLE | M27_ENTRY_B_BOOT_ROOT_TRUST)

enum m27_entry_snapshot_origin {
    M27_ENTRY_OBSERVATION_NONE = 0,
    M27_ENTRY_OBSERVATION_LEGACY_LOG = 1,
    M27_ENTRY_OBSERVATION_DIRECT_EL1 = 2
};

/* Only software-supplied, never reads EL1 registers. Even DIRECT_EL1 is an
 * untrusted *claim* until the caller separately proves its origin and timing.
 * TTBR0's virtual address walk after the kernel rewrites TCR has NOT been
 * established. An identity TTBR0 diagnostic is not an Apple TTBR1 handoff.
 */
struct m27_entry_el1_snapshot {
    uint64_t current_el;
    uint64_t sctlr_el1;
    uint64_t tcr_el1;
    uint64_t ttbr0_el1;
    uint64_t ttbr1_el1;
    uint64_t daif;
    uint64_t sp_pa;
    uint64_t id_aa64mmfr0_el1;
    uint64_t id_aa64isar1_el1;
    uint64_t id_aa64isar2_el1;
    enum m27_entry_snapshot_origin origin;
};

struct m27_entry_request {
    const void *kc;
    size_t kc_bytes;
    const void *boot_args; /* readable buffer of serialized 26A434 bytes */
    size_t boot_args_bytes;
    uint64_t phys_base, phys_bytes;
    uint64_t boot_args_pa, adt_pa;
    uint32_t adt_bytes;
    struct m27_entry_el1_snapshot snapshot;
};

struct m27_entry_report {
    enum m27_entry_status status;
    uint32_t blockers;
    uint32_t file_sets;
    uint32_t fixup_auth_pointers;
    uint64_t kernel_entry_va, kernel_entry_pa;
    uint64_t bootstrap_va, bootstrap_pa;
    uint64_t requested_boot_args_pa;
    uint64_t virt_base, phys_base, delta;
    uint64_t observed_ttbr0_el1, observed_ttbr1_el1;
    uint64_t observed_sctlr_el1, observed_tcr_el1;
    uint64_t vmapple_hvc_x0;
    uint32_t native_jump_allowed; /* ALWAYS 0, including on synthetic proofs */
};

/* Match exactly observed 26A434 machine-word signatures in already
 * mapped KC bytes. No decoding of an untrusted jump offset as a pointer. */
int m27_entry_match_vma2_bootstrap(const void *kc, size_t size,
                                  const struct m27_entry_report *layout);

/* Reads but never writes memory, signs pointers, sets TTBR or executes code.
 * A return of ANALYZED_BLOCKED means structural analysis succeeded and
 * hard execution blockers remain. It never means native handoff permitted.
 * A failed check zeros the report's candidate physical addresses and flags.
 */
enum m27_entry_status m27_entry_handoff_analyze(
    const struct m27_entry_request *request,
    struct m27_entry_report *report);
#endif
