/* SPDX-License-Identifier: MIT
 * No inline AArch64 instructions; all source-only and freestanding.
 * The real VMAPPLE kernel has an unconditional HVC #0 (x0=0xc1000000)
 * before SCTLR_EL1 is written. A functioning Apple virtual platform is a
 * prerequisite, not a detail a bootargs serializer can supply.
 */
#include "entry_handoff_guard.h"
#include "kc_loader.h"
#include "kc_fixups.h"

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
        (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32;
}
static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)p[1] << 8);
}
static int contains(uint64_t base, uint64_t extent, uint64_t start, uint64_t bytes)
{
    return start >= base && start - base <= extent &&
        bytes <= extent - (start - base);
}
static int disjoint(const void *a, size_t n, const void *b, size_t m)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    if (!b || !m) return 1;
    if (x > UINTPTR_MAX - n || y > UINTPTR_MAX - m) return 0;
    return !(n && x < y + m && y < x + n);
}
static void clear_result(struct m27_entry_report *out)
{
    uint8_t *p = (uint8_t *)out;
    for (size_t i = 0; i < sizeof(*out); i++) p[i] = 0;
    out->status = M27_ENTRY_BAD_ARGUMENT;
    out->blockers = M27_ENTRY_ALWAYS_BLOCKED | M27_ENTRY_B_EL1_STATE;
}

/* Actual VMAPPLE 26A434 __TEXT_EXEC file-backed instructions; these are
 * not derived from bundle strings or assumed from generic public XNU.
 *
 * The first instruction is PC-relative B +0x3bf0. The target at 0x8070
 * is also PC-relative when KC bytes are correctly staged to physical RAM.
 * Therefore the high virtual linked VA does not itself imply a high-VA
 * data access before the MMU is initialized. TTBR assumptions remain.
 */
struct signature_word { uint32_t offset, word; };
static const struct signature_word sig[] = {
    {48956544u, UINT32_C(0x14000efc)}, /* 0x9eb4480: b 0x9eb8070 */
    {48971888u, UINT32_C(0xd510109f)}, /* oslar_el1 unlock */
    {48971892u, UINT32_C(0xd5034fdf)}, /* daifset #15 */
    {48971896u, UINT32_C(0xaa0003f4)}, /* x20 <- boot_args x0 */
    {48971916u, UINT32_C(0xf9400696)}, /* ldr x22,[x20,#8] */
    {48971920u, UINT32_C(0xf9400a97)}, /* ldr x23,[x20,#16] */
    {48971924u, UINT32_C(0xf9400e98)}, /* ldr x24,[x20,#24] */
    {48971932u, UINT32_C(0xf9423a9a)}, /* ldr x26,[x20,#0x470] */
    {48972464u, UINT32_C(0xd5182041)}, /* msr TCR_EL1,x1 */
    {48972492u, UINT32_C(0xd5182020)}, /* msr TTBR1_EL1,x0 */
    {48972620u, UINT32_C(0xd2b82000)}, /* mov x0,#0xc1000000 */
    {48972624u, UINT32_C(0xd4000002)}, /* HVC #0 */
    {48972648u, UINT32_C(0xd5181000)}, /* msr SCTLR_EL1,x0 */
    {48972856u, UINT32_C(0xdac11841)}, /* autda x1,x2 */
};

int m27_entry_match_vma2_bootstrap(const void *kc, size_t size,
                                  const struct m27_entry_report *layout)
{
    if (!kc || !layout || size != M27_ENTRY_VMA2_BYTES ||
        layout->kernel_entry_va != M27_ENTRY_VMAPPLE_ENTRY_VA ||
        layout->bootstrap_va != M27_ENTRY_VMAPPLE_BOOT_VA ||
        layout->file_sets != M27_ENTRY_VMA2_FILESETS)
        return 0;
    const uint8_t *b = (const uint8_t *)kc;
    for (size_t i = 0; i < sizeof(sig) / sizeof(sig[0]); ++i) {
        if (sig[i].offset > size - 4 || rd32(b + sig[i].offset) != sig[i].word)
            return 0;
    }
    return 1;
}

static enum m27_entry_status verify_boot_args(
    const struct m27_entry_request *r, const struct mac27_kc_plan *kc)
{
    const uint8_t *ba = (const uint8_t *)r->boot_args;
    uint64_t v, p, n, top, adt_va, mem_actual;
    uint32_t adt_len;
    if (!ba || r->boot_args_bytes != M27_ENTRY_BOOT_ARGS_BYTES ||
        (r->boot_args_pa & (M27_ENTRY_PAGE_SIZE - 1)) ||
        (r->adt_pa & (M27_ENTRY_PAGE_SIZE - 1)) || !r->adt_bytes)
        return M27_ENTRY_BAD_BOOT_ARGS;
    if (rd16(ba) != 2 || rd16(ba + 2) != 2)
        return M27_ENTRY_BAD_BOOT_ARGS;
    v = rd64(ba + 8);
    p = rd64(ba + 16);
    n = rd64(ba + 24);
    top = rd64(ba + 32);
    adt_va = rd64(ba + 96);
    adt_len = rd32(ba + 104);
    mem_actual = rd64(ba + 0x478);
    if (v != kc->virt_base || p != r->phys_base || n != r->phys_bytes ||
        mem_actual < n || adt_len != r->adt_bytes ||
        !contains(r->phys_base, r->phys_bytes, r->adt_pa, r->adt_bytes) ||
        !contains(r->phys_base, r->phys_bytes,
                  r->boot_args_pa, M27_ENTRY_PAGE_SIZE) ||
        kc->kernel_end_pa > r->adt_pa ||
        r->adt_bytes > UINT64_MAX - r->adt_pa ||
        r->adt_pa + r->adt_bytes > r->boot_args_pa ||
        r->boot_args_pa > UINT64_MAX - M27_ENTRY_PAGE_SIZE ||
        top != r->boot_args_pa + M27_ENTRY_PAGE_SIZE ||
        r->adt_pa < r->phys_base ||
        r->adt_pa - r->phys_base > UINT64_MAX - kc->virt_base ||
        adt_va != kc->virt_base + (r->adt_pa - r->phys_base))
        return M27_ENTRY_BAD_MEMORY_LAYOUT;
    /* Boot flags +0x470 are present even if zero; do not make an unknown
     * nonzero bootFlag a privilege or native boot authorization. */
    (void)rd64(ba + M27_ENTRY_BOOT_FLAGS_OFFSET);
    return M27_ENTRY_ANALYZED_BLOCKED;
}

static enum m27_entry_status verify_snapshot(
    const struct m27_entry_el1_snapshot *s)
{
    unsigned granule16 = (unsigned)((s->id_aa64mmfr0_el1 >> 20) & 15u);
    /* The inspected shim path expects non-translating EL1 at the final
     * transfer. An MMU-on Apple-specific entry mode is NOT verified and
     * deliberately cannot be accepted by this baseline. */
    if (s->current_el != UINT64_C(0x4) || (s->sctlr_el1 & 1u) ||
        (s->sp_pa & 15u) || !s->sp_pa ||
        (granule16 != 1 && granule16 != 2))
        return M27_ENTRY_BAD_REGISTERS;
    /* TTBR0 and TTBR1 may retain historical values with SCTLR.M=0;
     * they are recorded, not interpreted as successful Apple tables. */
    return M27_ENTRY_ANALYZED_BLOCKED;
}

enum m27_entry_status m27_entry_handoff_analyze(
    const struct m27_entry_request *r,
    struct m27_entry_report *out)
{
    struct mac27_kc_plan kc;
    struct mac27_kc_fixup_report chains;
    struct m27_entry_report report;
    enum m27_entry_status reason = M27_ENTRY_BAD_ARGUMENT;
    if (!out || !r || !disjoint(out, sizeof(*out), r, sizeof(*r)))
        return M27_ENTRY_BAD_ARGUMENT;
    clear_result(&report);
    if (!r->kc || !r->boot_args ||
        !disjoint(out, sizeof(*out), r->kc, r->kc_bytes) ||
        !disjoint(out, sizeof(*out), r->boot_args, r->boot_args_bytes) ||
        r->kc_bytes != M27_ENTRY_VMA2_BYTES ||
        r->phys_base != M27_ENTRY_DIZI_PHYS ||
        r->phys_bytes != M27_ENTRY_DIZI_MEMORY) {
        goto done;
    }
    reason = M27_ENTRY_WRONG_KC;
    if (mac27_kc_plan(r->kc, r->kc_bytes, r->phys_base,
                      r->phys_bytes, &kc) != MAC27_KC_OK ||
        kc.cpu_subtype != M27_ENTRY_VMA2_SUBTYPE ||
        kc.fileset_count != M27_ENTRY_VMA2_FILESETS ||
        kc.entry_va != M27_ENTRY_VMAPPLE_ENTRY_VA ||
        kc.occupied_size > r->phys_bytes ||
        kc.kernel_end_pa > r->phys_base + r->phys_bytes)
        goto done;
    report.file_sets = kc.fileset_count;
    report.kernel_entry_va = kc.entry_va;
    report.kernel_entry_pa = kc.entry_pa;
    report.bootstrap_va = M27_ENTRY_VMAPPLE_BOOT_VA;
    report.virt_base = kc.virt_base;
    report.phys_base = r->phys_base;
    /* This delta is valid in the *mapped kernel image* and describes
     * PC-relative relocation, not a pre-existing TTBR1 mapping. */
    report.delta = r->phys_base - kc.virt_base; /* modular difference */
    if (M27_ENTRY_VMAPPLE_BOOT_VA < kc.virt_base ||
        M27_ENTRY_VMAPPLE_BOOT_VA - kc.virt_base >= kc.occupied_size)
        goto done;
    report.bootstrap_pa =
        r->phys_base + (M27_ENTRY_VMAPPLE_BOOT_VA - kc.virt_base);
    reason = M27_ENTRY_WRONG_MACHINE_CODE;
    if (!m27_entry_match_vma2_bootstrap(r->kc, r->kc_bytes, &report))
        goto done;
    reason = M27_ENTRY_WRONG_KC;
    if (mac27_kc_inspect_fixups(r->kc, r->kc_bytes, r->phys_base,
                                r->phys_bytes, &chains) != MAC27_FIXUP_OK ||
        !chains.authenticated || !chains.pointers)
        goto done;
    /* Protect host/target freestanding ABI from narrowing a hostile count. */
    report.fixup_auth_pointers = chains.authenticated > UINT32_MAX ?
        UINT32_MAX : (uint32_t)chains.authenticated;
    reason = verify_boot_args(r, &kc);
    if (reason != M27_ENTRY_ANALYZED_BLOCKED) goto done;
    reason = verify_snapshot(&r->snapshot);
    if (reason != M27_ENTRY_ANALYZED_BLOCKED) goto done;
    report.observed_ttbr0_el1 = r->snapshot.ttbr0_el1;
    report.observed_ttbr1_el1 = r->snapshot.ttbr1_el1;
    report.observed_sctlr_el1 = r->snapshot.sctlr_el1;
    report.observed_tcr_el1 = r->snapshot.tcr_el1;
    report.requested_boot_args_pa = r->boot_args_pa;
    report.vmapple_hvc_x0 = M27_ENTRY_VMAPPLE_HVC_X0;
    if (r->snapshot.origin != M27_ENTRY_OBSERVATION_DIRECT_EL1)
        report.blockers |= M27_ENTRY_B_EL1_STATE;
    else
        report.blockers &= ~M27_ENTRY_B_EL1_STATE;
    /* ALWAYS_BLOCKED is intentionally irreversible. No function here
     * measures PAC keys, implements an EL2 VMAPPLE hypervisor, verifies
     * TTBR0 contents, or builds true XNU27 platform/IOKit services. */
    report.blockers |= M27_ENTRY_ALWAYS_BLOCKED;
done:
    report.status = reason;
    if (reason != M27_ENTRY_ANALYZED_BLOCKED) {
        /* Zero candidate fields after ALL errors; never leak stale
         * apparently viable entry PA from an earlier partial inspection. */
        clear_result(&report);
        report.status = reason;
    }
    uint8_t *dst = (uint8_t *)out;
    const uint8_t *src = (const uint8_t *)&report;
    for (size_t i = 0; i < sizeof(report); i++) dst[i] = src[i];
    return reason;
}
