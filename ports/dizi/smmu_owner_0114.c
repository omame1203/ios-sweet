/* SPDX-License-Identifier: BSD-2-Clause
 * No MMIO, no use of 0102's proposed route values, and no device writes.
 */
#include "smmu_owner_0114.h"

static bool smr_match(uint32_t smr, uint16_t sid)
{
    if (!(smr & 0x80000000u)) return false;
    uint32_t id = smr & 0xffffu;
    uint32_t mask = (smr >> 16) & 0x7fffu; /* bit31 is VALID, never MASK */
    return ((id ^ sid) & (~mask & 0xffffu)) == 0;
}
static bool id2_supported(uint32_t id2)
{
    /* ARM SMMUv2 ID2.PTFS_4K[12], IAS[3:0], OAS[7:4].
     * 0x1022 in 0102 tests is SYNTHETIC, not a dizi measurement. */
    unsigned ias = id2 & 15u, oas = (id2 >> 4) & 15u;
    return (id2 & (1u << 12)) != 0 && ias >= 2 && ias <= 5 &&
        oas >= 2 && oas <= 5;
}
struct dz_0114_report dz_0114_evaluate(const struct dz_0114_snapshot *s)
{
    struct dz_0114_report r = {0};
    if (!s) return r;
    if (!s->id0_known || !s->id1_known || !s->scr0_known ||
        s->id0 != DZ_0114_ID0 || s->id1 != DZ_0114_ID1 ||
        (s->scr0 & ((1u << 0) | (1u << 3))) ||
        !(s->scr0 & (1u << 10))) return r;
    /* sCR0 differs across boot stages: do not treat the prior measured
     * value as static ownership permission; only check feature bits. */
    r.id2_stage1_ok = s->id2_known && id2_supported(s->id2);
    bool fully_observed = r.id2_stage1_ok;
    bool bad_route = false;
    for (unsigned i = 0; i < DZ_0114_SMRS; i++) {
        if (!s->smr_known[i]) { fully_observed = false; continue; }
        r.observed_smrs++;
        if (!(s->smr[i] & (1u << 31))) continue;
        r.valid_smrs++;
        if (smr_match(s->smr[i], DZ_0114_GPI_SID)) r.gpi_matches++;
        if (smr_match(s->smr[i], DZ_0114_QUP_SID)) r.qup_matches++;
        if (!s->s2cr_known[i]) { fully_observed = false; continue; }
        r.observed_s2crs++;
        unsigned type = (s->s2cr[i] >> 16) & 3u;
        unsigned cb = s->s2cr[i] & 255u;
        if (type == 3u || (type == 0u && cb >= DZ_0114_CBS)) bad_route = true;
    }
    if (r.gpi_matches || r.qup_matches || bad_route) {
        r.result = DZ_0114_CONFLICT;
        return r;
    }
    r.snapshot_complete = fully_observed;
    if (fully_observed) r.result = DZ_0114_READ_ONLY_CLEAR;
    return r;
}

enum dz_0114_result dz_0114_plan_contract(const struct dz_0114_snapshot *s,
    const struct dz_0114_authority *p)
{
    struct dz_0114_report r = dz_0114_evaluate(s);
    if (r.result != DZ_0114_READ_ONLY_CLEAR) return r.result;
    if (!p) return DZ_0114_UNKNOWN; /* no owner attestation */
    if (!p->snapshot_stable_and_fenced ||
        !p->hypervisor_exclusive || !p->gpi_stream_exclusive ||
        !p->qup_stream_exclusive || !p->smr_slots_exclusive ||
        !p->context_banks_exclusive || !p->page_tables_synced ||
        !p->tlb_and_fault_path_ready || !p->pinmux_clocks_irqs_owned ||
        !p->memory_and_cache_coherency_proven ||
        p->smr_gpi >= DZ_0114_SMRS || p->smr_qup >= DZ_0114_SMRS ||
        p->smr_gpi == p->smr_qup || p->cb_gpi >= DZ_0114_CBS ||
        p->cb_qup >= DZ_0114_CBS || p->cb_gpi == p->cb_qup)
        return DZ_0114_UNKNOWN;
    /* Require both candidate slots' S2CR explicitly observed as FAULT
     * and UNUSED SMR, and all live translation CB indices inspected. */
    if (!s->s2cr_known[p->smr_gpi] || !s->s2cr_known[p->smr_qup] ||
        (s->smr[p->smr_gpi] & (1u << 31)) ||
        (s->smr[p->smr_qup] & (1u << 31)) ||
        ((s->s2cr[p->smr_gpi] >> 16) & 3u) != 2u ||
        ((s->s2cr[p->smr_qup] >> 16) & 3u) != 2u)
        return DZ_0114_UNKNOWN;
    for (unsigned i = 0; i < DZ_0114_SMRS; i++) {
        if (!(s->smr[i] & (1u << 31))) continue;
        unsigned type = (s->s2cr[i] >> 16) & 3u;
        unsigned cb = s->s2cr[i] & 255u;
        if (type == 0u && (cb == p->cb_gpi || cb == p->cb_qup))
            return DZ_0114_CONFLICT;
    }
    /* This value authorizes a SOFTWARE PLAN ONLY. It does not activate a
     * context bank, install any PTE, allow DMA, TLBI or write an SMMU reg. */
    return DZ_0114_PLAN_ONLY;
}
