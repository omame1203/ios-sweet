/* SPDX-License-Identifier: BSD-2-Clause
 * Dizi apps-SMMUv2 READ-ONLY ownership evidence contract.
 * Pure value analysis. No hardware operations, allocator, DMA or MMIO.
 * All *_known fields start false; no register value infers ownership.
 */
#ifndef DIZI_SMMU_OWNER_0114_H
#define DIZI_SMMU_OWNER_0114_H
#include <stdbool.h>
#include <stdint.h>

#define DZ_0114_SMRS 120u /* FDT num-smr-override; ID0 reports 126 physical */
#define DZ_0114_CBS 77u
#define DZ_0114_GPI_SID 0x416u
#define DZ_0114_QUP_SID 0x403u
#define DZ_0114_ID0 0x4c017e7eu
#define DZ_0114_ID1 0x6000004du
#define DZ_0114_SCR0 0x00270406u /* measured in probe13; not an ownership grant */
#define DZ_0114_SMR0 0x80000060u /* measured probe12; one of 120 slots */

enum dz_0114_result {
    DZ_0114_UNKNOWN = 0,      /* partial, unread, altered, ID2 unproven */
    DZ_0114_CONFLICT,         /* SID match / invalid translation / CB use */
    DZ_0114_READ_ONLY_CLEAR,  /* NO matching valid SMRs in coherent snapshot */
    DZ_0114_PLAN_ONLY        /* out-of-band proof; STILL NO DMA activation */
};
struct dz_0114_snapshot {
    uint32_t id0, id1, id2, scr0;
    bool id0_known, id1_known, id2_known, scr0_known;
    uint32_t smr[DZ_0114_SMRS], s2cr[DZ_0114_SMRS];
    bool smr_known[DZ_0114_SMRS], s2cr_known[DZ_0114_SMRS];
};
struct dz_0114_report {
    enum dz_0114_result result;
    unsigned observed_smrs, valid_smrs, observed_s2crs;
    unsigned gpi_matches, qup_matches;
    bool id2_stage1_ok, snapshot_complete;
};
/* Authority CANNOT be inferred from SMR.VALID=0, a CB read or FDT SIDs.
 * The current kernel has NO producer for any of these attestations. */
struct dz_0114_authority {
    bool hypervisor_exclusive, gpi_stream_exclusive, qup_stream_exclusive;
    bool snapshot_stable_and_fenced; /* independent owner assures no SMR/CB races */
    bool smr_slots_exclusive, context_banks_exclusive;
    bool page_tables_synced, tlb_and_fault_path_ready;
    bool pinmux_clocks_irqs_owned, memory_and_cache_coherency_proven;
    unsigned smr_gpi, smr_qup, cb_gpi, cb_qup;
};
struct dz_0114_report dz_0114_evaluate(const struct dz_0114_snapshot *s);
/* Successful result is just permission to DESIGN a route, never a command. */
enum dz_0114_result dz_0114_plan_contract(const struct dz_0114_snapshot *s,
    const struct dz_0114_authority *proof);
#endif
