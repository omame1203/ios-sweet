/* SPDX-License-Identifier: BSD-2-Clause
 * No hardware: synthetic ID2/full scans/owner grants are NOT dizi evidence.
 */
#include "smmu_owner_0114.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned count;
#define CHECK(x) do { assert(x); ++count; } while (0)
static struct dz_0114_snapshot scan;
static struct dz_0114_authority proof;
static void reset(void)
{
    memset(&scan,0,sizeof(scan)); memset(&proof,0,sizeof(proof));
    scan.id0_known=scan.id1_known=scan.scr0_known=true;
    scan.id0=DZ_0114_ID0;scan.id1=DZ_0114_ID1;scan.scr0=DZ_0114_SCR0;
    scan.smr[0]=DZ_0114_SMR0;scan.smr_known[0]=true;
}
static void complete(void)
{
    reset(); scan.id2=0x1022u;scan.id2_known=true; /* synthetic! */
    for (unsigned i=0; i<DZ_0114_SMRS;i++){
        scan.smr_known[i]=true;
        scan.s2cr_known[i]=true;
        scan.s2cr[i]=2u<<16; /* S2CR FAULT for unused slots */
    }
    scan.s2cr[0]=0x300u | 7u; /* existing translated unrelated SID */
}
static void all_authority(void)
{
    proof.snapshot_stable_and_fenced=true;
    proof.hypervisor_exclusive=true;
    proof.gpi_stream_exclusive=true;
    proof.qup_stream_exclusive=true;
    proof.smr_slots_exclusive=true;
    proof.context_banks_exclusive=true;
    proof.page_tables_synced=true;
    proof.tlb_and_fault_path_ready=true;
    proof.pinmux_clocks_irqs_owned=true;
    proof.memory_and_cache_coherency_proven=true;
    proof.smr_gpi=10; proof.smr_qup=11;
    proof.cb_gpi=5; proof.cb_qup=6;
}
static void report_checks(void)
{
    CHECK(dz_0114_evaluate(NULL).result==DZ_0114_UNKNOWN);
    reset();struct dz_0114_report r=dz_0114_evaluate(&scan);
    CHECK(r.result==DZ_0114_UNKNOWN && r.observed_smrs==1);
    CHECK(r.valid_smrs==1 && r.observed_s2crs==0);
    CHECK(!r.id2_stage1_ok && !r.snapshot_complete);
    CHECK(r.gpi_matches==0 && r.qup_matches==0);
    CHECK(dz_0114_plan_contract(&scan,NULL)==DZ_0114_UNKNOWN);
    scan.id2_known=true;scan.id2=0x1022u;
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_UNKNOWN);
    complete();r=dz_0114_evaluate(&scan);
    CHECK(r.result==DZ_0114_READ_ONLY_CLEAR);
    CHECK(r.snapshot_complete && r.id2_stage1_ok);
    CHECK(r.observed_smrs==DZ_0114_SMRS && r.valid_smrs==1);
    CHECK(r.observed_s2crs==1);
    CHECK(r.gpi_matches==0 && r.qup_matches==0);
    CHECK(dz_0114_plan_contract(&scan,NULL)==DZ_0114_UNKNOWN);
    scan.id2_known=false;
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_UNKNOWN);
    scan.id2_known=true;scan.id2=0x0022u; /* missing 4K stage1 */
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_UNKNOWN);
    scan.id2=0x1027u; /* IAS unsupported */
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_UNKNOWN);
    scan.id2=0x1072u; /* OAS unsupported */
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_UNKNOWN);
    complete();scan.scr0 |= 1u;
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_UNKNOWN);
    complete();scan.scr0 |= (1u<<3);
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_UNKNOWN);
    complete();scan.scr0 &= ~(1u<<10);
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_UNKNOWN);
    complete();scan.id0++;
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_UNKNOWN);
    complete();scan.id1++;
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_UNKNOWN);
    complete();scan.id0_known=false;
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_UNKNOWN);
    complete();scan.smr_known[119]=false;
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_UNKNOWN);
    complete();scan.s2cr_known[0]=false;
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_UNKNOWN);
    complete();scan.s2cr[0]=(3u<<16);
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_CONFLICT);
    complete();scan.s2cr[0]=0u | 77u;
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_CONFLICT);
    complete();scan.smr[28]=0x80000416u;scan.s2cr[28]=0x10000u;
    r=dz_0114_evaluate(&scan);
    CHECK(r.result==DZ_0114_CONFLICT && r.gpi_matches==1 && r.qup_matches==0);
    complete();scan.smr[28]=0x80000403u;
    r=dz_0114_evaluate(&scan);
    CHECK(r.result==DZ_0114_CONFLICT && r.gpi_matches==0 && r.qup_matches==1);
    complete();scan.smr[28]=0x80010416u; /* masked bit0 matches GPI */
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_CONFLICT);
    complete();scan.smr[28]=0xffff0000u; /* wildcard both */
    r=dz_0114_evaluate(&scan);
    CHECK(r.result==DZ_0114_CONFLICT && r.gpi_matches==1 && r.qup_matches==1);
    complete();scan.smr[28]=0x00000403u; /* not valid: ignore */
    CHECK(dz_0114_evaluate(&scan).result==DZ_0114_READ_ONLY_CLEAR);
}
static void contract_checks(void)
{
    complete(); all_authority();
    CHECK(dz_0114_plan_contract(&scan,&proof)==DZ_0114_PLAN_ONLY);
    /* Even PLAN_ONLY is only a software planning result, NEVER DMA/CB write. */
#define PROOF_FAIL(field) do { all_authority();proof.field=false; \
    CHECK(dz_0114_plan_contract(&scan,&proof)==DZ_0114_UNKNOWN); } while (0)
    PROOF_FAIL(snapshot_stable_and_fenced);
    PROOF_FAIL(hypervisor_exclusive);
    PROOF_FAIL(gpi_stream_exclusive);
    PROOF_FAIL(qup_stream_exclusive);
    PROOF_FAIL(smr_slots_exclusive);
    PROOF_FAIL(context_banks_exclusive);
    PROOF_FAIL(page_tables_synced);
    PROOF_FAIL(tlb_and_fault_path_ready);
    PROOF_FAIL(pinmux_clocks_irqs_owned);
    PROOF_FAIL(memory_and_cache_coherency_proven);
#undef PROOF_FAIL
    all_authority();proof.smr_gpi=120;
    CHECK(dz_0114_plan_contract(&scan,&proof)==DZ_0114_UNKNOWN);
    all_authority();proof.cb_gpi=77;
    CHECK(dz_0114_plan_contract(&scan,&proof)==DZ_0114_UNKNOWN);
    all_authority();proof.smr_qup=proof.smr_gpi;
    CHECK(dz_0114_plan_contract(&scan,&proof)==DZ_0114_UNKNOWN);
    all_authority();proof.cb_qup=proof.cb_gpi;
    CHECK(dz_0114_plan_contract(&scan,&proof)==DZ_0114_UNKNOWN);
    all_authority();scan.smr[10]=0x80000070u; /* slot claimed by unrelated */
    CHECK(dz_0114_plan_contract(&scan,&proof)==DZ_0114_UNKNOWN);
    complete();all_authority();scan.s2cr_known[10]=false;
    CHECK(dz_0114_plan_contract(&scan,&proof)==DZ_0114_UNKNOWN);
    complete();all_authority();scan.s2cr[10]=0x300u;
    CHECK(dz_0114_plan_contract(&scan,&proof)==DZ_0114_UNKNOWN);
    complete();all_authority();scan.s2cr[0]=0x300u | 5u;
    CHECK(dz_0114_plan_contract(&scan,&proof)==DZ_0114_CONFLICT);
    complete();all_authority();scan.s2cr[0]=0x300u | 6u;
    CHECK(dz_0114_plan_contract(&scan,&proof)==DZ_0114_CONFLICT);
    complete();all_authority();scan.smr[40]=0x80000403u;
    CHECK(dz_0114_plan_contract(&scan,&proof)==DZ_0114_CONFLICT);
    complete();all_authority();scan.id2_known=false;
    CHECK(dz_0114_plan_contract(&scan,&proof)==DZ_0114_UNKNOWN);
}
int main(void)
{
    report_checks(); contract_checks();
    printf("PASS dizi 0114 partial read-only real observations, synthetic ID2/SMR/S2CR and hypothetical authority, %u assertions\n",count);
    return 0;
}
