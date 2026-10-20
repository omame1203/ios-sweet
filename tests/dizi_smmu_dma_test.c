/* SPDX-License-Identifier: BSD-2-Clause — offline hardware-free regression */
#define _POSIX_C_SOURCE 200112L
#include "dizi_smmu_dma.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d %s\n",__FILE__,__LINE__,#x); abort(); } ++checks; } while (0)
static int checks;
struct memory { unsigned count, freed, synced, fail_at, fail_sync; uint64_t next; int duplicate_pa; };
static int allocate(void *ctx, uint64_t **va, uint64_t *pa)
{
    struct memory *m=ctx;
    if (m->fail_at && m->count >= m->fail_at) return -1;
    void *p = NULL;
    if (posix_memalign(&p, 4096, 4096)) return -1;
    *va=p;
    *pa=m->next;
    if (!m->duplicate_pa) m->next += 4096;
    ++m->count;
    return 0;
}
static void release(void *ctx, uint64_t *va, uint64_t pa)
{ (void)pa; struct memory *m=ctx; ++m->freed; free(va); }
static int publish(void *ctx, const uint64_t *va, uint64_t pa)
{ (void)pa; (void)va; struct memory *m=ctx; ++m->synced; return m->fail_sync ? -1 : 0; }
static struct dz_pt_ops ops(struct memory *m)
{ struct dz_pt_ops v = {allocate,release,publish,m}; return v; }
static struct dz_domain *make(void)
{ struct dz_domain *d=calloc(1,sizeof(*d)); assert(d); return d; }
static void discard(struct dz_domain *d)
{ dz_domain_destroy(d); free(d); }
static uint64_t *leaf(struct dz_domain *d,uint32_t iova)
{
    uint64_t *root=d->tables[0].va;
    uint64_t l2pa=root[(iova>>30)&511] & ~UINT64_C(4095);
    uint64_t *l2=0,*l3=0;
    for(unsigned i=0;i<d->ntables;i++) if(d->tables[i].pa==l2pa)l2=d->tables[i].va;
    assert(l2);
    uint64_t l3pa=l2[(iova>>21)&511] & ~UINT64_C(4095);
    for(unsigned i=0;i<d->ntables;i++) if(d->tables[i].pa==l3pa)l3=d->tables[i].va;
    assert(l3);
    return &l3[(iova>>12)&511];
}
int main(void)
{
    const uint32_t id2=0x1022; /* synthetic! PTFS_4K=1, OAS40, IAS40 */
    struct memory mg={.next=0x88000000}, mq={.next=0x8c000000};
    struct dz_pt_ops og=ops(&mg), oq=ops(&mq);
    struct dz_domain *g=make(), *q=make();
    struct dz_domain *notzero=make();
    notzero->state=1;
    CHECK(dz_domain_init(notzero,DZ_GPI_RINGS,DZ_SMMU_ID0,DZ_SMMU_ID1,id2,&og)==DZ_INVALID);
    free(notzero);
    CHECK(dz_domain_init(g,DZ_GPI_RINGS,DZ_SMMU_ID0,DZ_SMMU_ID1,0,&og)==DZ_INVALID);
    CHECK(dz_domain_init(g,DZ_GPI_RINGS,0,DZ_SMMU_ID1,id2,&og)==DZ_INVALID);
    CHECK(dz_domain_init(g,DZ_GPI_RINGS,DZ_SMMU_ID0,DZ_SMMU_ID1,0x1072,&og)==DZ_INVALID); /* invalid OAS7 */
    CHECK(dz_domain_init(g,DZ_GPI_RINGS,DZ_SMMU_ID0,DZ_SMMU_ID1,0x1027,&og)==DZ_INVALID); /* invalid IAS7 */
    CHECK(dz_domain_init(g,DZ_GPI_RINGS,DZ_SMMU_ID0,DZ_SMMU_ID1,0x10f2,&og)==DZ_INVALID);
    CHECK(dz_domain_init(g,DZ_GPI_RINGS,DZ_SMMU_ID0,DZ_SMMU_ID1,id2,&og)==DZ_OK);
    CHECK(dz_domain_init(q,DZ_QUP_PAYLOADS,DZ_SMMU_ID0,DZ_SMMU_ID1,id2,&oq)==DZ_OK);
    CHECK(dz_domain_init(q,DZ_QUP_PAYLOADS,DZ_SMMU_ID0,DZ_SMMU_ID1,id2,&oq)==DZ_INVALID);
    CHECK(g->base==0x100000 && g->length==0x100000);
    CHECK(q->base==0x40000000 && q->length==0x10000000);
    uint32_t tx=0,rx=0,ev=0,buf=0;
    CHECK(dz_domain_map(g,0x90000000,4096,4096,DZ_DMA_RW,&tx)==DZ_OK);
    CHECK(dz_domain_map(g,0x90001000,4096,4096,DZ_DMA_RW,&rx)==DZ_OK);
    CHECK(dz_domain_map(g,0x90002000,4096,4096,DZ_DMA_RW,&ev)==DZ_OK);
    CHECK(tx==0x100000 && rx==0x101000 && ev==0x102000);
    CHECK(dz_domain_map(q,0xa0000000,8192,4096,DZ_DMA_READ,&buf)==DZ_OK);
    CHECK(buf==0x40000000);
    CHECK(dz_domain_covers(q,buf,8192,DZ_DMA_READ));
    CHECK(!dz_domain_covers(q,0x4ffff000,8192,DZ_DMA_READ));
    CHECK(!dz_domain_covers(q,buf,8192,DZ_DMA_WRITE));
    CHECK(!dz_domain_covers(q,buf+8000,1000,DZ_DMA_READ));
    CHECK(!dz_domain_covers(q,0xffffffff,4096,DZ_DMA_READ));
    CHECK((*leaf(g,tx) & UINT64_C(0x0000fffffffff000))==0x90000000);
    CHECK((*leaf(g,tx) & 0x403)==0x403); /* Valid/type and AF */
    CHECK((*leaf(g,tx) & (UINT64_C(3)<<53))==(UINT64_C(3)<<53)); /* XN */
    CHECK((*leaf(g,tx) & (1u<<11))!=0); /* nG, distinct ASIDs */
    CHECK((*leaf(g,tx) & (1u<<6))!=0); /* unprivileged DMA */
    CHECK((*leaf(q,buf) & (2u<<6))==(2u<<6)); /* AP RO for TX-only */
    CHECK(dz_domain_map(g,0,4096,4096,DZ_DMA_RW,0)==DZ_INVALID);
    CHECK(dz_domain_map(g,0x88000000,4096,4096,DZ_DMA_RW,&buf)==DZ_CONFLICT); /* root PTE page */
    CHECK(dz_domain_map(g,0x1000,0,4096,DZ_DMA_RW,&buf)==DZ_INVALID);
    CHECK(dz_domain_map(g,0x1000,4096,2048,DZ_DMA_RW,&buf)==DZ_INVALID);
    CHECK(dz_domain_map(g,0x1000,4096,6000,DZ_DMA_RW,&buf)==DZ_INVALID);
    CHECK(dz_domain_map(g,0x1234,4096,4096,DZ_DMA_RW,&buf)==DZ_INVALID);
    CHECK(dz_domain_map(g,UINT64_MAX-4095,8192,4096,DZ_DMA_RW,&buf)==DZ_INVALID);
    CHECK(dz_domain_map(g,0x300000,4096,4096,7,&buf)==DZ_INVALID);
    CHECK(dz_domain_unmap(g,rx,8192)==DZ_INVALID);
    CHECK(dz_domain_unmap(g,rx,4096)==DZ_OK);
    CHECK(!dz_domain_covers(g,rx,1,DZ_DMA_READ));
    CHECK(*leaf(g,rx)==0);
    CHECK(dz_domain_map(g,0x90000000,4096,4096,DZ_DMA_RW,&rx)==DZ_CONFLICT);
    CHECK(rx==0); /* failed allocation always clears caller's IOVA */
    CHECK(dz_domain_map(g,0x90003000,4096,4096,DZ_DMA_RW,&rx)==DZ_OK);
    CHECK(rx==0x101000);
    CHECK(dz_domain_seal(g)==DZ_OK && dz_domain_seal(q)==DZ_OK);
    CHECK(mg.synced==mg.count && mq.synced==mq.count);
    CHECK(dz_domain_map(g,0x90004000,4096,4096,DZ_DMA_RW,&buf)==DZ_NOT_READY);
    CHECK(dz_domain_unmap(g,rx,4096)==DZ_NOT_READY);
    CHECK(dz_gpi_check_rings(g,tx,rx,ev)==DZ_OK);
    CHECK(dz_gpi_check_rings(g,tx,tx,ev)==DZ_NOT_READY);
    CHECK(dz_gpi_check_rings(g,tx+1,rx,ev)==DZ_NOT_READY);
    CHECK(dz_gpi_check_rings(q,tx,rx,ev)==DZ_NOT_READY);
    struct dz_tre tre;
    CHECK(dz_gpi_spi_buffer_tre(q,tx,1,true,&tre)==DZ_NOT_READY);
    CHECK(dz_gpi_spi_buffer_tre(q,0x40000000,512,true,&tre)==DZ_OK);
    CHECK(tre.dword[0]==0x40000000 && tre.dword[1]==0 &&
          tre.dword[2]==512 && tre.dword[3]==((1u<<20)|(1u<<9)));
    CHECK(dz_gpi_spi_buffer_tre(q,0x40000000,512,false,&tre)==DZ_NOT_READY);
    CHECK(dz_gpi_spi_go_tre(0,&tre)==DZ_INVALID);
    CHECK(dz_gpi_spi_go_tre(1024,&tre)==DZ_OK);
    CHECK(tre.dword[0]==3 && tre.dword[2]==1024 &&
          tre.dword[3]==((2u<<20)|(1u<<11)|1u));
    struct dz_snapshot *s=calloc(1,sizeof(*s)); assert(s);
    s->id0=DZ_SMMU_ID0; s->id1=DZ_SMMU_ID1; s->id2=id2;
    s->scr0=0x270406;
    s->smr[0]=0x80000060; /* observed real SMR0 */
    struct dz_route_pair rp;
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_NOT_READY); /* no authority */
    s->exclusive_hypervisor_permission=true;
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_NOT_READY); /* S2CR0 not observed */
    s->s2cr_known[0]=true; s->s2cr[0]=0x300u|7u;
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_NO_SPACE); /* no slot or CB claims */
    s->slot_claimed[10]=s->slot_claimed[11]=true;
    s->cb_claimed[5]=s->cb_claimed[6]=true;
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_OK);
    CHECK(rp.gpi.sid==0x416 && rp.qup.sid==0x403);
    CHECK(rp.gpi.smr_slot==10 && rp.qup.smr_slot==11);
    CHECK(rp.gpi.cb_index==5 && rp.qup.cb_index==6);
    CHECK(rp.gpi.smr_offset==0x828 && rp.qup.s2cr_offset==0xc2c);
    CHECK(rp.gpi.smr_value==0x80000416 && rp.qup.smr_value==0x80000403);
    CHECK(rp.gpi.s2cr_value==(0x300u|5u));
    CHECK(rp.gpi.cbar_offset==0x1014 && rp.gpi.cba2r_offset==0x1814);
    CHECK(rp.gpi.cb_base_offset==0x85000 && rp.qup.cb_base_offset==0x86000);
    CHECK((rp.gpi.ttbr0 & 0xffffffffffffULL)==0x88000000u);
    CHECK((rp.gpi.ttbr0 >> 48)==6 && (rp.qup.ttbr0 >> 48)==7);
    CHECK(rp.gpi.mair0==0xff && rp.gpi.tcr2==(0x10u|2u));
    s->s2cr[0]=0x300u|5u; /* already used CB5 */
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_CONFLICT);
    s->s2cr[0]=0x300u|6u; /* already used CB6 */
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_CONFLICT);
    s->s2cr[0]=0x300u|7u;
    s->smr[60]=0x80000416;
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_CONFLICT);
    s->smr[60]=0x80010416; /* wildcard bit 0; includes SID 0x416 */
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_CONFLICT);
    s->smr[60]=0xffff0000; /* all SIDs; still conflict */
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_CONFLICT);
    s->smr[60]=0x00000403; /* invalid SMR; does not reserve SID */
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_OK);
    s->scr0 &= ~(1u<<10); /* unmatched bypass not approved */
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_NOT_READY);
    s->scr0 |= 1u<<10; s->scr0 |= 1u;
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_NOT_READY);
    s->scr0 &= ~1u; s->slot_claimed[10]=false;
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_NO_SPACE);
    s->slot_claimed[10]=true;
    s->cb_claimed[6]=false;
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_NO_SPACE);
    s->cb_claimed[6]=true;
    CHECK(dz_plan_routes(s,g,q,&rp)==DZ_OK);
    /* Independent IOVA spaces do not justify aliasing physical data pages. */
    struct memory ma={.next=0x9d000000};
    struct dz_domain *alias=make(); struct dz_pt_ops oa=ops(&ma);
    CHECK(dz_domain_init(alias,DZ_QUP_PAYLOADS,DZ_SMMU_ID0,DZ_SMMU_ID1,id2,&oa)==DZ_OK);
    uint32_t alias_iova=0;
    CHECK(dz_domain_map(alias,0x90000000,4096,4096,DZ_DMA_READ,&alias_iova)==DZ_OK);
    CHECK(dz_domain_seal(alias)==DZ_OK);
    CHECK(dz_plan_routes(s,g,alias,&rp)==DZ_NOT_READY);
    discard(alias); CHECK(ma.freed==ma.count);
    free(s);
    discard(g);discard(q);
    CHECK(mg.freed==mg.count && mq.freed==mq.count);
    /* Page table allocation failure during map poisons all future use. */
    struct memory mf={.next=0x90000000,.fail_at=2};
    struct dz_domain *f=make();struct dz_pt_ops of=ops(&mf);
    CHECK(dz_domain_init(f,DZ_GPI_RINGS,DZ_SMMU_ID0,DZ_SMMU_ID1,id2,&of)==DZ_OK);
    uint32_t v;
    CHECK(dz_domain_map(f,0xa0000000,4096,4096,DZ_DMA_RW,&v)==DZ_POISONED);
    CHECK(dz_domain_seal(f)==DZ_NOT_READY);
    discard(f); CHECK(mf.freed==mf.count);
    /* Fault after mapping some PTEs; partial mapping must never seal. */
    struct memory mp={.next=0x93000000,.fail_at=3};
    struct dz_domain *partial=make(); struct dz_pt_ops op=ops(&mp);
    CHECK(dz_domain_init(partial,DZ_QUP_PAYLOADS,DZ_SMMU_ID0,DZ_SMMU_ID1,id2,&op)==DZ_OK);
    CHECK(dz_domain_map(partial,0x94000000,0x400000,4096,DZ_DMA_RW,&v)==DZ_POISONED);
    CHECK(v==0 && partial->state!=0);
    CHECK(dz_domain_seal(partial)==DZ_NOT_READY);
    discard(partial); CHECK(mp.freed==mp.count);
    /* Reject an allocator supplying duplicate physical table page IDs. */
    struct memory md={.next=0x98000000,.duplicate_pa=1};
    struct dz_domain *dupe=make(); struct dz_pt_ops od=ops(&md);
    CHECK(dz_domain_init(dupe,DZ_GPI_RINGS,DZ_SMMU_ID0,DZ_SMMU_ID1,id2,&od)==DZ_OK);
    CHECK(dz_domain_map(dupe,0x99000000,4096,4096,DZ_DMA_RW,&v)==DZ_POISONED);
    discard(dupe); CHECK(md.freed==md.count);
    /* A new page-table page must not alias the in-flight DMA data page. */
    struct memory pm={.next=0xa0000000};
    struct dz_domain *pending=make(); struct dz_pt_ops pop=ops(&pm);
    CHECK(dz_domain_init(pending,DZ_GPI_RINGS,DZ_SMMU_ID0,DZ_SMMU_ID1,id2,&pop)==DZ_OK);
    CHECK(dz_domain_map(pending,0xa0001000,4096,4096,DZ_DMA_RW,&v)==DZ_POISONED);
    CHECK(dz_domain_seal(pending)==DZ_NOT_READY);
    discard(pending); CHECK(pm.freed==pm.count);
    /* Sync failure likewise blocks future map/plan. */
    struct memory ms={.next=0x90000000,.fail_sync=1};
    struct dz_domain *t=make();struct dz_pt_ops ot=ops(&ms);
    CHECK(dz_domain_init(t,DZ_GPI_RINGS,DZ_SMMU_ID0,DZ_SMMU_ID1,id2,&ot)==DZ_OK);
    CHECK(dz_domain_seal(t)==DZ_NOT_READY); /* empty domains cannot seal */
    CHECK(dz_domain_map(t,0x91000000,4096,4096,DZ_DMA_RW,&v)==DZ_OK);
    CHECK(dz_domain_seal(t)==DZ_POISONED);
    discard(t); CHECK(ms.freed==ms.count);
    /* Exhaust the 1MB GPI IOVA aperture exactly without wrapping. */
    struct memory ml={.next=0x90000000};
    struct dz_domain *l=make(); struct dz_pt_ops ol=ops(&ml);
    CHECK(dz_domain_init(l,DZ_GPI_RINGS,DZ_SMMU_ID0,DZ_SMMU_ID1,id2,&ol)==DZ_OK);
    CHECK(dz_domain_map(l,0x91000000,0x100000,4096,DZ_DMA_RW,&v)==DZ_OK);
    CHECK(v==0x100000);
    CHECK(dz_domain_map(l,0x92000000,4096,4096,DZ_DMA_RW,&v)==DZ_NO_SPACE);
    discard(l); CHECK(ml.freed==ml.count);
    printf("PASS %d offline SMMUv2/GPI assertions; AArch64 no-MMIO foundation\n", checks);
    return 0;
}
