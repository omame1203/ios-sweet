/* SPDX-License-Identifier: MIT -- fake-only register tests. */
#include "se9_clock.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned tests;
#define CHECK(x) do { ++tests; if (!(x)) { fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#x); abort(); } } while(0)
struct fake_mmio { struct se9_snapshot map; unsigned reads; int fail_read; };
static int fake_read(void *ctx, uint64_t pa, uint32_t *val)
{
    struct fake_mmio *m = ctx;
    if (!val || !m || m->fail_read) return -1;
    ++m->reads;
    for (unsigned i=0; i<m->map.count; ++i) {
        if (m->map.regs[i].pa == pa) {
            *val = m->map.regs[i].value;
            return 0;
        }
    }
    return -1;
}
static uint32_t *reg(struct se9_snapshot *m,uint64_t pa)
{
    for (unsigned i=0;i<m->count;i++) if(m->regs[i].pa==pa) return &m->regs[i].value;
    assert(0 && "unregistered fake PA");return NULL;
}
static void seed(struct fake_mmio *m)
{
    memset(m,0,sizeof(*m));
    struct se9_snapshot temp;
    /* First enumerate the precise allowlist by running against a seeded
     * callback independent from any real MMIO addresses. */
    static const uint64_t addresses[SE9_IO_MAX] = {
        SE9_GCC_VOTE, SE9_GCC_RCG_CMD, SE9_GCC_RCG_CFG,
        SE9_GCC_SE_CBCR, SE9_GCC_M_AHB_CBCR, SE9_GCC_S_AHB_CBCR,
        SE9_GPIO_CTL(10),SE9_GPIO_IO(10),SE9_GPIO_CTL(11),
        SE9_GPIO_CTL(12),SE9_GPIO_CTL(13),SE9_GPIO_IO(13),
        SE9_GPIO_CTL(54),SE9_GPIO_IO(54),SE9_GPIO_INTR(54),
        SE9_GPIO_INTR_ST(54)
    };
    m->map.count = SE9_IO_MAX;
    for (unsigned i=0;i<SE9_IO_MAX;i++) m->map.regs[i].pa=addresses[i];
    *reg(&m->map,SE9_GCC_VOTE)=0x40006bc0u;
    *reg(&m->map,SE9_GCC_RCG_CMD)=0x80000000u;
    *reg(&m->map,SE9_GCC_RCG_CFG)=0x00100000u;
    *reg(&m->map,SE9_GCC_SE_CBCR)=0x80004220u;
    *reg(&m->map,SE9_GCC_M_AHB_CBCR)=0;
    *reg(&m->map,SE9_GCC_S_AHB_CBCR)=8u;
    for(unsigned i=10;i<=12;i++) *reg(&m->map,SE9_GPIO_CTL(i))=1u;
    *reg(&m->map,SE9_GPIO_CTL(13))=0x2c3u;
    *reg(&m->map,SE9_GPIO_IO(13))=3u;
    *reg(&m->map,SE9_GPIO_CTL(54))=0;
    CHECK(se9_take_snapshot(fake_read,m,&temp)==SE9_OK);
    CHECK(m->reads==SE9_IO_MAX);
    CHECK(memcmp(&temp,&m->map,sizeof(temp))==0);
    m->reads=0;
}
static struct se9_ownership authorized(void)
{
    struct se9_ownership a={
        .gcc_exclusive=true,.rcg_exclusive=true,
        .wrap1_m_ahb_vote=true,.wrap1_s_ahb_vote=true,
        .se9_branch_vote=true,.tlmm_pins10_13_exclusive=true,
        .gpio54_exclusive=true,.irq54_route_exclusive=true,
        .spi_controller_idle=true,.chip_select_idle=true,
        .xo_19200000_verified=true,.voltage_corners_approved=true,
        .interrupt_handler_ready=true,.no_concurrent_clients=true
    };
    return a;
}
static int create(struct fake_mmio *m,const struct se9_ownership *a,
                  bool enable,struct se9_plan *p)
{
    return se9_make_plan(&m->map,a,enable,p);
}
int main(void)
{
    struct fake_mmio m;
    seed(&m);
    CHECK(SE9_GCC_BASE==0x100000u && SE9_GCC_VOTE==0x162008u);
    CHECK(SE9_GCC_RCG_CMD==0x1283b0u && SE9_GCC_RCG_CFG==0x1283b4u);
    CHECK(SE9_GCC_SE_CBCR==0x1283a8u && SE9_GPIO_CTL(10)==0xf10a000u);
    CHECK(SE9_GPIO_CTL(13)==0xf10d000u && SE9_GPIO_INTR(54)==0xf136008u);
    CHECK(SE9_GPIO_INTR_ST(54)==0xf13600cu);
    struct se9_plan p;
    struct se9_ownership a={0};
    CHECK(create(&m,&a,false,&p)==SE9_NO_OWNER && p.count==0);
    a=authorized();
    CHECK(create(&m,&a,false,&p)==SE9_OK);
    CHECK(p.source_hz==19200000 && p.spi_hz_max==9600000);
    CHECK(p.count==12 && !p.irq_armed_in_plan);
    CHECK(p.ops[0].pa==SE9_GCC_VOTE && p.ops[0].value==((1u<<20)|(1u<<21)));
    CHECK(p.ops[1].pa==SE9_GCC_RCG_CFG && p.ops[1].mask==0x371f && p.ops[1].value==1);
    CHECK(p.ops[2].pa==SE9_GCC_RCG_CMD && p.ops[2].value==1);
    CHECK(p.ops[3].kind==SE9_WAIT_BITS && p.ops[3].max_polls==500);
    CHECK(p.ops[4].pa==SE9_GCC_VOTE && p.ops[4].value==(1u<<25));
    CHECK(p.ops[5].kind==SE9_WAIT_BITS && p.ops[5].pa==SE9_GCC_SE_CBCR);
    CHECK(p.ops[6].pa==SE9_GPIO_CTL(10) && p.ops[9].pa==SE9_GPIO_CTL(13));
    CHECK(p.ops[10].pa==SE9_GPIO_CTL(54) && p.ops[11].pa==SE9_GPIO_INTR(54));
    CHECK((p.ops[11].value&0xffu)==0x74u); /* falling edge, target KPSS3, disabled */
    CHECK(se9_verify_unchanged(&p,fake_read,&m)==SE9_OK);
    struct se9_snapshot run=m.map;
    unsigned done=0;
    CHECK(se9_simulate(&p,&run,&done)==SE9_OK && done==p.count);
    CHECK((*reg(&run,SE9_GCC_VOTE)&((1u<<20)|(1u<<21)|(1u<<25))) ==
          ((1u<<20)|(1u<<21)|(1u<<25)));
    CHECK((*reg(&run,SE9_GCC_SE_CBCR)&(1u<<31))==0);
    CHECK(*reg(&run,SE9_GCC_RCG_CFG)==0x100001u); /* preserve HW_CLK_CTRL */
    for(unsigned i=10;i<=13;i++) CHECK((*reg(&run,SE9_GPIO_CTL(i))&0x3ffu)==0x84);
    CHECK((*reg(&run,SE9_GPIO_INTR(54))&0xffu)==0x74u);
    CHECK(*reg(&m.map,SE9_GCC_VOTE)==0x40006bc0u); /* snapshot isn't mutated */
    m.fail_read=1;
    struct se9_snapshot snap;
    CHECK(se9_take_snapshot(fake_read,&m,&snap)==SE9_INCOMPLETE && snap.count==0);
    CHECK(se9_verify_unchanged(&p,fake_read,&m)==SE9_INCOMPLETE);
    m.fail_read=0;
    *reg(&m.map,SE9_GPIO_CTL(12))=0x24u;
    CHECK(se9_verify_unchanged(&p,fake_read,&m)==SE9_STALE);
    CHECK(create(&m,&a,false,&p)==SE9_BAD_STATE);
    seed(&m);
    for (unsigned flag=0;flag<14;flag++) {
        a=authorized();
        bool *fields[]={&a.gcc_exclusive,&a.rcg_exclusive,&a.wrap1_m_ahb_vote,
          &a.wrap1_s_ahb_vote,&a.se9_branch_vote,&a.tlmm_pins10_13_exclusive,
          &a.gpio54_exclusive,&a.irq54_route_exclusive,&a.spi_controller_idle,
          &a.chip_select_idle,&a.xo_19200000_verified,&a.voltage_corners_approved,
          &a.interrupt_handler_ready,&a.no_concurrent_clients};
        *fields[flag]=false;
        CHECK(create(&m,&a,true,&p)==SE9_NO_OWNER);
        if(flag==12) CHECK(create(&m,&a,false,&p)==SE9_OK);
    }
    a=authorized();
    struct {uint64_t pa; uint32_t mask; uint32_t val;} bad[]={
      {SE9_GCC_VOTE,1u<<25,1u<<25},
      {SE9_GCC_VOTE,1u<<20,1u<<20},
      {SE9_GCC_RCG_CMD,1u,1u},
      {SE9_GCC_RCG_CMD,1u<<31,0},
      {SE9_GCC_SE_CBCR,1u<<31,0},
      {SE9_GCC_M_AHB_CBCR,1u<<31,1u<<31},
      {SE9_GCC_S_AHB_CBCR,1u<<31,1u<<31},
      {SE9_GPIO_CTL(13),1u<<9,0},
      {SE9_GPIO_IO(13),2u,0},
      {SE9_GPIO_CTL(54),1u<<9,1u<<9},
      {SE9_GPIO_INTR(54),1u,1u},
      {SE9_GPIO_INTR_ST(54),1u,1u},
      {SE9_GPIO_CTL(10),1u<<2,1u<<2},
      {SE9_GPIO_CTL(10),1u<<11,1u<<11}
    };
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
      seed(&m);
      uint32_t *v=reg(&m.map,bad[i].pa);
      *v=(*v&~bad[i].mask)|bad[i].val;
      CHECK(create(&m,&a,false,&p)==SE9_BAD_STATE);
      CHECK(p.count==0);
    }
    seed(&m);
    CHECK(create(&m,&a,true,&p)==SE9_OK && p.irq_armed_in_plan);
    CHECK((p.ops[11].value&0xffu)==0x75u);
    CHECK(se9_simulate(&p,&run,&done)==SE9_STALE); /* stale fake */
    run=m.map;
    CHECK(se9_simulate(&p,&run,&done)==SE9_OK);
    CHECK((*reg(&run,SE9_GPIO_INTR(54))&0xff)==0x75u);
    CHECK(se9_make_plan(NULL,&a,true,&p)==SE9_BAD_ARG);
    CHECK(se9_take_snapshot(NULL,NULL,&snap)==SE9_BAD_ARG);
    CHECK(se9_verify_unchanged(NULL,fake_read,&m)==SE9_BAD_ARG);
    CHECK(se9_simulate(NULL,&run,&done)==SE9_BAD_ARG);
    CHECK(se9_simulate(&p,&run,NULL)==SE9_BAD_ARG);
    struct se9_snapshot invalid=m.map;
    invalid.regs[0].pa=SE9_GPIO_CTL(10); /* duplicate, not canonical */
    CHECK(se9_make_plan(&invalid,&a,false,&p)==SE9_INCOMPLETE);
    CHECK(p.count==0);
    CHECK(se9_make_plan(NULL,&a,false,&p)==SE9_BAD_ARG);
    CHECK(p.count==0);
    invalid=m.map;
    invalid.regs[2].pa=invalid.regs[3].pa;
    CHECK(se9_make_plan(&invalid,&a,true,&p)==SE9_INCOMPLETE);
    CHECK(se9_take_snapshot(fake_read,NULL,&invalid)==SE9_INCOMPLETE);
    printf("PASS %u SE9 clock/TLMM fake MMIO assertions (no device I/O)\n",tests);
    return 0;
}
