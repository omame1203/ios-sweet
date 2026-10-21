/* SPDX-License-Identifier: BSD-2-Clause */
/* Host synthetic evidence exercises software only; NOT device attestation. */
#define _POSIX_C_SOURCE 200112L
#include "../gpi_transport_0117.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fixture {
    struct dz_domain g, q;
    struct dz_0114_snapshot smmu;
    struct dz_0114_authority owner;
    struct dz_0117_transport tr;
    struct dz_tre tx[DZ_0117_TX_ELEMS] __attribute__((aligned(16)));
    struct dz_tre rx[DZ_0117_RX_ELEMS] __attribute__((aligned(16)));
    struct dz_tre ev[DZ_0117_EV_ELEMS] __attribute__((aligned(16)));
    uint32_t tx_ring, rx_ring, event_ring, tx_buf, rx_buf;
    uint64_t next_pa;
    unsigned published, invalidated;
    bool deny_owner, fail_publish, fail_invalidate;
};

static int alloc_table(void *p, uint64_t **va, uint64_t *pa)
{
    struct fixture *f = p;
    void *ptr = NULL;
    if (posix_memalign(&ptr, DZ_DMA_PAGE, DZ_DMA_PAGE)) return -1;
    *va = ptr;
    *pa = f->next_pa;
    f->next_pa += DZ_DMA_PAGE;
    return 0;
}
static void free_table(void *p, uint64_t *va, uint64_t pa)
{
    (void)p;
    (void)pa;
    free(va);
}
static int sync_table(void *p, const uint64_t *va, uint64_t pa)
{
    (void)p;
    (void)va;
    (void)pa;
    return 0;
}
static bool synthetic_owner(void *p, uint16_t gpi, uint16_t qup)
{
    struct fixture *f = p;
    return !f->deny_owner && gpi == 0x416 && qup == 0x403;
}
static int publish(void *p, uint8_t chan, uint32_t off, uint32_t bytes)
{
    struct fixture *f = p;
    assert(chan <= 1);
    assert(off + bytes <= (chan ? DZ_0117_RX_BYTES : DZ_0117_TX_BYTES));
    assert(!(off & 15) && !(bytes & 15));
    f->published++;
    return f->fail_publish ? -1 : 0;
}
static int invalidate(void *p, uint32_t off, uint32_t bytes)
{
    struct fixture *f = p;
    assert(off + bytes <= DZ_0117_EV_BYTES && bytes == 16);
    f->invalidated++;
    return f->fail_invalidate ? -1 : 0;
}
static struct dz_0117_bind bind_args(struct fixture *f)
{
    struct dz_0117_bind b = {0};
    b.gpi = &f->g;
    b.qup = &f->q;
    b.snapshot = &f->smmu;
    b.authority = &f->owner;
    b.tx = f->tx;
    b.rx = f->rx;
    b.events = f->ev;
    b.tx_iova = f->tx_ring;
    b.rx_iova = f->rx_ring;
    b.event_iova = f->event_ring;
    b.ops = (struct dz_0117_ops){synthetic_owner, publish, invalidate, f};
    return b;
}
static void setup(struct fixture *f)
{
    memset(f, 0, sizeof(*f));
    f->next_pa = 0x80000000u;
    struct dz_pt_ops ops = {alloc_table, free_table, sync_table, f};
    assert(dz_domain_init(&f->g, DZ_GPI_RINGS, DZ_SMMU_ID0,
                          DZ_SMMU_ID1, 0x1022u, &ops) == DZ_OK);
    assert(dz_domain_init(&f->q, DZ_QUP_PAYLOADS, DZ_SMMU_ID0,
                          DZ_SMMU_ID1, 0x1022u, &ops) == DZ_OK);
    assert(dz_domain_map(&f->g, 0x90000000u, 4096, 4096, DZ_DMA_RW,
                         &f->tx_ring) == DZ_OK);
    assert(dz_domain_map(&f->g, 0x90001000u, 4096, 4096, DZ_DMA_RW,
                         &f->rx_ring) == DZ_OK);
    assert(dz_domain_map(&f->g, 0x90002000u, 4096, 4096, DZ_DMA_RW,
                         &f->event_ring) == DZ_OK);
    assert(dz_domain_map(&f->q, 0x90003000u, 4096, 4096, DZ_DMA_READ,
                         &f->tx_buf) == DZ_OK);
    assert(dz_domain_map(&f->q, 0x90004000u, 4096, 4096, DZ_DMA_WRITE,
                         &f->rx_buf) == DZ_OK);
    assert(dz_domain_seal(&f->g) == DZ_OK);
    assert(dz_domain_seal(&f->q) == DZ_OK);
    f->smmu.id0 = DZ_0114_ID0;
    f->smmu.id1 = DZ_0114_ID1;
    f->smmu.id2 = 0x1022;
    f->smmu.scr0 = 0x400;
    f->smmu.id0_known = f->smmu.id1_known = true;
    f->smmu.id2_known = f->smmu.scr0_known = true;
    for (unsigned i = 0; i < DZ_0114_SMRS; ++i) {
        f->smmu.smr_known[i] = f->smmu.s2cr_known[i] = true;
        f->smmu.s2cr[i] = 2u << 16;
    }
    f->owner.hypervisor_exclusive = true;
    f->owner.gpi_stream_exclusive = true;
    f->owner.qup_stream_exclusive = true;
    f->owner.snapshot_stable_and_fenced = true;
    f->owner.smr_slots_exclusive = true;
    f->owner.context_banks_exclusive = true;
    f->owner.page_tables_synced = true;
    f->owner.tlb_and_fault_path_ready = true;
    f->owner.pinmux_clocks_irqs_owned = true;
    f->owner.memory_and_cache_coherency_proven = true;
    f->owner.smr_gpi = 118;
    f->owner.smr_qup = 119;
    f->owner.cb_gpi = 75;
    f->owner.cb_qup = 76;
}
static void teardown(struct fixture *f)
{
    /* Only software domains, never hardware attached. */
    dz_domain_destroy(&f->g);
    dz_domain_destroy(&f->q);
}
static void event(struct fixture *f, uint16_t index, uint32_t ptr,
                  uint8_t chid, uint8_t type, uint8_t code, uint32_t len)
{
    f->ev[index].dword[0] = ptr;
    f->ev[index].dword[1] = 0;
    f->ev[index].dword[2] = len | ((uint32_t)code << 24);
    f->ev[index].dword[3] = ((uint32_t)type << 16) |
                           ((uint32_t)chid << 24);
}
static void complete(struct fixture *f, struct dz_0117_submission s,
                     unsigned first)
{
    struct dz_0117_completion c = {0};
    uint16_t pos = f->tr.event_rp;
    event(f, pos, first ? s.rx_last_tre_iova : s.tx_last_tre_iova,
          (uint8_t)first, 0x22, 2, 108);
    uint32_t rp = f->tr.event_iova + 16u * ((pos + 1u) % DZ_0117_EV_ELEMS);
    assert(dz_0117_handle_ieob(&f->tr, DZ_0117_IEOB, rp, &c) == DZ_0117_OK);
    assert(c.recycle_event_doorbell_iova ==
           f->event_ring + 16u * ((pos + 0u) % DZ_0117_EV_ELEMS));
    assert(!c.finished && c.tx_done == !first && c.rx_done == !!first);
    pos = f->tr.event_rp;
    event(f, pos, first ? s.tx_last_tre_iova : s.rx_last_tre_iova,
          (uint8_t)!first, 0x22, 2, 108);
    rp = f->tr.event_iova + 16u * ((pos + 1u) % DZ_0117_EV_ELEMS);
    assert(dz_0117_handle_ieob(&f->tr, DZ_0117_IEOB, rp, &c) == DZ_0117_OK);
    assert(c.recycle_event_doorbell_iova ==
           f->event_ring + 16u * ((pos + 0u) % DZ_0117_EV_ELEMS));
    assert(c.finished && c.bytes == 108 && c.tx_done && c.rx_done);
}

static void test_fail_closed(void)
{
    struct fixture *f = calloc(1, sizeof(*f));
    assert(f);
    setup(f);
    struct dz_0117_bind b = bind_args(f);
    f->deny_owner = true;
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_NOT_READY);
    f->deny_owner = false;
    f->smmu.smr[17] = 0x80000416; /* active GPI SID */
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_NOT_READY);
    f->smmu.smr[17] = 0x80000403; /* active QUP SID */
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_NOT_READY);
    f->smmu.smr[17] = 0;
    f->smmu.id2_known = false; /* no ID2 observation */
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_NOT_READY);
    f->smmu.id2_known = true;
    f->owner.gpi_stream_exclusive = false;
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_NOT_READY);
    f->owner.gpi_stream_exclusive = true;
    uint32_t state = f->q.state;
    f->q.state = 0x445a694fu; /* initialized, but not sealed */
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_NOT_READY);
    f->q.state = state;
    uint64_t pa = f->q.maps[0].pa;
    f->q.maps[0].pa = f->g.maps[0].pa; /* equal PA behind distinct SIDs */
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_NOT_READY);
    f->q.maps[0].pa = pa;
    b.rx_iova = b.tx_iova;
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_NOT_READY);
    b = bind_args(f);
    b.rx = b.tx;
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_NOT_READY);
    b = bind_args(f);
    b.ops.invalidate_events = NULL;
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_NOT_READY);
    b = bind_args(f);
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_OK);
    assert(dz_0117_initial_event_doorbell(&f->tr) ==
           f->event_ring + DZ_0117_EV_BYTES - 16u);
    struct dz_0117_submission s;
    assert(dz_0117_submit_spi(&f->tr, f->rx_buf, f->tx_buf, 108, &s) == DZ_0117_INVALID);
    assert(dz_0117_submit_spi(&f->tr, f->tx_buf, f->tx_buf, 108, &s) == DZ_0117_INVALID);
    assert(dz_0117_submit_spi(&f->tr, f->tx_buf, f->rx_buf, 0, &s) == DZ_0117_INVALID);
    assert(dz_0117_submit_spi(&f->tr, f->tx_buf, f->rx_buf, 0x1000000u, &s) == DZ_0117_INVALID);
    assert(dz_0117_submit_spi(&f->tr, f->tx_buf, f->rx_buf, 108, &s) == DZ_0117_OK);
    assert(dz_0117_submit_spi(&f->tr, f->tx_buf, f->rx_buf, 108, &s) == DZ_0117_BUSY);
    struct dz_0117_completion c;
    assert(dz_0117_handle_ieob(&f->tr, DZ_0117_IEOB | 4u,
               f->event_ring + 16u, &c) == DZ_0117_POISONED);
    assert(dz_0117_submit_spi(&f->tr, f->tx_buf, f->rx_buf, 108, &s) == DZ_0117_NOT_READY);
    teardown(f);
    free(f);
}

static void test_events_and_wrap(void)
{
    struct fixture *f = calloc(1, sizeof(*f));
    assert(f);
    setup(f);
    struct dz_0117_bind b = bind_args(f);
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_OK);
    for (unsigned i = 0; i < 130; ++i) {
        struct dz_0117_submission s = {0};
        assert(dz_0117_submit_spi(&f->tr, f->tx_buf, f->rx_buf, 108, &s) == DZ_0117_OK);
        assert(f->tx[f->tr.tx_last].dword[0] == f->tx_buf);
        assert(f->rx[f->tr.rx_last].dword[0] == f->rx_buf);
        complete(f, s, i & 1u);
    }
    assert(f->tr.event_rp == 4u); /* 260 events wrapped 256 entries */
    assert(f->published == 260 && f->invalidated == 260);
    teardown(f);
    free(f);
}

static void test_bad_event_and_sync(void)
{
    struct fixture *f = calloc(1, sizeof(*f));
    assert(f);
    setup(f);
    struct dz_0117_bind b = bind_args(f);
    struct dz_0117_submission s;
    struct dz_0117_completion c;
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_OK);
    f->fail_publish = true;
    assert(dz_0117_submit_spi(&f->tr, f->tx_buf, f->rx_buf, 108, &s) == DZ_0117_IO);
    assert(f->tr.magic != 0x47503137u);
    memset(&f->tr, 0, sizeof(f->tr));
    f->fail_publish = false;
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_OK);
    assert(dz_0117_submit_spi(&f->tr, f->tx_buf, f->rx_buf, 108, &s) == DZ_0117_OK);
    event(f, 0, s.rx_last_tre_iova, 1, 0x22, 2, 107); /* truncated */
    assert(dz_0117_handle_ieob(&f->tr, DZ_0117_IEOB,
               f->event_ring + 16u, &c) == DZ_0117_POISONED);
    memset(&f->tr, 0, sizeof(f->tr));
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_OK);
    assert(dz_0117_submit_spi(&f->tr, f->tx_buf, f->rx_buf, 108, &s) == DZ_0117_OK);
    event(f, 0, s.rx_last_tre_iova, 2, 0x22, 2, 108); /* bad channel */
    assert(dz_0117_handle_ieob(&f->tr, DZ_0117_IEOB,
               f->event_ring + 16u, &c) == DZ_0117_POISONED);
    memset(&f->tr, 0, sizeof(f->tr));
    assert(dz_0117_bind(&f->tr, &b) == DZ_0117_OK);
    assert(dz_0117_submit_spi(&f->tr, f->tx_buf, f->rx_buf, 108, &s) == DZ_0117_OK);
    f->fail_invalidate = true;
    event(f, 0, s.rx_last_tre_iova, 1, 0x22, 2, 108);
    assert(dz_0117_handle_ieob(&f->tr, DZ_0117_IEOB,
               f->event_ring + 16u, &c) == DZ_0117_POISONED);
    teardown(f);
    free(f);
}
static void test_malformed_completions(void)
{
    struct fixture *f = calloc(1, sizeof(*f));
    assert(f);
    setup(f);
    struct dz_0117_bind b = bind_args(f);
    for (unsigned scenario = 0; scenario < 9; ++scenario) {
        memset(&f->tr, 0, sizeof(f->tr));
        assert(dz_0117_bind(&f->tr, &b) == DZ_0117_OK);
        struct dz_0117_submission s;
        struct dz_0117_completion c;
        assert(dz_0117_submit_spi(&f->tr, f->tx_buf, f->rx_buf,
                                  108, &s) == DZ_0117_OK);
        event(f, 0, s.tx_last_tre_iova, 0, 0x22, 2, 108);
        uint32_t rp = f->event_ring + 16u;
        switch (scenario) {
        case 0: f->ev[0].dword[0] += 16u; break; /* wrong TRE */
        case 1: f->ev[0].dword[1] = 1u; break;  /* 64-bit pointer truncation */
        case 2: f->ev[0].dword[3] = 0x310000u; break; /* QUP notification */
        case 3: f->ev[0].dword[2] = (16u << 24) | 108u; break; /* error */
        case 4: f->ev[0].dword[3] |= 1u; break; /* nonzero status */
        case 5: f->ev[0].dword[2] = (2u << 24) | 0u; break; /* short */
        case 6: rp += 1u; break; /* misaligned event RP */
        case 7: rp += 32u; break; /* > 2 unacknowledged events */
        case 8: rp = f->event_ring; break; /* spurious IEOB, zero events */
        }
        assert(dz_0117_handle_ieob(&f->tr, DZ_0117_IEOB, rp, &c) ==
               DZ_0117_POISONED);
        assert(dz_0117_initial_event_doorbell(&f->tr) == 0);
    }
    teardown(f);
    free(f);
}
int main(void)
{
    test_fail_closed();
    test_events_and_wrap();
    test_bad_event_and_sync();
    test_malformed_completions();
    puts("0117: synthetic GPI transport tests passed (no hardware access)");
    return 0;
}
