/* SPDX-License-Identifier: BSD-2-Clause */
#include "gpi_transport_0117.h"
#include <string.h>

#define DZ_0117_MAGIC 0x47503137u
#define DZ_0117_BAD   0x47504244u
#define DZ_0117_COMPLETE 0x22u
#define DZ_0117_EOT 2u
#define DZ_0117_EOB 4u
/* 0102 dz_domain_seal() state value; requires completely sealed domains. */
#define DZ_0117_SEALED 0x445a6950u

static bool overlap(uint64_t a, uint64_t an, uint64_t b, uint64_t bn)
{
    return a < b + bn && b < a + an;
}

static bool domains_physically_disjoint(const struct dz_domain *g,
                                        const struct dz_domain *q)
{
    /* Both tables and payload mappings are owned by their respective SID.
     * Even separate virtual IOVAs must never describe the same DRAM. */
    for (unsigned i = 0; i < g->ntables; ++i) {
        for (unsigned j = 0; j < q->ntables; ++j)
            if (overlap(g->tables[i].pa, 4096, q->tables[j].pa, 4096))
                return false;
        for (unsigned j = 0; j < DZ_DMA_MAX_MAPS; ++j)
            if (q->maps[j].active && overlap(g->tables[i].pa, 4096,
                    q->maps[j].pa, q->maps[j].size)) return false;
    }
    for (unsigned i = 0; i < q->ntables; ++i)
        for (unsigned j = 0; j < DZ_DMA_MAX_MAPS; ++j)
            if (g->maps[j].active && overlap(q->tables[i].pa, 4096,
                    g->maps[j].pa, g->maps[j].size)) return false;
    for (unsigned i = 0; i < DZ_DMA_MAX_MAPS; ++i) {
        if (!g->maps[i].active) continue;
        for (unsigned j = 0; j < DZ_DMA_MAX_MAPS; ++j)
            if (q->maps[j].active && overlap(g->maps[i].pa,
                    g->maps[i].size, q->maps[j].pa,
                    q->maps[j].size)) return false;
    }
    return true;
}

static bool separate(uintptr_t a, size_t al, uintptr_t b, size_t bl)
{
    /* No wrap: ring memory is an ordinary validated 16-aligned CPU pointer. */
    return (a <= UINTPTR_MAX - al && b <= UINTPTR_MAX - bl) &&
        (a + al <= b || b + bl <= a);
}

int dz_0117_bind(struct dz_0117_transport *t, const struct dz_0117_bind *b)
{
    if (!t || !b || t->magic || !b->gpi || !b->qup || !b->snapshot ||
        !b->authority || !b->ops.verify_owner || !b->ops.publish ||
        !b->ops.invalidate_events || !b->tx || !b->rx || !b->events)
        return DZ_0117_NOT_READY;
    if (b->gpi == b->qup || b->gpi->kind != DZ_GPI_RINGS ||
        b->qup->kind != DZ_QUP_PAYLOADS ||
        b->gpi->state != DZ_0117_SEALED ||
        b->qup->state != DZ_0117_SEALED ||
        b->gpi->ntables > DZ_DMA_MAX_TABLES ||
        b->qup->ntables > DZ_DMA_MAX_TABLES ||
        !domains_physically_disjoint(b->gpi, b->qup) ||
        ((uintptr_t)b->tx & 15u) || ((uintptr_t)b->rx & 15u) ||
        ((uintptr_t)b->events & 15u) ||
        !separate((uintptr_t)b->tx, DZ_0117_TX_BYTES,
                  (uintptr_t)b->rx, DZ_0117_RX_BYTES) ||
        !separate((uintptr_t)b->tx, DZ_0117_TX_BYTES,
                  (uintptr_t)b->events, DZ_0117_EV_BYTES) ||
        !separate((uintptr_t)b->rx, DZ_0117_RX_BYTES,
                  (uintptr_t)b->events, DZ_0117_EV_BYTES) ||
        dz_gpi_check_rings(b->gpi, b->tx_iova, b->rx_iova,
                           b->event_iova) != DZ_OK ||
        dz_0114_plan_contract(b->snapshot, b->authority) != DZ_0114_PLAN_ONLY)
        return DZ_0117_NOT_READY;
    /* Snapshots and boot flags are NOT authority. A hardware owner must
     * separately prove stream isolation, faults, interrupts and coherency. */
    if (!b->ops.verify_owner(b->ops.ctx, DZ_0117_GPI_SID,
                              DZ_0117_QUP_SID)) return DZ_0117_NOT_READY;
    struct dz_0117_transport v = {0};
    v.magic = DZ_0117_MAGIC;
    v.ops = b->ops;
    v.qup = b->qup;
    v.tx = b->tx;
    v.rx = b->rx;
    v.events = b->events;
    v.tx_iova = b->tx_iova;
    v.rx_iova = b->rx_iova;
    v.event_iova = b->event_iova;
    v.event_wp = DZ_0117_EV_ELEMS - 1u;
    /* Software owns supplied coherent rings. They must not have been
     * registered with any GPI channel before this call. */
    memset(v.tx, 0, DZ_0117_TX_BYTES);
    memset(v.rx, 0, DZ_0117_RX_BYTES);
    memset(v.events, 0, DZ_0117_EV_BYTES);
    *t = v;
    return DZ_0117_OK;
}

uint32_t dz_0117_initial_event_doorbell(const struct dz_0117_transport *t)
{
    return t && t->magic == DZ_0117_MAGIC ?
        t->event_iova + 16u * t->event_wp : 0;
}

void dz_0117_fault(struct dz_0117_transport *t)
{
    if (t) t->magic = DZ_0117_BAD;
}

static uint16_t advance(uint16_t index, unsigned elements)
{
    return (uint16_t)((index + 1u) % elements);
}

int dz_0117_submit_spi(struct dz_0117_transport *t, uint32_t tx_iova,
    uint32_t rx_iova, uint32_t bytes, struct dz_0117_submission *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!t || !out) return DZ_0117_INVALID;
    if (t->magic != DZ_0117_MAGIC) return DZ_0117_NOT_READY;
    if (t->expected) return DZ_0117_BUSY;
    if (!bytes || bytes > 0xffffffu ||
        ((uint64_t)tx_iova < (uint64_t)rx_iova + bytes &&
         (uint64_t)rx_iova < (uint64_t)tx_iova + bytes) ||
        !dz_domain_covers(t->qup, tx_iova, bytes, DZ_DMA_READ) ||
        !dz_domain_covers(t->qup, rx_iova, bytes, DZ_DMA_WRITE))
        return DZ_0117_INVALID;
    /* Do not read or write customer payloads; XNU caller publishes them. */
    const uint16_t go = t->tx_wp;
    const uint16_t tx = advance(go, DZ_0117_TX_ELEMS);
    const uint16_t rx = t->rx_wp;
    struct dz_tre vgo = {{3u, 0, bytes, (2u << 20) | (1u << 11) | 1u}};
    struct dz_tre vtx = {{tx_iova, 0, bytes, (1u << 20) | (1u << 9)}};
    struct dz_tre vrx = {{rx_iova, 0, bytes, (1u << 20) | (1u << 9)}};
    t->tx[go] = vgo;
    t->tx[tx] = vtx;
    t->rx[rx] = vrx;
    /* Publish all TRE writes before returning any potential doorbell plan. */
    if (t->ops.publish(t->ops.ctx, 0, (uint32_t)go * 16u, 32u) ||
        t->ops.publish(t->ops.ctx, 1, (uint32_t)rx * 16u, 16u)) {
        dz_0117_fault(t);
        return DZ_0117_IO;
    }
    t->tx_last = tx;
    t->rx_last = rx;
    t->tx_wp = advance(tx, DZ_0117_TX_ELEMS);
    t->rx_wp = advance(rx, DZ_0117_RX_ELEMS);
    t->length = bytes;
    t->expected = 3u;
    t->completed = 0;
    out->tx_doorbell_iova = t->tx_iova + 16u * t->tx_wp;
    out->rx_doorbell_iova = t->rx_iova + 16u * t->rx_wp;
    out->tx_last_tre_iova = t->tx_iova + 16u * tx;
    out->rx_last_tre_iova = t->rx_iova + 16u * rx;
    return DZ_0117_OK;
}

static uint32_t word32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int dz_0117_handle_event(struct dz_0117_transport *t,
    const struct dz_tre *ere)
{
    const unsigned char *p = (const unsigned char *)ere;
    uint32_t ptr = word32(p), hi = word32(p + 4u);
    uint32_t length = word32(p + 8u) & 0xffffffu;
    uint8_t code = p[11], type = p[14], chid = p[15];
    if (type != DZ_0117_COMPLETE || chid > 1u ||
        (code != DZ_0117_EOT && code != DZ_0117_EOB) ||
        hi || !t->expected || length != t->length ||
        (word32(p + 12u) & 0xffffu) != 0u ||
        word32(p + 12u) >> 16 != ((uint32_t)type | ((uint32_t)chid << 8)))
        return DZ_0117_POISONED;
    const uint8_t bit = (uint8_t)(1u << chid);
    const uint32_t expected_iova = chid == 0u ?
        t->tx_iova + 16u * t->tx_last : t->rx_iova + 16u * t->rx_last;
    if ((t->completed & bit) || ptr != expected_iova)
        return DZ_0117_POISONED;
    t->completed |= bit;
    return DZ_0117_OK;
}

int dz_0117_handle_ieob(struct dz_0117_transport *t, uint32_t irq_type,
    uint32_t hw_rp_iova, struct dz_0117_completion *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!t || !out) return DZ_0117_INVALID;
    if (t->magic != DZ_0117_MAGIC) return DZ_0117_NOT_READY;
    if (!t->expected || !(irq_type & DZ_0117_IEOB) ||
        (irq_type & ~DZ_0117_IEOB) ||
        hw_rp_iova < t->event_iova ||
        hw_rp_iova >= t->event_iova + DZ_0117_EV_BYTES ||
        ((hw_rp_iova - t->event_iova) & 15u)) {
        dz_0117_fault(t);
        return DZ_0117_POISONED;
    }
    uint16_t end = (uint16_t)((hw_rp_iova - t->event_iova) / 16u);
    uint16_t available = (uint16_t)((end + DZ_0117_EV_ELEMS -
                                     t->event_rp) % DZ_0117_EV_ELEMS);
    /* Ring has no epoch counter; never consume an entire 256-entry lap. */
    if (!available || available > 2u) {
        dz_0117_fault(t);
        return DZ_0117_POISONED;
    }
    for (uint16_t i = 0; i < available; ++i) {
        const uint32_t off = (uint32_t)t->event_rp * 16u;
        if (t->ops.invalidate_events(t->ops.ctx, off, 16u) ||
            dz_0117_handle_event(t, &t->events[t->event_rp])) {
            dz_0117_fault(t);
            return DZ_0117_POISONED;
        }
        t->event_rp = advance(t->event_rp, DZ_0117_EV_ELEMS);
        t->event_wp = advance(t->event_wp, DZ_0117_EV_ELEMS);
    }
    if (available)
        out->recycle_event_doorbell_iova =
            t->event_iova + 16u * t->event_wp;
    out->tx_done = !!(t->completed & 1u);
    out->rx_done = !!(t->completed & 2u);
    out->finished = t->completed == t->expected;
    if (out->finished) {
        out->bytes = t->length;
        t->length = 0;
        t->expected = t->completed = 0;
    }
    return DZ_0117_OK;
}
