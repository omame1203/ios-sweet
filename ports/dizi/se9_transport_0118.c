/* SPDX-License-Identifier: MIT
 * Pure software SE9 / GPI SPI request and IRQ/EOT accounting.
 * The real dizi SE9 is FIFO-disabled (probe02), so FIFO command writes from
 * old patch 0100 cannot be used. No SE, GPI, GCC, TLMM or SMMU MMIO here.
 */
#include "se9_transport_0118.h"
#include <string.h>

/* This macro is forced to zero in the XNU patch and cannot be enabled by
 * a boot argument, external attestations or a mock backend. It protects
 * the live 0116 GUI while 0108 and SMMU ownership remain unresolved. */
#ifndef DIZI_SE9_0118_XNU_BACKEND_ALLOWED
#define DIZI_SE9_0118_XNU_BACKEND_ALLOWED 1
#endif

static bool in_pool(uint64_t address, uint64_t bytes, uint64_t base,
                    uint64_t region_size, uint64_t alignment)
{
    return bytes && address >= base && alignment &&
           !(address % alignment) && address - base < region_size &&
           bytes <= region_size - (address - base);
}

static bool disjoint(uint64_t a, uint64_t asize, uint64_t b, uint64_t bsize)
{
    return a <= b ? asize <= b - a : bsize <= a - b;
}

static bool grant_valid(const struct dizi_se9_spi_grant_0118 *g)
{
    if (!g || !g->epoch || g->epoch >= UINT32_MAX ||
        !g->se9_mmio_exclusive ||
        !g->gpi1_static_gpii0_exclusive || !g->se9_root_clock_applied ||
        !g->qup1_ahb_voted || !g->tlmm10_13_owned ||
        !g->gpio54_irq_routed || !g->gpi1_eot_irq_owned ||
        !g->cs0_exclusive ||
        !g->no_competing_clients || !g->sid403_qup_s1_mapped ||
        !g->sid416_gpi_s1_mapped || !g->gpi_dma_channels_ready ||
        !g->coherent_ring_buffers || !g->clock_power_active ||
        !g->spi_protocol_verified || !g->fifo_disabled_ro ||
        !g->geni_dma_mode_on) return false;
    /* Vendor GPI1 static GPII0: 64x16 byte TX/RX rings and
     * (64<<2)x16 byte event ring. IOVAs come from SID 0x416 only. */
    if (!in_pool(g->tx_ring_iova, 1024, DIZI_SE9_0118_GPI_IOVA,
                 DIZI_SE9_0118_GPI_IOVA_SIZE, 1024) ||
        !in_pool(g->rx_ring_iova, 1024, DIZI_SE9_0118_GPI_IOVA,
                 DIZI_SE9_0118_GPI_IOVA_SIZE, 1024) ||
        !in_pool(g->event_ring_iova, 4096, DIZI_SE9_0118_GPI_IOVA,
                 DIZI_SE9_0118_GPI_IOVA_SIZE, 4096) ||
        !disjoint(g->tx_ring_iova, 1024, g->rx_ring_iova, 1024) ||
        !disjoint(g->tx_ring_iova, 1024, g->event_ring_iova, 4096) ||
        !disjoint(g->rx_ring_iova, 1024, g->event_ring_iova, 4096))
        return false;
    return true;
}

static bool map_valid(const struct dizi_se9_spi_map_0118 *m,
                      uint64_t epoch, uint32_t bytes)
{
    return m->pinned && m->dma_mapped && m->coherent && m->epoch == epoch &&
           m->bytes >= bytes &&
           in_pool(m->iova, m->bytes, DIZI_SE9_0118_QUP_IOVA,
                   DIZI_SE9_0118_QUP_IOVA_SIZE, 1);
}

static int fault(struct dizi_se9_spi_0118 *bus, int reason)
{
    bus->state = DIZI_SE9_SPI_FAULT;
    bus->cs_held = false; /* Physical CS may be UNKNOWN; no new transaction. */
    bus->last_error = reason;
    return reason;
}

int dizi_se9_spi_open_0118(struct dizi_se9_spi_0118 *bus,
    const struct se9_plan *clock_plan,
    const struct dizi_se9_spi_grant_0118 *grant,
    const struct dizi_se9_spi_backend_0118 *backend)
{
    if (!bus) return DIZI_SE9_SPI_INVALID;
    memset(bus, 0, sizeof(*bus));
#if !DIZI_SE9_0118_XNU_BACKEND_ALLOWED
    (void)clock_plan; (void)grant; (void)backend;
    return DIZI_SE9_SPI_NO_OWNER;
#endif
    if (!clock_plan || !backend || !backend->submit || !backend->rx_sync)
        return DIZI_SE9_SPI_INVALID;
    /* A 0108 plan does not itself prove the clock is on; grant confirms
     * independent observed application and exclusive resource ownership. */
    if (!clock_plan->count || clock_plan->count > SE9_PLAN_MAX ||
        clock_plan->source_hz != SE9_XO_HZ ||
        clock_plan->spi_hz_max != SE9_NVT_MAX_HZ ||
        !clock_plan->irq_armed_in_plan || !grant_valid(grant))
        return DIZI_SE9_SPI_NO_OWNER;
    bus->grant = *grant;
    bus->backend = *backend;
    /* Top 32 bits bind an IRQ event to an independently granted epoch;
     * the lower 32 bits are a strictly monotone transaction sequence. */
    bus->next_token = (grant->epoch << 32) | 1u;
    bus->state = DIZI_SE9_SPI_IDLE;
    return DIZI_SE9_SPI_OK;
}

int dizi_se9_spi_submit_0118(struct dizi_se9_spi_0118 *bus,
    const struct dizi_se9_spi_request_0118 *req,
    uint64_t now_ticks, uint64_t *token_out)
{
    if (!bus || !req || !token_out) return DIZI_SE9_SPI_INVALID;
    *token_out = 0;
#if !DIZI_SE9_0118_XNU_BACKEND_ALLOWED
    (void)now_ticks;
    return DIZI_SE9_SPI_NO_OWNER;
#endif
    if (bus->state == DIZI_SE9_SPI_OFF) return DIZI_SE9_SPI_POWER;
    if (bus->state == DIZI_SE9_SPI_FAULT) return DIZI_SE9_SPI_STATE;
    if (bus->state != DIZI_SE9_SPI_IDLE) return DIZI_SE9_SPI_BUSY;
    if (bus->cs_held && now_ticks >= bus->deadline)
        return fault(bus, DIZI_SE9_SPI_TIMEOUT);
    if (!bus->grant.clock_power_active) return DIZI_SE9_SPI_POWER;
    if (!req->tx || !req->bytes || req->bytes > DIZI_SE9_0118_MAX_BYTES ||
        !req->timeout_ticks || req->bytes > UINT64_MAX - now_ticks ||
        req->timeout_ticks > UINT64_MAX - now_ticks ||
        req->chip_select != 0 || req->mode != 0 || req->bits_per_word != 8 ||
        req->speed_hz == 0 || req->speed_hz > SE9_NVT_MAX_HZ ||
        SE9_XO_HZ % req->speed_hz ||
        SE9_XO_HZ / req->speed_hz < 2 ||
        SE9_XO_HZ / req->speed_hz > 4095 ||
        req->continue_cs != bus->cs_held ||
        !map_valid(&req->tx_map, bus->grant.epoch, req->bytes) ||
        (req->rx && (!map_valid(&req->rx_map, bus->grant.epoch,
                                req->bytes) ||
         !disjoint(req->tx_map.iova, req->bytes, req->rx_map.iova,
                   req->bytes))) ||
        (!req->rx && (req->rx_map.iova || req->rx_map.bytes)))
        return DIZI_SE9_SPI_INVALID;
    if ((uint32_t)bus->next_token == UINT32_MAX)
        return fault(bus, DIZI_SE9_SPI_STATE);
    const uint64_t token = bus->next_token++;
    bus->request = *req;
    bus->current_token = token;
    bus->started_at = now_ticks;
    bus->deadline = now_ticks + req->timeout_ticks;
    bus->tx_done = false;
    bus->rx_done = false;
    bus->state = DIZI_SE9_SPI_SUBMITTING;
    /* This callback must queue correct GPI CONFIG0, GO and DMA TREs, in
     * the source-verified TX/RX order. No such XNU backend exists yet. */
    const uint32_t divider = SE9_XO_HZ / req->speed_hz;
    if (bus->backend.submit(bus->backend.ctx, req, divider, token))
        return fault(bus, DIZI_SE9_SPI_HW_ERR);
    if (bus->state != DIZI_SE9_SPI_SUBMITTING)
        return fault(bus, DIZI_SE9_SPI_STATE);
    bus->state = DIZI_SE9_SPI_IN_FLIGHT;
    *token_out = token;
    return DIZI_SE9_SPI_QUEUED;
}

int dizi_se9_spi_event_0118(struct dizi_se9_spi_0118 *bus,
    uint64_t token, enum dizi_se9_spi_event_0118 event,
    uint64_t now_ticks)
{
    if (!bus) return DIZI_SE9_SPI_INVALID;
    if (!token || token != bus->current_token)
        return DIZI_SE9_SPI_STALE;
    if (bus->state != DIZI_SE9_SPI_IN_FLIGHT)
        return DIZI_SE9_SPI_STATE;
    if (now_ticks < bus->started_at) return DIZI_SE9_SPI_STALE;
    if (now_ticks >= bus->deadline)
        return fault(bus, DIZI_SE9_SPI_TIMEOUT);
    if (event == DIZI_SE9_GPI_ERROR)
        return fault(bus, DIZI_SE9_SPI_HW_ERR);
    if (event == DIZI_SE9_GPI_TX_EOT) {
        if (bus->tx_done) return fault(bus, DIZI_SE9_SPI_HW_ERR);
        bus->tx_done = true;
    } else if (event == DIZI_SE9_GPI_RX_EOT && bus->request.rx) {
        if (bus->rx_done) return fault(bus, DIZI_SE9_SPI_HW_ERR);
        bus->rx_done = true;
    } else {
        return fault(bus, DIZI_SE9_SPI_HW_ERR);
    }
    if (!bus->tx_done || (bus->request.rx && !bus->rx_done))
        return DIZI_SE9_SPI_QUEUED;
    if (bus->request.rx &&
        bus->backend.rx_sync(bus->backend.ctx, &bus->request, token))
        return fault(bus, DIZI_SE9_SPI_HW_ERR);
    bus->cs_held = bus->request.keep_cs;
    bus->last_error = DIZI_SE9_SPI_OK;
    bus->state = DIZI_SE9_SPI_IDLE;
    return DIZI_SE9_SPI_OK;
}

int dizi_se9_spi_timeout_0118(struct dizi_se9_spi_0118 *bus,
    uint64_t now_ticks)
{
    if (!bus) return DIZI_SE9_SPI_INVALID;
    if (bus->state == DIZI_SE9_SPI_OFF) return DIZI_SE9_SPI_POWER;
    if (bus->state == DIZI_SE9_SPI_FAULT) return bus->last_error;
    if (bus->state == DIZI_SE9_SPI_IDLE) {
        if (bus->cs_held && now_ticks >= bus->deadline)
            return fault(bus, DIZI_SE9_SPI_TIMEOUT);
        return DIZI_SE9_SPI_OK;
    }
    if (now_ticks < bus->started_at) return DIZI_SE9_SPI_STALE;
    if (now_ticks < bus->deadline) return DIZI_SE9_SPI_QUEUED;
    return fault(bus, DIZI_SE9_SPI_TIMEOUT);
}

void dizi_se9_spi_power_lost_0118(struct dizi_se9_spi_0118 *bus)
{
    if (bus) (void)fault(bus, DIZI_SE9_SPI_POWER);
}
