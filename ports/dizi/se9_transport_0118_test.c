/* Synthetic ownership fixture ONLY: never execute on POCO Pad hardware. */
#include "se9_transport_0118.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#ifdef DIZI_SE9_0118_TEST_NATIVE_BRIDGE
#include "dizi_se9_spi_xnu_0118.h"
/* Test stand-in for 0108's verified hard-disabled XNU status. */
int dizi_se9_xnu_enabled(void) { return 0; }
#endif

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "CHECK %u failed line %d: %s\n", checks, __LINE__, #x); \
    return 1; } } while (0)

struct mock {
    unsigned submit_count, sync_count;
    int submit_fail, sync_fail;
    uint32_t divider;
    uint64_t token;
    const uint8_t *tx;
};
static int mock_submit(void *ctx, const struct dizi_se9_spi_request_0118 *req,
                       uint32_t divider, uint64_t token)
{
    struct mock *m = ctx;
    ++m->submit_count;
    m->divider = divider;
    m->token = token;
    m->tx = req->tx;
    return m->submit_fail;
}
static int mock_sync(void *ctx, const struct dizi_se9_spi_request_0118 *req,
                     uint64_t token)
{
    struct mock *m = ctx;
    ++m->sync_count;
    if (token != m->token || !req->rx) return -1;
    return m->sync_fail;
}

static struct dizi_se9_spi_grant_0118 good_grant(void)
{
    struct dizi_se9_spi_grant_0118 g = {
        .epoch = 91,
        .se9_mmio_exclusive = true,
        .gpi1_static_gpii0_exclusive = true,
        .se9_root_clock_applied = true,
        .qup1_ahb_voted = true,
        .tlmm10_13_owned = true,
        .gpio54_irq_routed = true,
        .gpi1_eot_irq_owned = true,
        .cs0_exclusive = true,
        .no_competing_clients = true,
        .sid403_qup_s1_mapped = true,
        .sid416_gpi_s1_mapped = true,
        .gpi_dma_channels_ready = true,
        .coherent_ring_buffers = true,
        .clock_power_active = true,
        .spi_protocol_verified = true,
        .fifo_disabled_ro = true,
        .geni_dma_mode_on = true,
        .tx_ring_iova = 0x100000,
        .rx_ring_iova = 0x100400,
        .event_ring_iova = 0x101000,
    };
    return g;
}

static struct se9_plan good_plan(void)
{
    struct se9_plan p;
    memset(&p, 0, sizeof(p));
    p.source_hz = SE9_XO_HZ;
    p.spi_hz_max = SE9_NVT_MAX_HZ;
    p.count = 1;
    p.irq_armed_in_plan = true;
    return p;
}

static struct dizi_se9_spi_request_0118 good_request(void)
{
    static const uint8_t tx[4] = {0x7f, 0, 0, 0};
    static uint8_t rx[4];
    struct dizi_se9_spi_request_0118 req;
    memset(&req, 0, sizeof(req));
    req.tx = tx;
    req.rx = rx;
    req.tx_map = (struct dizi_se9_spi_map_0118){0x40001000, 91, 4, true, true, true};
    req.rx_map = (struct dizi_se9_spi_map_0118){0x40002000, 91, 4, true, true, true};
    req.bytes = 4;
    req.speed_hz = 9600000;
    req.bits_per_word = 8;
    req.timeout_ticks = 100;
    return req;
}

static int open_good(struct dizi_se9_spi_0118 *bus, struct mock *m)
{
    struct dizi_se9_spi_grant_0118 g = good_grant();
    struct se9_plan p = good_plan();
    struct dizi_se9_spi_backend_0118 backend = {m, mock_submit, mock_sync};
    return dizi_se9_spi_open_0118(bus, &p, &g, &backend);
}

int main(void)
{
    struct dizi_se9_spi_0118 bus;
    struct mock m = {0};
    struct dizi_se9_spi_request_0118 req = good_request();
    uint64_t token = 0;
#if !DIZI_SE9_0118_XNU_BACKEND_ALLOWED
    CHECK(open_good(&bus, &m) == DIZI_SE9_SPI_NO_OWNER);
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 0, &token) == DIZI_SE9_SPI_NO_OWNER);
    CHECK(m.submit_count == 0 && m.sync_count == 0 && token == 0);
#ifdef DIZI_SE9_0118_TEST_NATIVE_BRIDGE
    struct dizi_se9_spi_grant_0118 g = good_grant();
    struct se9_plan p = good_plan();
    struct dizi_se9_spi_backend_0118 b = {&m, mock_submit, mock_sync};
    CHECK(!dizi_se9_spi_xnu_available_0118());
    CHECK(dizi_se9_spi_xnu_open_0118(&bus, &p, &g, &b) == DIZI_SE9_SPI_NO_OWNER);
    CHECK(m.submit_count == 0);
#endif
    puts("PASS 0118 native XNU hard-disabled; no backend invoked");
    return 0;
#else
    CHECK(open_good(&bus, &m) == DIZI_SE9_SPI_OK);
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 100, &token) == DIZI_SE9_SPI_QUEUED);
    CHECK(token == (UINT64_C(91) << 32 | 1u) &&
          m.token == token && m.submit_count == 1 && m.divider == 2);
    CHECK(dizi_se9_spi_timeout_0118(&bus, 199) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token + 1, DIZI_SE9_GPI_TX_EOT, 101) == DIZI_SE9_SPI_STALE);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_RX_EOT, 101) == DIZI_SE9_SPI_QUEUED);
    CHECK(m.sync_count == 0);
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 110, &token) == DIZI_SE9_SPI_BUSY);
    CHECK(dizi_se9_spi_event_0118(&bus, m.token, DIZI_SE9_GPI_TX_EOT, 101) == DIZI_SE9_SPI_OK);
    CHECK(m.sync_count == 1 && bus.state == DIZI_SE9_SPI_IDLE && !bus.cs_held);
    CHECK(dizi_se9_spi_event_0118(&bus, m.token, DIZI_SE9_GPI_TX_EOT, 101) == DIZI_SE9_SPI_STATE);
    CHECK(dizi_se9_spi_timeout_0118(&bus, 100000) == DIZI_SE9_SPI_OK);

    /* Chip-select fragment retained across two valid GO transfers. */
    req.keep_cs = true;
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 200, &token) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_TX_EOT, 201) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_RX_EOT, 201) == DIZI_SE9_SPI_OK);
    CHECK(bus.cs_held);
    req.keep_cs = false;
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 250, &token) == DIZI_SE9_SPI_INVALID);
    req.continue_cs = true;
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 250, &token) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_RX_EOT, 251) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_TX_EOT, 251) == DIZI_SE9_SPI_OK);
    CHECK(!bus.cs_held);

    /* TX-only firmware page/write; no fictitious RX completion needed. */
    req = good_request();
    req.rx = NULL;
    req.rx_map = (struct dizi_se9_spi_map_0118){0};
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 400, &token) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_TX_EOT, 401) == DIZI_SE9_SPI_OK);
    CHECK(m.sync_count == 3);

    /* Every malformed request fails before backend or any state change. */
    req = good_request();
    unsigned before = m.submit_count;
#define REJECT_REQ(modify) do { struct dizi_se9_spi_request_0118 bad = req; \
    modify; CHECK(dizi_se9_spi_submit_0118(&bus, &bad, 500, &token) == DIZI_SE9_SPI_INVALID); \
    CHECK(m.submit_count == before && bus.state == DIZI_SE9_SPI_IDLE); } while (0)
    REJECT_REQ(bad.bytes = 0);
    REJECT_REQ(bad.bytes = 5);
    REJECT_REQ(bad.bytes = UINT32_MAX);
    REJECT_REQ(bad.tx = NULL);
    REJECT_REQ(bad.timeout_ticks = 0);
    REJECT_REQ(bad.chip_select = 1);
    REJECT_REQ(bad.bits_per_word = 16);
    REJECT_REQ(bad.mode = 1);
    REJECT_REQ(bad.speed_hz = 0);
    REJECT_REQ(bad.speed_hz = 10000000);
    REJECT_REQ(bad.speed_hz = 9000000);
    REJECT_REQ(bad.continue_cs = true);
    REJECT_REQ(bad.tx_map.epoch++);
    REJECT_REQ(bad.rx_map.pinned = false);
    REJECT_REQ(bad.tx_map.coherent = false);
    REJECT_REQ(bad.tx_map.iova = 0x00100000);
    REJECT_REQ(bad.rx_map.iova = bad.tx_map.iova);
    REJECT_REQ(bad.rx_map.iova = 0x4fffffff);
    REJECT_REQ(bad.tx_map.iova = UINT64_MAX);
    REJECT_REQ(bad.rx = NULL);
#undef REJECT_REQ

    /* Invalid clock, missing independent permissions, ring collision. */
    struct dizi_se9_spi_grant_0118 g = good_grant();
    struct se9_plan p = good_plan();
    struct dizi_se9_spi_backend_0118 be = {&m, mock_submit, mock_sync};
    g.sid403_qup_s1_mapped = false;
    CHECK(dizi_se9_spi_open_0118(&bus, &p, &g, &be) == DIZI_SE9_SPI_NO_OWNER);
    g = good_grant(); g.sid416_gpi_s1_mapped = false;
    CHECK(dizi_se9_spi_open_0118(&bus, &p, &g, &be) == DIZI_SE9_SPI_NO_OWNER);
    g = good_grant(); g.fifo_disabled_ro = false;
    CHECK(dizi_se9_spi_open_0118(&bus, &p, &g, &be) == DIZI_SE9_SPI_NO_OWNER);
    g = good_grant(); g.gpi1_static_gpii0_exclusive = false;
    CHECK(dizi_se9_spi_open_0118(&bus, &p, &g, &be) == DIZI_SE9_SPI_NO_OWNER);
    g = good_grant(); g.gpi1_eot_irq_owned = false;
    CHECK(dizi_se9_spi_open_0118(&bus, &p, &g, &be) == DIZI_SE9_SPI_NO_OWNER);
    g = good_grant(); g.rx_ring_iova = g.tx_ring_iova;
    CHECK(dizi_se9_spi_open_0118(&bus, &p, &g, &be) == DIZI_SE9_SPI_NO_OWNER);
    g = good_grant(); g.event_ring_iova = 0x100800;
    CHECK(dizi_se9_spi_open_0118(&bus, &p, &g, &be) == DIZI_SE9_SPI_NO_OWNER);
    g = good_grant(); g.tx_ring_iova = 0x1fffff;
    CHECK(dizi_se9_spi_open_0118(&bus, &p, &g, &be) == DIZI_SE9_SPI_NO_OWNER);
    g = good_grant(); g.epoch = 0;
    CHECK(dizi_se9_spi_open_0118(&bus, &p, &g, &be) == DIZI_SE9_SPI_NO_OWNER);
    g = good_grant(); p.irq_armed_in_plan = false;
    CHECK(dizi_se9_spi_open_0118(&bus, &p, &g, &be) == DIZI_SE9_SPI_NO_OWNER);
    p = good_plan(); p.source_hz = 1234;
    CHECK(dizi_se9_spi_open_0118(&bus, &p, &g, &be) == DIZI_SE9_SPI_NO_OWNER);

    /* A timeout permanently poisons CS/rings; a late EOT cannot unblock. */
    CHECK(open_good(&bus, &m) == DIZI_SE9_SPI_OK);
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 100, &token) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_timeout_0118(&bus, 200) == DIZI_SE9_SPI_TIMEOUT);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_TX_EOT, 101) == DIZI_SE9_SPI_STATE);
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 201, &token) == DIZI_SE9_SPI_STATE);

    CHECK(open_good(&bus, &m) == DIZI_SE9_SPI_OK);
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 0, &token) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_TX_EOT, 1) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_TX_EOT, 1) == DIZI_SE9_SPI_HW_ERR);
    CHECK(bus.state == DIZI_SE9_SPI_FAULT);

    CHECK(open_good(&bus, &m) == DIZI_SE9_SPI_OK);
    m.sync_fail = -1;
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 0, &token) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_TX_EOT, 1) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_RX_EOT, 1) == DIZI_SE9_SPI_HW_ERR);
    m.sync_fail = 0;

    CHECK(open_good(&bus, &m) == DIZI_SE9_SPI_OK);
    m.submit_fail = -1;
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 0, &token) == DIZI_SE9_SPI_HW_ERR);
    CHECK(bus.state == DIZI_SE9_SPI_FAULT && token == 0);
    m.submit_fail = 0;

    CHECK(open_good(&bus, &m) == DIZI_SE9_SPI_OK);
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 0, &token) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_ERROR, 1) == DIZI_SE9_SPI_HW_ERR);

    CHECK(open_good(&bus, &m) == DIZI_SE9_SPI_OK);
    dizi_se9_spi_power_lost_0118(&bus);
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 0, &token) == DIZI_SE9_SPI_STATE);
    CHECK(bus.last_error == DIZI_SE9_SPI_POWER);

    CHECK(open_good(&bus, &m) == DIZI_SE9_SPI_OK);
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, UINT64_MAX - 40, &token) == DIZI_SE9_SPI_INVALID);
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 0, &token) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_RX_EOT, 1) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_timeout_0118(&bus, 100) == DIZI_SE9_SPI_TIMEOUT);

    /* Fragmented CS cannot be held forever across a stalled message. */
    CHECK(open_good(&bus, &m) == DIZI_SE9_SPI_OK);
    req.keep_cs = true;
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 0, &token) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_TX_EOT, 1) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_RX_EOT, 1) == DIZI_SE9_SPI_OK);
    CHECK(bus.cs_held);
    CHECK(dizi_se9_spi_timeout_0118(&bus, 100) == DIZI_SE9_SPI_TIMEOUT);
    CHECK(bus.state == DIZI_SE9_SPI_FAULT);

    /* Even without a scheduled timer callback, late EOT may not succeed. */
    CHECK(open_good(&bus, &m) == DIZI_SE9_SPI_OK);
    req.keep_cs = false;
    CHECK(dizi_se9_spi_submit_0118(&bus, &req, 200, &token) == DIZI_SE9_SPI_QUEUED);
    CHECK(dizi_se9_spi_event_0118(&bus, token, DIZI_SE9_GPI_RX_EOT, 300) == DIZI_SE9_SPI_TIMEOUT);
    CHECK(bus.state == DIZI_SE9_SPI_FAULT);

    printf("PASS %u 0118 synthetic GENI/GPI ownership, request, CS, EOT, DMA and timeout checks\n", checks);
    return 0;
#endif
}
