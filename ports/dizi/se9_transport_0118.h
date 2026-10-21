/* SPDX-License-Identifier: MIT
 * Dizi QUPv3 SE9 SPI / GPI completion contract. No device access here.
 * Vendor provenance: spi-msm-geni.c setup_gsi_xfer / GPI TX/RX callbacks;
 * dizi FDT: spi@a8c000, SEID3, GPII0, SIDs 0x403 and 0x416.
 */
#ifndef DIZI_SE9_TRANSPORT_0118_H
#define DIZI_SE9_TRANSPORT_0118_H
#include "se9_clock.h" /* 0108 clock/IRQ54 plan; XNU publication is disabled. */
#include <stdbool.h>
#include <stdint.h>

#ifndef DIZI_SE9_0118_XNU_BACKEND_ALLOWED
#define DIZI_SE9_0118_XNU_BACKEND_ALLOWED 1 /* only portable mock default */
#endif

#define DIZI_SE9_0118_SPI_PA UINT64_C(0x00a8c000)
#define DIZI_SE9_0118_GPI_SID 0x416u
#define DIZI_SE9_0118_QUP_SID 0x403u
#define DIZI_SE9_0118_MAX_BYTES 0xffffffu
#define DIZI_SE9_0118_QUP_IOVA UINT64_C(0x40000000)
#define DIZI_SE9_0118_QUP_IOVA_SIZE UINT64_C(0x10000000)
#define DIZI_SE9_0118_GPI_IOVA UINT64_C(0x00100000)
#define DIZI_SE9_0118_GPI_IOVA_SIZE UINT64_C(0x00100000)

enum dizi_se9_spi_rc_0118 {
    DIZI_SE9_SPI_OK = 0, DIZI_SE9_SPI_QUEUED = 1,
    DIZI_SE9_SPI_INVALID = -1, DIZI_SE9_SPI_NO_OWNER = -2,
    DIZI_SE9_SPI_POWER = -3, DIZI_SE9_SPI_BUSY = -4,
    DIZI_SE9_SPI_STALE = -5, DIZI_SE9_SPI_HW_ERR = -6,
    DIZI_SE9_SPI_TIMEOUT = -7, DIZI_SE9_SPI_STATE = -8
};
enum dizi_se9_spi_state_0118 {
    DIZI_SE9_SPI_OFF = 0, DIZI_SE9_SPI_IDLE,
    DIZI_SE9_SPI_SUBMITTING, DIZI_SE9_SPI_IN_FLIGHT,
    DIZI_SE9_SPI_FAULT
};
enum dizi_se9_spi_event_0118 {
    DIZI_SE9_GPI_TX_EOT = 1, DIZI_SE9_GPI_RX_EOT = 2,
    DIZI_SE9_GPI_ERROR = 3
};

/* Every flag is an INDEPENDENT grant from an audited platform owner.
 * DTB entries, boot args, an all-ones mock, or an observed register value
 * do not prove real ownership. The two SMMU domains are distinct. */
struct dizi_se9_spi_grant_0118 {
    uint64_t epoch;
    bool se9_mmio_exclusive, gpi1_static_gpii0_exclusive;
    bool se9_root_clock_applied, qup1_ahb_voted, tlmm10_13_owned;
    bool gpio54_irq_routed, gpi1_eot_irq_owned, cs0_exclusive;
    bool no_competing_clients;
    bool sid403_qup_s1_mapped, sid416_gpi_s1_mapped;
    bool gpi_dma_channels_ready, coherent_ring_buffers;
    bool clock_power_active, spi_protocol_verified;
    bool fifo_disabled_ro, geni_dma_mode_on;
    uint64_t tx_ring_iova, rx_ring_iova, event_ring_iova;
};

/* An external SMMU backend owns the actual pinned mapping and coherency.
 * This structure is a witness passed to the software protocol validator,
 * not an IOVA allocator. The IOVA is NEVER treated as a CPU physical PA. */
struct dizi_se9_spi_map_0118 {
    uint64_t iova, epoch;
    uint32_t bytes;
    bool pinned, dma_mapped, coherent;
};

struct dizi_se9_spi_request_0118 {
    const uint8_t *tx; /* Required for Novatek command and read transfers. */
    uint8_t *rx;       /* Optional TX-only; else true full duplex. */
    struct dizi_se9_spi_map_0118 tx_map, rx_map;
    uint32_t bytes, speed_hz;
    uint32_t timeout_ticks; /* Caller-provided bounded monotonic units. */
    uint8_t chip_select, bits_per_word, mode;
    bool continue_cs, keep_cs; /* GPI GO TRE FRAGMENTATION semantics. */
};

/* Caller must serialize submit, IRQ events, timeout and power-loss under one
 * platform lock, pass real monotonic ticks, and never reuse grant.epoch
 * until older GPI/IRQ completions have been fenced. A synthetic unit-test
 * grant NEVER constitutes physical ownership or allows enabling XNU.
 * Submit may enqueue only verified CONFIG0, GO, TX buffer and optional RX
 * buffer TREs, with the GPI RX and TX event paths independently armed.
 * Returning zero means QUEUED, not completed. Callback must not issue a
 * synchronous completion. This library makes NO register writes or DMA.
 * rx_sync runs after both matching EOTs and must verify DMA visibility. */
struct dizi_se9_spi_backend_0118 {
    void *ctx;
    int (*submit)(void *ctx, const struct dizi_se9_spi_request_0118 *req,
                  uint32_t geni_clk_divider, uint64_t token);
    int (*rx_sync)(void *ctx, const struct dizi_se9_spi_request_0118 *req,
                   uint64_t token);
};

struct dizi_se9_spi_0118 {
    struct dizi_se9_spi_backend_0118 backend;
    struct dizi_se9_spi_grant_0118 grant;
    struct dizi_se9_spi_request_0118 request;
    enum dizi_se9_spi_state_0118 state;
    int last_error;
    uint64_t next_token, current_token, started_at, deadline;
    bool tx_done, rx_done, cs_held;
};

int dizi_se9_spi_open_0118(struct dizi_se9_spi_0118 *bus,
    const struct se9_plan *clock_plan,
    const struct dizi_se9_spi_grant_0118 *grant,
    const struct dizi_se9_spi_backend_0118 *backend);
int dizi_se9_spi_submit_0118(struct dizi_se9_spi_0118 *bus,
    const struct dizi_se9_spi_request_0118 *req,
    uint64_t now_ticks, uint64_t *token_out);
int dizi_se9_spi_event_0118(struct dizi_se9_spi_0118 *bus,
    uint64_t token, enum dizi_se9_spi_event_0118 event,
    uint64_t now_ticks); /* source must be an actual monotonic IRQ timestamp */
int dizi_se9_spi_timeout_0118(struct dizi_se9_spi_0118 *bus,
    uint64_t now_ticks);
void dizi_se9_spi_power_lost_0118(struct dizi_se9_spi_0118 *bus);

#endif
