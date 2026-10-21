/* SPDX-License-Identifier: BSD-2-Clause */
/* Qualcomm GPII0 / SE9 bounded SPI transport SOFTWARE core.
 * Hardware enable, ring doorbells, IRQ ACK, IOMMU programming, DMA allocation
 * and MMIO are absent. Only a separately attested future owner can connect it.
 * MiCode: drivers/dma/qcom/gpi.c, include/linux/msm_gpi.h,
 * drivers/spi/spi-msm-geni.c. Never infer ownership from an unused SMR.
 */
#ifndef DIZI_GPI_TRANSPORT_0117_H
#define DIZI_GPI_TRANSPORT_0117_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dizi_smmu_dma.h"
#include "smmu_owner_0114.h"

#define DZ_0117_GPI_SID       DZ_0114_GPI_SID
#define DZ_0117_QUP_SID       DZ_0114_QUP_SID
#define DZ_0117_TX_ELEMS      64u
#define DZ_0117_RX_ELEMS      64u
#define DZ_0117_EV_ELEMS      256u
#define DZ_0117_TRE_BYTES     16u
#define DZ_0117_TX_BYTES      (DZ_0117_TX_ELEMS * DZ_0117_TRE_BYTES)
#define DZ_0117_RX_BYTES      (DZ_0117_RX_ELEMS * DZ_0117_TRE_BYTES)
#define DZ_0117_EV_BYTES      (DZ_0117_EV_ELEMS * DZ_0117_TRE_BYTES)
#define DZ_0117_IEOB          0x08u

enum dz_0117_status {
    DZ_0117_OK = 0, DZ_0117_INVALID = -1, DZ_0117_NOT_READY = -2,
    DZ_0117_BUSY = -3, DZ_0117_POISONED = -4, DZ_0117_IO = -5
};

/* These callbacks have to be implemented by the real hardware owner.
 * verify_owner MUST validate independent, fresh stream/domain and IRQ/cache
 * authority (not bootargs or mutable snapshots supplied by consumers).
 * publish: CPU->device TRE visibility. invalidate: device->CPU event visibility.
 * No callbacks for doorbell/SMR/TLBI/MMIO writes are defined in 0117. */
struct dz_0117_ops {
    bool (*verify_owner)(void *ctx, uint16_t gpi_sid, uint16_t qup_sid);
    int (*publish)(void *ctx, uint8_t chan, uint32_t byte_offset,
                   uint32_t byte_count);
    int (*invalidate_events)(void *ctx, uint32_t byte_offset,
                             uint32_t byte_count);
    void *ctx;
};

struct dz_0117_bind {
    const struct dz_domain *gpi, *qup;
    const struct dz_0114_snapshot *snapshot;
    const struct dz_0114_authority *authority;
    struct dz_0117_ops ops;
    struct dz_tre *tx, *rx, *events;
    uint32_t tx_iova, rx_iova, event_iova;
};

/* Must zero-initialize the transport before calling dz_0117_bind. Exactly
 * one in-flight SPI transfer. Request buffers are IOVAs in the
 * separately sealed QUP domain; ring IOVAs are in the sealed GPI domain.
 * Caller serializes submit/complete, and owns stable coherent buffers. */
struct dz_0117_transport {
    uint32_t magic;
    struct dz_0117_ops ops;
    const struct dz_domain *qup;
    struct dz_tre *tx, *rx, *events;
    uint32_t tx_iova, rx_iova, event_iova;
    uint16_t tx_wp, rx_wp, event_rp, event_wp;
    uint16_t tx_last, rx_last;
    uint32_t length;
    uint8_t expected, completed;
};

struct dz_0117_submission {
    uint32_t tx_doorbell_iova, rx_doorbell_iova;
    uint32_t tx_last_tre_iova, rx_last_tre_iova;
};

struct dz_0117_completion {
    uint32_t bytes;
    uint32_t recycle_event_doorbell_iova; /* plan, NEVER written here */
    bool tx_done, rx_done, finished;
};

/* Returns NOT_READY with any missing attestation/callback/proven mapping.
 * No implicit hardware activation; callers must never ring doors themselves
 * without a separately reviewed, owned and proven hardware backend. */
int dz_0117_bind(struct dz_0117_transport *t, const struct dz_0117_bind *b);
/* Event ring initial posted WP = final ERE (MiCode gpi_config_ev_channel).
 * Returns 0 if transport was never attested or has been poisoned. */
uint32_t dz_0117_initial_event_doorbell(const struct dz_0117_transport *t);
/* SPI FULL_DUPLEX=3, CS0 only. Both nonzero IOVAs required, equal length.
 * tx/rx are caller-owned mapped buffers. No implicit sync of payloads. */
int dz_0117_submit_spi(struct dz_0117_transport *t, uint32_t tx_iova,
    uint32_t rx_iova, uint32_t bytes, struct dz_0117_submission *out);
/* Model IRQ drain: peer has separately sampled IEOB status and event RP
 * after synchronizing device writes. hw_rp is a GPI-domain ring IOVA.
 * The function never ACKs IRQ or rings an event doorbell. `out` holds a
 * recycle doorbell plan only after freshly drained entries. */
int dz_0117_handle_ieob(struct dz_0117_transport *t, uint32_t irq_type,
    uint32_t hw_rp_iova, struct dz_0117_completion *out);
/* Explicit timeout/fault quarantine: never silently retry DMA. */
void dz_0117_fault(struct dz_0117_transport *t);
#endif
