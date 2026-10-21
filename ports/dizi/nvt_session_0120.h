/* SPDX-License-Identifier: MIT
 * POCO Pad Novatek SRAM load -> identity/boot handshake -> IRQ frame state.
 * Synchronous transaction coordinator. No MMIO, DMA or fake ownership.
 */
#ifndef DIZI_NVT_SESSION_0120_H
#define DIZI_NVT_SESSION_0120_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "nt36532_fw.h"

#define DIZI_NVT0120_CONTACTS 10u
#define DIZI_NVT0120_REPORT 108u

enum dizi_nvt0120_state {
    DIZI_NVT0120_STOPPED = 0, DIZI_NVT0120_LOADING,
    DIZI_NVT0120_AWAIT_BOOT, DIZI_NVT0120_ACTIVE,
    DIZI_NVT0120_FAILED
};

/* All proofs must come from independently authenticated kernel owners.
 * Boot arguments, FDT declarations, fake tests, or register snapshots do
 * NOT create authorization or an IOVA mapping. */
struct dizi_nvt0120_lease {
    bool smmu_gpi_sid416_owned;
    bool smmu_qup_sid403_owned;
    bool gpi_event_ring_owned;
    bool qup_data_iova_mapped;
    bool se9_gcc_tlmm_owned;
    bool irq54_owned;
    bool spi_chip_identity_read;
    bool no_other_touch_reader;
};

struct dizi_nvt0120_ops {
    void *context;
    int (*select_page)(void *, uint32_t);
    int (*write_sram)(void *, uint8_t, const uint8_t *, size_t);
    /* Must verify all hardware firmware CRCs and complete Novatek boot.
     * Sender cannot infer readiness merely from last successful SPI write. */
    int (*verify_boot)(void *, uint8_t fw_version);
    /* Delivers hardware-verified finger updates into Apple's HID path. */
    void (*contact)(void *, unsigned id, bool down, unsigned x, unsigned y);
};

struct dizi_nvt0120_session {
    enum dizi_nvt0120_state state;
    struct dizi_nvt0120_ops ops;
    uint32_t active_mask;
    uint16_t x[DIZI_NVT0120_CONTACTS], y[DIZI_NVT0120_CONTACTS];
    unsigned consecutive_bad_frames;
};

/* Begin only on an authorized, exclusively leased DMA/GENI transport.
 * Binary blob is user-provided, never embedded or trusted by file name.
 * A failed or ambiguous boot poisons this session until reset. */
int dizi_nvt0120_start(struct dizi_nvt0120_session *s,
    const struct dizi_nvt0120_lease *lease,
    const struct dizi_nvt0120_ops *ops, const uint8_t *firmware,
    size_t firmware_size);

/* Existing Novatek super-resolution 108-byte report, not the SPI dummy
 * bytes. Atomic parse-before-publish, no events on malformed frames.
 * Repeat failures release contacts to avoid stuck touches. */
int dizi_nvt0120_frame(struct dizi_nvt0120_session *s,
    const uint8_t *packet, size_t size);
void dizi_nvt0120_stop(struct dizi_nvt0120_session *s);

#endif
