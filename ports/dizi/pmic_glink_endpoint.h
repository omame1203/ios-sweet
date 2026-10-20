/*
 * Native XNU PMIC-GLINK endpoint API for a FUTURE Qualcomm ADSP backend.
 *
 * This file does NOT activate SMEM, Q6, GLINK, an interrupt, or a charger.
 * A backend must first implement the FDT-described ADSP PID2 SMEM GLINK
 * link, negotiate versions and an OPEN_ACK for PMIC_RTR_ADSP_APPS, check
 * msm/adsp/charger_pd, obtain exclusive local channel/ring ownership, and
 * drain prior-epoch responses. All six DIZI_PMIC_EV_* bits defined in
 * DiziPmicGlinkSched.h are proofs supplied by that backend, not defaults.
 *
 * All calls execute at thread/workloop context, not in a hard IRQ.
 * The backend serializes send+close for its channel and tags each RX with
 * the epoch of the actual channel. Wire messages have no sequence number.
 */
#ifndef DIZI_PMIC_GLINK_ENDPOINT_H
#define DIZI_PMIC_GLINK_ENDPOINT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Requires boot flags dizihw=1 dizibattery=1 dizipmictransport=1 AND
 * channel name "PMIC_RTR_ADSP_APPS" AND exact DIZI_PMIC_EV_ALL evidence.
 * A previously used local epoch cannot be reopened. */
bool dizi_pmic_glink_transport_open(uint64_t epoch, uint32_t evidence,
    const char *channel, bool exclusive_owner);

/* Return false if closed, not yet due, or one GET is already outstanding.
 * On true, exactly 24 bytes are ready for a SINGLE GLINK rpmsg TX operation.
 * No send is performed by XNU SweetBattery. */
bool dizi_pmic_glink_transport_next_get(uint64_t epoch,
    uint8_t out[24], size_t *length);

/* Entire validated GLINK channel payload, never raw ring memory.
 * Return true only for a validated response or recognized notification. */
bool dizi_pmic_glink_transport_receive_epoch(uint64_t epoch,
    const uint8_t *bytes, size_t size);

/* Link removal, SSR/PDR down and TX error all invalidate telemetry.
 * An outdated epoch cannot close a newer live channel. */
void dizi_pmic_glink_transport_closed_epoch(uint64_t epoch);
void dizi_pmic_glink_transport_tx_failed(uint64_t epoch);

#ifdef __cplusplus
}
#endif
#endif /* DIZI_PMIC_GLINK_ENDPOINT_H */
