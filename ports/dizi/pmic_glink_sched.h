/*
 * Dizi Qualcomm PMIC-GLINK request scheduler / verified channel handoff.
 *
 * This is deliberately ABOVE GLINK/rpmsg: no MMIO, SMEM allocation, remoteproc
 * boot, interrupt, ring access, or power writes occur here. MiCode's Linux
 * stack uses qcom_glink_smem -> qcom_glink_native -> rpmsg -> pmic_glink.
 * The remote endpoint is ADSP PID 2 / PMIC_RTR_ADSP_APPS, with charger_pd
 * service readiness and SSR/PDR notifications. The XNU port lacks that stack.
 *
 * Callers must serialize entry with the same mutex as dizi_bc_state. A
 * prospective backend must quiesce sends during close, drain stale RX after
 * SSR/PDR, and assign an increasing epoch only after fresh channel OPEN_ACK.
 * Frames have no sequence/epoch on the wire: epoch tags below are LOCAL
 * metadata, never a replacement for a genuine remote restart barrier.
 */
#ifndef DIZI_PMIC_GLINK_SCHED_H
#define DIZI_PMIC_GLINK_SCHED_H

#include "DiziPmicTelemetry.h"

#define DIZI_PMIC_EV_ADSP_RUNNING      (1u << 0)
#define DIZI_PMIC_EV_CHARGER_PD_UP     (1u << 1)
#define DIZI_PMIC_EV_VERSION_ACK       (1u << 2)
#define DIZI_PMIC_EV_CHANNEL_OPEN_ACK  (1u << 3)
#define DIZI_PMIC_EV_EXCLUSIVE_OWNER   (1u << 4)
#define DIZI_PMIC_EV_RX_DRAINED        (1u << 5)
#define DIZI_PMIC_EV_ALL              ((1u << 6) - 1u)

/* Query rate is lower than BC_FRESH_MS: 8 properties per ~1s plus 5s pause. */
#define DIZI_PMIC_GET_SPACING_MS 100u
#define DIZI_PMIC_ROUND_PAUSE_MS 5000u

struct dizi_pmic_sched {
    uint64_t max_epoch;  /* never reused across a lost link */
    uint64_t active_epoch;
    uint64_t next_due_ms;
    uint64_t last_clock_ms;
    uint32_t evidence;
    uint8_t ready;
    uint8_t in_flight;
    uint8_t in_flight_slot;
    uint8_t next_slot;
};

static inline uint64_t
dizi_pmic_sched_after(uint64_t now, uint64_t interval)
{
    return UINT64_MAX - now < interval ? UINT64_MAX : now + interval;
}

/* Force all telemetry unknown, release outstanding transaction. */
static inline void
dizi_pmic_sched_close(struct dizi_pmic_sched *s, struct dizi_bc_state *bc)
{
    if (!s || !bc) return;
    dizi_bc_link(bc, false, false);
    s->ready = 0;
    s->active_epoch = 0;
    s->evidence = 0;
    s->in_flight = 0;
    s->in_flight_slot = 0;
    s->next_slot = 0;
    s->next_due_ms = 0;
    s->last_clock_ms = 0;
}

/* Hardware/GLINK ownership cannot be inferred by this function. The backend
 * provides evidence AFTER real IPCC/SMEM/GLINK + PDR verification; this API
 * MUST NOT be called on a guessed FDT address or a mere firmware-running bit.
 * On failure, even a previously healthy link is invalidated. */
static inline bool
dizi_pmic_sched_open(struct dizi_pmic_sched *s, struct dizi_bc_state *bc,
    uint64_t epoch, uint32_t verified_evidence, bool exclusive_owner)
{
    if (!s || !bc) return false;
    if (!exclusive_owner || verified_evidence != DIZI_PMIC_EV_ALL ||
        !epoch || epoch <= s->max_epoch || s->ready) {
        dizi_pmic_sched_close(s, bc);
        return false;
    }
    dizi_pmic_sched_close(s, bc);
    s->max_epoch = s->active_epoch = epoch;
    s->evidence = verified_evidence;
    s->ready = 1;
    dizi_bc_link(bc, true, true);
    return true;
}

static inline bool
dizi_pmic_sched_ready(const struct dizi_pmic_sched *s,
    const struct dizi_bc_state *bc, uint64_t epoch)
{
    return s && bc && s->ready && bc->online && bc->owned &&
        s->evidence == DIZI_PMIC_EV_ALL && epoch &&
        s->active_epoch == epoch;
}

/* Check one outstanding GET's timeout BEFORE any access to its response.
 * A timeout requires an actual fresh GLINK/PDR epoch, never an immediate
 * retry against the same channel with an indistinguishable late response. */
static inline bool
dizi_pmic_sched_check(struct dizi_pmic_sched *s, struct dizi_bc_state *bc,
    uint64_t now_ms)
{
    if (!s || !bc || !s->ready) return false;
    if ((s->last_clock_ms && now_ms < s->last_clock_ms) ||
        !bc->online || !bc->owned ||
        (s->in_flight && !bc->pending) ||
        dizi_bc_expire(bc, now_ms)) {
        dizi_pmic_sched_close(s, bc);
        return false;
    }
    s->last_clock_ms = now_ms;
    return true;
}

/* Plan EXACTLY one 0105 24-byte GET. The caller must transmit it with the
 * verified endpoint, check its epoch AGAIN under the endpoint's send/close
 * serialization lock, and report any send error via dizi_pmic_sched_tx_error.
 * No request is sent by this function. */
static inline bool
dizi_pmic_sched_next(struct dizi_pmic_sched *s, struct dizi_bc_state *bc,
    uint64_t epoch, uint64_t now_ms, uint8_t out[24], size_t *out_len)
{
    if (!dizi_pmic_sched_ready(s, bc, epoch) ||
        !dizi_pmic_sched_check(s, bc, now_ms) || s->in_flight ||
        now_ms < s->next_due_ms || !out || !out_len)
        return false;
    if (!dizi_bc_make_get(bc, s->next_slot, now_ms, out, out_len))
        return false;
    s->in_flight = 1;
    s->in_flight_slot = s->next_slot;
    return *out_len == 24;
}

static inline void
dizi_pmic_sched_tx_error(struct dizi_pmic_sched *s,
    struct dizi_bc_state *bc, uint64_t epoch)
{
    if (dizi_pmic_sched_ready(s, bc, epoch))
        dizi_pmic_sched_close(s, bc);
}

/* Deliver only a complete GLINK channel payload, never SMEM ring bytes.
 * All owner/opcode/property/value checking stays in 0105's parser.
 * Notifications may arrive mid-request; they do not complete the request.
 * The endpoint MUST attach its own true local epoch to every received frame. */
static inline bool
dizi_pmic_sched_receive(struct dizi_pmic_sched *s, struct dizi_bc_state *bc,
    uint64_t epoch, const uint8_t *data, size_t len, uint64_t now_ms)
{
    if (!dizi_pmic_sched_ready(s, bc, epoch) ||
        !dizi_pmic_sched_check(s, bc, now_ms) || !data ||
        len < 12 || len > 24)
        return false;
    bool accepted = dizi_bc_receive(bc, data, len, now_ms);
    if (s->in_flight && !bc->pending) {
        /* A valid reply OR a rejected/failed property clears the slot.
         * Wrong opcodes leave pending and ultimately time out. */
        s->in_flight = 0;
        s->next_slot = (uint8_t)((s->in_flight_slot + 1u) % DIZI_BC_COUNT);
        s->next_due_ms = dizi_pmic_sched_after(now_ms,
            s->next_slot ? DIZI_PMIC_GET_SPACING_MS : DIZI_PMIC_ROUND_PAUSE_MS);
    }
    return accepted;
}

#endif /* DIZI_PMIC_GLINK_SCHED_H */
