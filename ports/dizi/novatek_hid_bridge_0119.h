/* Source-only, no-MMIO NT36532 -> IOHIDEvent frame planner (2026).
 * 0100 dz_parse validates the chip's report checksum, firmware WDT/ESD,
 * contact IDs and 16000x25600 super-resolution ranges; its coordinates are
 * divided by 10 before passing here. This planner is an additional barrier.
 * A frame with a physical contact MUST have passed the 0100 post-start
 * trim/cascade/firmware handshake and a fresh successful SPI read.
 * No synthetic down is possible on a transport error. An explicit cancel
 * releases only contacts previously accepted from a real report.
 */
#ifndef DIZI_NOVATEK_HID_BRIDGE_0119_H
#define DIZI_NOVATEK_HID_BRIDGE_0119_H
#include <stdint.h>
#include <stdbool.h>

#define DIZI_NVT_HID_CONTACTS 10u
#define DIZI_NVT_HID_MASK ((1u << DIZI_NVT_HID_CONTACTS) - 1u)
#define DIZI_NVT_HID_PANEL_W 1600
#define DIZI_NVT_HID_PANEL_H 2560
#define DIZI_NVT_HID_EDGE_PX 48

struct dizi_nvt_hid_frame {
    uint32_t active;
    int32_t x[DIZI_NVT_HID_CONTACTS];
    int32_t y[DIZI_NVT_HID_CONTACTS];
    uint64_t sequence;  /* locally monotonically increasing per report */
    bool verified_spi_report; /* not an invented readiness bit */
    bool cancel; /* allowed ONLY to release previously confirmed contacts */
};

struct dizi_nvt_hid_state {
    uint64_t sequence;
    uint32_t active;
    uint32_t edges;
    int32_t fx[DIZI_NVT_HID_CONTACTS]; /* 16.16 normalized to canvas */
    int32_t fy[DIZI_NVT_HID_CONTACTS];
};

struct dizi_nvt_hid_plan {
    uint32_t active, changed, started, ended, moved, edges;
    int32_t fx[DIZI_NVT_HID_CONTACTS];
    int32_t fy[DIZI_NVT_HID_CONTACTS];
};

static inline bool
dizi_nvt_hid_plan(const struct dizi_nvt_hid_state *old,
    const struct dizi_nvt_hid_frame *frame, int logical_w, int logical_h,
    struct dizi_nvt_hid_state *next, struct dizi_nvt_hid_plan *out)
{
    if (!old || !frame || !next || !out || next == old ||
        frame->sequence == 0 || frame->sequence <= old->sequence ||
        logical_w <= 0 || logical_h <= 0 || logical_w > 16384 ||
        logical_h > 16384 || (frame->active & ~DIZI_NVT_HID_MASK))
        return false;
    if (frame->cancel) {
        /* SPI failure may only end physical touches observed previously. */
        if (frame->verified_spi_report || frame->active != 0 || !old->active)
            return false;
    } else if (!frame->verified_spi_report) {
        return false;
    }

    struct dizi_nvt_hid_state ns = *old;
    struct dizi_nvt_hid_plan plan = {0};
    uint32_t mask = frame->cancel ? 0 : frame->active;
    plan.active = mask;
    plan.started = mask & ~old->active;
    plan.ended = old->active & ~mask;
    int off_x = (logical_w - DIZI_NVT_HID_PANEL_W) / 2;
    int off_y = (logical_h - DIZI_NVT_HID_PANEL_H) / 2;

    for (unsigned i = 0; i < DIZI_NVT_HID_CONTACTS; ++i) {
        uint32_t bit = 1u << i;
        if (mask & bit) {
            int x = frame->x[i], y = frame->y[i];
            if (x < 0 || x >= DIZI_NVT_HID_PANEL_W ||
                y < 0 || y >= DIZI_NVT_HID_PANEL_H)
                return false; /* do not clip physically impossible raw data */
            int cx = x + off_x, cy = y + off_y;
            if (cx < 0) cx = 0;
            if (cy < 0) cy = 0;
            if (cx >= logical_w) cx = logical_w - 1;
            if (cy >= logical_h) cy = logical_h - 1;
            /* This is the precise 16.16 mapping in 0099 SweetHIDTouch. */
            int32_t fx = (int32_t)(((int64_t)cx << 16) / logical_w);
            int32_t fy = (int32_t)(((int64_t)cy << 16) / logical_h);
            if (plan.started & bit) {
                if (cx < DIZI_NVT_HID_EDGE_PX ||
                    cx > logical_w - 1 - DIZI_NVT_HID_EDGE_PX ||
                    cy < DIZI_NVT_HID_EDGE_PX ||
                    cy > logical_h - 1 - DIZI_NVT_HID_EDGE_PX)
                    ns.edges |= bit;
                else
                    ns.edges &= ~bit;
            } else if (old->fx[i] != fx || old->fy[i] != fy) {
                plan.moved |= bit;
            }
            ns.fx[i] = fx;
            ns.fy[i] = fy;
        } else if (plan.ended & bit) {
            /* Keep last real coordinate for touch-up; don't invent a point. */
        } else {
            ns.edges &= ~bit;
        }
    }
    plan.changed = plan.started | plan.ended | plan.moved;
    plan.edges = ns.edges;
    for (unsigned i = 0; i < DIZI_NVT_HID_CONTACTS; ++i) {
        plan.fx[i] = ns.fx[i];
        plan.fy[i] = ns.fy[i];
    }
    ns.active = mask;
    ns.sequence = frame->sequence;
    /* Caller commits after IOHIDEvent allocations succeed. No side effects
     * or partially visible touches in the rejection path. */
    *next = ns;
    *out = plan;
    return true;
}

#endif /* DIZI_NOVATEK_HID_BRIDGE_0119_H */
