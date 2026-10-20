/*
 * POCO Pad (dizi) LCD GPIO57 backlight ownership gate, source-only.
 *
 * Android FDT describes a BOE NT36532 CPHY VIDEO panel (alternative CSOT),
 * GPIO57 backlight enable, GPIO98 reset, and external 12-bit brightness.
 * Its selected BOE panel-supply-entries phandle points at a "dummy" supply.
 * None of those static descriptions proves that XNU owns the pin, reset,
 * DSI engine, or display rails inherited from ABL/Gunyah firmware.
 *
 * The witness is reserved for a FUTURE kernel-only controller that really
 * observes all of the facts below. This interface never touches MMIO or
 * creates such a witness from a boot argument or a firmware tree.
 * Callers must hold the framebuffer power lock through request/completion.
 */
#ifndef DIZI_LCD_BACKLIGHT_OWNER_0116_H
#define DIZI_LCD_BACKLIGHT_OWNER_0116_H

#include "sweet_lcd.h"

#define DIZI_LCD_0116_BOE_IDENTIFIED        (1u << 0)
#define DIZI_LCD_0116_DSI_VIDEO_OBSERVED   (1u << 1)
#define DIZI_LCD_0116_GPIO57_EXCLUSIVE     (1u << 2)
#define DIZI_LCD_0116_GPIO57_OUTPUT        (1u << 3)
#define DIZI_LCD_0116_GPIO57_ACTIVE_HIGH   (1u << 4)
#define DIZI_LCD_0116_GPIO57_READBACK      (1u << 5)
#define DIZI_LCD_0116_DISPLAY_RAILS_STABLE (1u << 6)
#define DIZI_LCD_0116_RESET98_STABLE       (1u << 7)
#define DIZI_LCD_0116_BACKEND_PRESENT      (1u << 8)
#define DIZI_LCD_0116_REQUIRED (DIZI_LCD_0116_BOE_IDENTIFIED | \
    DIZI_LCD_0116_DSI_VIDEO_OBSERVED | DIZI_LCD_0116_GPIO57_EXCLUSIVE | \
    DIZI_LCD_0116_GPIO57_OUTPUT | DIZI_LCD_0116_GPIO57_ACTIVE_HIGH | \
    DIZI_LCD_0116_GPIO57_READBACK | DIZI_LCD_0116_DISPLAY_RAILS_STABLE | \
    DIZI_LCD_0116_RESET98_STABLE | DIZI_LCD_0116_BACKEND_PRESENT)

struct dizi_lcd_owner_0116 {
    bool armed; /* dizihw=1 dizilcd=1 diziblowner=1, none grants ownership */
};

/* A snapshot of READ-ONLY, independently verified kernel driver state.
 * Crucially, this structure is never constructed by the XNU 0116 driver:
 * no trusted observer or GPIO ownership backend exists today. */
struct dizi_lcd_witness_0116 {
    uint32_t observed_bits;
    uint32_t framebuffer_generation;
};

static inline void
dizi_lcd_owner_0116_init(struct dizi_lcd_owner_0116 *owner,
    bool selected, bool opt_in)
{
    owner->armed = selected && opt_in;
}

/* Missing bits are reported honestly, with an absent observer treated as
 * UNKNOWN, rather than inferring a pin state from a static FDT or the splash. */
static inline uint32_t
dizi_lcd_owner_0116_missing(const struct dizi_lcd_owner_0116 *owner,
    const struct dizi_lcd_witness_0116 *witness,
    const struct sweet_lcd_backlight_ops *ops)
{
    uint32_t observed = 0;
    if (owner != 0 && owner->armed && witness != 0)
        observed = witness->observed_bits & ~DIZI_LCD_0116_BACKEND_PRESENT;
    if (owner != 0 && owner->armed && ops != 0 &&
        ops->get_enabled != 0 && ops->set_enabled != 0)
        observed |= DIZI_LCD_0116_BACKEND_PRESENT;
    return DIZI_LCD_0116_REQUIRED & ~observed;
}

/* The witnessed generation must match the current 0103/0109 fade epoch's
 * hardware generation before granting the existing readback-verified backend.
 * A stale snapshot is not an authorization for a later power transition. */
static inline bool
dizi_lcd_owner_0116_proof(const struct dizi_lcd_owner_0116 *owner,
    const struct sweet_lcd_state *lcd,
    const struct dizi_lcd_witness_0116 *witness,
    const struct sweet_lcd_backlight_ops *ops,
    struct sweet_lcd_proof *proof)
{
    if (owner == 0 || !owner->armed || lcd == 0 || !lcd->selected ||
        witness == 0 || ops == 0 || proof == 0 ||
        witness->framebuffer_generation != lcd->generation ||
        dizi_lcd_owner_0116_missing(owner, witness, ops) != 0)
        return false;
    proof->boe_panel_confirmed = true;
    proof->dsi_video_scanning = true;
    proof->tlmm57_exclusive_owner = true;
    proof->tlmm57_is_gpio_output = true;
    proof->tlmm57_active_high_confirmed = true;
    return true;
}

/* This wrapper is the sole authorized 0116 XNU entry into the 0103 power
 * model. A failed witness forwards NULL proof/ops, preserving software black
 * and preventing a physical toggle. For actual IO, 0103 still demands
 * hardware get/set readback and rolls back failed writes. */
static inline int
dizi_lcd_owner_0116_request(struct sweet_lcd_state *lcd,
    const struct dizi_lcd_owner_0116 *owner, bool off,
    const struct dizi_lcd_witness_0116 *witness,
    const struct sweet_lcd_backlight_ops *ops)
{
    struct sweet_lcd_proof proof;
    if (dizi_lcd_owner_0116_proof(owner, lcd, witness, ops, &proof))
        return sweet_lcd_request(lcd, off, &proof, ops);
    return sweet_lcd_request(lcd, off, 0, 0);
}

static inline int
dizi_lcd_owner_0116_black_frame_done(struct sweet_lcd_state *lcd,
    const struct dizi_lcd_owner_0116 *owner, uint32_t generation,
    const struct dizi_lcd_witness_0116 *witness,
    const struct sweet_lcd_backlight_ops *ops)
{
    struct sweet_lcd_proof proof;
    if (dizi_lcd_owner_0116_proof(owner, lcd, witness, ops, &proof))
        return sweet_lcd_black_frame_done(lcd, generation, &proof, ops);
    return sweet_lcd_black_frame_done(lcd, generation, 0, 0);
}

#endif /* DIZI_LCD_BACKLIGHT_OWNER_0116_H */
