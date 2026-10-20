/* Software-only exhaustive ownership contract tests for XNU LCD 0116. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "lcd_backlight_owner_0116.h"

struct fake_pin_0116 {
    bool enabled;
    unsigned reads;
    unsigned writes;
    bool fail_write;
};

static bool read_pin(void *ctx, bool *enabled)
{
    struct fake_pin_0116 *pin = (struct fake_pin_0116 *)ctx;
    ++pin->reads;
    *enabled = pin->enabled;
    return true;
}

static bool write_pin(void *ctx, bool enabled)
{
    struct fake_pin_0116 *pin = (struct fake_pin_0116 *)ctx;
    ++pin->writes;
    if (pin->fail_write)
        return false;
    pin->enabled = enabled;
    return true;
}

static void init_panel(struct sweet_lcd_state *lcd)
{
    sweet_lcd_init(lcd, true, true, 1600, 2560);
    assert(lcd->selected);
}

static void try_complete_0116(uint32_t mask, bool opt_in,
    bool stale_generation, bool backend_available, bool *written)
{
    struct fake_pin_0116 pin = { true, 0, 0, false };
    struct sweet_lcd_backlight_ops ops = { &pin, read_pin, write_pin };
    struct sweet_lcd_state lcd;
    struct dizi_lcd_owner_0116 owner;
    struct dizi_lcd_witness_0116 witness = {0, 0};
    init_panel(&lcd);
    dizi_lcd_owner_0116_init(&owner, lcd.selected, opt_in);
    assert(dizi_lcd_owner_0116_request(&lcd, &owner, true,
        &witness, &ops) == SWEET_LCD_OK);
    assert(lcd.phase == SWEET_LCD_FADING);
    assert(pin.reads == 0 && pin.writes == 0);
    witness.observed_bits = mask;
    witness.framebuffer_generation = lcd.generation - (stale_generation ? 1u : 0u);
    const struct sweet_lcd_backlight_ops *use_ops = backend_available ? &ops : 0;
    const int result = dizi_lcd_owner_0116_black_frame_done(
        &lcd, &owner, lcd.generation, &witness, use_ops);
    const bool authorized = opt_in && !stale_generation &&
        backend_available && (mask & (DIZI_LCD_0116_REQUIRED &
        ~DIZI_LCD_0116_BACKEND_PRESENT)) ==
        (DIZI_LCD_0116_REQUIRED & ~DIZI_LCD_0116_BACKEND_PRESENT);
    /* Witness bits may never fabricate the existence of an IO backend. */
    if (authorized) {
        assert(result == SWEET_LCD_OK);
        assert(lcd.phase == SWEET_LCD_BACKLIGHT_GATED);
        assert(!pin.enabled);
        assert(pin.writes == 1);
        witness.framebuffer_generation = lcd.generation;
        assert(dizi_lcd_owner_0116_request(&lcd, &owner, false,
            &witness, &ops) == SWEET_LCD_OK);
        assert(pin.enabled && pin.writes == 2);
    } else {
        assert(result == SWEET_LCD_DEFERRED);
        assert(lcd.phase == SWEET_LCD_SOFTWARE_BLACK);
        assert(pin.enabled && pin.writes == 0);
    }
    *written = pin.writes != 0;
}

int main(void)
{
    struct dizi_lcd_owner_0116 owner;
    struct sweet_lcd_state lcd;
    struct sweet_lcd_proof proof;
    struct dizi_lcd_witness_0116 witness;
    struct fake_pin_0116 pin = {true, 0, 0, false};
    struct sweet_lcd_backlight_ops ops = {&pin, read_pin, write_pin};
    init_panel(&lcd);
    dizi_lcd_owner_0116_init(&owner, false, true);
    assert(!owner.armed);
    dizi_lcd_owner_0116_init(&owner, true, false);
    assert(!owner.armed);
    dizi_lcd_owner_0116_init(&owner, true, true);
    assert(owner.armed);
    assert(dizi_lcd_owner_0116_missing(&owner, NULL, NULL) == DIZI_LCD_0116_REQUIRED);
    assert(!dizi_lcd_owner_0116_proof(&owner, &lcd, NULL, &ops, &proof));
    witness.observed_bits = DIZI_LCD_0116_REQUIRED;
    witness.framebuffer_generation = lcd.generation;
    assert(dizi_lcd_owner_0116_proof(&owner, &lcd, &witness, &ops, &proof));
    assert(proof.boe_panel_confirmed && proof.dsi_video_scanning &&
        proof.tlmm57_exclusive_owner && proof.tlmm57_is_gpio_output &&
        proof.tlmm57_active_high_confirmed);
    assert(dizi_lcd_owner_0116_missing(&owner, &witness, NULL) &
        DIZI_LCD_0116_BACKEND_PRESENT);
    witness.framebuffer_generation++;
    assert(!dizi_lcd_owner_0116_proof(&owner, &lcd, &witness, &ops, &proof));
    witness.framebuffer_generation--;
    struct sweet_lcd_backlight_ops readonly = {&pin, read_pin, NULL};
    assert(!dizi_lcd_owner_0116_proof(&owner, &lcd, &witness, &readonly, &proof));

    unsigned granted = 0, refused = 0;
    for (uint32_t mask = 0; mask <= DIZI_LCD_0116_REQUIRED; ++mask) {
        for (unsigned opt = 0; opt < 2; ++opt) {
            for (unsigned stale = 0; stale < 2; ++stale) {
                for (unsigned backend = 0; backend < 2; ++backend) {
                    bool written = false;
                    try_complete_0116(mask, opt != 0, stale != 0,
                        backend != 0, &written);
                    if (written) ++granted;
                    else ++refused;
                }
            }
        }
    }
    assert(granted == 2 && refused == 4094);
    /* The opt-in flag alone, even with FDT details copied into a mask,
     * is never enough without a genuine backend + a fresh owner witness. */
    assert(pin.writes == 0);
    printf("lcd 0116: %u synthetic grants, %u denied; no real MMIO\n",
        granted, refused);
    return 0;
}
