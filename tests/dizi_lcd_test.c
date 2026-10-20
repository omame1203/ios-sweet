/* Host-side assertions: no hardware is touched. Simulated callbacks only. */
#include <assert.h>
#include <stdio.h>
#include "sweet_lcd.h"
struct fake { bool on, fail_read, fail_write, fail_after_write, fail_undo; unsigned writes, reads; };
static bool fake_get(void *ctx, bool *on) {
    struct fake *f = ctx; ++f->reads;
    if (f->fail_read) return false;
    *on = f->on; return true;
}
static bool fake_set(void *ctx, bool on) {
    struct fake *f = ctx; ++f->writes;
    if (f->fail_write || (f->fail_undo && on)) return false;
    f->on = on;
    if (f->fail_after_write) { f->fail_after_write = false; return false; }
    return true;
}
static struct sweet_lcd_proof proof = {true,true,true,true,true};
int main(void) {
    struct sweet_lcd_state s;
    struct fake f = {.on=true};
    struct sweet_lcd_backlight_ops ops = {&f, fake_get, fake_set};
    sweet_lcd_init(&s,true,false,1600,2560);
    assert(!s.selected && s.phase==SWEET_LCD_UNMANAGED);
    assert(sweet_lcd_request(&s,true,&proof,&ops)==SWEET_LCD_DEFERRED);
    assert(!f.writes);
    sweet_lcd_init(&s,true,true,1600,2400);
    assert(!s.selected);
    sweet_lcd_init(&s,true,true,1600,2560);
    assert(s.selected && s.phase==SWEET_LCD_INHERITED_LIT);
    assert(sweet_lcd_set_brightness(&s,4096)==SWEET_LCD_ERROR);
    assert(s.requested_brightness==4095);
    assert(sweet_lcd_set_brightness(&s,0)==SWEET_LCD_DEFERRED);
    assert(s.requested_brightness==0 && f.writes==0);
    assert(sweet_lcd_request(&s,true,0,0)==SWEET_LCD_OK);
    unsigned gen=s.generation;
    assert(sweet_lcd_black_frame_done(&s,gen,0,0)==SWEET_LCD_DEFERRED);
    assert(s.phase==SWEET_LCD_SOFTWARE_BLACK && f.writes==0 && f.on);
    assert(sweet_lcd_request(&s,false,0,0)==SWEET_LCD_OK);
    assert(s.phase==SWEET_LCD_INHERITED_LIT);
    assert(sweet_lcd_black_frame_done(&s,gen,&proof,&ops)==SWEET_LCD_DEFERRED);
    assert(f.writes==0);
    assert(sweet_lcd_request(&s,true,0,0)==SWEET_LCD_OK);
    gen=s.generation;
    struct sweet_lcd_proof unverified=proof;
    unverified.tlmm57_active_high_confirmed=false;
    assert(sweet_lcd_black_frame_done(&s,gen,&unverified,&ops)==SWEET_LCD_DEFERRED);
    assert(s.phase==SWEET_LCD_SOFTWARE_BLACK && f.writes==0);
    assert(sweet_lcd_request(&s,false,0,0)==SWEET_LCD_OK);
    assert(sweet_lcd_request(&s,true,&proof,&ops)==SWEET_LCD_OK);
    gen=s.generation;
    assert(sweet_lcd_request(&s,true,&proof,&ops)==SWEET_LCD_OK && s.generation==gen);
    assert(sweet_lcd_black_frame_done(&s,gen,&proof,&ops)==SWEET_LCD_OK);
    assert(s.phase==SWEET_LCD_BACKLIGHT_GATED && !f.on && f.writes==1);
    assert(sweet_lcd_request(&s,false,0,0)==SWEET_LCD_ERROR && !f.on);
    assert(s.phase==SWEET_LCD_BACKLIGHT_GATED);
    assert(sweet_lcd_request(&s,false,&proof,&ops)==SWEET_LCD_OK);
    assert(f.on && s.phase==SWEET_LCD_INHERITED_LIT);
    /* Readback failed -> no write. */
    f.fail_read=true;
    assert(sweet_lcd_request(&s,true,&proof,&ops)==SWEET_LCD_OK);
    gen=s.generation;
    unsigned writes=f.writes;
    assert(sweet_lcd_black_frame_done(&s,gen,&proof,&ops)==SWEET_LCD_ERROR);
    assert(f.writes==writes && s.phase==SWEET_LCD_SOFTWARE_BLACK);
    f.fail_read=false;
    assert(sweet_lcd_request(&s,false,&proof,&ops)==SWEET_LCD_OK);
    /* Write reports failure after changing pin: rollback to original on. */
    f.fail_after_write=true;
    assert(sweet_lcd_request(&s,true,&proof,&ops)==SWEET_LCD_OK);
    gen=s.generation;
    writes=f.writes;
    assert(sweet_lcd_black_frame_done(&s,gen,&proof,&ops)==SWEET_LCD_ERROR);
    assert(f.on && f.writes==writes+2 && s.phase==SWEET_LCD_SOFTWARE_BLACK);
    assert(sweet_lcd_request(&s,false,&proof,&ops)==SWEET_LCD_OK);
    /* Rollback impossible: fault is sticky and safety state remains black. */
    f.fail_after_write=true;
    f.fail_undo=true;
    assert(sweet_lcd_request(&s,true,&proof,&ops)==SWEET_LCD_OK);
    gen=s.generation;
    assert(sweet_lcd_black_frame_done(&s,gen,&proof,&ops)==SWEET_LCD_ERROR);
    assert(!f.on && s.phase==SWEET_LCD_FAULT);
    assert(sweet_lcd_request(&s,false,&proof,&ops)==SWEET_LCD_ERROR);
    assert(sweet_lcd_set_brightness(&s,100)==SWEET_LCD_ERROR);
    puts("PASS: dizi LCD safe policy, gating, no-op, rollback, sticky fault, stale epoch");
}
