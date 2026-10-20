/* Test-only mock interfaces. Actual 0110 vsyncFired and selector12 sections
 * are pasted here by test-dizi-lcd-generation-race.py from applied XNU source. */
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>
#include "sweet_lcd.h"

using OSObject = void;
using IOLock = std::mutex;
static constexpr int kIOReturnSuccess = 0, kIOReturnNotReady = -1;
static constexpr uint32_t SWEET_FB_SWAP_REC_SIZE = 0x46c, SWEET_FB_NOTIFY_VSYNC=5, SWEET_FB_VSYNC_US=16667;
static thread_local bool in_vsync;
static thread_local int lock_index, unlock_index;
struct PauseHook {
    std::mutex mutex;
    std::condition_variable cv;
    int target=0;
    bool on_lock=false, hit=false, released=false;
    void arm(int n, bool locked) {
        std::lock_guard<std::mutex> guard(mutex);
        target=n; on_lock=locked; hit=false; released=false;
    }
    void pause_if(bool locked,int seq) {
        std::unique_lock<std::mutex> guard(mutex);
        if (target != seq || on_lock != locked) return;
        hit=true; cv.notify_all();
        if (!cv.wait_for(guard,std::chrono::seconds(4),[&]{return released;})) std::abort();
    }
    void wait_hit() {
        std::unique_lock<std::mutex> guard(mutex);
        if (!cv.wait_for(guard,std::chrono::seconds(4),[&]{return hit;})) std::abort();
    }
    void release() { std::lock_guard<std::mutex> guard(mutex); released=true; cv.notify_all(); }
} hook;
static void IOLockLock(IOLock *lock) {
    lock->lock();
    if (in_vsync) hook.pause_if(true,++lock_index);
}
static void IOLockUnlock(IOLock *lock) {
    lock->unlock();
    if (in_vsync) hook.pause_if(false,++unlock_index);
}
struct IOMobileFramebufferUserClient { void notify(unsigned,const uint64_t*,unsigned) {} };
struct ClientList { unsigned getCount() const {return 0;} void *getObject(unsigned) const{return nullptr;} };
struct IOTimerEventSource { int calls=0; void setTimeoutUS(unsigned) { ++calls; } };
static uint64_t mach_absolute_time() {return 42;}
static void *IOMallocData(size_t n) {return malloc(n);}
static void IOFreeData(void *p, size_t) {free(p);}
struct AppleCLCD {
    uint64_t fVsyncCount=0;
    uint32_t fWidth=4, fHeight=4, fRowBytes=16, fFlushTicks=1;
    uintptr_t fPixels=0;
    IOLock *fLock;
    ClientList *fClients;
    bool fPowerOff=false, fDirty=false;
    uint32_t fFadeStep=0;
    uint64_t fFadeEpoch=0;
    struct sweet_lcd_state fDiziLCD;
    uint8_t fPending[SWEET_FB_SWAP_REC_SIZE]={};
    std::vector<uint32_t> pixels;
    int presentations=0;
    IOLock actual_lock;
    ClientList actual_clients;
    AppleCLCD(): fLock(&actual_lock), fClients(&actual_clients), pixels(16,0xFFFFFFFFu) {
        fPixels=(uintptr_t)pixels.data();
        sweet_lcd_init(&fDiziLCD,true,true,1600,2560); // opt-in virtual panel
    }
    static void vsyncFired(OSObject *,IOTimerEventSource *);
    void present(const uint8_t *) {
        ++presentations;
        for (auto &pixel : pixels) pixel=0xFFFFFFFFu;
    }
};
struct MockArgs { uint64_t scalarInput[1]; };
static int mock_power(AppleCLCD *fFB, bool desired_off) {
    MockArgs storage={ {desired_off ? 0u : 1u} };
    MockArgs *args=&storage;
    int ret=kIOReturnSuccess;
/* BEGIN_EXTRACTED_POWER */
/* END_EXTRACTED_POWER */
    return ret;
}
/* BEGIN_EXTRACTED_VSYNC */
/* END_EXTRACTED_VSYNC */

static std::thread vsync_async(AppleCLCD &fb,IOTimerEventSource &timer) {
    return std::thread([&]{in_vsync=true;lock_index=0;unlock_index=0;
        AppleCLCD::vsyncFired((OSObject *)&fb,&timer); in_vsync=false;});
}
static void snapshot_equal(const std::vector<uint32_t>& pixels, const AppleCLCD& fb) {
    assert(pixels==fb.pixels);
}
static void scenario_before_first_row() {
    AppleCLCD fb; IOTimerEventSource timer;
    assert(mock_power(&fb,true)==kIOReturnSuccess);
    hook.arm(1,false); auto worker=vsync_async(fb,timer);hook.wait_hit();
    assert(mock_power(&fb,false)==kIOReturnSuccess);
    auto after_on=fb.pixels;
    hook.release();worker.join();snapshot_equal(after_on,fb);
    for (auto pixel:fb.pixels) assert(pixel==0xFFFFFFFFu);
    AppleCLCD::vsyncFired((OSObject*)&fb,&timer);
    assert(fb.presentations==1 && !fb.fPowerOff && fb.fFadeEpoch==2);
}
static void scenario_after_first_row() {
    AppleCLCD fb; IOTimerEventSource timer;
    assert(mock_power(&fb,true)==kIOReturnSuccess);
    hook.arm(2,false);auto worker=vsync_async(fb,timer);hook.wait_hit();
    assert(fb.pixels[0]==0x7F7F7F7Fu && fb.pixels[4]==0xFFFFFFFFu);
    assert(mock_power(&fb,false)==kIOReturnSuccess);
    auto after_on=fb.pixels;
    hook.release();worker.join();snapshot_equal(after_on,fb);
    AppleCLCD::vsyncFired((OSObject*)&fb,&timer);
    for (auto pixel:fb.pixels) assert(pixel==0xFFFFFFFFu);
}
static void scenario_aba_off_on_off() {
    AppleCLCD fb; IOTimerEventSource timer;
    assert(mock_power(&fb,true)==kIOReturnSuccess);
    hook.arm(3,false);auto worker=vsync_async(fb,timer);hook.wait_hit();
    assert(mock_power(&fb,false)==kIOReturnSuccess);
    assert(mock_power(&fb,true)==kIOReturnSuccess);
    assert(fb.fPowerOff && fb.fFadeEpoch==3 && fb.fFadeStep==0);
    auto after_new_off=fb.pixels;
    hook.release();worker.join();snapshot_equal(after_new_off,fb);
    AppleCLCD::vsyncFired((OSObject*)&fb,&timer);
    assert(fb.fFadeStep==1 && fb.pixels[0]==0x3F3F3F3Fu && fb.pixels[8]==0x7F7F7F7Fu);
}
static void scenario_stale_black_completion() {
    AppleCLCD fb; IOTimerEventSource timer;
    assert(mock_power(&fb,true)==kIOReturnSuccess);
    fb.fFadeStep=6;
    hook.arm((int)fb.fHeight+1,false);
    auto worker=vsync_async(fb,timer);hook.wait_hit();
    assert(mock_power(&fb,false)==kIOReturnSuccess);
    auto after_on=fb.pixels;
    hook.release();worker.join();snapshot_equal(after_on,fb);
    assert(fb.fDiziLCD.phase==SWEET_LCD_INHERITED_LIT && fb.fDiziLCD.off_requested==false);
    AppleCLCD::vsyncFired((OSObject*)&fb,&timer);
    assert(fb.presentations==1);
}
static void scenario_aba_before_black_completion() {
    AppleCLCD fb; IOTimerEventSource timer;
    assert(mock_power(&fb,true)==kIOReturnSuccess);
    fb.fFadeStep=6;
    hook.arm((int)fb.fHeight+1,false);
    auto worker=vsync_async(fb,timer);hook.wait_hit();
    assert(mock_power(&fb,false)==kIOReturnSuccess);
    assert(mock_power(&fb,true)==kIOReturnSuccess);
    assert(fb.fPowerOff && fb.fFadeEpoch==3);
    auto after_new_off=fb.pixels;
    hook.release();worker.join();snapshot_equal(after_new_off,fb);
    assert(fb.fDiziLCD.phase==SWEET_LCD_FADING);
    assert(fb.fDiziLCD.off_requested && fb.fFadeStep==0);
    AppleCLCD::vsyncFired((OSObject*)&fb,&timer);
    assert(fb.fDiziLCD.phase==SWEET_LCD_FADING && fb.fFadeStep==1);
}
static void scenario_on_waits_for_row_lock() {
    AppleCLCD fb; IOTimerEventSource timer;
    assert(mock_power(&fb,true)==kIOReturnSuccess);
    hook.arm(2,true); auto worker=vsync_async(fb,timer);hook.wait_hit();
    std::atomic<bool> on_done=false;
    auto caller=std::thread([&]{ assert(mock_power(&fb,false)==kIOReturnSuccess); on_done.store(true); });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    assert(!on_done.load()); // VSYNC currently owns the short one-row lock.
    hook.release();caller.join();auto after_on=fb.pixels;
    worker.join();snapshot_equal(after_on,fb);
    assert(on_done.load());
}
static void scenario_default_off_model() {
    AppleCLCD fb;
    sweet_lcd_init(&fb.fDiziLCD,false,false,1600,2560);
    assert(!fb.fDiziLCD.selected);
    assert(mock_power(&fb,true)==kIOReturnSuccess);
    assert(mock_power(&fb,false)==kIOReturnSuccess);
    assert(fb.fFadeEpoch==2 && !fb.fPowerOff);
    assert(fb.fDiziLCD.phase==SWEET_LCD_UNMANAGED);
}
int main() {
    scenario_before_first_row();
    scenario_after_first_row();
    scenario_aba_off_on_off();
    scenario_stale_black_completion();
    scenario_aba_before_black_completion();
    scenario_on_waits_for_row_lock();
    scenario_default_off_model();
    std::cout << "PASS 0109 adversarial: snapshot-before-pixels, mid-row, ABA, last-row black completion, black completion ABA, lock contention, default-disabled" << std::endl;
}
