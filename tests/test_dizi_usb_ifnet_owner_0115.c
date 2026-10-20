/* Offline ownership contract: synthetic events, no USB/ifnet hardware. */
#include "usb_ifnet_owner_0115.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static void test_legacy_default(void)
{
    struct dizi_usb_owner_state s = {0};
    assert(s.phase == DZ_USB_OWNER_IDLE && s.owner == DZ_USB_OWNER_NONE);
    assert(!dizi_usb_owner_claim(&s, false, 0, 0));
    assert(dizi_usb_owner_claim(&s, false, 0, 1));
    assert(s.owner == DZ_USB_OWNER_BSD && s.phase == DZ_USB_OWNER_RESERVED);
    assert(s.proof == 0);
    assert(!dizi_usb_owner_claim(&s, true, DZ_USB_NATIVE_ALL, 2));
    assert(!dizi_usb_owner_attached(&s, DZ_USB_OWNER_APPLE_IOKIT, 1));
    assert(!dizi_usb_owner_attached(&s, DZ_USB_OWNER_BSD, 2));
    assert(dizi_usb_owner_attached(&s, DZ_USB_OWNER_BSD, 1));
    assert(dizi_usb_owner_transmits(&s, DZ_USB_OWNER_BSD, 1));
    assert(!dizi_usb_owner_transmits(&s, DZ_USB_OWNER_APPLE_IOKIT, 1));
    assert(!dizi_usb_owner_transmits(&s, DZ_USB_OWNER_BSD, 2));
    assert(!dizi_usb_owner_abort_reserved(&s, DZ_USB_OWNER_BSD, 1));
    assert(!dizi_usb_owner_claim(&s, true, DZ_USB_NATIVE_ALL, 2));
    assert(!dizi_usb_owner_detach_begin(&s, DZ_USB_OWNER_APPLE_IOKIT, 1));
    assert(dizi_usb_owner_detach_begin(&s, DZ_USB_OWNER_BSD, 1));
    assert(!dizi_usb_owner_transmits(&s, DZ_USB_OWNER_BSD, 1));
    assert(!dizi_usb_owner_claim(&s, true, DZ_USB_NATIVE_ALL, 2));
    assert(!dizi_usb_owner_detach_done(&s, DZ_USB_OWNER_BSD, 1, false));
    assert(!dizi_usb_owner_detach_done(&s, DZ_USB_OWNER_APPLE_IOKIT, 1, true));
    assert(dizi_usb_owner_detach_done(&s, DZ_USB_OWNER_BSD, 1, true));
    assert(s.owner == DZ_USB_OWNER_NONE && s.phase == DZ_USB_OWNER_IDLE);
    assert(!dizi_usb_owner_claim(&s, false, 0, 1)); /* no epoch reuse */
    assert(dizi_usb_owner_claim(&s, false, 0, 2));
}

static void test_native_requires_every_proof(void)
{
    for (unsigned bit = 0; bit < 6; bit++) {
        struct dizi_usb_owner_state s = {0};
        uint32_t evidence = DZ_USB_NATIVE_ALL & ~(1u << bit);
        assert(!dizi_usb_owner_claim(&s, true, evidence, 1));
        assert(s.phase == DZ_USB_OWNER_BLOCKED);
        assert(!dizi_usb_owner_claim(&s, false, 0, 2)); /* explicit failure cannot fallback */
        assert(!dizi_usb_owner_attached(&s, DZ_USB_OWNER_BSD, 1));
        assert(!dizi_usb_owner_attached(&s, DZ_USB_OWNER_APPLE_IOKIT, 1));
    }
    struct dizi_usb_owner_state extra = {0};
    assert(!dizi_usb_owner_claim(&extra, true, DZ_USB_NATIVE_ALL | (1u << 31), 1));
    assert(extra.phase == DZ_USB_OWNER_BLOCKED);
    struct dizi_usb_owner_state s = {0};
    assert(dizi_usb_owner_claim(&s, true, DZ_USB_NATIVE_ALL, 1));
    assert(s.owner == DZ_USB_OWNER_APPLE_IOKIT);
    assert(s.proof == DZ_USB_NATIVE_ALL);
    assert(!dizi_usb_owner_attached(&s, DZ_USB_OWNER_BSD, 1));
    assert(dizi_usb_owner_attached(&s, DZ_USB_OWNER_APPLE_IOKIT, 1));
    assert(!dizi_usb_owner_transmits(&s, DZ_USB_OWNER_BSD, 1));
    assert(dizi_usb_owner_transmits(&s, DZ_USB_OWNER_APPLE_IOKIT, 1));
    assert(!dizi_usb_owner_claim(&s, false, 0, 2)); /* no parallel BSD */
    assert(dizi_usb_owner_detach_begin(&s, DZ_USB_OWNER_APPLE_IOKIT, 1));
    assert(!dizi_usb_owner_claim(&s, false, 0, 2)); /* asynchronous detach */
    assert(dizi_usb_owner_detach_done(&s, DZ_USB_OWNER_APPLE_IOKIT, 1, true));
    assert(dizi_usb_owner_claim(&s, false, 0, 2));
}

static void test_abort_and_aba(void)
{
    struct dizi_usb_owner_state s = {0};
    assert(dizi_usb_owner_claim(&s, false, 0, 7));
    assert(!dizi_usb_owner_abort_reserved(&s, DZ_USB_OWNER_BSD, 6));
    assert(dizi_usb_owner_abort_reserved(&s, DZ_USB_OWNER_BSD, 7));
    assert(!dizi_usb_owner_claim(&s, false, 0, 7));
    assert(dizi_usb_owner_claim(&s, false, 0, 8));
    assert(dizi_usb_owner_attached(&s, DZ_USB_OWNER_BSD, 8));
    assert(!dizi_usb_owner_detach_begin(&s, DZ_USB_OWNER_BSD, 7));
    assert(!dizi_usb_owner_detach_done(&s, DZ_USB_OWNER_BSD, 7, true));
    assert(dizi_usb_owner_detach_begin(&s, DZ_USB_OWNER_BSD, 8));
    assert(!dizi_usb_owner_attached(&s, DZ_USB_OWNER_BSD, 8));
    assert(dizi_usb_owner_detach_done(&s, DZ_USB_OWNER_BSD, 8, true));
    assert(dizi_usb_owner_claim(&s, false, 0, 9));
    assert(!dizi_usb_owner_attached(&s, DZ_USB_OWNER_BSD, 8));
    assert(dizi_usb_owner_attached(&s, DZ_USB_OWNER_BSD, 9));
}

static void test_adversarial_orders(void)
{
    /* Explore many interleavings in a deterministic pseudo-random walk.
     * Maintain a separate expected single-active-ifnet model. */
    struct dizi_usb_owner_state s = {0};
    uint64_t epoch = 0;
    uint32_t state = 0x73a31b55u;
    for (unsigned i = 0; i < 60000u; i++) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        unsigned action = state % 9u;
        if (action == 0 && s.phase == DZ_USB_OWNER_IDLE) {
            epoch++;
            (void)dizi_usb_owner_claim(&s, false, 0, epoch);
        } else if (action == 1 && s.phase == DZ_USB_OWNER_RESERVED) {
            (void)dizi_usb_owner_attached(&s, DZ_USB_OWNER_BSD, epoch);
        } else if (action == 2 && s.phase == DZ_USB_OWNER_RESERVED) {
            (void)dizi_usb_owner_abort_reserved(&s, DZ_USB_OWNER_BSD, epoch);
        } else if (action == 3 && s.phase == DZ_USB_OWNER_ACTIVE) {
            (void)dizi_usb_owner_detach_begin(&s, DZ_USB_OWNER_BSD, epoch);
        } else if (action == 4 && s.phase == DZ_USB_OWNER_DRAINING) {
            (void)dizi_usb_owner_detach_done(&s, DZ_USB_OWNER_BSD, epoch, true);
        } else {
            assert(!dizi_usb_owner_claim(&s, true, 0, epoch));
            assert(!dizi_usb_owner_attached(&s, DZ_USB_OWNER_APPLE_IOKIT, epoch));
        }
        assert((s.phase == DZ_USB_OWNER_IDLE) == (s.owner == DZ_USB_OWNER_NONE));
        assert(s.phase != DZ_USB_OWNER_ACTIVE || s.owner == DZ_USB_OWNER_BSD);
        assert(!dizi_usb_owner_transmits(&s, DZ_USB_OWNER_APPLE_IOKIT, epoch));
        assert((s.phase == DZ_USB_OWNER_ACTIVE) ==
            dizi_usb_owner_transmits(&s, DZ_USB_OWNER_BSD, epoch));
        assert(s.max_epoch >= s.epoch);
    }
}

int main(void)
{
    test_legacy_default();
    test_native_requires_every_proof();
    test_abort_and_aba();
    test_adversarial_orders();
    puts("PASS 0115 ifnet ownership model: BSD default, native proof, single owner, asynchronous detach, epoch/ABA, fail closed and 60000 transitions");
    return 0;
}
