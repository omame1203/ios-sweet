/* Source-only synthetic 0119 frames; no SPI/firmware/device operation. */
#include "novatek_hid_bridge_0119.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static bool apply(struct dizi_nvt_hid_state *state,
    const struct dizi_nvt_hid_frame *frame, int w, int h,
    struct dizi_nvt_hid_plan *out)
{
    struct dizi_nvt_hid_state next;
    if (!dizi_nvt_hid_plan(state, frame, w, h, &next, out)) return false;
    *state = next;
    return true;
}

static void test_gate_and_atomic_failures(void)
{
    struct dizi_nvt_hid_state state = {0}, next = {0};
    struct dizi_nvt_hid_plan plan = {0};
    struct dizi_nvt_hid_frame f = {.active = 1, .sequence = 1};
    f.x[0] = 800; f.y[0] = 1280;
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 2048, &next, &plan));
    assert(!state.sequence && !next.sequence);
    f.verified_spi_report = true;
    assert(!dizi_nvt_hid_plan(NULL, &f, 1536, 2048, &next, &plan));
    assert(!dizi_nvt_hid_plan(&state, NULL, 1536, 2048, &next, &plan));
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 2048, &state, &plan));
    assert(!dizi_nvt_hid_plan(&state, &f, 0, 2048, &next, &plan));
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, -1, &next, &plan));
    assert(!dizi_nvt_hid_plan(&state, &f, 16385, 2048, &next, &plan));
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 16385, &next, &plan));
    f.active |= 1u << 10;
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 2048, &next, &plan));
    f.active = 1;
    f.x[0] = -1;
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 2048, &next, &plan));
    f.x[0] = 1600;
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 2048, &next, &plan));
    f.x[0] = 800; f.y[0] = 2560;
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 2048, &next, &plan));
    f.y[0] = -1;
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 2048, &next, &plan));
    f.y[0] = 1280;
    f.sequence = 0;
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 2048, &next, &plan));
    f.sequence = 1;
    assert(apply(&state, &f, 1536, 2048, &plan));
    assert(state.active == 1 && plan.started == 1);
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 2048, &next, &plan));
    f.sequence = 2;
    f.verified_spi_report = false;
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 2048, &next, &plan));
    assert(state.sequence == 1 && state.active == 1);
    f.cancel = true;
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 2048, &next, &plan)); /* nonzero cancel cannot press */
    f.active = 0;
    f.verified_spi_report = true;
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 2048, &next, &plan)); /* cancel may not claim new SPI proof */
    f.verified_spi_report = false;
    assert(apply(&state, &f, 1536, 2048, &plan));
    assert(plan.ended == 1 && plan.active == 0 && plan.changed == 1);
    f.sequence = 3;
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 2048, &next, &plan)); /* cannot fabricate up when no touch */
}

static void test_mapping_and_frame_coherence(void)
{
    struct dizi_nvt_hid_state state = {0};
    struct dizi_nvt_hid_plan p = {0};
    struct dizi_nvt_hid_frame f = {.sequence = 1, .active = 3, .verified_spi_report = true};
    f.x[0] = 0; f.y[0] = 0;
    f.x[1] = 800; f.y[1] = 1280;
    assert(apply(&state, &f, 1536, 2048, &p));
    assert(p.active == 3 && p.changed == 3 && p.started == 3 && !p.ended && !p.moved);
    assert((p.edges & 1u) != 0 && (p.edges & 2u) == 0);
    assert(p.fx[0] == 0 && p.fy[0] == 0); /* centre-cropped edge */
    assert(p.fx[1] == 32768 && p.fy[1] == 32768); /* 0.5 normalized */
    f.sequence = 2;
    assert(apply(&state, &f, 1536, 2048, &p));
    assert(p.changed == 0); /* verified repeated frame is not movement */
    f.sequence = 3;
    f.x[0] = 800;
    assert(apply(&state, &f, 1536, 2048, &p));
    assert(p.moved == 1 && p.changed == 1);
    assert((p.edges & 1u) != 0); /* edge bit latched since physical down */
    f.sequence = 4; f.active = 2;
    assert(apply(&state, &f, 1536, 2048, &p));
    assert(p.ended == 1 && p.active == 2 && p.changed == 1);
    assert(p.fx[0] == 32768); /* final physically reported x kept on up */
    f.sequence = 5; f.active = 0;
    assert(apply(&state, &f, 1536, 2048, &p));
    assert(p.ended == 2 && p.changed == 2 && p.active == 0);
    f.sequence = 6; f.active = 0;
    assert(apply(&state, &f, 1536, 2048, &p));
    assert(p.changed == 0 && !state.active);
    f.sequence = 7; f.active = (1u << 9); f.x[9] = 1599; f.y[9] = 2559;
    assert(apply(&state, &f, 1536, 2048, &p));
    assert(p.started == (1u << 9));
    assert(p.fx[9] >= 0 && p.fx[9] < 65536);
    assert(p.fy[9] >= 0 && p.fy[9] < 65536);
    assert((p.edges & (1u << 9)) != 0);
}

static void test_atomic_rejection_and_unsent_all_up(void)
{
    struct dizi_nvt_hid_state state = {0}, next;
    struct dizi_nvt_hid_plan p = {0};
    struct dizi_nvt_hid_frame f = {.sequence = 1, .active = 0, .verified_spi_report = true};
    assert(apply(&state, &f, 1536, 2048, &p));
    assert(p.changed == 0 && !state.active); /* No phantom contact after SPI reports empty */
    f.sequence = 2; f.active = 1023;
    for (unsigned i = 0; i < 10; i++) { f.x[i] = 100; f.y[i] = 100; }
    assert(apply(&state, &f, 1536, 2048, &p));
    assert(p.changed == 1023);
    struct dizi_nvt_hid_state snap = state;
    f.sequence = 3; f.x[9] = 1600;
    assert(!dizi_nvt_hid_plan(&state, &f, 1536, 2048, &next, &p));
    assert(!memcmp(&state, &snap, sizeof(state)));
    f.x[9] = 100; f.active = 0;
    assert(apply(&state, &f, 1536, 2048, &p));
    assert(p.ended == 1023 && p.changed == 1023);
}

static void test_long_sequence(void)
{
    struct dizi_nvt_hid_state state = {0};
    struct dizi_nvt_hid_plan p = {0};
    struct dizi_nvt_hid_frame f = {.verified_spi_report = true};
    uint32_t prng = 0xbadc0ffeu;
    for (unsigned n = 0; n < 45000; ++n) {
        f.sequence++;
        prng ^= prng << 13; prng ^= prng >> 17; prng ^= prng << 5;
        f.active = prng & DIZI_NVT_HID_MASK;
        for (unsigned i = 0; i < 10; i++) {
            f.x[i] = (int32_t)((prng + 137u * i) % 1600u);
            f.y[i] = (int32_t)((prng + 269u * i) % 2560u);
        }
        assert(apply(&state, &f, 1536, 2048, &p));
        assert(p.active == f.active && state.active == f.active);
        assert(!(p.started & p.ended));
        assert(!(p.started & p.moved));
        assert(!(p.ended & p.moved));
        assert((p.changed & ~DIZI_NVT_HID_MASK) == 0);
        for (unsigned i = 0; i < 10; i++) {
            assert(p.fx[i] >= 0 && p.fx[i] < 65536);
            assert(p.fy[i] >= 0 && p.fy[i] < 65536);
        }
    }
}

int main(void)
{
    test_gate_and_atomic_failures();
    test_mapping_and_frame_coherence();
    test_atomic_rejection_and_unsent_all_up();
    test_long_sequence();
    puts("PASS 0119 NT36532 HID: physical-proof gate, 10-ID coherent frame, 16.16 mapping, edge latch, replay/geometry/invalid rejection, all-up and 45k adversarial frames");
    return 0;
}
