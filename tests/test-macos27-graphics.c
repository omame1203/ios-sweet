/* SPDX-License-Identifier: MIT
 * Synthetic policy/geometry only. No driver, IOCTL, GPU, or macOS runtime.
 */
#include "../ports/macos27/graphics_readiness.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void gate_tests(void)
{
    struct m27_graphics_assessment null = m27_graphics_assess(NULL);
    assert(!null.desktop_display_candidate && !null.windowserver_candidate &&
        !null.accelerated_candidate);
    assert(null.absent_from_source == M27_GFX_ALL);

    struct m27_graphics_evidence old = m27_graphics_known_dizi_0116();
    assert(old.source_present == M27_GFX_FB_LAYOUT);
    assert(old.legacy_source == M27_LEGACY_0116_EXPECTED);
    assert(!old.runtime_proven && !old.incompatible);
    struct m27_graphics_assessment a = m27_graphics_assess(&old);
    assert(a.absent_from_source == (M27_GFX_ALL & ~M27_GFX_FB_LAYOUT));
    assert(a.unproven_at_runtime == M27_GFX_ALL);
    assert(a.eligible == 0 && !a.desktop_display_candidate &&
        !a.windowserver_candidate && !a.accelerated_candidate);

    /* Fake proof bitmask supplied by synthetic test is NOT an ABI probe.
     * Runtime claims without source implementation must never pass.
     */
    old.runtime_proven = M27_GFX_ALL;
    a = m27_graphics_assess(&old);
    assert(!a.desktop_display_candidate && a.eligible == M27_GFX_FB_LAYOUT);
    old.source_present = M27_GFX_ALL;
    old.runtime_proven = M27_GFX_DESKTOP_DISPLAY_REQUIRED;
    a = m27_graphics_assess(&old);
    assert(a.desktop_display_candidate && !a.windowserver_candidate &&
        !a.accelerated_candidate);
    old.runtime_proven = M27_GFX_WINDOWSERVER_REQUIRED;
    a = m27_graphics_assess(&old);
    assert(a.windowserver_candidate && !a.accelerated_candidate);
    old.runtime_proven = M27_GFX_ALL;
    a = m27_graphics_assess(&old);
    assert(a.accelerated_candidate);
    /* Each mandatory capability must be proven independently. */
    for (unsigned i = 0; i < 17; ++i) {
        old.runtime_proven = M27_GFX_ALL & ~(1u << i);
        a = m27_graphics_assess(&old);
        assert(!a.accelerated_candidate);
        if (M27_GFX_DESKTOP_DISPLAY_REQUIRED & (1u << i))
            assert(!a.desktop_display_candidate);
        if (M27_GFX_WINDOWSERVER_REQUIRED & (1u << i))
            assert(!a.windowserver_candidate);
    }
    old.runtime_proven = M27_GFX_ALL;
    for (unsigned i = 0; i < 17; ++i) {
        old.incompatible = 1u << i;
        a = m27_graphics_assess(&old);
        assert(!a.accelerated_candidate);
        assert((a.eligible & (1u << i)) == 0);
    }
    old.incompatible = 0;
    old.runtime_proven = ~0u;
    old.source_present = ~0u;
    a = m27_graphics_assess(&old);
    assert(a.eligible == M27_GFX_ALL);
    assert(!a.absent_from_source && !a.conflicts);
}

static void geometry_tests(void)
{
    struct m27_graphics_geometry g = {0};
    struct m27_graphics_copy_plan cp = {0};
    struct m27_graphics_rect r = {0, 0, 1536, 2048};
    /* This is a mathematically valid *hypothetical* stride/extent,
     * not a real observation of POCO Pad framebuffer memory.
     * 0116 centers 1536x2048 inside 1600x2560. */
    assert(m27_graphics_geometry_init(&g, 1600, 2560, 6400,
        6400ull * 2560, 1536, 2048, M27_GFX_FORMAT_SOURCE_BGRA));
    assert(g.panel_origin_x == -32 && g.panel_origin_y == -256);
    assert(m27_graphics_copy_plan(&g, &r, 1536 * 4,
        1536ull * 4 * 2048, &cp));
    assert(cp.src.x == 0 && cp.src.y == 0);
    assert(cp.panel_dst.x == 32 && cp.panel_dst.y == 256);
    assert(cp.panel_dst.width == 1536 && cp.panel_dst.height == 2048);
    assert(cp.src_offset == 0);
    assert(cp.panel_offset == 256ull * 6400 + 32 * 4);
    assert(cp.copy_bytes_per_row == 1536 * 4);

    r = (struct m27_graphics_rect){1530, 2040, 20, 20};
    assert(m27_graphics_copy_plan(&g, &r, 6144, 6144ull * 2048, &cp));
    assert(cp.src.x == 1530 && cp.src.y == 2040);
    assert(cp.src.width == 6 && cp.src.height == 8);
    assert(cp.panel_dst.x == 1562 && cp.panel_dst.y == 2296);

    r = (struct m27_graphics_rect){-8, -10, 20, 21};
    assert(m27_graphics_copy_plan(&g, &r, 6144, 6144ull * 2048, &cp));
    assert(cp.src.x == 0 && cp.src.y == 0);
    assert(cp.src.width == 12 && cp.src.height == 11);
    assert(cp.panel_dst.x == 32 && cp.panel_dst.y == 256);
    assert(cp.src_offset == 0);

    /* Reverse case: desktop canvas larger than inherited panel.
     * Only center 1600x2560 portion can be projected; no OOB reads.
     */
    assert(m27_graphics_geometry_init(&g, 1600, 2560, 6400,
        6400ull * 2560, 1920, 2880, M27_GFX_FORMAT_SOURCE_BGRA));
    assert(g.panel_origin_x == 160 && g.panel_origin_y == 160);
    r = (struct m27_graphics_rect){0, 0, 1920, 2880};
    assert(m27_graphics_copy_plan(&g, &r, 7680, 7680ull * 2880, &cp));
    assert(cp.src.x == 160 && cp.src.y == 160);
    assert(cp.src.width == 1600 && cp.src.height == 2560);
    assert(cp.panel_dst.x == 0 && cp.panel_dst.y == 0);
    assert(cp.src_offset == 160ull * 7680 + 160 * 4);
    assert(cp.panel_offset == 0);
    assert(cp.copy_bytes_per_row == 6400);

    /* Odd crop: match 0116 signed integer /2 truncation. */
    assert(m27_graphics_geometry_init(&g, 1600, 2560, 6400,
        6400ull * 2560, 1535, 2047, M27_GFX_FORMAT_SOURCE_BGRA));
    assert(g.panel_origin_x == -32 && g.panel_origin_y == -256);
}

static void reject_tests(void)
{
    struct m27_graphics_geometry g = {0}, sentinel = {0};
    struct m27_graphics_copy_plan cp = {0}, before;
    struct m27_graphics_rect r = {0, 0, 1600, 2560};
    assert(!m27_graphics_geometry_init(NULL, 1600, 2560, 6400,
        16384000, 1536, 2048, M27_GFX_FORMAT_SOURCE_BGRA));
    assert(!m27_graphics_geometry_init(&g, 1600, 2560, 6399,
        16384000, 1536, 2048, M27_GFX_FORMAT_SOURCE_BGRA));
    assert(!m27_graphics_geometry_init(&g, 1600, 2560, 6396,
        16384000, 1536, 2048, M27_GFX_FORMAT_SOURCE_BGRA));
    assert(!m27_graphics_geometry_init(&g, 1600, 2560, 6400,
        6400ull * 2560 - 1, 1536, 2048, M27_GFX_FORMAT_SOURCE_BGRA));
    assert(!m27_graphics_geometry_init(&g, 1600, 2560, 6400,
        UINT64_MAX, 1536, 2048, 0u));
    assert(!m27_graphics_geometry_init(&g, 1600, 2560, 6400,
        UINT64_MAX, 0, 2048, M27_GFX_FORMAT_SOURCE_BGRA));
    assert(!m27_graphics_geometry_init(&g, 1600, 2560, 6400,
        UINT64_MAX, 1536, 16385, M27_GFX_FORMAT_SOURCE_BGRA));
    assert(!memcmp(&g, &sentinel, sizeof(g)));

    assert(m27_graphics_geometry_init(&g, 1600, 2560, 6400,
        6400ull * 2560, 1536, 2048, M27_GFX_FORMAT_SOURCE_BGRA));
    memset(&cp, 0xA5, sizeof(cp)); before = cp;
    r.width = -1;
    assert(!m27_graphics_copy_plan(&g, &r, 6144, UINT64_MAX, &cp));
    r.width = 1600;
    r.x = INT32_MAX;
    assert(!m27_graphics_copy_plan(&g, &r, 6144, UINT64_MAX, &cp));
    r.x = INT32_MIN;
    assert(!m27_graphics_copy_plan(&g, &r, 6144, UINT64_MAX, &cp));
    r.x = 0;
    r.y = INT32_MIN;
    assert(!m27_graphics_copy_plan(&g, &r, 6144, UINT64_MAX, &cp));
    r.y = 0;
    assert(!m27_graphics_copy_plan(&g, &r, 6000, UINT64_MAX, &cp));
    assert(!m27_graphics_copy_plan(&g, &r, 6144,
        6144ull * 2048 - 1, &cp));
    g.panel_origin_x++;
    assert(!m27_graphics_copy_plan(&g, &r, 6144, UINT64_MAX, &cp));
    assert(!memcmp(&cp, &before, sizeof(cp))); /* rejected => no output */
}

static void stress_tests(void)
{
    uint32_t rng = 0x12345678u;
    struct m27_graphics_geometry g;
    struct m27_graphics_copy_plan p;
    assert(m27_graphics_geometry_init(&g, 1600, 2560, 6400,
        6400ull * 2560, 1536, 2048, M27_GFX_FORMAT_SOURCE_BGRA));
    for (unsigned j = 0; j < 110000; j++) {
        rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
        struct m27_graphics_rect r = {
            (int32_t)(rng % 25000) - 12000,
            (int32_t)((rng >> 3) % 25000) - 12000,
            (int32_t)((rng >> 7) % 5000) + 1,
            (int32_t)((rng >> 11) % 5000) + 1
        };
        if (!m27_graphics_copy_plan(&g, &r, 6144, 6144ull * 2048, &p))
            continue;
        assert(p.src.x >= 0 && p.src.y >= 0);
        assert(p.src.width > 0 && p.src.height > 0);
        assert(p.src.x + p.src.width <= 1536);
        assert(p.src.y + p.src.height <= 2048);
        assert(p.panel_dst.x >= 0 && p.panel_dst.y >= 0);
        assert(p.panel_dst.x + p.panel_dst.width <= 1600);
        assert(p.panel_dst.y + p.panel_dst.height <= 2560);
        assert(p.src.width == p.panel_dst.width);
        assert(p.src.height == p.panel_dst.height);
        assert(p.src_offset + (uint64_t)(p.src.height-1)*6144 +
            p.copy_bytes_per_row <= 6144ull * 2048);
        assert(p.panel_offset + (uint64_t)(p.panel_dst.height-1)*6400 +
            p.copy_bytes_per_row <= 6400ull * 2560);
    }
}

int main(void)
{
    gate_tests();
    geometry_tests();
    reject_tests();
    stress_tests();
    puts("PASS macOS27 graphics readiness: legacy != desktop, 17 fail-closed proofs, 0116 crop/stride, 110k hostile rectangles; no MMIO");
    return 0;
}
