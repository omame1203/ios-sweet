/* SPDX-License-Identifier: MIT */
#include "graphics_readiness.h"

struct m27_graphics_evidence
m27_graphics_known_dizi_0116(void)
{
    struct m27_graphics_evidence e = {0};
    /* Present in XNU source only: PE_current_console + checked strides.
     * Not a proof that an IOFramebuffer or macOS27 ABI exists. */
    e.source_present = M27_GFX_FB_LAYOUT;
    e.legacy_source = M27_LEGACY_0116_EXPECTED;
    return e;
}

struct m27_graphics_assessment
m27_graphics_assess(const struct m27_graphics_evidence *e)
{
    struct m27_graphics_assessment a = {0};
    if (!e) {
        a.absent_from_source = M27_GFX_ALL;
        a.unproven_at_runtime = M27_GFX_ALL;
        return a;
    }
    /* A runtime claim without a matching implemented source is never proof.
     * Compatibility evidence cannot override explicit conflicts. */
    a.absent_from_source = M27_GFX_ALL & ~e->source_present;
    a.unproven_at_runtime = M27_GFX_ALL & ~e->runtime_proven;
    a.conflicts = M27_GFX_ALL & e->incompatible;
    a.eligible = M27_GFX_ALL & e->source_present &
        e->runtime_proven & ~e->incompatible;
    a.desktop_display_candidate =
        (a.eligible & M27_GFX_DESKTOP_DISPLAY_REQUIRED) ==
        M27_GFX_DESKTOP_DISPLAY_REQUIRED;
    a.windowserver_candidate =
        (a.eligible & M27_GFX_WINDOWSERVER_REQUIRED) ==
        M27_GFX_WINDOWSERVER_REQUIRED;
    a.accelerated_candidate =
        (a.eligible & M27_GFX_ACCELERATED_REQUIRED) ==
        M27_GFX_ACCELERATED_REQUIRED;
    return a;
}

bool m27_graphics_geometry_init(struct m27_graphics_geometry *dst,
    uint32_t panel_w, uint32_t panel_h, uint32_t panel_stride,
    uint64_t panel_alloc_len, uint32_t canvas_w, uint32_t canvas_h,
    uint32_t pixel_format)
{
    if (!dst || !panel_w || !panel_h || !canvas_w || !canvas_h ||
        panel_w > 8192 || panel_h > 8192 ||
        canvas_w > 16384 || canvas_h > 16384 ||
        pixel_format != M27_GFX_FORMAT_SOURCE_BGRA ||
        panel_stride % 4 != 0 ||
        (uint64_t)panel_w * 4 > panel_stride ||
        (uint64_t)panel_stride * panel_h > panel_alloc_len)
        return false;
    struct m27_graphics_geometry value = {
        .panel_width = panel_w, .panel_height = panel_h,
        .row_bytes = panel_stride, .canvas_width = canvas_w,
        .canvas_height = canvas_h, .pixel_format = pixel_format,
        .framebuffer_bytes = panel_alloc_len,
        .panel_origin_x = ((int32_t)canvas_w - (int32_t)panel_w) / 2,
        .panel_origin_y = ((int32_t)canvas_h - (int32_t)panel_h) / 2
    };
    *dst = value;
    return true;
}

/* Half-open [x, x+w) ranges; source logical clipping first, then the
 * target panel bounds. int64_t prevents overflow with hostile int32 input.
 */
static bool clip_pair(int64_t *x, int64_t *width, int64_t *source_x,
    int64_t limit)
{
    if (*x < 0) {
        *source_x -= *x;
        *width += *x;
        *x = 0;
    }
    if (*x >= limit || *width <= 0) return false;
    if (*width > limit - *x) *width = limit - *x;
    return *width > 0;
}

bool m27_graphics_copy_plan(const struct m27_graphics_geometry *g,
    const struct m27_graphics_rect *r,
    uint32_t source_stride, uint64_t source_alloc_len,
    struct m27_graphics_copy_plan *out)
{
    if (!g || !r || !out || !r->width || !r->height ||
        r->width < 0 || r->height < 0 ||
        g->pixel_format != M27_GFX_FORMAT_SOURCE_BGRA ||
        !g->panel_width || !g->panel_height ||
        !g->canvas_width || !g->canvas_height ||
        g->panel_width > 8192 || g->panel_height > 8192 ||
        g->canvas_width > 16384 || g->canvas_height > 16384 ||
        g->row_bytes % 4 || source_stride % 4 ||
        (uint64_t)g->panel_width * 4 > g->row_bytes ||
        (uint64_t)g->canvas_width * 4 > source_stride ||
        (uint64_t)g->row_bytes * g->panel_height > g->framebuffer_bytes ||
        (uint64_t)source_stride * g->canvas_height > source_alloc_len ||
        g->panel_origin_x !=
            ((int32_t)g->canvas_width - (int32_t)g->panel_width) / 2 ||
        g->panel_origin_y !=
            ((int32_t)g->canvas_height - (int32_t)g->panel_height) / 2)
        return false;
    int64_t sx = r->x, sy = r->y, w = r->width, h = r->height;
    int64_t skipped_x = 0, skipped_y = 0;
    if (!clip_pair(&sx, &w, &skipped_x, g->canvas_width) ||
        !clip_pair(&sy, &h, &skipped_y, g->canvas_height))
        return false;
    /* Source logical coordinates are absolute; skipping negative space
     * was already accounted for by clipping to the source surface. */
    int64_t dx = sx - g->panel_origin_x;
    int64_t dy = sy - g->panel_origin_y;
    int64_t source_advance_x = 0, source_advance_y = 0;
    if (!clip_pair(&dx, &w, &source_advance_x, g->panel_width) ||
        !clip_pair(&dy, &h, &source_advance_y, g->panel_height))
        return false;
    sx += source_advance_x;
    sy += source_advance_y;
    (void)skipped_x;
    (void)skipped_y;
    uint64_t src_start = (uint64_t)sy * source_stride + (uint64_t)sx * 4;
    uint64_t dst_start = (uint64_t)dy * g->row_bytes + (uint64_t)dx * 4;
    uint64_t copy_row = (uint64_t)w * 4;
    uint64_t src_last = src_start + (uint64_t)(h - 1) * source_stride + copy_row;
    uint64_t dst_last = dst_start + (uint64_t)(h - 1) * g->row_bytes + copy_row;
    if (src_last > source_alloc_len || dst_last > g->framebuffer_bytes)
        return false;
    struct m27_graphics_copy_plan plan = {
        .src = {(int32_t)sx, (int32_t)sy, (int32_t)w, (int32_t)h},
        .panel_dst = {(int32_t)dx, (int32_t)dy, (int32_t)w, (int32_t)h},
        .src_offset = src_start, .panel_offset = dst_start,
        .copy_bytes_per_row = (uint32_t)copy_row
    };
    *out = plan;
    return true;
}
