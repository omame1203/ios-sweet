/* SPDX-License-Identifier: MIT
 * macOS 27 Golden Gate / POCO Pad dizi: graphics feasibility ONLY.
 *
 * Read-only, freestanding policy and CPU address-mapping math. This does
 * NOT implement IOFramebuffer, IOAccelerator, AppleDCP, Adreno, Metal,
 * WindowServer, driver matching, user clients, scanout, or boot.
 * Evidence must be independently measured; bootargs/FDT and a compiled
 * pseudo-controller are NOT proof of a desktop userland ABI.
 */
#ifndef DIZI_MACOS27_GRAPHICS_READINESS_H
#define DIZI_MACOS27_GRAPHICS_READINESS_H
#include <stdint.h>
#include <stdbool.h>

enum m27_graphics_capability {
    M27_GFX_FB_LAYOUT          = 1u << 0,  /* mapped CPU framebuffer layout */
    M27_GFX_SCANOUT_OWNER      = 1u << 1,  /* live stable panel scanout owner */
    M27_GFX_IOFRAMEBUFFER      = 1u << 2,  /* actual desktop IOFramebuffer */
    M27_GFX_IOFB_SERVER        = 1u << 3,  /* IOFBServerConnectType ABI */
    M27_GFX_DISPLAY_MODES      = 1u << 4,  /* desktop modes / display identity */
    M27_GFX_FRAME_COMPLETION   = 1u << 5,  /* verified frame completion/VSYNC */
    M27_GFX_IOSURFACE_27       = 1u << 6,  /* macOS27 IOSurface ABI/lifetime */
    M27_GFX_DISPLAY_PIPELINE  = 1u << 7,  /* DCP-equivalent display provider */
    M27_GFX_WINDOWSERVER      = 1u << 8,  /* real macOS27 WS protocol witness */
    M27_GFX_HID_POINTER       = 1u << 9,  /* desktop pointer / cursor events */
    M27_GFX_HID_KEYBOARD      = 1u << 10, /* desktop keyboard input */
    M27_GFX_GPU_DRIVER        = 1u << 11, /* real Adreno GPU driver in XNU */
    M27_GFX_IOACCELERATOR     = 1u << 12, /* real accelerator service / ABI */
    M27_GFX_METAL_DEVICE     = 1u << 13, /* working Metal runtime and shaders */
    M27_GFX_GPU_MEMORY       = 1u << 14, /* safe GPU VM/IOMMU and buffer sync */
    M27_GFX_GPU_SCHEDULER    = 1u << 15, /* validated GPU job/fence scheduling */
    M27_GFX_POWER_LIFECYCLE  = 1u << 16, /* runtime panel/backlight/resume */
};

#define M27_GFX_ALL ((uint32_t)((1u << 17) - 1u))
/* A desktop display experiment is not equivalent to WindowServer success.
 * A DCP driver is not *by itself* mandatory on Qualcomm: a verified
 * substitute may satisfy DISPLAY_PIPELINE; an Apple AGX driver cannot be
 * assumed to control the Adreno 710 discovered in the dizi device tree.
 */
#define M27_GFX_DESKTOP_DISPLAY_REQUIRED (M27_GFX_FB_LAYOUT | \
    M27_GFX_SCANOUT_OWNER | M27_GFX_IOFRAMEBUFFER | M27_GFX_IOFB_SERVER | \
    M27_GFX_DISPLAY_MODES | M27_GFX_FRAME_COMPLETION | \
    M27_GFX_IOSURFACE_27 | M27_GFX_DISPLAY_PIPELINE | \
    M27_GFX_POWER_LIFECYCLE)
#define M27_GFX_WINDOWSERVER_REQUIRED (M27_GFX_DESKTOP_DISPLAY_REQUIRED | \
    M27_GFX_WINDOWSERVER | M27_GFX_HID_POINTER | M27_GFX_HID_KEYBOARD)
#define M27_GFX_ACCELERATED_REQUIRED (M27_GFX_WINDOWSERVER_REQUIRED | \
    M27_GFX_GPU_DRIVER | M27_GFX_IOACCELERATOR | M27_GFX_METAL_DEVICE | \
    M27_GFX_GPU_MEMORY | M27_GFX_GPU_SCHEDULER)

/* Legacy features observed in 0116 source: never substitute these for their
 * similarly named macOS 27 desktop capabilities.
 */
enum m27_legacy_feature {
    M27_LEGACY_BOOT_FB        = 1u << 0,
    M27_LEGACY_IOMOBILE_FB    = 1u << 1,
    M27_LEGACY_IOSURFACE_16   = 1u << 2,
    M27_LEGACY_CPU_COPY       = 1u << 3,
    M27_LEGACY_TIMER_VSYNC    = 1u << 4,
    M27_LEGACY_MOBILE_TOUCH   = 1u << 5,
    M27_LEGACY_CONSUMER_KEYS  = 1u << 6,
    M27_LEGACY_SW_BLACK_ONLY  = 1u << 7,
    M27_LEGACY_ADRENO_FDT     = 1u << 8
};
#define M27_LEGACY_0116_EXPECTED ((uint32_t)((1u << 9) - 1u))

struct m27_graphics_evidence {
    uint32_t source_present;  /* compiled or in inspected source: NOT runtime */
    uint32_t runtime_proven;  /* independent macOS27 interface measurements */
    uint32_t incompatible;    /* actual observed conflict, not merely absent */
    uint32_t legacy_source;   /* source's mobile/boot features only */
};

struct m27_graphics_assessment {
    uint32_t absent_from_source; /* no source-backed implementation supplied */
    uint32_t unproven_at_runtime;
    uint32_t conflicts;
    uint32_t eligible;           /* intersection of compatible+verified bits */
    bool desktop_display_candidate; /* hypothetical gated test only */
    bool windowserver_candidate;    /* hypothetical gated test only */
    bool accelerated_candidate;    /* hypothetical gated test only */
};

/* 0116 source inventory; not a hardware probe and never asserts macOS ABI.
 * The framebuffer layout is implemented in source, but its physical stride,
 * hardware owner, and macOS compatibility are not independently proven.
 */
struct m27_graphics_evidence m27_graphics_known_dizi_0116(void);
struct m27_graphics_assessment m27_graphics_assess(
    const struct m27_graphics_evidence *evidence);

#define M27_GFX_FORMAT_SOURCE_BGRA 0x42475241u /* 0116 SweetFramebuffer */

struct m27_graphics_geometry {
    uint32_t panel_width, panel_height, row_bytes;
    uint32_t canvas_width, canvas_height;
    uint32_t pixel_format;
    uint64_t framebuffer_bytes; /* independently measured mapped extent */
    int32_t panel_origin_x, panel_origin_y;
};

struct m27_graphics_rect {
    int32_t x, y, width, height;
};
struct m27_graphics_copy_plan {
    struct m27_graphics_rect src, panel_dst;
    uint64_t src_offset, panel_offset;
    uint32_t copy_bytes_per_row;
};

/* Pure address-range and crop validation. These functions never dereference
 * addresses, read registers, copy pixels, or claim hardware ownership.
 * Row-byte/panel allocation lengths MUST come from a real observed mapping.
 */
bool m27_graphics_geometry_init(struct m27_graphics_geometry *dst,
    uint32_t panel_w, uint32_t panel_h, uint32_t panel_stride,
    uint64_t panel_alloc_len, uint32_t canvas_w, uint32_t canvas_h,
    uint32_t pixel_format);
bool m27_graphics_copy_plan(const struct m27_graphics_geometry *geometry,
    const struct m27_graphics_rect *logical_rectangle,
    uint32_t source_stride, uint64_t source_alloc_len,
    struct m27_graphics_copy_plan *out);
#endif
