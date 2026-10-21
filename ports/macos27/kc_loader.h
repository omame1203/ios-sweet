#ifndef DIZI_MACOS27_KC_LOADER_H
#define DIZI_MACOS27_KC_LOADER_H

#include <stddef.h>
#include <stdint.h>

#define MAC27_KC_MAX_SEGMENTS 32
#define MAC27_KC_MAX_BYTES (UINT64_C(256) * 1024 * 1024)
#define MAC27_KC_BLOCK UINT64_C(0x2000000)
#define MAC27_KC_PAGE UINT64_C(0x4000)

struct mac27_kc_segment {
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t protection;
};

struct mac27_kc_plan {
    uint64_t virt_base, phys_base, memory_size, occupied_size;
    uint64_t entry_va, entry_pa, kernel_end_va, kernel_end_pa;
    uint64_t kernel_header_pa, fixups_pa;
    uint32_t segment_count, fileset_count, cpu_subtype, fixups_size;
    struct mac27_kc_segment segments[MAC27_KC_MAX_SEGMENTS];
};

enum mac27_kc_error {
    MAC27_KC_OK = 0, MAC27_KC_ARGUMENT, MAC27_KC_FORMAT,
    MAC27_KC_RANGE, MAC27_KC_MAPPING, MAC27_KC_CAPACITY
};

/* Decompressed MH_FILESET input only. These functions do not authenticate
 * IMG4, strip/sign/resolve any pointer, execute the entry or grant physical
 * RAM ownership. All fileset providers and raw fixups remain in the image.
 * A successful copy is NOT a boot-ready or CPU-compatible macOS kernel.
 * The caller must supply an owned destination window; no physical accesses
 * are performed by planning, and loading writes only the supplied window.
 */
int mac27_kc_plan(const void *file, size_t size, uint64_t phys_base,
                  uint64_t memory_size, struct mac27_kc_plan *out);
int mac27_kc_load(const void *file, size_t size, uint64_t phys_base,
                  uint64_t memory_size, void *window, size_t window_size,
                  struct mac27_kc_plan *out);

#endif
