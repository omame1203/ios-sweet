#ifndef DIZI_MACOS27_KC_FIXUPS_H
#define DIZI_MACOS27_KC_FIXUPS_H

#include "kc_loader.h"

/* Read-only traversal of the real KC's dyld chained pointers.  Format 8 is
 * DYLD_CHAINED_PTR_64_KERNEL_CACHE (NOT ARM64E_KERNEL/format 7).
 * No output pointer is signed, rebased, dereferenced or executed. */
struct mac27_kc_fixup_report {
    uint64_t pointers, authenticated, unauthenticated, nonzero_cache_level;
    uint64_t pages_with_chains, multi_start_pages;
    uint32_t segments_with_chains;
};

enum mac27_fixup_error {
    MAC27_FIXUP_OK = 0, MAC27_FIXUP_ARGUMENT, MAC27_FIXUP_MACHO,
    MAC27_FIXUP_FORMAT, MAC27_FIXUP_BOUNDS, MAC27_FIXUP_UNSUPPORTED
};

int mac27_kc_inspect_fixups(const void *kc, size_t size,
                           uint64_t phys_base, uint64_t memory_size,
                           struct mac27_kc_fixup_report *report);

/* The 26A434 KC is never considered runnable just because its fixup chain is
 * structurally valid. Authenticated pointers require valid PAC keys/ISA and
 * correct slide, and nonzero cache levels require an actual dependency. */
int mac27_kc_fixups_need_runtime(const struct mac27_kc_fixup_report *report);

#endif
