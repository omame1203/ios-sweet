#ifndef DIZI_MACOS27_KC_PLAIN_REBASE_H
#define DIZI_MACOS27_KC_PLAIN_REBASE_H

#include "kc_fixups.h"

/* A caller assertion about its independently established, exclusive writable
 * RAM. This API does not establish MMU/SMMU ownership or change permissions.
 * phys_base and memory_size must be the parameters used by mac27_kc_load().
 * The loaded_window starts at phys_base, spans at least plan.occupied_size,
 * and initially contains an EXACT raw mac27_kc_load() image of source.
 * source is immutable and disjoint from the window throughout this call.
 * No Apple code, including authenticated pointers, is ever executed/signed.
 */
struct mac27_kc_plain_ownership {
    uint64_t phys_base, memory_size;
    uint64_t exclusive_start, exclusive_size;
    uint32_t exclusive_writable_ram;  /* must be exactly 1; externally verified */
};

struct mac27_kc_plain_report {
    uint64_t plain_rebased, authenticated_preserved;
    uint64_t base_pointer0, mapped_bytes;
};

enum mac27_kc_plain_error {
    MAC27_PLAIN_OK = 0, MAC27_PLAIN_ARGUMENT, MAC27_PLAIN_OWNERSHIP,
    MAC27_PLAIN_MACHO, MAC27_PLAIN_FIXUPS, MAC27_PLAIN_RANGE,
    MAC27_PLAIN_TARGET, MAC27_PLAIN_OVERLAP, MAC27_PLAIN_COPY
};

/* All-or-nothing on nonconcurrent caller-owned buffers. On ANY error the
 * complete destination and report remain byte-for-byte unchanged. First
 * validates every chain (including auth ones), then rewrites ONLY isAuth=0
 * format-8 pointers to basePointers[0] + 30-bit target. Rejects cacheLevel>0.
 * A successful result is still NOT boot-ready: all PAC fixups remain encoded.
 */
int mac27_kc_plain_rebase(const void *source, size_t source_size,
                         const struct mac27_kc_plain_ownership *ownership,
                         void *loaded_window, size_t window_size,
                         struct mac27_kc_plain_report *report);

#endif
