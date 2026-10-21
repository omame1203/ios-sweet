#include "kc_fixups.h"

#define LC_CHAINED_FIXUPS 0x80000034u
#define PTR_64_KERNEL_CACHE 8u
#define START_NONE 0xffffu
#define START_MULTI 0x8000u
#define START_LAST 0x8000u

static uint16_t rd16(const uint8_t *b)
{ return (uint16_t)((uint16_t)b[0] | (uint16_t)b[1] << 8); }
static uint32_t rd32(const uint8_t *b)
{ return (uint32_t)rd16(b) | (uint32_t)rd16(b + 2) << 16; }
static uint64_t rd64(const uint8_t *b)
{ return (uint64_t)rd32(b) | (uint64_t)rd32(b + 4) << 32; }
static int within(uint64_t off, uint64_t n, uint64_t limit)
{ return off <= limit && n <= limit - off; }

static int chain(const uint8_t *kc, size_t size,
                 const struct mac27_kc_segment *seg, uint64_t page,
                 uint16_t start, uint16_t pagesize,
                 struct mac27_kc_fixup_report *r)
{
    uint64_t current = start;
    /* Format 8 advances in 4-byte units. A 64-bit entry is allowed to
     * straddle the last four bytes of a page; its 8-byte read must still
     * fit the actual file-backed segment. */
    if ((start & 3) || start >= pagesize)
        return MAC27_FIXUP_BOUNDS;
    for (;;) {
        uint64_t offset = page * (uint64_t)pagesize + current;
        uint64_t value, next;
        if (!within(offset, 8, seg->filesize) ||
            !within(seg->fileoff + offset, 8, size))
            return MAC27_FIXUP_BOUNDS;
        value = rd64(kc + seg->fileoff + offset);
        ++r->pointers;
        if (value >> 63) ++r->authenticated;
        else ++r->unauthenticated;
        if ((value >> 30) & 3u) ++r->nonzero_cache_level;
        next = (value >> 51) & 0xfffu;
        if (!next) return MAC27_FIXUP_OK;
        if (next > (UINT64_MAX - current) / 4) return MAC27_FIXUP_BOUNDS;
        current += next * 4;
        if (current >= pagesize) return MAC27_FIXUP_BOUNDS;
    }
}

int mac27_kc_inspect_fixups(const void *input, size_t size,
                           uint64_t phys_base, uint64_t memory_size,
                           struct mac27_kc_fixup_report *report)
{
    const uint8_t *kc = input;
    struct mac27_kc_plan plan;
    struct mac27_kc_fixup_report r = {0};
    uint64_t cursor, command_end, fixup_off = 0, fixup_size = 0;
    uint32_t count;
    if (!kc || !report ||
        ((uintptr_t)report <= UINTPTR_MAX - sizeof(*report) &&
         (uintptr_t)kc <= UINTPTR_MAX - size &&
         (uintptr_t)report < (uintptr_t)kc + size &&
         (uintptr_t)kc < (uintptr_t)report + sizeof(*report)))
        return MAC27_FIXUP_ARGUMENT;
    if (mac27_kc_plan(input, size, phys_base, memory_size, &plan))
        return MAC27_FIXUP_MACHO;
    count = rd32(kc + 16);
    cursor = 32;
    command_end = cursor + rd32(kc + 20);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t cmd = rd32(kc + cursor), length = rd32(kc + cursor + 4);
        if (cmd == LC_CHAINED_FIXUPS) {
            fixup_off = rd32(kc + cursor + 8);
            fixup_size = rd32(kc + cursor + 12);
        }
        cursor += length;
    }
    if (cursor != command_end || !within(fixup_off, fixup_size, size) || fixup_size < 28)
        return MAC27_FIXUP_BOUNDS;
    const uint8_t *base = kc + fixup_off;
    uint32_t starts = rd32(base + 4);
    if (rd32(base) != 0 || rd32(base + 16) != 0 ||
        !within(starts, 4, fixup_size) ||
        rd32(base + 8) > fixup_size || rd32(base + 12) > fixup_size)
        return MAC27_FIXUP_FORMAT;
    uint32_t nsegs = rd32(base + starts);
    if (nsegs != plan.segment_count ||
        !within(starts + 4, (uint64_t)nsegs * 4, fixup_size))
        return MAC27_FIXUP_FORMAT;
    for (uint32_t i = 0; i < nsegs; ++i) {
        uint32_t offset = rd32(base + starts + 4 + 4 * i);
        if (!offset) continue;
        if (offset < 4 + nsegs * 4 || !within((uint64_t)starts + offset, 22, fixup_size))
            return MAC27_FIXUP_BOUNDS;
        const uint8_t *starts_seg = base + starts + offset;
        uint32_t segsize = rd32(starts_seg);
        uint16_t pagesize = rd16(starts_seg + 4), fmt = rd16(starts_seg + 6);
        uint16_t pages = rd16(starts_seg + 20);
        const struct mac27_kc_segment *seg = &plan.segments[i];
        if (fmt != PTR_64_KERNEL_CACHE || pagesize != MAC27_KC_PAGE)
            return MAC27_FIXUP_UNSUPPORTED;
        if (segsize < 22 || !within((uint64_t)starts + offset, segsize, fixup_size) ||
            (uint64_t)pages * pagesize > seg->vmsize ||
            !within(22, (uint64_t)pages * 2, segsize) ||
            rd64(starts_seg + 8) != seg->vmaddr - plan.segments[0].vmaddr)
            return MAC27_FIXUP_BOUNDS;
        ++r.segments_with_chains;
        uint64_t aux_count = (segsize - 22 - (uint64_t)pages * 2) / 2;
        const uint8_t *aux = starts_seg + 22 + pages * 2;
        for (uint16_t page = 0; page < pages; ++page) {
            uint16_t first = rd16(starts_seg + 22 + page * 2);
            if (first == START_NONE) continue;
            ++r.pages_with_chains;
            if (first & START_MULTI) {
                uint64_t index = first & ~START_MULTI;
                int last = 0;
                ++r.multi_start_pages;
                for (; index < aux_count; ++index) {
                    uint16_t start = rd16(aux + index * 2);
                    int error = chain(kc, size, seg, page, start & ~START_LAST, pagesize, &r);
                    if (error) return error;
                    if (start & START_LAST) { last = 1; break; }
                }
                if (!last) return MAC27_FIXUP_BOUNDS;
            } else {
                int error = chain(kc, size, seg, page, first, pagesize, &r);
                if (error) return error;
            }
        }
    }
    report->pointers = r.pointers;
    report->authenticated = r.authenticated;
    report->unauthenticated = r.unauthenticated;
    report->nonzero_cache_level = r.nonzero_cache_level;
    report->pages_with_chains = r.pages_with_chains;
    report->multi_start_pages = r.multi_start_pages;
    report->segments_with_chains = r.segments_with_chains;
    return MAC27_FIXUP_OK;
}

int mac27_kc_fixups_need_runtime(const struct mac27_kc_fixup_report *report)
{
    return !report || report->authenticated || report->nonzero_cache_level ||
           report->unauthenticated;
}
