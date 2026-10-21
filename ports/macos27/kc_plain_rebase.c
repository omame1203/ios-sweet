#include "kc_plain_rebase.h"

#define CHAINED_FIXUPS 0x80000034u
#define FILESET_ENTRY 0x80000035u
#define START_NONE 0xffffu
#define START_MULTI 0x8000u
#define FORMAT_KERNEL_CACHE_64 8u
#define FORMAT8_TARGET_MASK UINT64_C(0x3fffffff)
#define FORMAT8_EXTRA_MASK UINT64_C(0x7ffff00000000)
#define MAX_PROVIDER_BOUNDARIES 512u

static uint16_t r16(const uint8_t *p)
{ return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8); }
static uint32_t r32(const uint8_t *p)
{ return (uint32_t)r16(p) | (uint32_t)r16(p + 2) << 16; }
static uint64_t r64(const uint8_t *p)
{ return (uint64_t)r32(p) | (uint64_t)r32(p + 4) << 32; }
static void w64(uint8_t *p, uint64_t v)
{ for (unsigned i = 0; i != 8; ++i) p[i] = (uint8_t)(v >> (8 * i)); }
static int fits(uint64_t off, uint64_t bytes, uint64_t bound)
{ return off <= bound && bytes <= bound - off; }
static int overlap(uintptr_t a, size_t n, uintptr_t b, size_t m)
{
    return n > UINTPTR_MAX - a || m > UINTPTR_MAX - b ||
           (a < b + m && b < a + n);
}
static int owned_range(uint64_t addr, uint64_t len,
                       const struct mac27_kc_plain_ownership *o)
{
    return addr >= o->exclusive_start &&
           fits(addr - o->exclusive_start, len, o->exclusive_size);
}
static int virtual_target(const struct mac27_kc_plan *p, uint64_t target)
{
    for (uint32_t i = 0; i != p->segment_count; ++i) {
        const struct mac27_kc_segment *s = &p->segments[i];
        if (target >= s->vmaddr && target - s->vmaddr < s->vmsize)
            return 1;
    }
    return 0;
}

/* A full source-versus-destination check also rejects rebasing the same
 * window twice and rejects writing to an unrelated/misloaded image. */
static int raw_copy_matches(const uint8_t *src, const uint8_t *window,
                            const struct mac27_kc_plan *p, size_t window_size)
{
    for (uint32_t i = 0; i != p->segment_count; ++i) {
        const struct mac27_kc_segment *s = &p->segments[i];
        uint64_t dst = s->vmaddr - p->virt_base;
        if (!fits(dst, s->filesize, window_size)) return 0;
        for (uint64_t j = 0; j != s->filesize; ++j)
            if (window[dst + j] != src[s->fileoff + j]) return 0;
    }
    return 1;
}

/* Sorted embedded Mach-O header starts. The first 32 bytes of each
 * provider (and any 8-byte word straddling its start) are never fixup
 * destinations. Actual provider offsets are NOT 16KiB aligned. */
static int crosses_provider(const uint64_t *edges, uint32_t count, uint64_t off)
{
    uint32_t low = 0, high = count;
    while (low < high) {
        uint32_t mid = low + (high - low) / 2;
        if (edges[mid] < off) low = mid + 1;
        else high = mid;
    }
    /* Any previous provider header could overlap this 8-byte word. */
    if (low && off - edges[low - 1] < 32) return 1;
    /* A future provider boundary inside the word is equally unsafe. */
    return low < count && edges[low] - off < 8;
}

static int used(uint8_t *bitmap, uint32_t word)
{
    uint32_t byte = word >> 3;
    uint8_t mask = (uint8_t)(1u << (word & 7));
    if (bitmap[byte] & mask) return 1;
    bitmap[byte] |= mask;
    return 0;
}

struct walker {
    const uint8_t *src;
    uint8_t *window;
    size_t source_size, window_size;
    const uint64_t *provider_edges;
    uint32_t provider_count;
    uint64_t fixoff, fixsize;
    const struct mac27_kc_plan *plan;
    const struct mac27_kc_plain_ownership *owner;
    uint64_t plain, authenticated;
    int commit;
};

/* Each page has 4096 four-byte slots. Even a pointer at page_size-4
 * occupies the first 4 bytes of the following page; carry tracks this. */
static int walk_chain(struct walker *w, const struct mac27_kc_segment *seg,
                      uint64_t page, uint16_t first, uint16_t page_size,
                      uint8_t *bitmap, unsigned *carry)
{
    uint64_t current = first;
    if ((first & 3) || first >= page_size) return MAC27_PLAIN_RANGE;
    for (;;) {
        uint64_t rel = page * (uint64_t)page_size + current;
        uint64_t off = seg->fileoff + rel;
        uint64_t dst = seg->vmaddr - w->plan->virt_base + rel;
        if (!fits(rel, 8, seg->filesize) ||
            !fits(off, 8, w->source_size) ||
            !fits(dst, 8, w->window_size)) return MAC27_PLAIN_RANGE;
        if (off < w->fixoff + w->fixsize && w->fixoff < off + 8)
            return MAC27_PLAIN_RANGE;
        if (used(bitmap, (uint32_t)current / 4)) return MAC27_PLAIN_OVERLAP;
        if (current + 4 < page_size) {
            if (used(bitmap, (uint32_t)(current + 4) / 4)) return MAC27_PLAIN_OVERLAP;
        } else {
            if (*carry) return MAC27_PLAIN_OVERLAP;
            *carry = 1;
        }
        uint64_t raw = r64(w->src + off);
        uint64_t cache_level = (raw >> 30) & 3u;
        uint64_t target = w->plan->segments[0].vmaddr + (raw & FORMAT8_TARGET_MASK);
        uint64_t pa = w->owner->phys_base + (target - w->plan->virt_base);
        uint64_t next = (raw >> 51) & 0xfffu;
        if (cache_level ||
            (!(raw >> 63) && (raw & FORMAT8_EXTRA_MASK))) return MAC27_PLAIN_FIXUPS;
        if (!virtual_target(w->plan, target) ||
            !owned_range(pa, 1, w->owner)) return MAC27_PLAIN_TARGET;
        if (!w->commit && crosses_provider(w->provider_edges, w->provider_count, off))
            return MAC27_PLAIN_RANGE;
        if (raw >> 63) {
            ++w->authenticated;
        } else {
            ++w->plain;
            if (w->commit) w64(w->window + dst, target);
        }
        if (!next) return MAC27_PLAIN_OK;
        current += next * 4; /* bounded: 4095*4 + <=16380 */
        if (current >= page_size) return MAC27_PLAIN_RANGE;
    }
}

static int run_chains(struct walker *w, uint64_t fixoff, uint64_t fixsize)
{
    const uint8_t *fix = w->src + fixoff;
    uint32_t starts = r32(fix + 4);
    uint32_t nsegs;
    if (r32(fix) || r32(fix + 16) || starts < 28 ||
        !fits(starts, 4, fixsize)) return MAC27_PLAIN_FIXUPS;
    nsegs = r32(fix + starts);
    if (nsegs != w->plan->segment_count ||
        !fits((uint64_t)starts + 4, (uint64_t)nsegs * 4, fixsize))
        return MAC27_PLAIN_FIXUPS;
    for (uint32_t i = 0; i != nsegs; ++i) {
        uint32_t offset = r32(fix + starts + 4 + 4 * i);
        if (!offset) continue;
        const struct mac27_kc_segment *seg = &w->plan->segments[i];
        if (offset < 4 + nsegs * 4 ||
            !fits((uint64_t)starts + offset, 22, fixsize)) return MAC27_PLAIN_FIXUPS;
        const uint8_t *in = fix + starts + offset;
        uint32_t segsize = r32(in);
        uint16_t pgsize = r16(in + 4), format = r16(in + 6);
        uint16_t pages = r16(in + 20);
        if (format != FORMAT_KERNEL_CACHE_64 || pgsize != MAC27_KC_PAGE ||
            (seg->protection & 4) ||
            !fits((uint64_t)starts + offset, segsize, fixsize) ||
            segsize < 22 || !fits(22, (uint64_t)pages * 2, segsize) ||
            ((segsize - 22 - (uint64_t)pages * 2) & 1) ||
            (uint64_t)pages * pgsize > seg->vmsize ||
            r64(in + 8) != seg->vmaddr - w->plan->segments[0].vmaddr)
            return MAC27_PLAIN_FIXUPS;
        uint64_t aux_count = (segsize - 22 - (uint64_t)pages * 2) / 2;
        const uint8_t *aux = in + 22 + (uint64_t)pages * 2;
        unsigned pending = 0;
        for (uint32_t page = 0; page != pages; ++page) {
            uint8_t bitmap[MAC27_KC_PAGE / 32];
            for (size_t j = 0; j != sizeof(bitmap); ++j) bitmap[j] = 0;
            if (pending) bitmap[0] = 1; /* 4 bytes used by previous page */
            pending = 0;
            uint16_t first = r16(in + 22 + (uint64_t)page * 2);
            if (first == START_NONE) continue;
            if (first & START_MULTI) {
                uint64_t index = first & ~START_MULTI;
                int done = 0;
                for (; index < aux_count; ++index) {
                    uint16_t off = r16(aux + index * 2);
                    int err = walk_chain(w, seg, page, off & ~START_MULTI,
                                         pgsize, bitmap, &pending);
                    if (err) return err;
                    if (off & START_MULTI) { done = 1; break; }
                }
                if (!done) return MAC27_PLAIN_FIXUPS;
            } else {
                int err = walk_chain(w, seg, page, first, pgsize, bitmap, &pending);
                if (err) return err;
            }
        }
    }
    return MAC27_PLAIN_OK;
}

int mac27_kc_plain_rebase(const void *source, size_t source_size,
                         const struct mac27_kc_plain_ownership *ownership,
                         void *loaded_window, size_t window_size,
                         struct mac27_kc_plain_report *report)
{
    struct mac27_kc_plan plan;
    struct mac27_kc_fixup_report read_only;
    struct mac27_kc_plain_report result;
    const uint8_t *src = source;
    uint8_t *dst = loaded_window;
    uint64_t fixoff = 0, fixsize = 0, cursor;
    uint64_t provider_edges[MAX_PROVIDER_BOUNDARIES];
    uint32_t provider_count = 0;
    int saw_fixups = 0;
    if (!source || !ownership || !loaded_window || !report ||
        overlap((uintptr_t)src, source_size, (uintptr_t)dst, window_size) ||
        overlap((uintptr_t)dst, window_size, (uintptr_t)ownership, sizeof(*ownership)) ||
        overlap((uintptr_t)dst, window_size, (uintptr_t)report, sizeof(*report)) ||
        overlap((uintptr_t)src, source_size, (uintptr_t)report, sizeof(*report)) ||
        overlap((uintptr_t)src, source_size, (uintptr_t)ownership, sizeof(*ownership)) ||
        overlap((uintptr_t)report, sizeof(*report), (uintptr_t)ownership, sizeof(*ownership)))
        return MAC27_PLAIN_ARGUMENT;
    if (ownership->exclusive_writable_ram != 1 ||
        !ownership->exclusive_size ||
        ownership->exclusive_size > UINT64_MAX - ownership->exclusive_start ||
        ownership->memory_size > UINT64_MAX - ownership->phys_base ||
        !owned_range(ownership->phys_base, window_size, ownership))
        return MAC27_PLAIN_OWNERSHIP;
    if (mac27_kc_plan(src, source_size, ownership->phys_base,
                      ownership->memory_size, &plan)) return MAC27_PLAIN_MACHO;
    if (plan.occupied_size > window_size) return MAC27_PLAIN_RANGE;
    if (mac27_kc_inspect_fixups(src, source_size, ownership->phys_base,
                                ownership->memory_size, &read_only)) return MAC27_PLAIN_FIXUPS;
    if (!raw_copy_matches(src, dst, &plan, window_size)) return MAC27_PLAIN_COPY;
    cursor = 32;
    for (uint32_t i = 0; i != r32(src + 16); ++i) {
        uint32_t cmd = r32(src + cursor), length = r32(src + cursor + 4);
        if (cmd == CHAINED_FIXUPS) {
            if (++saw_fixups != 1) return MAC27_PLAIN_FIXUPS;
            fixoff = r32(src + cursor + 8);
            fixsize = r32(src + cursor + 12);
        } else if (cmd == FILESET_ENTRY) {
            if (provider_count == MAX_PROVIDER_BOUNDARIES)
                return MAC27_PLAIN_FIXUPS;
            uint64_t edge = r64(src + cursor + 16);
            uint32_t j = provider_count++;
            while (j && provider_edges[j - 1] > edge) {
                provider_edges[j] = provider_edges[j - 1];
                --j;
            }
            provider_edges[j] = edge;
        }
        cursor += length;
    }
    if (saw_fixups != 1 || fixsize < 28 || !fits(fixoff, fixsize, source_size))
        return MAC27_PLAIN_FIXUPS;
    struct walker w = {src, dst, source_size, window_size,
                       provider_edges, provider_count, fixoff, fixsize,
                       &plan, ownership, 0, 0, 0};
    int err = run_chains(&w, fixoff, fixsize);
    if (err) return err;
    if (w.plain != read_only.unauthenticated ||
        w.authenticated != read_only.authenticated || read_only.nonzero_cache_level)
        return MAC27_PLAIN_FIXUPS;
    result.plain_rebased = w.plain;
    result.authenticated_preserved = w.authenticated;
    result.base_pointer0 = plan.segments[0].vmaddr;
    result.mapped_bytes = plan.occupied_size;
    w.commit = 1;
    /* The validated immutable source makes this second traversal infallible;
     * window and metadata must not be modified concurrently by the caller. */
    (void)run_chains(&w, fixoff, fixsize);
    for (size_t i = 0; i != sizeof(result); ++i)
        ((uint8_t *)report)[i] = ((const uint8_t *)&result)[i];
    return MAC27_PLAIN_OK;
}
