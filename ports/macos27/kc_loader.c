#include "kc_loader.h"

#define SEGMENT_64 0x19u
#define UNIXTHREAD 5u
#define FILESET_ENTRY 0x80000035u
#define CHAINED_FIXUPS 0x80000034u

static uint32_t u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t u64(const uint8_t *p)
{
    return (uint64_t)u32(p) | (uint64_t)u32(p + 4) << 32;
}

static int fits(uint64_t offset, uint64_t length, uint64_t limit)
{
    return offset <= limit && length <= limit - offset;
}

static int overlaps(uintptr_t a, size_t as, uintptr_t b, size_t bs)
{
    return as > UINTPTR_MAX - a || bs > UINTPTR_MAX - b || (a < b + bs && b < a + as);
}

static int name_is(const uint8_t *bytes, uint64_t size, const char *name)
{
    for (uint64_t i = 0; i < size; i++) {
        if (bytes[i] != (uint8_t)name[i]) return 0;
        if (!bytes[i]) return 1;
    }
    return 0;
}

static int mapped_file(const struct mac27_kc_plan *p, uint64_t offset,
                       uint64_t length, uint64_t *va)
{
    for (uint32_t i = 0; i < p->segment_count; i++) {
        const struct mac27_kc_segment *s = &p->segments[i];
        if (offset >= s->fileoff && fits(offset - s->fileoff, length, s->filesize)) {
            *va = s->vmaddr + offset - s->fileoff;
            return 1;
        }
    }
    return 0;
}

int mac27_kc_plan(const void *input, size_t size, uint64_t phys_base,
                  uint64_t memory_size, struct mac27_kc_plan *out)
{
    const uint8_t *b = input;
    struct mac27_kc_plan p;
    uint64_t end, cursor, header_va = 0, kernel_va = 0, kernel_off = 0;
    uint64_t fixups_off = 0, high = 0, low = UINT64_MAX, va;
    uint32_t count, threads = 0, kernels = 0, fixups = 0;
    if (!b || !out || overlaps((uintptr_t)b, size, (uintptr_t)out, sizeof(p)))
        return MAC27_KC_ARGUMENT;
    if (size < 32 || size > MAC27_KC_MAX_BYTES || !memory_size ||
        (phys_base & (MAC27_KC_BLOCK - 1)) || (memory_size & (MAC27_KC_PAGE - 1)) ||
        memory_size > UINT64_MAX - phys_base)
        return MAC27_KC_RANGE;
    if (u32(b) != 0xfeedfacfu || u32(b + 4) != 0x100000cu || u32(b + 12) != 12)
        return MAC27_KC_FORMAT;
    count = u32(b + 16);
    if (!count || count > 4096 || u32(b + 20) > 0x200000 ||
        u32(b + 20) < (uint64_t)count * 8 || !fits(32, u32(b + 20), size))
        return MAC27_KC_FORMAT;
    for (size_t i = 0; i < sizeof(p); i++) ((uint8_t *)&p)[i] = 0;
    p.cpu_subtype = u32(b + 8);
    p.phys_base = phys_base;
    p.memory_size = memory_size;
    cursor = 32; end = cursor + u32(b + 20);
    for (uint32_t i = 0; i < count; i++) {
        uint32_t cmd, length;
        if (!fits(cursor, 8, end)) return MAC27_KC_FORMAT;
        cmd = u32(b + cursor); length = u32(b + cursor + 4);
        if (length < 8 || (length & 7) || !fits(cursor, length, end)) return MAC27_KC_FORMAT;
        if (cmd == SEGMENT_64) {
            struct mac27_kc_segment *s;
            if (length < 72 || u32(b + cursor + 64) * UINT64_C(80) + 72 != length)
                return MAC27_KC_FORMAT;
            if (p.segment_count == MAC27_KC_MAX_SEGMENTS) return MAC27_KC_CAPACITY;
            s = &p.segments[p.segment_count++];
            s->vmaddr = u64(b + cursor + 24); s->vmsize = u64(b + cursor + 32);
            s->fileoff = u64(b + cursor + 40); s->filesize = u64(b + cursor + 48);
            s->protection = u32(b + cursor + 60);
            if (!s->vmsize || (s->vmaddr & (MAC27_KC_PAGE - 1)) ||
                (s->vmsize & (MAC27_KC_PAGE - 1)) || s->vmaddr < UINT64_C(0xffff000000000000) ||
                s->vmsize > UINT64_MAX - s->vmaddr || s->filesize > s->vmsize ||
                !fits(s->fileoff, s->filesize, size)) return MAC27_KC_RANGE;
            for (uint32_t j = 0; j + 1 < p.segment_count; j++) {
                const struct mac27_kc_segment *t = &p.segments[j];
                if (s->vmaddr < t->vmaddr + t->vmsize && t->vmaddr < s->vmaddr + s->vmsize)
                    return MAC27_KC_MAPPING;
                if (s->filesize && t->filesize && s->fileoff < t->fileoff + t->filesize &&
                    t->fileoff < s->fileoff + s->filesize) return MAC27_KC_MAPPING;
            }
            if (s->vmaddr < low) low = s->vmaddr;
            if (s->vmaddr + s->vmsize > high) high = s->vmaddr + s->vmsize;
            if (name_is(b + cursor + 8, 16, "__TEXT")) {
                if (header_va || s->fileoff || s->filesize < end) return MAC27_KC_FORMAT;
                header_va = s->vmaddr;
            }
        } else if (cmd == UNIXTHREAD) {
            if (++threads != 1 || length != 288 || u32(b + cursor + 8) != 6 ||
                u32(b + cursor + 12) != 68) return MAC27_KC_FORMAT;
            p.entry_va = u64(b + cursor + 16 + 32 * 8);
        } else if (cmd == CHAINED_FIXUPS) {
            if (++fixups != 1 || length != 16) return MAC27_KC_FORMAT;
            fixups_off = u32(b + cursor + 8); p.fixups_size = u32(b + cursor + 12);
            if (p.fixups_size < 28 || !fits(fixups_off, p.fixups_size, size)) return MAC27_KC_RANGE;
        } else if (cmd == FILESET_ENTRY) {
            uint32_t string_offset;
            if (length < 40) return MAC27_KC_FORMAT;
            string_offset = u32(b + cursor + 24);
            if (string_offset < 32 || string_offset >= length || u32(b + cursor + 28))
                return MAC27_KC_FORMAT;
            int terminated = 0;
            for (uint32_t j = string_offset; j < length; j++) if (!b[cursor + j]) { terminated = 1; break; }
            if (!terminated || !b[cursor + string_offset]) return MAC27_KC_FORMAT;
            if (!fits(u64(b + cursor + 16), 32, size)) return MAC27_KC_RANGE;
            if (name_is(b + cursor + string_offset, length - string_offset, "com.apple.kernel")) {
                if (++kernels != 1) return MAC27_KC_FORMAT;
                kernel_va = u64(b + cursor + 8); kernel_off = u64(b + cursor + 16);
            }
            p.fileset_count++;
        }
        cursor += length;
    }
    if (cursor != end || !p.segment_count || !header_va || low != header_va ||
        threads != 1 || kernels != 1 || fixups != 1) return MAC27_KC_FORMAT;
    p.virt_base = low & ~(MAC27_KC_BLOCK - 1);
    p.occupied_size = high - p.virt_base;
    if (p.occupied_size > memory_size) return MAC27_KC_CAPACITY;
    p.kernel_end_va = high; p.kernel_end_pa = phys_base + p.occupied_size;
    if (!mapped_file(&p, fixups_off, p.fixups_size, &va)) return MAC27_KC_MAPPING;
    p.fixups_pa = phys_base + (va - p.virt_base);
    if (!mapped_file(&p, kernel_off, 104, &va) || va != kernel_va ||
        u32(b + kernel_off) != 0xfeedfacfu || u32(b + kernel_off + 4) != 0x100000cu ||
        u32(b + kernel_off + 12) != 2 || !(u32(b + kernel_off + 24) & 0x80000000u) ||
        u32(b + kernel_off + 32) != SEGMENT_64 || u64(b + kernel_off + 56) != kernel_va)
        return MAC27_KC_FORMAT;
    p.kernel_header_pa = phys_base + (kernel_va - p.virt_base);
    int executable = 0;
    for (uint32_t i = 0; i < p.segment_count; i++) {
        const struct mac27_kc_segment *s = &p.segments[i];
        if ((s->protection & 4) && p.entry_va >= s->vmaddr && p.entry_va - s->vmaddr < s->filesize)
            executable = 1;
    }
    if (!executable) return MAC27_KC_MAPPING;
    p.entry_pa = phys_base + (p.entry_va - p.virt_base);
    cursor = 32;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t length = u32(b + cursor + 4);
        if (u32(b + cursor) == FILESET_ENTRY &&
            (!mapped_file(&p, u64(b + cursor + 16), 32, &va) || va != u64(b + cursor + 8)))
            return MAC27_KC_MAPPING;
        cursor += length;
    }
    for (size_t i = 0; i < sizeof(p); i++) ((uint8_t *)out)[i] = ((uint8_t *)&p)[i];
    return MAC27_KC_OK;
}

int mac27_kc_load(const void *file, size_t size, uint64_t phys_base,
                  uint64_t memory_size, void *window, size_t window_size,
                  struct mac27_kc_plan *out)
{
    struct mac27_kc_plan p;
    int error;
    if (!window || !out || overlaps((uintptr_t)window, window_size, (uintptr_t)file, size) ||
        overlaps((uintptr_t)window, window_size, (uintptr_t)out, sizeof(p)) ||
        overlaps((uintptr_t)file, size, (uintptr_t)out, sizeof(p))) return MAC27_KC_ARGUMENT;
    error = mac27_kc_plan(file, size, phys_base, memory_size, &p);
    if (error) return error;
    if (p.occupied_size > window_size) return MAC27_KC_CAPACITY;
    for (uint32_t i = 0; i < p.segment_count; i++) {
        const struct mac27_kc_segment *s = &p.segments[i];
        uint8_t *dst = (uint8_t *)window + (s->vmaddr - p.virt_base);
        const uint8_t *src = (const uint8_t *)file + s->fileoff;
        for (uint64_t j = 0; j < s->filesize; j++) dst[j] = src[j];
        for (uint64_t j = s->filesize; j < s->vmsize; j++) dst[j] = 0;
    }
    for (size_t i = 0; i < sizeof(p); i++) ((uint8_t *)out)[i] = ((uint8_t *)&p)[i];
    return MAC27_KC_OK;
}
