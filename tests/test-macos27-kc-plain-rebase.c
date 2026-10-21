#define main included_kc_loader_main
#include "test-macos27-kc-loader.c"
#undef main
#include "../ports/macos27/kc_plain_rebase.h"

static uint64_t get64(const unsigned char *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) v |= (uint64_t)p[i] << (i * 8);
    return v;
}

static void prepared(unsigned char *file)
{
    fixture(file);
    put32(file + 476, 80); /* chained fixups LC_LINKEDIT_DATA filesize */
    unsigned char *b = file + 0x7000;
    memset(b, 0, 80);
    put32(b + 4, 28); /* starts offset */
    put32(b + 8, 80); put32(b + 12, 80); /* no imports */
    put32(b + 28, 2); /* two outer segments */
    put32(b + 32, 12); /* segment 0 has chains */
    put32(b + 40, 26); /* segment record with two pages */
    b[44] = 0; b[45] = 0x40; /* page size 16KiB */
    b[46] = 8; /* pointer format 8 */
    b[60] = 2; /* two pages */
    b[62] = 0xff; b[63] = 0xff; /* page0 empty */
    b[64] = 0; b[65] = 0x11; /* page1 starts at 0x1100 */
    put64(file + 0x5100, (UINT64_C(2) << 51) | UINT64_C(0x8800));
    put64(file + 0x5108, (UINT64_C(1) << 63) | (UINT64_C(0xabcd) << 32) |
           (UINT64_C(1) << 48) | (UINT64_C(2) << 49) | UINT64_C(0x9000));
}

static struct mac27_kc_plain_ownership owner(void)
{
    struct mac27_kc_plain_ownership o = {PHYS, MEMORY, PHYS, MEMORY, 1};
    return o;
}

static void reject_plain(unsigned char *src, unsigned char *dst, size_t cap,
                         struct mac27_kc_plain_ownership *o)
{
    struct mac27_kc_plain_report report;
    memset(&report, 0x5a, sizeof(report));
    unsigned char *before = malloc(cap);
    assert(before);
    memcpy(before, dst, cap);
    assert(mac27_kc_plain_rebase(src, FILE_BYTES, o, dst, cap, &report) != 0);
    assert(!memcmp(before, dst, cap));
    for (size_t i = 0; i < sizeof(report); i++) assert(((unsigned char *)&report)[i] == 0x5a);
    free(before);
}

static void synthetic_plain(void)
{
    unsigned char *src = malloc(FILE_BYTES);
    assert(src);
    prepared(src);
    struct mac27_kc_plain_ownership o = owner();
    struct mac27_kc_plan p;
    assert(!mac27_kc_plan(src, FILE_BYTES, PHYS, MEMORY, &p));
    size_t window_bytes = (size_t)p.occupied_size;
    unsigned char *window = malloc(window_bytes);
    assert(window);
    assert(!mac27_kc_load(src, FILE_BYTES, PHYS, MEMORY, window, window_bytes, &p));
    struct mac27_kc_plain_report r;
    assert(!mac27_kc_plain_rebase(src, FILE_BYTES, &o, window, window_bytes, &r));
    assert(r.plain_rebased == 1 && r.authenticated_preserved == 1);
    assert(r.base_pointer0 == BASE && r.mapped_bytes == p.occupied_size);
    assert(get64(window + (BASE - p.virt_base) + 0x5100) == BASE + 0x8800);
    assert(get64(window + (BASE - p.virt_base) + 0x5108) == get64(src + 0x5108));
    assert(get64(src + 0x5100) != get64(window + (BASE - p.virt_base) + 0x5100));
    reject_plain(src, window, window_bytes, &o); /* raw bytes no longer match */
    /* Page-local multi-start list: two independent chains, then duplicate
     * starts which would otherwise attempt overlapping 8-byte writes. */
    prepared(src);
    unsigned char *multi = src + 0x7000;
    put32(multi + 40, 30); /* 2 extra 16-bit chain starts */
    multi[64] = 0x00; multi[65] = 0x80; /* first aux entry index 0 */
    multi[66] = 0x00; multi[67] = 0x11; /* first chain start 0x1100 */
    multi[68] = 0x08; multi[69] = 0x91; /* last chain start 0x1108 */
    put64(src + 0x5100, 0x8800); /* terminate first chain */
    assert(!mac27_kc_load(src, FILE_BYTES, PHYS, MEMORY, window, window_bytes, &p));
    assert(!mac27_kc_plain_rebase(src, FILE_BYTES, &o, window, window_bytes, &r));
    assert(r.plain_rebased == 1 && r.authenticated_preserved == 1);
    multi[68] = 0; /* duplicate 0x1100; reject overlapping chains */
    assert(!mac27_kc_load(src, FILE_BYTES, PHYS, MEMORY, window, window_bytes, &p));
    reject_plain(src, window, window_bytes, &o);
    const struct {
        size_t off;
        uint64_t value;
        int wide;
    } mutations[] = {
        {0x5100, (UINT64_C(1) << 30) | 0x8800, 1}, /* cache level 1 */
        {0x5108, (UINT64_C(1) << 63) | (UINT64_C(3) << 30) | 0x9000, 1},
        {0x5100, 0x10000, 1}, /* target in unmapped hole */
        {0x5100, (UINT64_C(0xfff) << 51) | 0x8800, 1}, /* next off page */
        {0x5100, (UINT64_C(1) << 32) | 0x8800, 1}, /* auth-only metadata */
        {0x702e, 7, 0}, /* arm64e format 7 unsupported */
        {0x703e, 0x00, 0}, /* invalid page0 start */
        {0x7020, 0xfffffffc, 0}, /* invalid starts table offset */
        {0x7040, 0x00ff, 0}, /* malformed page start */
        {0x7028, 0xffffffff, 0}, /* invalid segment record length */
    };
    for (size_t i = 0; i < sizeof(mutations) / sizeof(*mutations); ++i) {
        prepared(src);
        if (mutations[i].wide) put64(src + mutations[i].off, mutations[i].value);
        else put32(src + mutations[i].off, (uint32_t)mutations[i].value);
        memset(window, 0x5a, window_bytes);
        if (!mac27_kc_load(src, FILE_BYTES, PHYS, MEMORY, window, window_bytes, &p))
            reject_plain(src, window, window_bytes, &o);
    }
    prepared(src);
    assert(!mac27_kc_load(src, FILE_BYTES, PHYS, MEMORY, window, window_bytes, &p));
    o.exclusive_writable_ram = 0; reject_plain(src, window, window_bytes, &o);
    o = owner(); o.exclusive_start = PHYS + 0x4000; reject_plain(src, window, window_bytes, &o);
    o = owner(); o.exclusive_size = 0x8000; reject_plain(src, window, window_bytes, &o);
    o = owner(); o.phys_base += 0x4000; reject_plain(src, window, window_bytes, &o);
    o = owner(); window[BASE - p.virt_base + 0x5100] ^= 1;
    reject_plain(src, window, window_bytes, &o);
    window[BASE - p.virt_base + 0x5100] ^= 1;
    assert(mac27_kc_plain_rebase(src, FILE_BYTES, &o, src, FILE_BYTES, &r) == MAC27_PLAIN_ARGUMENT);
    assert(mac27_kc_plain_rebase(src, FILE_BYTES, &o, window, window_bytes, (void *)window) == MAC27_PLAIN_ARGUMENT);
    o = owner(); o.exclusive_start = UINT64_MAX - 3;
    reject_plain(src, window, window_bytes, &o);
    free(src); free(window);
    puts("PASS synthetic: strict non-auth rebase, auth preserved, transactional rejects, ownership and overlap");
}

static void real_plain(const char *path, const char *samples)
{
    FILE *f = fopen(path, "rb"); assert(f);
    assert(!fseek(f, 0, SEEK_END));
    long n = ftell(f); assert(n > 0 && (uint64_t)n <= MAC27_KC_MAX_BYTES);
    rewind(f);
    unsigned char *src = malloc((size_t)n); assert(src);
    assert(fread(src, (size_t)n, 1, f) == 1 && !fclose(f));
    struct mac27_kc_plan p;
    struct mac27_kc_plain_ownership o = owner();
    assert(!mac27_kc_plan(src, (size_t)n, PHYS, MEMORY, &p));
    unsigned char *window = malloc((size_t)p.occupied_size); assert(window);
    memset(window, 0xa5, (size_t)p.occupied_size);
    assert(!mac27_kc_load(src, (size_t)n, PHYS, MEMORY, window, (size_t)p.occupied_size, &p));
    struct mac27_kc_plain_report r;
    int result = mac27_kc_plain_rebase(src, (size_t)n, &o, window, (size_t)p.occupied_size, &r);
    if (result) fprintf(stderr, "rebase failed %s: %d\n", path, result);
    assert(!result);
    f = fopen(samples, "r"); assert(f);
    uint64_t file_off, window_off, raw, expected;
    size_t count = 0;
    while (fscanf(f, "%" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64,
                  &file_off, &window_off, &raw, &expected) == 4) {
        assert(file_off <= (uint64_t)n - 8 && window_off <= p.occupied_size - 8);
        assert(get64(src + file_off) == raw);
        assert(get64(window + window_off) == expected);
        ++count;
    }
    assert(feof(f) && !fclose(f) && count > 20);
    printf("PASS real %s: %" PRIu64 " plain + %" PRIu64 " auth intact, %zu Python-oracle samples\n",
           path, r.plain_rebased, r.authenticated_preserved, count);
    assert(r.base_pointer0 == p.segments[0].vmaddr && r.mapped_bytes == p.occupied_size);
    free(window); free(src);
}

int main(int argc, char **argv)
{
    synthetic_plain();
    if (argc == 3) real_plain(argv[1], argv[2]);
    return 0;
}
