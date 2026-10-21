#define main existing_kc_loader_test_main
#include "test-macos27-kc-loader.c"
#undef main
#include "../shim/macos27_kc.h"

static void fixup_fixture(unsigned char *kc)
{
    fixture(kc);
    unsigned char *b = kc + 0x7000;
    memset(b, 0, 64);
    put32(b + 4, 28);              /* starts_offset */
    put32(b + 8, 64);              /* imports_offset */
    put32(b + 12, 64);             /* symbols_offset */
    put32(b + 28, 2);             /* 2 Mach-O segments */
    put32(b + 36, 12);            /* starts for second segment */
    put32(b + 40, 24);            /* size of starts_in_segment */
    b[44] = 0; b[45] = 0x40;       /* 16KiB page */
    b[46] = 8;                    /* DYLD_CHAINED_PTR_64_KERNEL_CACHE */
    put64(b + 48, 0x8000);        /* relative to first segment vmaddr */
    b[60] = 1;                    /* 1 page */
    b[62] = 0; b[63] = 1;         /* start 0x100 */
    put64(kc + 0x8100, (UINT64_C(1) << 63) | (UINT64_C(1) << 32) | 0x1234);
}

static void synthetic_shim(void)
{
    unsigned char *kc = malloc(FILE_BYTES); assert(kc);
    fixup_fixture(kc);
    unsigned char adt[0x220];
    for (size_t i = 0; i < sizeof(adt); ++i) adt[i] = (unsigned char)i;
    static const char line[] = "cpus=1 -v";
    struct mac27_shim_request req = {0};
    req.phys_base = PHYS;
    req.memory_size = MEMORY;
    req.adt = adt;
    req.adt_size = sizeof(adt);
    req.command_line = line;
    req.command_line_size = sizeof(line) - 1;
    struct mac27_shim_layout layout;
    struct mac27_kc_fixup_report report;
    assert(mac27_kc_inspect_fixups(kc, FILE_BYTES, PHYS, MEMORY, &report) == 0);
    assert(report.pointers == 1 && report.authenticated == 1 && !report.unauthenticated);
    assert(mac27_kc_fixups_need_runtime(&report));
    assert(mac27_shim_plan(kc, FILE_BYTES, &req, &layout) == 0);
    assert(!layout.native_boot_allowed);
    uint64_t prefix = BASE - layout.kc.virt_base;
    assert(layout.kc.entry_pa == PHYS + prefix + 0x8000);
    size_t cap = (size_t)(layout.top_pa - PHYS);
    unsigned char *window = malloc(cap + 1); assert(window);
    memset(window, 0xa5, cap + 1);
    assert(mac27_shim_stage(kc, FILE_BYTES, &req, &layout, window, cap) == 0);
    assert(window[cap] == 0xa5 && window[0] == 0xa5);
    assert(!memcmp(window + (layout.adt_pa - PHYS), adt, sizeof(adt)));
    assert(!memcmp(window + (layout.kc.entry_pa - PHYS), kc + 0x8000, 0x4000));
    assert(!memcmp(window + prefix + 0x8100, kc + 0x8100, 8)); /* auth chain unchanged */
    const struct mac27_boot_args *ba = (const void *)(window + layout.boot_args_pa - PHYS);
    assert(ba->virt_base == layout.kc.virt_base && ba->phys_base == PHYS);
    assert(ba->device_tree_va == ba->virt_base + layout.adt_pa - PHYS);
    assert(ba->device_tree_length == sizeof(adt));
    assert(ba->boot_flags == 0 && ba->top_of_kernel_data == layout.top_pa);
    assert(!strcmp(ba->command_line, line));
    for (size_t i = sizeof(*ba); i < MAC27_KC_PAGE; ++i)
        assert(window[layout.boot_args_pa - PHYS + i] == 0);
    struct mac27_kc_plain_ownership owner = {PHYS, MEMORY, PHYS, MEMORY, 1};
    struct mac27_kc_plain_report plain_report = {0};
    memset(window, 0xa5, cap + 1);
    /* This compact fixture locates a fixup in an executable segment.
     * The stricter plain resolver MUST refuse it instead of writing code. */
    assert(mac27_shim_stage_plain(kc, FILE_BYTES, &req, &layout, &owner,
                                  window, cap, &plain_report) == MAC27_SHIM_PLAIN_REBASE);
    assert(plain_report.plain_rebased == 0 && plain_report.authenticated_preserved == 0);
    assert(!memcmp(window + prefix + 0x8100, kc + 0x8100, 8));
    assert(!layout.native_boot_allowed && window[cap] == 0xa5);
    /* Fail closed before touching even a single destination byte. */
    memset(window, 0xa5, cap);
    req.reserved_count = 1;
    req.reserved[0].pa = layout.adt_pa;
    req.reserved[0].bytes = MAC27_KC_PAGE;
    struct mac27_shim_layout previous = layout;
    assert(mac27_shim_plan(kc, FILE_BYTES, &req, &layout) == MAC27_SHIM_MEMORY);
    assert(!memcmp(&previous, &layout, sizeof(layout)));
    assert(mac27_shim_stage(kc, FILE_BYTES, &req, &layout, window, cap) == MAC27_SHIM_MEMORY);
    for (size_t i = 0; i < cap; ++i) assert(window[i] == 0xa5);
    req.reserved_count = 0;
    layout.native_boot_allowed = 1;
    assert(mac27_shim_stage(kc, FILE_BYTES, &req, &layout, window, cap) == MAC27_SHIM_ARGUMENT);
    layout.native_boot_allowed = 0;
    assert(mac27_shim_stage(kc, FILE_BYTES, &req, &layout, window, cap - 1) == MAC27_SHIM_MEMORY);
    assert(mac27_shim_stage(kc, FILE_BYTES, &req, &layout, kc, FILE_BYTES) == MAC27_SHIM_ARGUMENT);
    fixup_fixture(kc);
    kc[0x703e] = 0xfe; kc[0x703f] = 0x3f; /* malformed unaligned start */
    assert(mac27_kc_inspect_fixups(kc, FILE_BYTES, PHYS, MEMORY, &report) == MAC27_FIXUP_BOUNDS);
    fixup_fixture(kc);
    kc[0x702e] = 7; /* ARM64E_KERNEL is format 7; reject as wrong format */
    assert(mac27_kc_inspect_fixups(kc, FILE_BYTES, PHYS, MEMORY, &report) == MAC27_FIXUP_UNSUPPORTED);
    fixup_fixture(kc);
    put32(kc + 8, 0); /* Reject a fabricated plain ARM64 KC from the shim. */
    assert(mac27_shim_plan(kc, FILE_BYTES, &req, &layout) == MAC27_SHIM_KC);
    puts("PASS dizi shim: genuine format8 auth-chain scan, ADT/1152-byte boot args and partial plain rebase staged, overlap/capacity/forgery rejected, no jump");
    free(window); free(kc);
}

static void real_shim(const char *path)
{
    FILE *f = fopen(path, "rb"); assert(f);
    assert(!fseek(f, 0, SEEK_END)); long n = ftell(f); assert(n > 0);
    rewind(f); unsigned char *kc = malloc((size_t)n); assert(kc);
    assert(fread(kc, (size_t)n, 1, f) == 1); assert(!fclose(f));
    unsigned char adt[64] = {0};  /* host-only placement token, NOT a valid ADT */
    struct mac27_shim_request req = {0};
    req.phys_base = PHYS; req.memory_size = MEMORY;
    req.adt = adt; req.adt_size = sizeof(adt);
    struct mac27_shim_layout layout;
    assert(mac27_shim_plan(kc, (size_t)n, &req, &layout) == 0);
    assert(!layout.native_boot_allowed && layout.fixups.pointers > 0);
    assert(layout.fixups.authenticated > 0);
    if (strstr(path, "kernel.vma2.macho")) {
        struct mac27_kc_plain_ownership owner = {PHYS, MEMORY, PHYS, MEMORY, 1};
        struct mac27_kc_plain_report plain = {0};
        size_t cap = (size_t)(layout.top_pa - PHYS);
        unsigned char *window = malloc(cap); assert(window);
        memset(window, 0xa5, cap);
        assert(mac27_shim_stage_plain(kc, (size_t)n, &req, &layout, &owner,
                                      window, cap, &plain) == MAC27_SHIM_OK);
        assert(plain.plain_rebased == 89086 && plain.authenticated_preserved == 599964);
        assert(!layout.native_boot_allowed);
        free(window);
        puts("PASS genuine VMA2 shim: 89,086 plain pointers rebased in host RAM, all 599,964 PAC fixups remain encoded; no entry");
    }
    printf("PASS real KC shim layout %s: %" PRIu64 " chains (%" PRIu64 " authenticated), 16KiB boot args PA 0x%" PRIx64 " (no execution)\n",
           path, layout.fixups.pointers, layout.fixups.authenticated, layout.boot_args_pa);
    free(kc);
}

int main(int argc, char **argv)
{
    synthetic_shim();
    for (int i = 1; i < argc; ++i) real_shim(argv[i]);
    return 0;
}
