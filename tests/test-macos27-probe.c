/* Exercise the exact decompressed-KC discovery used by the optional dizi
 * preflight.  Simulated physical memory only; never touch a real FDT/device. */
#define main kc_loader_fixture_main
#include "test-macos27-kc-loader.c"
#undef main
#include "../shim/macos27_kc_probe.h"

static uint64_t fdt_start, fdt_end;
static int fdt_available = 1;

int fdt_chosen_u64(uintptr_t fdt, const char *property, uint64_t *out)
{
    (void)fdt;
    if (!fdt_available || !out) return 0;
    if (!strcmp(property, "linux,initrd-start")) *out = fdt_start;
    else if (!strcmp(property, "linux,initrd-end")) *out = fdt_end;
    else return 0;
    return 1;
}

static void valid_fixture(unsigned char *out)
{
    fixture(out);
    unsigned char *f = out + 0x7000;
    memset(f, 0, 64);
    put32(f + 4, 28);
    put32(f + 8, 64);
    put32(f + 12, 64);
    put32(f + 28, 2);
    put32(f + 36, 12);
    put32(f + 40, 24);
    f[45] = 0x40; f[46] = 8;
    put64(f + 48, 0x8000);
    f[60] = 1; f[63] = 1;
    put64(out + 0x8100, UINT64_C(1) << 63);
}

int main(void)
{
    enum { PREFIX = 151, SUFFIX = 37 };
    unsigned char *buf = malloc(PREFIX + FILE_BYTES + SUFFIX);
    assert(buf);
    memset(buf, 0x5a, PREFIX + FILE_BYTES + SUFFIX);
    /* A decoy Mach-O magic in the vendor ramdisk cannot be accepted as KC. */
    memcpy(buf + 11, "\xcf\xfa\xed\xfe", 4);
    valid_fixture(buf + PREFIX);
    fdt_start = (uintptr_t)buf;
    fdt_end = fdt_start + PREFIX + FILE_BYTES + SUFFIX;
    assert(!strcmp(mac27_dizi_probe_dtb(0),
                   "macOS27: real KC parsed; PAC/APFS/driver gate BLOCKED"));
    buf[PREFIX + 0x702e] = 7;  /* wrong chained pointer format */
    assert(!strcmp(mac27_dizi_probe_dtb(0),
                   "macOS27: no validated decompressed KC in initrd"));
    valid_fixture(buf + PREFIX);
    fdt_end = fdt_start + PREFIX + 4095;
    assert(!strcmp(mac27_dizi_probe_dtb(0),
                   "macOS27: no validated decompressed KC in initrd"));
    fdt_end = fdt_start + MAC27_KC_MAX_BYTES + 1;
    assert(!strcmp(mac27_dizi_probe_dtb(0), "macOS27: missing/bad initrd"));
    fdt_available = 0;
    assert(!strcmp(mac27_dizi_probe_dtb(0), "macOS27: missing/bad initrd"));
    free(buf);
    puts("PASS optional dizi macOS27 shim probe: unaligned vendor prefix, decoy, malformed KC, truncated/oversize/missing FDT, never jumps");
    return 0;
}
