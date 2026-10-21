/* Source-only FDT/PC-relative BRK candidate checks. NO XNU instruction runs. */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../ports/macos27/execution_platform_guard.h"

static unsigned assertions;
#define CHECK(c) do { ++assertions; assert(c); } while (0)
enum { FDT_CAP=16384, CODE_SIZE=0x3bf4 };
static uint8_t fdt[FDT_CAP], code[CODE_SIZE];
static size_t sp, np;
static struct m27_xg_range live[7];
static struct m27_xg_request req;
static struct m27_xg_report rep;

static void w32(size_t at, uint32_t v)
{
    fdt[at] = (uint8_t)(v >> 24);
    fdt[at + 1] = (uint8_t)(v >> 16);
    fdt[at + 2] = (uint8_t)(v >> 8);
    fdt[at + 3] = (uint8_t)v;
}
static void w64(size_t at, uint64_t v)
{
    w32(at, (uint32_t)(v >> 32));
    w32(at + 4, (uint32_t)v);
}
static void token(uint32_t v) { w32(sp, v); sp += 4; }
static size_t str(const char *s)
{
    size_t off = np, len = strlen(s) + 1;
    memcpy(fdt + 8192 + np, s, len);
    np += len;
    return off;
}
static void prop(const char *name, const uint32_t *values, size_t count)
{
    token(3);
    w32(sp, (uint32_t)count * 4);
    w32(sp + 4, (uint32_t)str(name));
    sp += 8;
    for (size_t i=0; i<count; ++i) {
        w32(sp, values[i]);
        sp += 4;
    }
}
static void node(const char *name)
{
    token(1);
    size_t n = strlen(name) + 1;
    memcpy(fdt + sp, name, n);
    sp = (sp + n + 3) & ~(size_t)3;
}
static void endnode(void) { token(2); }
static void property_value(const char *name, uint32_t val)
{
    prop(name, &val, 1);
}
static void init_fdt(int dynamic)
{
    memset(fdt, 0, sizeof(fdt)); sp = 72; np = 0;
    node("");
    property_value("#address-cells", 2);
    property_value("#size-cells", 2);
    node("memory");
    uint32_t memory[] = {8, 0xc0000000, 0, 0xc0000000};
    prop("reg", memory, 4);
    endnode();
    node("chosen");
    property_value("linux,initrd-start", 0xb719f000);
    property_value("linux,initrd-end", 0xb7ffe6c4);
    endnode();
    node("reserved-memory");
    property_value("#address-cells", 2);
    property_value("#size-cells", 2);
    node("splash_region");
    uint32_t splash[] = {0, 0xb8000000, 0, 0x02b00000};
    prop("reg", splash, 4);
    endnode();
    node("ramoops@80D00000");
    uint32_t ramoops[] = {0, 0x80d00000, 0, 0x200000};
    prop("reg", ramoops, 4);
    endnode();
    if (dynamic) {
        node("linux,cma");
        property_value("size", 0x1000);
        endnode();
    }
    endnode(); endnode(); token(9);
    w32(0, 0xd00dfeed);
    w32(4, (uint32_t)(8192 + np));
    w32(8, 72);
    w32(12, 8192);
    w32(16, 40);
    w32(20, 17);
    w32(24, 16);
    w32(28, 0);
    w32(32, (uint32_t)np);
    w32(36, (uint32_t)(sp - 72));
    /* memory reservation map: terminating 0,0 at 40 */
}
static void put_code(uint32_t first, uint32_t last)
{
    code[0] = (uint8_t)first; code[1] = (uint8_t)(first >> 8);
    code[2] = (uint8_t)(first >> 16); code[3] = (uint8_t)(first >> 24);
    code[CODE_SIZE-4] = (uint8_t)last;
    code[CODE_SIZE-3] = (uint8_t)(last >> 8);
    code[CODE_SIZE-2] = (uint8_t)(last >> 16);
    code[CODE_SIZE-1] = (uint8_t)(last >> 24);
}
static void make_live(void)
{
    live[0] = (struct m27_xg_range){0xb719f000, 0xb7ffe6c4-0xb719f000, M27_XG_INITRD};
    live[1] = (struct m27_xg_range){0x8a030000, 8192+np, M27_XG_DTB};
    live[2] = (struct m27_xg_range){0xb8000000, 0x2b00000, M27_XG_FRAMEBUFFER};
    live[3] = (struct m27_xg_range){0x80d00000, 0x200000, M27_XG_RAMOOPS};
    live[4] = (struct m27_xg_range){0x8a000000, 0x10000, M27_XG_SHIM};
    live[5] = (struct m27_xg_range){0x8a010000, 0x10000, M27_XG_STACK};
    live[6] = (struct m27_xg_range){0x8a020000, 0x10000, M27_XG_TTBR_TABLES};
}
static void init_request(int dynamic)
{
    init_fdt(dynamic); make_live(); memset(code, 0, sizeof(code));
    put_code(M27_XG_BRANCH_WORD, M27_XG_BRK_WORD);
    memset(&req, 0, sizeof(req));
    req.fdt = fdt; req.fdt_capacity = 8192 + np;
    req.fdt_pa = 0x8a030000;
    req.live = live; req.live_count = 7;
    req.kernel_pa = M27_XG_PHYS; req.kernel_bytes = M27_XG_PHYS_SIZE;
    req.instrumented_copy = code; req.instrumented_capacity = CODE_SIZE;
    req.copy_pa = req.entry_pa = M27_XG_ENTRY_PA;
    req.brk_target_pa = M27_XG_DEST_PA;
    req.source_26a434_manifest_matched = 1; req.separate_mutable_copy = 1;
    req.el1.current_el = 4; req.el1.origin = M27_XG_ORIGIN_DIRECT_EL1;
    req.el1.instruction_va = M27_XG_ENTRY_PA;
}
static uint32_t check(void)
{
    CHECK(m27_xg_analyze(&req, &rep) == M27_XG_BLOCKED);
    CHECK(rep.native_entry_allowed == 0);
    CHECK(rep.blockers & M27_XG_B_EXECUTE_UNATTESTED);
    CHECK(rep.blockers & M27_XG_B_RAM_OWNERSHIP_UNKNOWN);
    CHECK(rep.blockers & M27_XG_B_BRK_EXCEPTION_UNKNOWN);
    return rep.blockers;
}
static void tests(void)
{
    init_request(0);
    CHECK(check() == (M27_XG_B_EXECUTE_UNATTESTED |
                      M27_XG_B_RAM_OWNERSHIP_UNKNOWN |
                      M27_XG_B_BRK_EXCEPTION_UNKNOWN |
                      M27_XG_B_REGISTERS_UNATTESTED));
    CHECK(rep.structurally_plausible == 1);
    CHECK(rep.physical_entry == M27_XG_ENTRY_PA);
    CHECK(rep.physical_brk_target == M27_XG_DEST_PA);
    CHECK(rep.ddr_regions == 1 && rep.fixed_reservations == 2);
    CHECK(rep.captured_splash_pa == 0xb8000000);
    CHECK(rep.captured_ramoops_pa == 0x80d00000);
    CHECK(rep.captured_initrd_start == 0xb719f000);
    init_request(1);
    CHECK(check() & M27_XG_B_DYNAMIC_RESERVATION);
    CHECK(rep.dynamic_reserved_children == 1);
    init_request(0); w32(0, 0);
    CHECK(check() & M27_XG_B_FDT_INVALID);
    init_request(0); w32(4, 0xffffffff);
    CHECK(check() & M27_XG_B_FDT_INVALID);
    init_request(0); w32(16, 999999);
    CHECK(check() & M27_XG_B_FDT_INVALID);
    init_request(0); w32(36, 0);
    CHECK(check() & M27_XG_B_FDT_INVALID);
    init_request(0); w32(12, 88); /* overlapping property string and struct */
    CHECK(check() & M27_XG_B_FDT_INVALID);
    init_request(0); w64(40, M27_XG_PHYS); w64(48, 0x4000);
    CHECK(check() & M27_XG_B_FIXED_RESERVATION);
    CHECK(rep.valid_fdt == 1);
    init_request(0); live[0].pa++;
    CHECK(check() & M27_XG_B_LIVE_RANGE_MISSING);
    init_request(0); live[6].pa = M27_XG_PHYS;
    CHECK(check() & M27_XG_B_LIVE_OVERLAP);
    init_request(0); live[6].pa = live[5].pa;
    CHECK(check() & M27_XG_B_LIVE_OVERLAP);
    init_request(0); live[6].bytes = UINT64_MAX;
    CHECK(check() & M27_XG_B_LIVE_RANGE_MISSING);
    init_request(0); req.live_count=6;
    CHECK(check() & M27_XG_B_LIVE_RANGE_MISSING);
    init_request(0); live[3].kind = M27_XG_FRAMEBUFFER;
    CHECK(check() & M27_XG_B_LIVE_RANGE_MISSING);
    init_request(0); live[0].pa = UINT64_MAX-4;
    CHECK(check() & M27_XG_B_LIVE_RANGE_MISSING);
    init_request(0); req.el1.sctlr_el1 = 1;
    CHECK(check() & M27_XG_B_EL1_MMU_STATE);
    CHECK(rep.blockers & M27_XG_B_ALIAS_UNPROVEN);
    init_request(0); req.el1.instruction_va = M27_XG_ENTRY_VA;
    CHECK(check() & M27_XG_B_ALIAS_UNPROVEN);
    init_request(0); req.el1.current_el = 8;
    CHECK(check() & M27_XG_B_EL1_MMU_STATE);
    init_request(0); req.el1.origin = M27_XG_ORIGIN_SAVED_LOG;
    CHECK(check() & M27_XG_B_REGISTERS_UNATTESTED);
    init_request(0); req.brk_target_pa++;
    CHECK(check() & M27_XG_B_TARGET_MISMATCH);
    init_request(0); req.copy_pa++;
    CHECK(check() & M27_XG_B_TARGET_MISMATCH);
    init_request(0); req.instrumented_capacity = 4;
    CHECK(check() & M27_XG_B_CODE_COPY);
    init_request(0); put_code(M27_XG_BRANCH_WORD ^ 1, M27_XG_BRK_WORD);
    CHECK(check() & M27_XG_B_TARGET_MISMATCH);
    init_request(0); put_code(M27_XG_BRANCH_WORD, 0xd503201f);
    CHECK(check() & M27_XG_B_BRK_NOT_INSTRUMENTED);
    init_request(0); req.source_26a434_manifest_matched = 0;
    CHECK(check() & M27_XG_B_KC_PROVENANCE);
    init_request(0); req.separate_mutable_copy = 0;
    CHECK(check() & M27_XG_B_KC_PROVENANCE);
    init_request(0); req.kernel_pa++;
    CHECK(check() & M27_XG_B_FDT_INVALID);
    init_request(0); req.live_count = M27_XG_MAX_LIVE_REGIONS + 1;
    CHECK(check() & M27_XG_B_FDT_INVALID);
    CHECK(m27_xg_analyze(&req, NULL) == M27_XG_BAD_ARGUMENT);
}
static void saved_fdt(const char *path)
{
    FILE *fd = fopen(path, "rb");
    CHECK(fd != NULL);
    CHECK(fseek(fd, 0, SEEK_END) == 0);
    long length = ftell(fd);
    CHECK(length > 40 && length < (long)M27_XG_MAX_FDT_BYTES);
    rewind(fd);
    uint8_t *b = malloc((size_t)length);
    CHECK(b != NULL);
    CHECK(fread(b, 1, (size_t)length, fd) == (size_t)length);
    fclose(fd);
    init_request(0);
    req.fdt = b; req.fdt_capacity = (size_t)length;
    live[1].bytes = (uint32_t)length;
    uint32_t blockers = check();
    CHECK(rep.valid_fdt == 1);
    CHECK(rep.ddr_regions >= 1 && rep.fixed_reservations >= 2);
    CHECK(rep.captured_splash_pa == 0xb8000000);
    CHECK(rep.captured_ramoops_pa == 0x80d00000);
    CHECK(rep.captured_initrd_start == 0xb719f000);
    CHECK(rep.captured_initrd_end == 0xb7ffe6c4);
    CHECK((blockers & (M27_XG_B_NOT_DDR | M27_XG_B_FIXED_RESERVATION |
                       M27_XG_B_FDT_INVALID)) == 0);
    CHECK(rep.dynamic_reserved_children > 0);
    printf("PASS saved dizi FDT: %u DDR banks, %u fixed reservations, %u dynamic/unbounded children; exec BLOCKED\n",
           rep.ddr_regions, rep.fixed_reservations, rep.dynamic_reserved_children);
    free(b);
}
int main(int argc, char **argv)
{
    tests();
    if (argc == 2) saved_fdt(argv[1]);
    printf("PASS %u platform guard assertions; ALWAYS no XNU entry\n", assertions);
    return 0;
}
