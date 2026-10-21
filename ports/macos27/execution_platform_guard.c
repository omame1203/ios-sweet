#include "execution_platform_guard.h"

/* FDT v17: big-endian bounded, no libc, no global data, no MMIO. */
#define FDT_MAGIC UINT32_C(0xd00dfeed)
#define FDT_BEGIN 1u
#define FDT_END_NODE 2u
#define FDT_PROP 3u
#define FDT_NOP 4u
#define FDT_END 9u
#define MAX_DEPTH 32u

enum node_kind {
    NK_OTHER, NK_ROOT, NK_MEMORY, NK_RESERVED, NK_RESERVED_CHILD,
    NK_CHOSEN
};
struct node {
    unsigned kind, parent_a, parent_s, child_a, child_s, has_reg;
    unsigned name_splash, name_ramoops;
};
struct region { uint64_t pa, bytes; };
struct fdt_evidence {
    struct region ddr[M27_XG_MAX_FDT_REGIONS];
    struct region reserved[M27_XG_MAX_FDT_REGIONS];
    uint32_t nddr, nreserved, dynamic;
    uint64_t initrd_start, initrd_end;
    uint64_t splash_pa, splash_len, ramoops_pa, ramoops_len;
    unsigned got_initrd_start, got_initrd_end, splash, ramoops;
};

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static uint64_t be64(const uint8_t *p)
{
    return ((uint64_t)be32(p) << 32) | be32(p + 4);
}
static uint32_t le32(const uint8_t *p)
{
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static int fits(uint64_t off, uint64_t n, uint64_t size)
{
    return off <= size && n <= size - off;
}
static int bounded(uint64_t a, uint64_t n)
{
    return n && a <= UINT64_MAX - n;
}
static int overlap(uint64_t a, uint64_t an, uint64_t b, uint64_t bn)
{
    if (!bounded(a, an) || !bounded(b, bn)) return 1;
    return a < b + bn && b < a + an;
}
static int inside(uint64_t a, uint64_t n, uint64_t b, uint64_t bn)
{
    return bounded(a, n) && bounded(b, bn) && a >= b && n <= bn &&
           a - b <= bn - n;
}
static int eqstr(const uint8_t *a, uint32_t len, const char *name)
{
    unsigned i;
    for (i = 0; i < len; i++) {
        if (a[i] != (uint8_t)name[i]) return 0;
        if (a[i] == 0) return 1;
    }
    return 0;
}
static int prefix(const uint8_t *a, uint32_t len, const char *name)
{
    unsigned i = 0;
    while (name[i]) {
        if (i == len || a[i] != (uint8_t)name[i]) return 0;
        i++;
    }
    return 1;
}
static void zero(void *p, size_t n)
{
    uint8_t *dst = p;
    for (size_t i = 0; i < n; ++i) dst[i] = 0;
}
static void store_report(struct m27_xg_report *out,
                         const struct m27_xg_report *src)
{
    /* Freestanding shim must never acquire an implicit libc dependency. */
    volatile uint8_t *dst = (volatile uint8_t *)out;
    const uint8_t *b = (const uint8_t *)src;
    for (size_t i = 0; i < sizeof(*src); ++i) dst[i] = b[i];
}
static int add_region(struct region *out, uint32_t *count, uint64_t a, uint64_t n)
{
    if (!bounded(a, n) || *count >= M27_XG_MAX_FDT_REGIONS)
        return 0;
    out[*count].pa = a;
    out[*count].bytes = n;
    ++*count;
    return 1;
}
static int cells_value(const uint8_t *p, unsigned cells, uint64_t *v)
{
    if (cells == 1) { *v = be32(p); return 1; }
    if (cells == 2) { *v = be64(p); return 1; }
    return 0;
}
static int reg_regions(const uint8_t *p, uint32_t bytes, unsigned a,
                       unsigned s, struct fdt_evidence *e, struct node *node)
{
    unsigned width = a + s;
    if (!a || !s || a > 2 || s > 2 || !bytes ||
        bytes % (width * 4) || node->has_reg) return 0;
    node->has_reg = 1;
    for (uint32_t off = 0; off < bytes; off += width * 4) {
        uint64_t addr, length;
        if (!cells_value(p + off, a, &addr) ||
            !cells_value(p + off + a * 4, s, &length)) return 0;
        if (node->kind == NK_MEMORY) {
            /* Qualcomm's captured /memory reg contains a zero-length
             * placeholder; it does NOT grant any DDR ownership. */
            if (!length) continue;
            if (!add_region(e->ddr, &e->nddr, addr, length)) return 0;
        } else if (node->kind == NK_RESERVED_CHILD) {
            if (!add_region(e->reserved, &e->nreserved, addr, length)) return 0;
            if (node->name_splash) {
                if (e->splash || bytes != width * 4) return 0;
                e->splash = 1; e->splash_pa = addr; e->splash_len = length;
            }
            if (node->name_ramoops) {
                if (e->ramoops || bytes != width * 4) return 0;
                e->ramoops = 1; e->ramoops_pa = addr; e->ramoops_len = length;
            }
        }
    }
    return 1;
}
static int fdt_parse(const void *input, size_t capacity, uint64_t dtb_pa,
                     struct fdt_evidence *e, uint32_t *dtb_bytes)
{
    const uint8_t *b = input;
    uint32_t total, st, strings, szst, szstr, rsv, cursor, finish, depth = 0;
    struct node stack[MAX_DEPTH];
    int found_end = 0;
    if (!b || capacity < 40 || capacity > M27_XG_MAX_FDT_BYTES ||
        be32(b) != FDT_MAGIC) return 0;
    total = be32(b + 4);
    st = be32(b + 8);
    strings = be32(b + 12);
    rsv = be32(b + 16);
    szstr = be32(b + 32);
    szst = be32(b + 36);
    if (be32(b + 20) < 17 || total < 56 || total > capacity ||
        total > M27_XG_MAX_FDT_BYTES ||
        !fits(st, szst, total) || !fits(strings, szstr, total) ||
        !fits(rsv, 16, total) || st < 40 || !szstr || !szst ||
        !bounded(dtb_pa, total) || (st & 3u) || (rsv & 7u) ||
        ((uint64_t)st < (uint64_t)strings + szstr &&
         (uint64_t)strings < (uint64_t)st + szst))
        return 0;
    /* The /memreserve block is (addr,size) 64-bit BE pairs terminated
     * by (0,0), which must end before the structure starts. */
    int terminated = 0;
    for (uint32_t pos = rsv; fits(pos, 16, st); pos += 16) {
        uint64_t a = be64(b + pos), n = be64(b + pos + 8);
        if (!a && !n) { terminated = 1; break; }
        if (!add_region(e->reserved, &e->nreserved, a, n)) return 0;
    }
    if (!terminated) return 0;
    cursor = st;
    finish = st + szst;
    while (fits(cursor, 4, finish)) {
        uint32_t token = be32(b + cursor);
        cursor += 4;
        if (token == FDT_BEGIN) {
            unsigned nlen = 0, kind = NK_OTHER;
            struct node *n;
            unsigned parent_kind = depth ? stack[depth - 1].kind : NK_OTHER;
            if (depth >= MAX_DEPTH) return 0;
            while (cursor + nlen < finish && b[cursor + nlen]) nlen++;
            if (cursor + nlen >= finish) return 0;
            if (!depth) {
                if (nlen) return 0;
                kind = NK_ROOT;
            } else if (parent_kind == NK_ROOT) {
                if (eqstr(b + cursor, nlen + 1, "memory") ||
                    prefix(b + cursor, nlen + 1, "memory@")) kind = NK_MEMORY;
                else if (eqstr(b + cursor, nlen + 1, "reserved-memory")) kind = NK_RESERVED;
                else if (eqstr(b + cursor, nlen + 1, "chosen")) kind = NK_CHOSEN;
            } else if (parent_kind == NK_RESERVED) kind = NK_RESERVED_CHILD;
            n = &stack[depth];
            n->kind = kind; n->has_reg = n->name_splash = n->name_ramoops = 0;
            if (depth) {
                n->parent_a = stack[depth - 1].child_a;
                n->parent_s = stack[depth - 1].child_s;
            } else n->parent_a = n->parent_s = 2;
            n->child_a = n->parent_a;
            n->child_s = n->parent_s;
            if (kind == NK_RESERVED_CHILD) {
                n->name_splash = eqstr(b + cursor, nlen + 1, "splash_region");
                n->name_ramoops = prefix(b + cursor, nlen + 1, "ramoops@");
            }
            depth++;
            cursor += nlen + 1;
            if (cursor > UINT32_MAX - 3) return 0;
            cursor = (cursor + 3) & ~3u;
            if (cursor > finish) return 0;
        } else if (token == FDT_END_NODE) {
            if (!depth) return 0;
            if (stack[depth - 1].kind == NK_RESERVED_CHILD &&
                !stack[depth - 1].has_reg) e->dynamic++;
            depth--;
        } else if (token == FDT_PROP) {
            uint32_t bytes, off, name_end;
            const uint8_t *v, *name;
            struct node *n;
            if (!depth || !fits(cursor, 8, finish)) return 0;
            bytes = be32(b + cursor); off = be32(b + cursor + 4);
            cursor += 8;
            if (!fits(cursor, bytes, finish) || off >= szstr) return 0;
            name_end = off;
            while (name_end < szstr && b[strings + name_end]) ++name_end;
            if (name_end == szstr) return 0;
            name = b + strings + off; v = b + cursor;
            n = &stack[depth - 1];
            if (eqstr(name, name_end - off + 1, "#address-cells")) {
                /* GPIO/interrupt children may legitimately use zero address
                 * cells; only /memory and reserved reg need 1 or 2. */
                if (bytes != 4 || (n->child_a = be32(v)) > 2)
                    return 0;
            } else if (eqstr(name, name_end - off + 1, "#size-cells")) {
                /* /cpus legally declares #size-cells=0. Only reg-bearing
                 * /memory and reserved-memory children require nonzero. */
                if (bytes != 4 || (n->child_s = be32(v)) > 2)
                    return 0;
            } else if (eqstr(name, name_end - off + 1, "reg") &&
                       (n->kind == NK_MEMORY || n->kind == NK_RESERVED_CHILD)) {
                if (!reg_regions(v, bytes, n->parent_a, n->parent_s, e, n))
                    return 0;
            } else if (n->kind == NK_CHOSEN &&
                       (eqstr(name, name_end - off + 1, "linux,initrd-start") ||
                        eqstr(name, name_end - off + 1, "linux,initrd-end"))) {
                uint64_t val = 0;
                if ((bytes != 4 && bytes != 8) ||
                    !cells_value(v, bytes / 4, &val)) return 0;
                if (eqstr(name, name_end - off + 1, "linux,initrd-start")) {
                    if (e->got_initrd_start++) return 0;
                    e->initrd_start = val;
                } else {
                    if (e->got_initrd_end++) return 0;
                    e->initrd_end = val;
                }
            }
            cursor += bytes;
            if (cursor > UINT32_MAX - 3) return 0;
            cursor = (cursor + 3) & ~3u;
            if (cursor > finish) return 0;
        } else if (token == FDT_NOP) {
            continue;
        } else if (token == FDT_END) {
            if (depth || found_end) return 0;
            found_end = 1;
            break;
        } else return 0;
    }
    if (!found_end || !e->nddr || !e->splash || !e->ramoops ||
        e->got_initrd_start != 1 || e->got_initrd_end != 1 ||
        !bounded(e->initrd_start, e->initrd_end - e->initrd_start) ||
        e->initrd_start >= e->initrd_end)
        return 0;
    *dtb_bytes = total;
    return 1;
}

enum m27_xg_status m27_xg_analyze(const struct m27_xg_request *q,
                                  struct m27_xg_report *out)
{
    struct m27_xg_report r;
    struct fdt_evidence evidence;
    uint32_t dtb_size = 0, categories = 0;
    int inside_bank = 0, inside_copy = 0;
    if (!out) return M27_XG_BAD_ARGUMENT;
    zero(&r, sizeof(r)); zero(&evidence, sizeof(evidence));
    r.blockers = M27_XG_B_EXECUTE_UNATTESTED | M27_XG_B_RAM_OWNERSHIP_UNKNOWN |
                 M27_XG_B_BRK_EXCEPTION_UNKNOWN | M27_XG_B_REGISTERS_UNATTESTED;
    /* Once a request arrives, ALWAYS return a report with fail-closed bits.
     * Host-supplied structures do not become reliable EL2 attestations. */
    if (!q || !q->fdt || !q->instrumented_copy ||
        q->live_count > M27_XG_MAX_LIVE_REGIONS ||
        (q->live_count && !q->live) ||
        q->kernel_pa != M27_XG_PHYS ||
        q->kernel_bytes != M27_XG_PHYS_SIZE) {
        r.blockers |= M27_XG_B_FDT_INVALID;
        store_report(out, &r);
        return M27_XG_BLOCKED;
    }
    if (!fdt_parse(q->fdt, q->fdt_capacity, q->fdt_pa, &evidence, &dtb_size)) {
        r.blockers |= M27_XG_B_FDT_INVALID;
        store_report(out, &r);
        return M27_XG_BLOCKED;
    }
    r.valid_fdt = 1;
    r.ddr_regions = evidence.nddr;
    r.fixed_reservations = evidence.nreserved;
    r.dynamic_reserved_children = evidence.dynamic;
    r.captured_initrd_start = evidence.initrd_start;
    r.captured_initrd_end = evidence.initrd_end;
    r.captured_splash_pa = evidence.splash_pa;
    r.captured_splash_bytes = evidence.splash_len;
    r.captured_ramoops_pa = evidence.ramoops_pa;
    r.captured_ramoops_bytes = evidence.ramoops_len;
    for (uint32_t i = 0; i < evidence.nddr; ++i)
        if (inside(q->kernel_pa, q->kernel_bytes,
                   evidence.ddr[i].pa, evidence.ddr[i].bytes))
            inside_bank = 1;
    if (!inside_bank) r.blockers |= M27_XG_B_NOT_DDR;
    for (uint32_t i = 0; i < evidence.nreserved; ++i)
        if (overlap(q->kernel_pa, q->kernel_bytes, evidence.reserved[i].pa,
                    evidence.reserved[i].bytes))
            r.blockers |= M27_XG_B_FIXED_RESERVATION;
    if (evidence.dynamic) r.blockers |= M27_XG_B_DYNAMIC_RESERVATION;
    if (!bounded(q->fdt_pa, dtb_size) ||
        overlap(q->kernel_pa, q->kernel_bytes, q->fdt_pa, dtb_size))
        r.blockers |= M27_XG_B_LIVE_OVERLAP;
    for (size_t i = 0; i < q->live_count; ++i) {
        const struct m27_xg_range *x = &q->live[i];
        if (x->kind < M27_XG_INITRD || x->kind > M27_XG_OTHER ||
            !bounded(x->pa, x->bytes)) {
            r.blockers |= M27_XG_B_LIVE_RANGE_MISSING;
            continue;
        }
        if (x->kind != M27_XG_OTHER && (categories & (1u << x->kind)))
            r.blockers |= M27_XG_B_LIVE_RANGE_MISSING;
        categories |= (1u << x->kind);
        ++r.live_ranges_checked;
        if (overlap(q->kernel_pa, q->kernel_bytes, x->pa, x->bytes))
            r.blockers |= M27_XG_B_LIVE_OVERLAP;
        for (size_t j = 0; j < i; ++j) {
            const struct m27_xg_range *previous = &q->live[j];
            if (overlap(x->pa, x->bytes, previous->pa, previous->bytes))
                r.blockers |= M27_XG_B_LIVE_OVERLAP;
        }
        if ((x->kind == M27_XG_INITRD &&
             (x->pa != evidence.initrd_start ||
              x->bytes != evidence.initrd_end - evidence.initrd_start)) ||
            (x->kind == M27_XG_DTB &&
             (x->pa != q->fdt_pa || x->bytes < dtb_size)) ||
            (x->kind == M27_XG_FRAMEBUFFER &&
             (x->pa != evidence.splash_pa || x->bytes != evidence.splash_len)) ||
            (x->kind == M27_XG_RAMOOPS &&
             (x->pa != evidence.ramoops_pa || x->bytes != evidence.ramoops_len)))
            r.blockers |= M27_XG_B_LIVE_RANGE_MISSING;
    }
    /* Require shim code/stack/table provenance, not just stale FDT. */
    if ((categories & ((1u << M27_XG_TTBR_TABLES) * 2 - 2)) !=
        ((1u << M27_XG_TTBR_TABLES) * 2 - 2))
        r.blockers |= M27_XG_B_LIVE_RANGE_MISSING;

    if (q->source_26a434_manifest_matched != 1 ||
        q->separate_mutable_copy != 1)
        r.blockers |= M27_XG_B_KC_PROVENANCE;
    if (q->entry_pa != M27_XG_ENTRY_PA ||
        q->brk_target_pa != M27_XG_DEST_PA ||
        q->copy_pa != q->entry_pa)
        r.blockers |= M27_XG_B_TARGET_MISMATCH;
    if (!bounded(q->copy_pa, q->instrumented_capacity) ||
        !inside(q->entry_pa, UINT64_C(4), q->copy_pa,
                q->instrumented_capacity) ||
        !inside(q->brk_target_pa, UINT64_C(4), q->copy_pa,
                q->instrumented_capacity))
        r.blockers |= M27_XG_B_CODE_COPY;
    else inside_copy = 1;
    if (inside_copy && q->instrumented_capacity <= UINT32_MAX) {
        const uint8_t *code = q->instrumented_copy;
        uint64_t first = q->entry_pa - q->copy_pa;
        uint64_t dest = q->brk_target_pa - q->copy_pa;
        r.branch_word = le32(code + first);
        r.brk_word = le32(code + dest);
        /* Decode unconditional B imm26 sign-extension, scaled by 4. */
        int64_t displacement = (int64_t)(int32_t)(
            (r.branch_word & UINT32_C(0x03ffffff)) << 6) >> 4;
        if ((r.branch_word & UINT32_C(0xfc000000)) != UINT32_C(0x14000000) ||
            r.branch_word != M27_XG_BRANCH_WORD ||
            displacement != (int64_t)(M27_XG_DEST_PA - M27_XG_ENTRY_PA))
            r.blockers |= M27_XG_B_TARGET_MISMATCH;
        if (r.brk_word != M27_XG_BRK_WORD)
            r.blockers |= M27_XG_B_BRK_NOT_INSTRUMENTED;
    } else r.blockers |= M27_XG_B_CODE_COPY;

    if (q->el1.origin != M27_XG_ORIGIN_DIRECT_EL1 ||
        q->el1.current_el != UINT64_C(4))
        r.blockers |= M27_XG_B_REGISTERS_UNATTESTED;
    r.observed_current_el = q->el1.current_el;
    r.observed_sctlr_el1 = q->el1.sctlr_el1;
    r.observed_tcr_el1 = q->el1.tcr_el1;
    r.observed_ttbr0_el1 = q->el1.ttbr0_el1;
    r.observed_ttbr1_el1 = q->el1.ttbr1_el1;
    if (q->el1.current_el != UINT64_C(4) ||
        (q->el1.sctlr_el1 & 1u))
        r.blockers |= M27_XG_B_EL1_MMU_STATE;
    if ((q->el1.sctlr_el1 & 1u) ||
        q->el1.instruction_va != q->entry_pa)
        r.blockers |= M27_XG_B_ALIAS_UNPROVEN;
    /* TTBR0/TTBR1 are recorded by caller but do not prove a TLB walk.
     * Under SCTLR.M=0 they do not translate the branch fetch.
     * Under M=1 the shim's 8GiB TTBR0 map cannot cover 0x8c3eb4480.
     * Stage-2 translation, R-X permissions, I-cache coherency and
     * Qualcomm XPUs are NEVER attested here; there is no execute grant. */
    r.physical_entry = M27_XG_ENTRY_PA;
    r.physical_brk_target = M27_XG_DEST_PA;
    r.structurally_plausible =
        (r.blockers & ~(M27_XG_B_EXECUTE_UNATTESTED |
                        M27_XG_B_RAM_OWNERSHIP_UNKNOWN |
                        M27_XG_B_BRK_EXCEPTION_UNKNOWN |
                        M27_XG_B_REGISTERS_UNATTESTED)) == 0;
    r.native_entry_allowed = 0;
    store_report(out, &r);
    return M27_XG_BLOCKED;
}
