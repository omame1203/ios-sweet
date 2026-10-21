/* SPDX-License-Identifier: MIT
 * Strict, DEFAULT-DISABLED 26A434 first-B instruction experiment.
 * A BRK installed at the genuine B target prevents execution of the first
 * privileged XNU bootstrap MSR OSLAR_EL1. SHA256 matches the original pinned
 * 81,444,864-byte decompressed VMAPPLE raw MH_FILESET, not IMG4 trust.
 */
#include "macos27_entry_experiment.h"

#if defined(__aarch64__) && \
    defined(DIZI_MACOS27_XNU_ENTRY_EXPERIMENT) && DIZI_MACOS27_XNU_ENTRY_EXPERIMENT == 1 && \
    defined(MAC27_ENTRY_EXPERIMENT_HANDLER_WIRED) && MAC27_ENTRY_EXPERIMENT_HANDLER_WIRED == 1
#define MAC27_EXPERIMENT_NATIVE 1
#else
#define MAC27_EXPERIMENT_NATIVE 0
#endif

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int inside(uint64_t base, uint64_t total, uint64_t p, uint64_t bytes)
{
    return total && total <= UINT64_MAX - base && p >= base &&
           p - base <= total && bytes <= total - (p - base);
}

static int disjoint(const void *a, size_t an, const void *b, size_t bn)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    if (x > UINTPTR_MAX - an || y > UINTPTR_MAX - bn) return 0;
    return !(an && bn && x < y + bn && y < x + an);
}

int mac27_entry_experiment_validate(const struct mac27_entry_experiment_request *r)
{
    if (!r || r->explicit_request != 1 || !r->original_kc || !r->copy ||
        r->original_bytes != MAC27_EXPERIMENT_KC_SIZE ||
        r->copy_capacity < MAC27_EXPERIMENT_KC_SIZE ||
        r->exclusive_ram_verified != 1 || r->write_exec_verified != 1 ||
        r->single_cpu_vectors_verified != 1 ||
        !inside(MAC27_EXPERIMENT_DIZI_BASE, MAC27_EXPERIMENT_DIZI_SIZE,
                r->owned_pa, r->owned_bytes) ||
        !inside(r->owned_pa, r->owned_bytes, r->copy_pa,
                MAC27_EXPERIMENT_KC_SIZE) ||
        (r->copy_pa & (MAC27_EXPERIMENT_PAGE - 1)) ||
        !disjoint(r->original_kc, r->original_bytes,
                  r->copy, MAC27_EXPERIMENT_KC_SIZE) ||
        !disjoint(r->original_kc, r->original_bytes, r, sizeof(*r)) ||
        !disjoint(r->copy, MAC27_EXPERIMENT_KC_SIZE, r, sizeof(*r)))
        return 0;
    /* The original KC is unmodified at both tested sites. A separate FULL
     * pinned SHA256 is ALWAYS checked immediately before copying in run(). */
    const uint8_t *kc = (const uint8_t *)r->original_kc;
    if (le32(kc + MAC27_EXPERIMENT_ENTRY_OFFSET) != MAC27_EXPERIMENT_BRANCH ||
        le32(kc + MAC27_EXPERIMENT_TARGET_OFFSET) != MAC27_EXPERIMENT_ORIGINAL_TARGET)
        return 0;
    if (!r->boot_args_pa)
        return !r->boot_args && !r->boot_args_bytes && !r->boot_args_verified;
    if (!r->boot_args || r->boot_args_bytes != 1152 ||
        r->boot_args_verified != 1 || (r->boot_args_pa & 7) ||
        !inside(r->owned_pa, r->owned_bytes, r->boot_args_pa, 1152) ||
        !disjoint(r->boot_args, 1152, r->copy, MAC27_EXPERIMENT_KC_SIZE) ||
        !disjoint(r->boot_args, 1152, r, sizeof(*r)) ||
        !(r->boot_args_pa < r->copy_pa ||
          r->boot_args_pa - r->copy_pa >= MAC27_EXPERIMENT_KC_SIZE))
        return 0;
    /* x0's boot_args must be an externally verified exact 1152-byte image;
     * first Apple B neither dereferences nor mutates this pointer. */
    return 1;
}

int mac27_entry_experiment_match_brk(struct mac27_entry_experiment_trap *p,
                                    uint64_t slot, uint64_t esr, uint64_t elr,
                                    uint64_t *resume_pc)
{
    if (!p || !resume_pc || slot != 4 ||
        esr != MAC27_EXPERIMENT_ESR || p->armed != 1 || p->hit ||
        !p->entry_pc || (p->entry_pc & 3) ||
        p->entry_pc > UINT64_MAX - (MAC27_EXPERIMENT_TARGET_OFFSET - MAC27_EXPERIMENT_ENTRY_OFFSET) ||
        p->target_pc != p->entry_pc +
                        (MAC27_EXPERIMENT_TARGET_OFFSET - MAC27_EXPERIMENT_ENTRY_OFFSET) ||
        (p->target_pc & 3) || p->target_pc != elr ||
        !p->resume_pc || (p->resume_pc & 3) ||
        p->resume_pc == p->entry_pc || p->resume_pc == p->target_pc)
        return 0;
    /* On this precise synchronous EL1 BRK64, the kernel has executed one
     * Apple instruction: original B +0x3bf0. BRK is ours, not Apple's.
     * No replay of the BRK, no OSLAR, HVC, PAC, or native boot success. */
    *resume_pc = p->resume_pc;
    p->hit = 1;
    p->armed = 0;
    return 1;
}

/* Standalone SHA-256 (FIPS 180-4): no libc, malloc or source modifications.
 * In particular the digest is measured over ALL source bytes, not merely
 * the observed B/OSLAR words which a synthetic KC can trivially counterfeit.
 */
static const uint32_t sha_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static uint32_t rr(uint32_t v, unsigned n)
{ return (v >> n) | (v << (32 - n)); }

static void sha_block(uint32_t h[8], const uint8_t b[64])
{
    uint32_t w[64], a, c, d, e, f, g, z, j;
    for (unsigned i = 0; i < 16; ++i) {
        const uint8_t *p = b + 4 * i;
        w[i] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
               (uint32_t)p[2] << 8 | p[3];
    }
    for (unsigned i = 16; i < 64; ++i)
        w[i] = w[i - 16] + (rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >> 3)) +
               w[i - 7] + (rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >> 10));
    a = h[0]; c = h[1]; d = h[2]; e = h[3];
    f = h[4]; g = h[5]; z = h[6]; j = h[7];
    for (unsigned i = 0; i < 64; ++i) {
        uint32_t t1 = j + (rr(f, 6) ^ rr(f, 11) ^ rr(f, 25)) +
                      ((f & g) ^ (~f & z)) + sha_k[i] + w[i];
        uint32_t t2 = (rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) +
                      ((a & c) ^ (a & d) ^ (c & d));
        j = z; z = g; g = f; f = e + t1;
        e = d; d = c; c = a; a = t1 + t2;
    }
    h[0] += a; h[1] += c; h[2] += d; h[3] += e;
    h[4] += f; h[5] += g; h[6] += z; h[7] += j;
}

void mac27_entry_experiment_sha256(const void *data, size_t size, uint8_t out[32])
{
    static const uint32_t init[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    uint32_t h[8];
    uint8_t tail[128];
    if (!out) return;
    for (unsigned i = 0; i < 32; ++i) out[i] = 0;
    if ((!data && size) || (uint64_t)size > UINT64_MAX / 8) return;
    for (unsigned i = 0; i < 8; ++i) h[i] = init[i];
    const uint8_t *p = (const uint8_t *)data;
    size_t full = size & ~(size_t)63;
    for (size_t off = 0; off < full; off += 64) sha_block(h, p + off);
    size_t remain = size - full;
    for (unsigned i = 0; i < 128; ++i) tail[i] = 0;
    for (size_t i = 0; i < remain; ++i) tail[i] = p[full + i];
    tail[remain] = 0x80;
    size_t padded = remain + 1 + 8 <= 64 ? 64 : 128;
    uint64_t bits = (uint64_t)size * 8;
    for (unsigned i = 0; i < 8; ++i) tail[padded - 1 - i] = (uint8_t)(bits >> (i * 8));
    sha_block(h, tail);
    if (padded == 128) sha_block(h, tail + 64);
    for (unsigned i = 0; i < 8; ++i)
        for (unsigned j2 = 0; j2 < 4; ++j2)
            out[4 * i + j2] = (uint8_t)(h[i] >> (24 - 8 * j2));
}

#if MAC27_EXPERIMENT_NATIVE
extern uint8_t vectors[];
extern uint8_t mac27_entry_experiment_resume[];
extern unsigned mac27_entry_experiment_trampoline(uint64_t bootargs, uint64_t entry_pc);
static struct mac27_entry_experiment_trap active_trap;

static uint64_t reg_current_el(void)
{ uint64_t v; __asm__ volatile ("mrs %0, CurrentEL" : "=r"(v)); return v; }
static uint64_t reg_sctlr(void)
{ uint64_t v; __asm__ volatile ("mrs %0, SCTLR_EL1" : "=r"(v)); return v; }
static uint64_t reg_vbar(void)
{ uint64_t v; __asm__ volatile ("mrs %0, VBAR_EL1" : "=r"(v)); return v; }
static uint64_t reg_daif(void)
{ uint64_t v; __asm__ volatile ("mrs %0, DAIF" : "=r"(v)); return v; }
static uint64_t reg_spsel(void)
{ uint64_t v; __asm__ volatile ("mrs %0, SPSel" : "=r"(v)); return v; }

static void synchronize_instruction(uint64_t entry_pc, uint64_t target_pc)
{
    uint64_t ctr, line;
    __asm__ volatile ("mrs %0, CTR_EL0" : "=r"(ctr));
    line = UINT64_C(4) << ((ctr >> 16) & 15);
    uint64_t a = entry_pc & ~(line - 1), b = target_pc & ~(line - 1);
    __asm__ volatile ("dc cvau, %0" : : "r"(a) : "memory");
    if (b != a) __asm__ volatile ("dc cvau, %0" : : "r"(b) : "memory");
    __asm__ volatile ("dsb ish" ::: "memory");
    __asm__ volatile ("ic ivau, %0" : : "r"(a) : "memory");
    if (b != a) __asm__ volatile ("ic ivau, %0" : : "r"(b) : "memory");
    __asm__ volatile ("dsb ish; isb" ::: "memory");
}

int mac27_entry_experiment_exc_handler(uint64_t slot, uint64_t *regs)
{
    uint64_t esr, elr, resume = 0;
    if (slot != 4 || !regs || active_trap.armed != 1) return 0;
    __asm__ volatile ("mrs %0, ESR_EL1" : "=r"(esr));
    __asm__ volatile ("mrs %0, ELR_EL1" : "=r"(elr));
    if (!mac27_entry_experiment_match_brk(&active_trap, slot, esr, elr, &resume))
        return 0;
    __asm__ volatile ("msr ELR_EL1, %0; isb" : : "r"(resume) : "memory");
    return 1;
}

enum mac27_entry_experiment_status mac27_entry_experiment_run(
    const struct mac27_entry_experiment_request *r)
{
    static const uint8_t pinned[32] = {
        0xca,0x55,0xea,0x8c,0x4c,0x86,0x17,0x0e,
        0x87,0x03,0x80,0xae,0x55,0x01,0xb8,0xb4,
        0x3a,0xdb,0x2d,0x2d,0x3d,0xb2,0x8b,0xe4,
        0x53,0x1b,0x30,0x40,0x65,0x3b,0xe2,0x03
    };
    uint8_t digest[32];
    if (!r || r->explicit_request != 1) return MAC27_EXP_DISABLED;
    if (!mac27_entry_experiment_validate(r)) return MAC27_EXP_BAD_INPUT;
    if (active_trap.armed || active_trap.hit) return MAC27_EXP_BUSY;
    /* Make all memory references and the BR X1 actual PA references. The
     * existing shim 16K TTBR0 only covers low 8GiB and is NOT applicable. */
    if ((uint64_t)(uintptr_t)r->copy != r->copy_pa ||
        (r->boot_args_pa && (uint64_t)(uintptr_t)r->boot_args != r->boot_args_pa))
        return MAC27_EXP_NOT_OWNED;
    /* MMU and caches off, EL1h, VBAR on original known EL1 exception table,
     * all DAIF masked. The caller needs additional genuine FDT/PA/execution
     * rights attestation; these simple register checks cannot replace it. */
    if (reg_current_el() != 4 || reg_spsel() != 1 ||
        (reg_daif() & UINT64_C(0x3c0)) != UINT64_C(0x3c0) ||
        reg_vbar() != (uint64_t)(uintptr_t)vectors ||
        (reg_sctlr() & UINT64_C(0x1005)) != 0)
        return MAC27_EXP_BAD_EL1;
    mac27_entry_experiment_sha256(r->original_kc, r->original_bytes, digest);
    uint32_t diff = 0;
    for (unsigned i = 0; i < 32; ++i) diff |= digest[i] ^ pinned[i];
    if (diff) return MAC27_EXP_WRONG_KC;
    /* Pinned original was fully read BEFORE writes. Rehash the exact raw
     * copy before BRK patch to detect corrupt/stale or transient transfers. */
    const uint8_t *src = (const uint8_t *)r->original_kc;
    volatile uint8_t *dst = (volatile uint8_t *)r->copy;
    for (size_t i = 0; i < r->original_bytes; ++i) dst[i] = src[i];
    mac27_entry_experiment_sha256(r->copy, r->original_bytes, digest);
    diff = 0;
    for (unsigned i = 0; i < 32; ++i) diff |= digest[i] ^ pinned[i];
    if (diff) return MAC27_EXP_WRONG_KC;
    /* Once the copy's original bootstrap has been confirmed, prevent any
     * execution of OSLAR by inserting our private immediate BRK. */
    uint64_t entry = r->copy_pa + MAC27_EXPERIMENT_ENTRY_OFFSET;
    uint64_t target = r->copy_pa + MAC27_EXPERIMENT_TARGET_OFFSET;
    volatile uint32_t *bootstrap = (volatile uint32_t *)(uintptr_t)target;
    if (*bootstrap != MAC27_EXPERIMENT_ORIGINAL_TARGET) return MAC27_EXP_WRONG_KC;
    *bootstrap = MAC27_EXPERIMENT_BRK_WORD;
    __asm__ volatile ("dsb sy" ::: "memory");
    if (*bootstrap != MAC27_EXPERIMENT_BRK_WORD ||
        le32((const uint8_t *)(uintptr_t)entry) != MAC27_EXPERIMENT_BRANCH)
        return MAC27_EXP_WRONG_KC;
    synchronize_instruction(entry, target);
    active_trap.entry_pc = entry;
    active_trap.target_pc = target;
    active_trap.resume_pc = (uint64_t)(uintptr_t)mac27_entry_experiment_resume;
    active_trap.hit = 0;
    __asm__ volatile ("dsb sy" ::: "memory");
    active_trap.armed = 1;
    __asm__ volatile ("dsb sy; isb" ::: "memory");
    unsigned resumed = mac27_entry_experiment_trampoline(r->boot_args_pa, entry);
    active_trap.armed = 0;
    if (resumed != 1 || active_trap.hit != 1) return MAC27_EXP_TRAP_NOT_SEEN;
    /* The only positive evidence is the exact BRK syndrome/ELR after ONE
     * original 26A434 entry B instruction. No native XNU boot happened. */
    return MAC27_EXP_TRAPPED_ONE_B;
}

#else
int mac27_entry_experiment_exc_handler(uint64_t slot, uint64_t *regs)
{
    (void)slot; (void)regs;
    return 0;
}

enum mac27_entry_experiment_status mac27_entry_experiment_run(
    const struct mac27_entry_experiment_request *r)
{
    (void)r;
    return MAC27_EXP_DISABLED;
}
#endif
