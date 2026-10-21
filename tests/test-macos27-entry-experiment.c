/* Host-only proof of structural rejection and strict, one-shot BRK match.
 * No AArch64 code execution, no physical memory, no boot image or device.
 */
#include "../shim/macos27_entry_experiment.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *source, *copy;
static struct mac27_entry_experiment_request r;

static void word(uint8_t *p, size_t offset, uint32_t w)
{
    for (unsigned i = 0; i < 4; ++i) p[offset + i] = (uint8_t)(w >> (8 * i));
}

static void vectors(void)
{
    uint8_t digest[32];
    static const uint8_t empty[32] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    };
    static const uint8_t abc[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    static const uint8_t million_a[32] = {
        0xcd,0xc7,0x6e,0x5c,0x99,0x14,0xfb,0x92,0x81,0xa1,0xc7,0xe2,0x84,0xd7,0x3e,0x67,
        0xf1,0x80,0x9a,0x48,0xa4,0x97,0x20,0x0e,0x04,0x6d,0x39,0xcc,0xc7,0x11,0x2c,0xd0
    };
    mac27_entry_experiment_sha256(NULL, 0, digest);
    assert(!memcmp(digest, empty, 32));
    mac27_entry_experiment_sha256("abc", 3, digest);
    assert(!memcmp(digest, abc, 32));
    uint8_t *a = malloc(1000000);
    assert(a);
    memset(a, 'a', 1000000);
    mac27_entry_experiment_sha256(a, 1000000, digest);
    assert(!memcmp(digest, million_a, 32));
    free(a);
}

static void init(void)
{
    source = calloc(1, MAC27_EXPERIMENT_KC_SIZE);
    copy = malloc(MAC27_EXPERIMENT_KC_SIZE);
    assert(source && copy);
    word(source, MAC27_EXPERIMENT_ENTRY_OFFSET, MAC27_EXPERIMENT_BRANCH);
    word(source, MAC27_EXPERIMENT_TARGET_OFFSET, MAC27_EXPERIMENT_ORIGINAL_TARGET);
    memset(&r, 0, sizeof(r));
    r.original_kc = source;
    r.original_bytes = MAC27_EXPERIMENT_KC_SIZE;
    r.copy = copy;
    r.copy_capacity = MAC27_EXPERIMENT_KC_SIZE;
    r.copy_pa = MAC27_EXPERIMENT_DIZI_BASE + MAC27_EXPERIMENT_PAGE;
    r.owned_pa = MAC27_EXPERIMENT_DIZI_BASE;
    r.owned_bytes = MAC27_EXPERIMENT_DIZI_SIZE;
    r.explicit_request = 1;
    r.exclusive_ram_verified = 1;
    r.write_exec_verified = 1;
    r.single_cpu_vectors_verified = 1;
}

static void structural(void)
{
    init();
    assert(MAC27_EXPERIMENT_TARGET_OFFSET - MAC27_EXPERIMENT_ENTRY_OFFSET == 0x3bf0);
    assert(MAC27_EXPERIMENT_BRK_WORD == (0xd4200000U | (0x4e27U << 5)));
    assert(mac27_entry_experiment_validate(&r) == 1);
    assert(mac27_entry_experiment_run(&r) == MAC27_EXP_DISABLED); /* host disabled */

    struct mac27_entry_experiment_request t = r;
    t.explicit_request = 2; assert(!mac27_entry_experiment_validate(&t));
    t = r; t.exclusive_ram_verified = 0; assert(!mac27_entry_experiment_validate(&t));
    t = r; t.write_exec_verified = 0; assert(!mac27_entry_experiment_validate(&t));
    t = r; t.single_cpu_vectors_verified = 0; assert(!mac27_entry_experiment_validate(&t));
    t = r; t.original_bytes--; assert(!mac27_entry_experiment_validate(&t));
    t = r; t.copy_capacity--; assert(!mac27_entry_experiment_validate(&t));
    t = r; t.copy_pa++; assert(!mac27_entry_experiment_validate(&t));
    t = r; t.copy_pa = MAC27_EXPERIMENT_DIZI_BASE - MAC27_EXPERIMENT_PAGE;
    assert(!mac27_entry_experiment_validate(&t));
    t = r; t.copy_pa = MAC27_EXPERIMENT_DIZI_BASE + MAC27_EXPERIMENT_DIZI_SIZE;
    assert(!mac27_entry_experiment_validate(&t));
    t = r; t.owned_pa = MAC27_EXPERIMENT_DIZI_BASE + MAC27_EXPERIMENT_DIZI_SIZE;
    assert(!mac27_entry_experiment_validate(&t));
    t = r; t.owned_bytes = UINT64_MAX; assert(!mac27_entry_experiment_validate(&t));
    t = r; t.copy = source; assert(!mac27_entry_experiment_validate(&t));
    t = r; t.boot_args_verified = 1; assert(!mac27_entry_experiment_validate(&t));
    t = r; t.boot_args_pa = r.copy_pa + MAC27_EXPERIMENT_PAGE;
    assert(!mac27_entry_experiment_validate(&t));
    t = r; t.boot_args_pa = r.copy_pa + MAC27_EXPERIMENT_PAGE;
    t.boot_args = copy; t.boot_args_bytes = 1152; t.boot_args_verified = 1;
    assert(!mac27_entry_experiment_validate(&t));
    t = r; t.boot_args_pa = r.copy_pa + MAC27_EXPERIMENT_KC_SIZE + MAC27_EXPERIMENT_PAGE;
    t.boot_args = source + 16; t.boot_args_bytes = 1152; t.boot_args_verified = 1;
    assert(mac27_entry_experiment_validate(&t));
    t.boot_args_bytes = 736; assert(!mac27_entry_experiment_validate(&t));
    t = r; t.original_kc = NULL; assert(!mac27_entry_experiment_validate(&t));
    t = r; t.original_kc = copy; assert(!mac27_entry_experiment_validate(&t));
    word(source, MAC27_EXPERIMENT_ENTRY_OFFSET, MAC27_EXPERIMENT_BRANCH ^ 1);
    assert(!mac27_entry_experiment_validate(&r));
    word(source, MAC27_EXPERIMENT_ENTRY_OFFSET, MAC27_EXPERIMENT_BRANCH);
    word(source, MAC27_EXPERIMENT_TARGET_OFFSET, MAC27_EXPERIMENT_ORIGINAL_TARGET ^ 1);
    assert(!mac27_entry_experiment_validate(&r));
    word(source, MAC27_EXPERIMENT_TARGET_OFFSET, MAC27_EXPERIMENT_ORIGINAL_TARGET);
    assert(mac27_entry_experiment_validate(&r));
    free(source);
    free(copy);
}

static void traps(void)
{
    struct mac27_entry_experiment_trap p = {
        .entry_pc = MAC27_EXPERIMENT_DIZI_BASE + MAC27_EXPERIMENT_PAGE + MAC27_EXPERIMENT_ENTRY_OFFSET,
        .target_pc = MAC27_EXPERIMENT_DIZI_BASE + MAC27_EXPERIMENT_PAGE + MAC27_EXPERIMENT_TARGET_OFFSET,
        .resume_pc = 0x14004, .armed = 1
    }, t;
    uint64_t resume = UINT64_C(0xbaadbaad);
    t = p;
    assert(!mac27_entry_experiment_match_brk(&p, 5, MAC27_EXPERIMENT_ESR, p.target_pc, &resume));
    assert(!memcmp(&t, &p, sizeof p) && resume == UINT64_C(0xbaadbaad));
    assert(!mac27_entry_experiment_match_brk(&p, 0, MAC27_EXPERIMENT_ESR, p.target_pc, &resume));
    assert(!mac27_entry_experiment_match_brk(&p, 4, MAC27_EXPERIMENT_ESR ^ 1, p.target_pc, &resume));
    assert(!mac27_entry_experiment_match_brk(&p, 4, MAC27_EXPERIMENT_ESR ^ (1ULL << 25), p.target_pc, &resume));
    assert(!mac27_entry_experiment_match_brk(&p, 4, MAC27_EXPERIMENT_ESR, p.entry_pc, &resume));
    assert(!mac27_entry_experiment_match_brk(&p, 4, MAC27_EXPERIMENT_ESR, p.target_pc + 4, &resume));
    assert(!mac27_entry_experiment_match_brk(&p, 4, MAC27_EXPERIMENT_ESR, p.target_pc, NULL));
    assert(!memcmp(&t, &p, sizeof p) && resume == UINT64_C(0xbaadbaad));
    t = p; t.target_pc += 4;
    assert(!mac27_entry_experiment_match_brk(&t, 4, MAC27_EXPERIMENT_ESR, p.target_pc, &resume));
    t = p; t.resume_pc = t.target_pc;
    assert(!mac27_entry_experiment_match_brk(&t, 4, MAC27_EXPERIMENT_ESR, p.target_pc, &resume));
    t = p; t.entry_pc = UINT64_MAX - 3;
    assert(!mac27_entry_experiment_match_brk(&t, 4, MAC27_EXPERIMENT_ESR, p.target_pc, &resume));
    assert(mac27_entry_experiment_match_brk(&p, 4, MAC27_EXPERIMENT_ESR, p.target_pc, &resume));
    assert(resume == 0x14004 && p.armed == 0 && p.hit == 1);
    assert(!mac27_entry_experiment_match_brk(&p, 4, MAC27_EXPERIMENT_ESR, p.target_pc, &resume));
    assert(mac27_entry_experiment_exc_handler(4, NULL) == 0); /* host disabled */
}

int main(void)
{
    vectors(); structural(); traps();
    puts("PASS macOS27 single-B experiment: SHA256 vectors, fail-closed ownership, exact BRK64/ELR and one-shot recovery; NO device XNU instruction");
    return 0;
}
