/* Host-only adversarial test for source-grounded macOS27 entry guard.
 * The tested module never reads system registers, maps physical memory,
 * modifies an Apple KC or jumps to any executable Apple address.
 */
#include "../ports/macos27/entry_handoff_guard.h"
#include "../ports/macos27/boot_args.h"
#include "../ports/macos27/kc_loader.h"
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *load_regular(const char *name, size_t *extent)
{
    FILE *f = fopen(name, "rb");
    if (!f) return NULL;
    assert(fseek(f, 0, SEEK_END) == 0);
    long length = ftell(f);
    assert(length == M27_ENTRY_VMA2_BYTES);
    assert(fseek(f, 0, SEEK_SET) == 0);
    uint8_t *buf = malloc((size_t)length);
    assert(buf);
    assert(fread(buf, 1, (size_t)length, f) == (size_t)length);
    assert(fclose(f) == 0);
    *extent = (size_t)length;
    return buf;
}

static uint64_t up(uint64_t n)
{
    assert(n <= UINT64_MAX - 0x3fffu);
    return (n + 0x3fffu) & ~UINT64_C(0x3fff);
}

static void prepare(const uint8_t *kc, size_t bytes,
                    struct m27_entry_request *req, uint8_t *args)
{
    struct mac27_kc_plan plan;
    struct mac27_boot_params parameters = {0};
    assert(mac27_kc_plan(kc, bytes,
        M27_ENTRY_DIZI_PHYS, M27_ENTRY_DIZI_MEMORY, &plan) == MAC27_KC_OK);
    memset(req, 0, sizeof(*req));
    req->kc = kc;
    req->kc_bytes = bytes;
    req->phys_base = M27_ENTRY_DIZI_PHYS;
    req->phys_bytes = M27_ENTRY_DIZI_MEMORY;
    req->adt_pa = up(plan.kernel_end_pa);
    req->adt_bytes = 4096;
    req->boot_args_pa = up(req->adt_pa + req->adt_bytes);
    req->boot_args = args;
    req->boot_args_bytes = MAC27_BOOT_ARGS_SIZE;
    req->snapshot.origin = M27_ENTRY_OBSERVATION_DIRECT_EL1;
    req->snapshot.current_el = 4;
    req->snapshot.sctlr_el1 = 0;
    req->snapshot.id_aa64mmfr0_el1 = UINT64_C(1) << 20;
    req->snapshot.sp_pa = M27_ENTRY_DIZI_PHYS + UINT64_C(0xa0000000);
    req->snapshot.ttbr0_el1 = M27_ENTRY_DIZI_PHYS + UINT64_C(0x10000);
    req->snapshot.ttbr1_el1 = 0;
    req->snapshot.tcr_el1 = 0;
    parameters.virt_base = plan.virt_base;
    parameters.phys_base = M27_ENTRY_DIZI_PHYS;
    parameters.mem_size = parameters.mem_size_actual = M27_ENTRY_DIZI_MEMORY;
    parameters.top_of_kernel_data = req->boot_args_pa + M27_ENTRY_PAGE_SIZE;
    parameters.boot_args_pa = req->boot_args_pa;
    parameters.device_tree_pa = req->adt_pa;
    parameters.device_tree_length = req->adt_bytes;
    assert(mac27_encode_boot_args(args, MAC27_BOOT_ARGS_SIZE, &parameters) ==
           MAC27_ARGS_OK);
}

static void insist_blocked(const struct m27_entry_request *r,
                           enum m27_entry_status expectation)
{
    struct m27_entry_report result;
    memset(&result, 0x5a, sizeof(result));
    assert(m27_entry_handoff_analyze(r, &result) == expectation);
    assert(result.status == expectation);
    assert(result.native_jump_allowed == 0);
    assert(result.blockers & M27_ENTRY_B_HVC_VMAPPLE);
    assert(result.blockers & M27_ENTRY_B_ARM64E_PAC);
    assert(result.blockers & M27_ENTRY_B_TTBR0_LIFECYCLE);
    assert(result.blockers & M27_ENTRY_B_BOARD_IOKIT_PLATFORM);
    if (expectation != M27_ENTRY_ANALYZED_BLOCKED) {
        assert(!result.kernel_entry_pa && !result.bootstrap_pa);
        assert(!result.requested_boot_args_pa);
    } else {
        assert(result.kernel_entry_va == M27_ENTRY_VMAPPLE_ENTRY_VA);
        assert(result.bootstrap_va == M27_ENTRY_VMAPPLE_BOOT_VA);
        assert(result.bootstrap_pa > result.kernel_entry_pa);
        assert(result.requested_boot_args_pa == r->boot_args_pa);
        assert(result.vmapple_hvc_x0 == M27_ENTRY_VMAPPLE_HVC_X0);
        assert(result.file_sets == 216);
        assert(result.fixup_auth_pointers > 0);
    }
}

static void test_negative_without_kc(void)
{
    uint8_t dummy[512] = {0};
    struct m27_entry_report out = {0};
    struct m27_entry_request req = {0};
    req.kc = dummy; req.kc_bytes = sizeof(dummy);
    req.boot_args = dummy; req.boot_args_bytes = sizeof(dummy);
    req.phys_base = M27_ENTRY_DIZI_PHYS;
    req.phys_bytes = M27_ENTRY_DIZI_MEMORY;
    insist_blocked(&req, M27_ENTRY_BAD_ARGUMENT);
    assert(!m27_entry_match_vma2_bootstrap(NULL, 0, &out));
    assert(!m27_entry_match_vma2_bootstrap(dummy, sizeof(dummy), &out));
    assert(m27_entry_handoff_analyze(NULL, &out) == M27_ENTRY_BAD_ARGUMENT);
    assert(m27_entry_handoff_analyze(&req, NULL) == M27_ENTRY_BAD_ARGUMENT);
    assert(m27_entry_handoff_analyze(&req, (struct m27_entry_report *)(void *)&req) ==
           M27_ENTRY_BAD_ARGUMENT);
    req.kc_bytes = M27_ENTRY_VMA2_BYTES;
    req.boot_args = NULL;
    insist_blocked(&req, M27_ENTRY_BAD_ARGUMENT);
    puts("PASS no-KC negative, unsafe alias, short buffer, absent input refused");
}

static void test_real(const char *filename)
{
    size_t length = 0;
    uint8_t *kc = load_regular(filename, &length);
    assert(kc && length == M27_ENTRY_VMA2_BYTES);
    uint8_t bootargs[MAC27_BOOT_ARGS_SIZE], duplicate[MAC27_BOOT_ARGS_SIZE];
    struct m27_entry_request r, baseline;
    struct m27_entry_report result;
    prepare(kc, length, &r, bootargs);
    baseline = r;
    memcpy(duplicate, bootargs, sizeof(duplicate));

    insist_blocked(&r, M27_ENTRY_ANALYZED_BLOCKED);
    assert(m27_entry_handoff_analyze(&r, &result) == M27_ENTRY_ANALYZED_BLOCKED);
    assert(result.blockers == M27_ENTRY_ALWAYS_BLOCKED);
    assert(!result.native_jump_allowed);
    assert(m27_entry_handoff_analyze(&baseline, &result) ==
           M27_ENTRY_ANALYZED_BLOCKED);
    assert(m27_entry_match_vma2_bootstrap(kc, length, &result));
    assert(result.kernel_entry_pa == M27_ENTRY_DIZI_PHYS +
        (M27_ENTRY_VMAPPLE_ENTRY_VA - result.virt_base));
    assert(result.bootstrap_pa == M27_ENTRY_DIZI_PHYS +
        (M27_ENTRY_VMAPPLE_BOOT_VA - result.virt_base));
    puts("PASS real 26A434 entry machine words: x20 bootargs, TTBR1/TCR, "
         "HVC before SCTLR, PAC autda; never execute");

    r.snapshot.origin = M27_ENTRY_OBSERVATION_LEGACY_LOG;
    assert(m27_entry_handoff_analyze(&r, &result) == M27_ENTRY_ANALYZED_BLOCKED);
    assert(result.blockers & M27_ENTRY_B_EL1_STATE);
    r = baseline;
    r.snapshot.sctlr_el1 = 1; insist_blocked(&r, M27_ENTRY_BAD_REGISTERS);
    r = baseline;
    r.snapshot.current_el = 8; insist_blocked(&r, M27_ENTRY_BAD_REGISTERS);
    r = baseline;
    r.snapshot.id_aa64mmfr0_el1 = 0; insist_blocked(&r, M27_ENTRY_BAD_REGISTERS);
    r = baseline;
    r.snapshot.sp_pa = 0; insist_blocked(&r, M27_ENTRY_BAD_REGISTERS);
    r = baseline;
    r.snapshot.sp_pa++; insist_blocked(&r, M27_ENTRY_BAD_REGISTERS);
    r = baseline;
    r.snapshot.ttbr0_el1 = UINT64_MAX;
    r.snapshot.ttbr1_el1 = UINT64_MAX;
    insist_blocked(&r, M27_ENTRY_ANALYZED_BLOCKED);
    assert(result.native_jump_allowed == 0);

    r = baseline;
    r.boot_args_bytes = 736;
    insist_blocked(&r, M27_ENTRY_BAD_BOOT_ARGS);
    r = baseline;
    memcpy(duplicate, bootargs, sizeof(duplicate));
    duplicate[0] = 0;
    r.boot_args = duplicate;
    insist_blocked(&r, M27_ENTRY_BAD_BOOT_ARGS);
    r = baseline;
    memcpy(duplicate, bootargs, sizeof(duplicate));
    duplicate[8] ^= 1;
    r.boot_args = duplicate;
    insist_blocked(&r, M27_ENTRY_BAD_MEMORY_LAYOUT);
    r = baseline;
    memcpy(duplicate, bootargs, sizeof(duplicate));
    duplicate[0x470] = 0xff; /* unknown flags are not boot authority */
    r.boot_args = duplicate;
    insist_blocked(&r, M27_ENTRY_ANALYZED_BLOCKED);
    r = baseline;
    r.adt_pa = r.boot_args_pa; insist_blocked(&r, M27_ENTRY_BAD_MEMORY_LAYOUT);
    r = baseline;
    r.adt_pa = UINT64_MAX - 0x3fff;
    insist_blocked(&r, M27_ENTRY_BAD_MEMORY_LAYOUT);
    r = baseline;
    r.boot_args_pa++;
    insist_blocked(&r, M27_ENTRY_BAD_BOOT_ARGS);
    r = baseline;
    r.phys_base += 0x4000;
    insist_blocked(&r, M27_ENTRY_BAD_ARGUMENT);
    r = baseline;
    r.phys_bytes = 0;
    insist_blocked(&r, M27_ENTRY_BAD_ARGUMENT);
    r = baseline;
    r.kc_bytes--;
    insist_blocked(&r, M27_ENTRY_BAD_ARGUMENT);

    /* Check each observed instruction independently and restore each byte.
     * The bytes are in the PRIVATE host copy, never the Apple source file. */
    static const uint32_t offsets[] = {
        48956544, 48971888, 48971892, 48971896, 48971916, 48971920,
        48971924, 48971932, 48972464, 48972492, 48972620, 48972624,
        48972648, 48972856
    };
    for (size_t i = 0; i < sizeof(offsets)/sizeof(offsets[0]); i++) {
        unsigned n = offsets[i];
        kc[n] ^= 0x1;
        insist_blocked(&baseline, M27_ENTRY_WRONG_MACHINE_CODE);
        kc[n] ^= 0x1;
    }
    assert(m27_entry_match_vma2_bootstrap(kc, length, &result));

    /* 120k deterministic attempts to promote caller data to boot authority.
     * Snapshot origin, values, and stored result bits are untrusted. */
    uint32_t seed = 0x26a43473u;
    for (unsigned i = 0; i < 120000; i++) {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        result.native_jump_allowed = seed | 1u;
        result.blockers = 0;
        assert(m27_entry_match_vma2_bootstrap(kc, length, &result));
        /* Metadata-only predicate cannot mutate prior result or authorize
         * handoff. The re-entrant analyze path reinitializes its result. */
        if ((i & 0xfffu) == 0) {
            assert(m27_entry_handoff_analyze(&baseline, &result) ==
                M27_ENTRY_ANALYZED_BLOCKED);
            assert(!result.native_jump_allowed);
            assert(result.blockers & M27_ENTRY_B_HVC_VMAPPLE);
        }
    }
    puts("PASS host 120k spoofed report attempts, 14 instruction tamper "
         "mutations, malformed layouts/registers, always fail closed");
    free(kc);
}

int main(int argc, char **argv)
{
    test_negative_without_kc();
    if (argc > 1) test_real(argv[1]);
    else puts("SKIP private 26A434 genuine KC absent: no synthetic boot success");
    puts("PASS 26A434 entry handoff source preflight; no Apple code execution");
    return 0;
}
