/*
 * Synthetic portable CPU/PAC gate tests. Never invokes privileged reads.
 * Genuine saved device evidence is validated separately by Python runner.
 */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "../ports/macos27/cpu_compat_gate.h"

#define FIELD(n,s) ((uint64_t)(n) << (s))
#define ISAR1(a,i,g,h) (FIELD(a,4)|FIELD(i,8)|FIELD(g,24)|FIELD(h,28))
#define ISAR2(a,g) (FIELD(a,12)|FIELD(g,8))

static unsigned checks;
#define CHECK(x) do { checks++; assert(x); } while (0)
static struct mac27_cpu_sample cpu[8];
static uint64_t mids[8];
static struct mac27_cpu_result r;
static struct mac27_cpu_kc_target target;

static void reset_all(void)
{
    unsigned i;
    target.cputype = MAC27_CPU_MACH_ARM64;
    target.cpusubtype = 0xc0000002u;
    target.filetype = MAC27_CPU_KC_FILESET;
    target.darwin_major = 27;
    target.chained_fixup_format = MAC27_CPU_KC_FIXUP_AUTH64;
    target.verified_26A434_manifest = 1;
    for (i = 0; i < 8; ++i) {
        /* Synthetic "FDT-like" MPIDR: 0,0x100,...0x700; these do not
         * claim to be an observed register on a real dizi core. */
        mids[i] = (uint64_t)i << 8;
        cpu[i].mpidr_el1 = mids[i];
        cpu[i].id_aa64isar1_el1 = ISAR1(1,0,1,0);
        cpu[i].id_aa64isar2_el1 = 0;
        cpu[i].origin = MAC27_CPU_ORIGIN_DIRECT_EL1;
        cpu[i].isar1_observed = 1;
        cpu[i].isar2_observed = 1;
        cpu[i].reserved[0] = cpu[i].reserved[1] = 0;
    }
}

static enum mac27_cpu_block assess(void)
{
    CHECK(mac27_cpu_assess_26a434(&target, cpu, 8, mids, 8, &r) == 0);
    CHECK(r.native_mac27_ready == 0);
    return r.reason;
}

static void empty_and_bad_arguments(void)
{
    reset_all();
    CHECK(mac27_cpu_assess_26a434(&target, cpu, 8, mids, 8, NULL) == -1);
    CHECK(mac27_cpu_assess_26a434(NULL, cpu, 8, mids, 8, &r) == -1);
    CHECK(mac27_cpu_assess_26a434(&target, NULL, 8, mids, 8, &r) == -1);
    CHECK(mac27_cpu_assess_26a434(&target, cpu, 8, NULL, 8, &r) == -1);
    CHECK(mac27_cpu_assess_26a434(&target, cpu, 0, mids, 8, &r) == -1);
    CHECK(mac27_cpu_assess_26a434(&target, cpu, 8, mids, 0, &r) == -1);
    CHECK(mac27_cpu_assess_26a434(&target, cpu, 9, mids, 8, &r) == -1);
    CHECK(mac27_cpu_assess_26a434(&target, cpu, 8, mids, 9, &r) == -1);
    CHECK(r.native_mac27_ready == 0);
}

static void exact_kernel_abi(void)
{
    reset_all();
    CHECK(assess() == MAC27_CPU_ARCH_PAC_CANDIDATE_ONLY);
    CHECK(r.hardware_pac_candidate == 1);
    CHECK(r.inspected_count == 8);
    CHECK(r.address_algorithm == MAC27_CPU_PAC_QARMA5);
    CHECK(r.generic_algorithm == MAC27_CPU_PAC_QARMA5);
    target.cputype = 7; CHECK(assess() == MAC27_CPU_WRONG_KC);
    reset_all(); target.cpusubtype = 0xc0000001; CHECK(assess() == MAC27_CPU_WRONG_KC);
    reset_all(); target.cpusubtype = 0xc0000102; CHECK(assess() == MAC27_CPU_WRONG_KC);
    reset_all(); target.filetype = 2; CHECK(assess() == MAC27_CPU_WRONG_KC);
    reset_all(); target.darwin_major = 26; CHECK(assess() == MAC27_CPU_WRONG_KC);
    reset_all(); target.chained_fixup_format = 7; CHECK(assess() == MAC27_CPU_WRONG_KC);
    reset_all(); target.verified_26A434_manifest = 0; CHECK(assess() == MAC27_CPU_WRONG_KC);
    reset_all(); target.verified_26A434_manifest = 2; CHECK(assess() == MAC27_CPU_WRONG_KC);
}

static void registers_and_provenance(void)
{
    reset_all(); cpu[0].origin = MAC27_CPU_ORIGIN_NONE;
    CHECK(assess() == MAC27_CPU_NO_DIRECT_ISAR);
    reset_all(); cpu[0].origin = MAC27_CPU_ORIGIN_LINUX_FEATURES;
    CHECK(assess() == MAC27_CPU_NO_DIRECT_ISAR);
    reset_all(); cpu[0].origin = MAC27_CPU_ORIGIN_FDT;
    CHECK(assess() == MAC27_CPU_NO_DIRECT_ISAR);
    reset_all(); cpu[3].isar1_observed = 0;
    CHECK(assess() == MAC27_CPU_NO_DIRECT_ISAR); CHECK(r.first_failing_sample == 3);
    reset_all(); cpu[5].isar2_observed = 0;
    CHECK(assess() == MAC27_CPU_NO_DIRECT_ISAR); CHECK(r.first_failing_sample == 5);
    reset_all(); cpu[6].isar1_observed = 2;
    CHECK(assess() == MAC27_CPU_NO_DIRECT_ISAR);
    reset_all(); cpu[6].isar2_observed = 2;
    CHECK(assess() == MAC27_CPU_NO_DIRECT_ISAR);
    reset_all();
    CHECK(mac27_cpu_assess_26a434(&target, cpu, 7, mids, 8, &r) == 0);
    CHECK(r.reason == MAC27_CPU_INCOMPLETE_CPU_SET);
    reset_all(); cpu[1].mpidr_el1 = cpu[0].mpidr_el1;
    CHECK(assess() == MAC27_CPU_INCOMPLETE_CPU_SET);
    reset_all(); cpu[1].mpidr_el1 = UINT64_C(0x300000);
    CHECK(assess() == MAC27_CPU_INCOMPLETE_CPU_SET);
    reset_all(); mids[2] = mids[1];
    CHECK(assess() == MAC27_CPU_INCOMPLETE_CPU_SET);
    reset_all(); cpu[1].mpidr_el1 = UINT64_C(0x01000000) | mids[1];
    CHECK(assess() == MAC27_CPU_ARCH_PAC_CANDIDATE_ONLY);
}

static void precise_isar1_fields(void)
{
    unsigned v;
    reset_all();
    cpu[3].id_aa64isar1_el1 = 0;
    CHECK(assess() == MAC27_CPU_NO_ADDRESS_PAC); CHECK(r.first_failing_sample == 3);
    reset_all(); cpu[3].id_aa64isar1_el1 = FIELD(1,24);
    CHECK(assess() == MAC27_CPU_NO_ADDRESS_PAC);
    reset_all(); cpu[3].id_aa64isar1_el1 = FIELD(1,4);
    CHECK(assess() == MAC27_CPU_NO_GENERIC_PAC);
    reset_all(); cpu[3].id_aa64isar1_el1 = FIELD(1,8) | FIELD(1,28);
    CHECK(assess() == MAC27_CPU_MIXED_PAC_ALGORITHM);
    reset_all(); cpu[3].id_aa64isar1_el1 = FIELD(1,8) | FIELD(1,24);
    CHECK(assess() == MAC27_CPU_MIXED_PAC_ALGORITHM);
    reset_all(); cpu[3].id_aa64isar1_el1 = FIELD(1,4) | FIELD(1,28);
    CHECK(assess() == MAC27_CPU_MIXED_PAC_ALGORITHM);
    for (v = 7; v < 16; ++v) {
        reset_all(); cpu[0].id_aa64isar1_el1 = ISAR1(v,0,1,0);
        CHECK(assess() == MAC27_CPU_BAD_REGISTER_VALUE);
    }
    for (v = 2; v < 16; ++v) {
        reset_all(); cpu[0].id_aa64isar1_el1 = ISAR1(1,0,v,0);
        CHECK(assess() == MAC27_CPU_BAD_REGISTER_VALUE);
        reset_all(); cpu[0].id_aa64isar1_el1 = ISAR1(1,0,0,v);
        CHECK(assess() == MAC27_CPU_BAD_REGISTER_VALUE);
    }
    reset_all(); cpu[0].id_aa64isar1_el1 = ISAR1(1,1,1,0);
    CHECK(assess() == MAC27_CPU_BAD_REGISTER_VALUE);
    reset_all(); cpu[0].id_aa64isar1_el1 = ISAR1(1,0,1,1);
    CHECK(assess() == MAC27_CPU_BAD_REGISTER_VALUE);
}

static void isar2_families_and_multicore(void)
{
    unsigned i;
    reset_all();
    for (i = 0; i < 8; i++) {
        cpu[i].id_aa64isar1_el1 = 0;
        cpu[i].id_aa64isar2_el1 = ISAR2(1,1);
    }
    CHECK(assess() == MAC27_CPU_ARCH_PAC_CANDIDATE_ONLY);
    CHECK(r.address_algorithm == MAC27_CPU_PAC_QARMA3);
    reset_all(); cpu[0].id_aa64isar2_el1 = ISAR2(1,1);
    CHECK(assess() == MAC27_CPU_BAD_REGISTER_VALUE); /* APA vs APA3 */
    reset_all(); cpu[0].id_aa64isar1_el1 = ISAR1(1,0,0,0);
    cpu[0].id_aa64isar2_el1 = ISAR2(0,1);
    CHECK(assess() == MAC27_CPU_MIXED_PAC_ALGORITHM);
    reset_all(); cpu[0].id_aa64isar2_el1 = ISAR2(7,0);
    CHECK(assess() == MAC27_CPU_BAD_REGISTER_VALUE);
    reset_all(); cpu[0].id_aa64isar2_el1 = ISAR2(0,3);
    CHECK(assess() == MAC27_CPU_BAD_REGISTER_VALUE);
    reset_all(); cpu[7].id_aa64isar1_el1 = ISAR1(1,0,0,0);
    cpu[7].id_aa64isar2_el1 = ISAR2(0,1);
    CHECK(assess() == MAC27_CPU_MIXED_PAC_ALGORITHM);
    CHECK(r.first_failing_sample == 7);
}

static void x1_pauth_lr_and_optional_probe(void)
{
    unsigned i;
    reset_all();
    target.cpusubtype = 0x8000000cu;
    CHECK(assess() == MAC27_CPU_PAUTH_LR_UNPROVEN);
    for (i = 0; i < 8; i++)
        cpu[i].id_aa64isar1_el1 = ISAR1(6,0,1,0);
    CHECK(assess() == MAC27_CPU_ARCH_PAC_CANDIDATE_ONLY);
    reset_all();
    target.cpusubtype = 0x8000000cu;
    for (i = 0; i < 8; i++) {
        cpu[i].id_aa64isar1_el1 = 0;
        cpu[i].id_aa64isar2_el1 = ISAR2(6,1);
    }
    CHECK(assess() == MAC27_CPU_ARCH_PAC_CANDIDATE_ONLY);
    cpu[5].id_aa64isar2_el1 = ISAR2(5,1);
    CHECK(assess() == MAC27_CPU_PAUTH_LR_UNPROVEN);
    CHECK(mac27_cpu_read_el1_optional(NULL) == -1);
#if !defined(__aarch64__) || !defined(MAC27_CPU_ENABLE_EL1_READ)
    CHECK(mac27_cpu_read_el1_optional(&cpu[0]) == -1);
#endif
}

int main(void)
{
    empty_and_bad_arguments();
    exact_kernel_abi();
    registers_and_provenance();
    precise_isar1_fields();
    isar2_families_and_multicore();
    x1_pauth_lr_and_optional_probe();
    printf("PASS %u macOS27 PAC/ISAR1+ISAR2 synthetic assertions; native_ready=0\n", checks);
    return 0;
}
