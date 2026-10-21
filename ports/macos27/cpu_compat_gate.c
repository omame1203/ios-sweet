#include "cpu_compat_gate.h"

#define NIBBLE(v, shift) ((unsigned)(((v) >> (shift)) & UINT64_C(15)))

static void clear_result(struct mac27_cpu_result *r)
{
    r->reason = MAC27_CPU_BAD_ARGUMENT;
    r->address_algorithm = MAC27_CPU_PAC_NONE;
    r->generic_algorithm = MAC27_CPU_PAC_NONE;
    r->first_failing_sample = 0;
    r->inspected_count = 0;
    r->hardware_pac_candidate = 0;
    r->native_mac27_ready = 0;
}

static int bad_pac_field(unsigned apa, unsigned api, unsigned gpa,
                         unsigned gpi, unsigned apa3, unsigned gpa3)
{
    /* Architected registers provide 4-bit ENCODINGS, not bit flags.
     * Value 0 = absent; 1..6 address-PAC revisions, generic-PAC only 1.
     * Fields > these known values are reserved, not "greater support".
     * Algorithm variants on the same address or generic channel are
     * mutually exclusive per the ARM register definitions. */
    return apa > 6 || api > 6 || apa3 > 6 || gpa > 1 || gpi > 1 ||
           gpa3 > 1 || (apa && (api || apa3)) || (api && apa3) ||
           (gpa && (gpi || gpa3)) || (gpi && gpa3);
}

static enum mac27_cpu_algorithm addr_alg(unsigned apa, unsigned api, unsigned apa3)
{
    if (apa) return MAC27_CPU_PAC_QARMA5;
    if (apa3) return MAC27_CPU_PAC_QARMA3;
    if (api) return MAC27_CPU_PAC_IMPL_DEFINED;
    return MAC27_CPU_PAC_NONE;
}

static enum mac27_cpu_algorithm gen_alg(unsigned gpa, unsigned gpi, unsigned gpa3)
{
    if (gpa) return MAC27_CPU_PAC_QARMA5;
    if (gpa3) return MAC27_CPU_PAC_QARMA3;
    if (gpi) return MAC27_CPU_PAC_IMPL_DEFINED;
    return MAC27_CPU_PAC_NONE;
}

int mac27_cpu_assess_26a434(const struct mac27_cpu_kc_target *target,
                           const struct mac27_cpu_sample *samples,
                           size_t count, const uint64_t *expected,
                           size_t expected_count, struct mac27_cpu_result *out)
{
    size_t i, j;
    unsigned subtype;
    if (!out) return -1;
    clear_result(out);
    if (!target || !samples || !expected || !count || !expected_count ||
        count > MAC27_CPU_MAX_SAMPLES || expected_count > MAC27_CPU_MAX_SAMPLES)
        return -1;

    /* A supplied target is still only a claim until its provenance has
     * been checked. This method NEVER validates the Apple signature. */
    subtype = target->cpusubtype & 0x00ffffffu;
    if (target->cputype != MAC27_CPU_MACH_ARM64 ||
        (subtype != MAC27_CPU_ABI_ARM64E &&
         subtype != MAC27_CPU_ABI_ARM64E_X1) ||
        target->filetype != MAC27_CPU_KC_FILESET ||
        target->darwin_major != 27 ||
        target->chained_fixup_format != MAC27_CPU_KC_FIXUP_AUTH64 ||
        target->verified_26A434_manifest != 1) {
        out->reason = MAC27_CPU_WRONG_KC;
        return 0;
    }
    if (count != expected_count) {
        out->reason = MAC27_CPU_INCOMPLETE_CPU_SET;
        return 0;
    }
    for (i = 0; i < count; i++) {
        unsigned apa, api, gpa, gpi, apa3, gpa3, lr;
        enum mac27_cpu_algorithm address, generic;
        const struct mac27_cpu_sample *s = &samples[i];
        int located = 0;
        out->first_failing_sample = (uint32_t)i;
        /* Each MPIDR must appear exactly once and only from expected[].
         * Ignore MPIDR U/MT status bits but do not discard Aff3..Aff0. */
        for (j = 0; j < expected_count; j++)
            if ((expected[j] & UINT64_C(0xff00ffffff)) ==
                (s->mpidr_el1 & UINT64_C(0xff00ffffff))) {
                size_t k;
                located++;
                for (k = 0; k < i; k++)
                    if ((samples[k].mpidr_el1 & UINT64_C(0xff00ffffff)) ==
                        (s->mpidr_el1 & UINT64_C(0xff00ffffff))) {
                        out->reason = MAC27_CPU_INCOMPLETE_CPU_SET;
                        return 0;
                    }
            }
        if (located != 1) {
            out->reason = MAC27_CPU_INCOMPLETE_CPU_SET;
            return 0;
        }
        if (s->origin != MAC27_CPU_ORIGIN_DIRECT_EL1 ||
            s->isar1_observed != 1 || s->isar2_observed != 1) {
            out->reason = MAC27_CPU_NO_DIRECT_ISAR;
            return 0;
        }
        apa = NIBBLE(s->id_aa64isar1_el1, MAC27_CPU_ISAR1_APA_SHIFT);
        api = NIBBLE(s->id_aa64isar1_el1, MAC27_CPU_ISAR1_API_SHIFT);
        gpa = NIBBLE(s->id_aa64isar1_el1, MAC27_CPU_ISAR1_GPA_SHIFT);
        gpi = NIBBLE(s->id_aa64isar1_el1, MAC27_CPU_ISAR1_GPI_SHIFT);
        apa3 = NIBBLE(s->id_aa64isar2_el1, MAC27_CPU_ISAR2_APA3_SHIFT);
        gpa3 = NIBBLE(s->id_aa64isar2_el1, MAC27_CPU_ISAR2_GPA3_SHIFT);
        if (bad_pac_field(apa, api, gpa, gpi, apa3, gpa3)) {
            out->reason = MAC27_CPU_BAD_REGISTER_VALUE;
            return 0;
        }
        address = addr_alg(apa, api, apa3);
        generic = gen_alg(gpa, gpi, gpa3);
        if (!address) {
            out->reason = MAC27_CPU_NO_ADDRESS_PAC;
            return 0;
        }
        if (!generic) {
            out->reason = MAC27_CPU_NO_GENERIC_PAC;
            return 0;
        }
        /* An implementation-defined algorithm or mixed address/generic
         * algorithms cannot be equated with Apple's PAC behavior. */
        if (address == MAC27_CPU_PAC_IMPL_DEFINED ||
            generic == MAC27_CPU_PAC_IMPL_DEFINED || address != generic ||
            (i && (address != out->address_algorithm ||
                   generic != out->generic_algorithm))) {
            out->reason = MAC27_CPU_MIXED_PAC_ALGORITHM;
            return 0;
        }
        if (subtype == MAC27_CPU_ABI_ARM64E_X1) {
            /* Arm v9.5 value 6 advertises PAuth_LR (PC+SP diversifier).
             * QARMA3 APA3 or QARMA5 APA, not generic GPA value. */
            lr = address == MAC27_CPU_PAC_QARMA5 ? apa : apa3;
            if (lr != 6) {
                out->reason = MAC27_CPU_PAUTH_LR_UNPROVEN;
                return 0;
            }
        }
        out->address_algorithm = address;
        out->generic_algorithm = generic;
        out->inspected_count++;
    }
    out->reason = MAC27_CPU_ARCH_PAC_CANDIDATE_ONLY;
    out->hardware_pac_candidate = 1;
    /* No trustworthy producer for Apple 26A434 KC fixup/key initial state,
     * SCTLR_EL1 PAC enable, HCR/SCR trap routing, native CPU ABI and boot
     * security. Candidate != native readiness. */
    out->native_mac27_ready = 0;
    return 0;
}

int mac27_cpu_read_el1_optional(struct mac27_cpu_sample *out)
{
    if (!out) return -1;
#if defined(__aarch64__) && defined(MAC27_CPU_ENABLE_EL1_READ) && MAC27_CPU_ENABLE_EL1_READ == 1
    uint64_t el, mpidr, isar1, isar2;
    __asm__ volatile ("mrs %0, CurrentEL" : "=r"(el));
    if (((el >> 2) & 3u) != 1u) return -1;
    /* May trap under hypervisor/firmware restrictions. Caller must arrange
     * safe access in privileged code before opting in. Read-only only. */
    __asm__ volatile ("mrs %0, MPIDR_EL1" : "=r"(mpidr));
    __asm__ volatile ("mrs %0, ID_AA64ISAR1_EL1" : "=r"(isar1));
    __asm__ volatile ("mrs %0, ID_AA64ISAR2_EL1" : "=r"(isar2));
    out->mpidr_el1 = mpidr;
    out->id_aa64isar1_el1 = isar1;
    out->id_aa64isar2_el1 = isar2;
    out->origin = MAC27_CPU_ORIGIN_DIRECT_EL1;
    out->isar1_observed = out->isar2_observed = 1;
    out->reserved[0] = out->reserved[1] = 0;
    return 0;
#else
    /* Returning -1 is safer than simulating a register read on the host. */
    return -1;
#endif
}
