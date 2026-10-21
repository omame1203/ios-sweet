#ifndef MAC27_CPU_COMPAT_GATE_H
#define MAC27_CPU_COMPAT_GATE_H

/*
 * Source-only Qualcomm dizi <-> authentic macOS 27 26A434 CPU preflight.
 *
 * Provenance:
 *  - backup/dizi/cpu.txt: Android /proc/cpuinfo, 4x ARM part 0xd05 (A55)
 *    and 4x part 0xd41 (A78), no advertised 'paca' or 'pacg'. Neither
 *    absence nor presence of Linux HWCAP is a raw per-core ISAR sample.
 *  - backup/dizi/fdt: qcom,kryo CPU nodes and PSCI MPIDRs; no PAC register.
 *  - research/macos27-26A434 genuine manifest-matched Apple KC, as audited
 *    by ports/macos27/kernel_collection.py: Darwin 27, arm64e Mach-O, 16K
 *    chained fixups format 8. An arm64e.x1 *userland* image does not imply
 *    the kernel uses subtype 12 or PAuth_LR.
 *  - Arm ID_AA64ISAR1_EL1 architected fields; Linux sysreg.h/cpufeature.c:
 *       APA [7:4] API [11:8] GPA [27:24] GPI [31:28]
 *    ID_AA64ISAR2_EL1: GPA3 [11:8], APA3 [15:12].
 *
 * This is a capability gate, not a PAC emulator, shim, KC loader, SMC,
 * trap bypass, pointer resigning utility, or promise of native execution.
 * NO model-name or FDT-based assumptions set observed register values.
 * Architected support alone does NOT prove Apple's boot ABI, key state,
 * EL2/EL3 traps, SSV, PAC fixup handling or runtime.
 */
#include <stdint.h>
#include <stddef.h>

#define MAC27_CPU_MAX_SAMPLES 8u
#define MAC27_CPU_ABI_ARM64E 2u
#define MAC27_CPU_ABI_ARM64E_X1 12u
#define MAC27_CPU_MACH_ARM64 0x0100000cu
#define MAC27_CPU_KC_FILESET 12u
#define MAC27_CPU_KC_FIXUP_AUTH64 8u

/* A sample must originate from privilege-controlled direct, same-context
 * register reads. Passing a fabricated 'EL1' origin is not attestation;
 * the integration must establish provenance independently. */
enum mac27_cpu_origin {
    MAC27_CPU_ORIGIN_NONE = 0,
    MAC27_CPU_ORIGIN_LINUX_FEATURES = 1,
    MAC27_CPU_ORIGIN_FDT = 2,
    MAC27_CPU_ORIGIN_DIRECT_EL1 = 3
};

enum mac27_cpu_field {
    MAC27_CPU_ISAR1_APA_SHIFT = 4,
    MAC27_CPU_ISAR1_API_SHIFT = 8,
    MAC27_CPU_ISAR1_GPA_SHIFT = 24,
    MAC27_CPU_ISAR1_GPI_SHIFT = 28,
    MAC27_CPU_ISAR2_GPA3_SHIFT = 8,
    MAC27_CPU_ISAR2_APA3_SHIFT = 12
};

struct mac27_cpu_sample {
    uint64_t mpidr_el1;
    uint64_t id_aa64isar1_el1;
    uint64_t id_aa64isar2_el1;
    enum mac27_cpu_origin origin;
    uint8_t isar1_observed;
    uint8_t isar2_observed;
    uint8_t reserved[2];
};

struct mac27_cpu_kc_target {
    uint32_t cputype;
    uint32_t cpusubtype;     /* Mach-O capability flags in high 8 bits. */
    uint32_t filetype;
    uint32_t darwin_major;
    uint32_t chained_fixup_format;
    uint32_t verified_26A434_manifest; /* validated by independent caller */
};

enum mac27_cpu_block {
    MAC27_CPU_BAD_ARGUMENT = 1,
    MAC27_CPU_WRONG_KC,
    MAC27_CPU_NO_DIRECT_ISAR,
    MAC27_CPU_INCOMPLETE_CPU_SET,
    MAC27_CPU_BAD_REGISTER_VALUE,
    MAC27_CPU_NO_ADDRESS_PAC,
    MAC27_CPU_NO_GENERIC_PAC,
    MAC27_CPU_MIXED_PAC_ALGORITHM,
    MAC27_CPU_PAUTH_LR_UNPROVEN,
    MAC27_CPU_ARCH_PAC_CANDIDATE_ONLY
};

enum mac27_cpu_algorithm {
    MAC27_CPU_PAC_NONE = 0,
    MAC27_CPU_PAC_QARMA5 = 1,
    MAC27_CPU_PAC_QARMA3 = 2,
    MAC27_CPU_PAC_IMPL_DEFINED = 3
};

struct mac27_cpu_result {
    enum mac27_cpu_block reason;
    enum mac27_cpu_algorithm address_algorithm;
    enum mac27_cpu_algorithm generic_algorithm;
    uint32_t first_failing_sample;
    uint32_t inspected_count;
    uint32_t hardware_pac_candidate;
    uint32_t native_mac27_ready; /* ALWAYS 0 until independently implemented. */
};

/*
 * expected_mpidr[] must be established from the actual selected FDT CPU
 * topology, not inferred from CPU part names. Every selected CPU is required.
 * No unsafe "just CPU0" opt-out or accidental successes for empty sets.
 * Never reads hardware. Returns 0 for a structurally valid assessment,
 * not for native boot readiness; out->reason explains the block.
 */
int mac27_cpu_assess_26a434(const struct mac27_cpu_kc_target *target,
                           const struct mac27_cpu_sample *samples,
                           size_t sample_count,
                           const uint64_t *expected_mpidr,
                           size_t expected_count,
                           struct mac27_cpu_result *out);

/*
 * Optional CPU register sampler: assembled only with explicit
 * MAC27_CPU_ENABLE_EL1_READ=1 and AArch64. It is not invoked by assess().
 * Must be called in privileged EL1 context on the SAME intended PE, with
 * suitable ID-register access configured by actual firmware/hypervisor.
 * A trap can occur before the function returns; absence of an exception
 * cannot be inferred by offline tests. No hardware writes.
 * Returns 0 only after reading MPIDR and both ID registers at EL1.
 */
int mac27_cpu_read_el1_optional(struct mac27_cpu_sample *out);

#endif
