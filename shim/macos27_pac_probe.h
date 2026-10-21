#ifndef DIZI_MACOS27_PAC_PROBE_H
#define DIZI_MACOS27_PAC_PROBE_H

/*
 * macOS 27 / POCO Pad passive PAC register evidence contract.
 *
 * DEFAULT: no system-register reads and no hardware access. This header
 * does NOT enable the opt-in macros. See macos27_pac_probe.c for the
 * synchronous-exception/trap warning before enabling the direct backend.
 *
 * Host callbacks are deliberately tagged MOCK, *never* direct EL1 evidence,
 * regardless of their values. A simulated positive PAC result cannot satisfy
 * the existing cpu_compat_gate's MAC27_CPU_ORIGIN_DIRECT_EL1 requirement.
 *
 * This observes only CPU ID registers. It cannot attest to PAC key values,
 * SCTLR_EL1 authentication state, EL2 virtualization, Apple KC pointer
 * signing, valid execution, or boot readiness.
 */
#include <stdint.h>
#include "../ports/macos27/cpu_compat_gate.h"

enum mac27_pac_probe_reg {
    MAC27_PAC_REG_CURRENT_EL = 0,
    MAC27_PAC_REG_MPIDR_EL1 = 1,
    MAC27_PAC_REG_ISAR1_EL1 = 2,
    MAC27_PAC_REG_ISAR2_EL1 = 3
};

enum mac27_pac_probe_source {
    MAC27_PAC_SOURCE_NONE = 0,
    MAC27_PAC_SOURCE_MOCK = 1,
    MAC27_PAC_SOURCE_DIRECT_EL1 = 2
};

enum mac27_pac_probe_status {
    MAC27_PAC_PROBE_OK = 0,
    MAC27_PAC_PROBE_BAD_ARGUMENT = 1,
    MAC27_PAC_PROBE_DISABLED = 2,
    MAC27_PAC_PROBE_WRONG_EL = 3,
    MAC27_PAC_PROBE_READ_FAILED = 4,
    MAC27_PAC_PROBE_NOT_ATTESTED = 5
};

#define MAC27_PAC_PROBE_EL1 UINT64_C(4)
#define MAC27_PAC_PROBE_ALL_READS UINT32_C(15)

/* Values are only committed on full success. Failed observations are zeroed.
 * origin is advisory software provenance, not a cryptographic attestation.
 * native_boot_ready is ALWAYS zero, including for a real EL1 observation.
 */
struct mac27_pac_probe_observation {
    uint64_t current_el;
    uint64_t mpidr_el1;
    uint64_t id_aa64isar1_el1;
    uint64_t id_aa64isar2_el1;
    uint32_t complete_mask;
    enum mac27_pac_probe_source source;
    uint32_t native_boot_ready;
};

/* MOCK ONLY. Callback returns zero for a value read and nonzero on failure.
 * Running this on a host, QEMU, or with synthetic PAC values cannot establish
 * a feature of any physical dizi CPU. No direct MRS instructions are used.
 */
struct mac27_pac_probe_reader {
    int (*read)(void *ctx, enum mac27_pac_probe_reg reg, uint64_t *value);
    void *ctx;
};
int mac27_pac_probe_mock(const struct mac27_pac_probe_reader *reader,
                        struct mac27_pac_probe_observation *out);

/*
 * DIRECT EL1: no-op by default, regardless of operator_request.
 * The following must BOTH be explicitly defined to 1 at compilation:
 *   MAC27_PAC_PROBE_ENABLE_EL1_READ
 *   MAC27_PAC_PROBE_TRAP_RECOVERY_CONFIRMED
 * and the target must be __aarch64__. operator_request must also be 1.
 *
 * This is NOT an exception-safe or returning probe by itself! Even after
 * reading CurrentEL, later MRS of MPIDR/ISAR1/ISAR2 may trap to EL2 or
 * raise an exception. A caller must *independently* prove privileged EL1
 * execution, access permissions, and a return-safe synchronous-exception
 * handler before defining those macros or invoking this function. Without
 * that proof LEAVE THE MACROS DISABLED; no in-function C fallback can catch
 * an exception that prevents return. The function writes no CPU registers.
 *
 * Source must NEVER be invoked by normal iPadOS shim or auto-boot paths.
 * This worker does not implement or wire an exception handler.
 */
int mac27_pac_probe_el1(struct mac27_pac_probe_observation *out,
                       uint32_t operator_request);

/*
 * Translate only fully successful, directly observed EL1 records to the
 * existing cpu_compat_gate ABI. MOCK records are rejected and zeroed.
 * Memory can be forged; this API is not evidence of physical provenance on
 * its own. Run mac27_cpu_assess_26a434 on the selected per-CPU set
 * independently; even candidate PAC there does NOT mean boot ready.
 */
int mac27_pac_probe_to_cpu_sample(
    const struct mac27_pac_probe_observation *observation,
    struct mac27_cpu_sample *out);

#endif
