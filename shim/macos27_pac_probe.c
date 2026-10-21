#include "macos27_pac_probe.h"

static void clear_observation(struct mac27_pac_probe_observation *out)
{
    out->current_el = 0;
    out->mpidr_el1 = 0;
    out->id_aa64isar1_el1 = 0;
    out->id_aa64isar2_el1 = 0;
    out->complete_mask = 0;
    out->source = MAC27_PAC_SOURCE_NONE;
    out->native_boot_ready = 0;
}

static void clear_sample(struct mac27_cpu_sample *out)
{
    out->mpidr_el1 = 0;
    out->id_aa64isar1_el1 = 0;
    out->id_aa64isar2_el1 = 0;
    out->origin = MAC27_CPU_ORIGIN_NONE;
    out->isar1_observed = 0;
    out->isar2_observed = 0;
    out->reserved[0] = 0;
    out->reserved[1] = 0;
}

int mac27_pac_probe_mock(const struct mac27_pac_probe_reader *reader,
                        struct mac27_pac_probe_observation *out)
{
    struct mac27_pac_probe_observation tmp;
    int (*read_reg)(void *, enum mac27_pac_probe_reg, uint64_t *);
    void *ctx;
    if (!out) return MAC27_PAC_PROBE_BAD_ARGUMENT;
    clear_observation(out);
    if (!reader || !reader->read) return MAC27_PAC_PROBE_BAD_ARGUMENT;
    read_reg = reader->read;
    ctx = reader->ctx;
    clear_observation(&tmp);
    if (read_reg(ctx, MAC27_PAC_REG_CURRENT_EL, &tmp.current_el))
        return MAC27_PAC_PROBE_READ_FAILED;
    if (tmp.current_el != MAC27_PAC_PROBE_EL1)
        return MAC27_PAC_PROBE_WRONG_EL;
    if (read_reg(ctx, MAC27_PAC_REG_MPIDR_EL1, &tmp.mpidr_el1) ||
        read_reg(ctx, MAC27_PAC_REG_ISAR1_EL1, &tmp.id_aa64isar1_el1) ||
        read_reg(ctx, MAC27_PAC_REG_ISAR2_EL1, &tmp.id_aa64isar2_el1))
        return MAC27_PAC_PROBE_READ_FAILED;
    tmp.complete_mask = MAC27_PAC_PROBE_ALL_READS;
    tmp.source = MAC27_PAC_SOURCE_MOCK;
    *out = tmp;
    return MAC27_PAC_PROBE_OK;
}

int mac27_pac_probe_el1(struct mac27_pac_probe_observation *out,
                       uint32_t operator_request)
{
    if (!out) return MAC27_PAC_PROBE_BAD_ARGUMENT;
    clear_observation(out);
    if (operator_request != 1) return MAC27_PAC_PROBE_DISABLED;
#if defined(__aarch64__) && \
    defined(MAC27_PAC_PROBE_ENABLE_EL1_READ) && \
    MAC27_PAC_PROBE_ENABLE_EL1_READ == 1 && \
    defined(MAC27_PAC_PROBE_TRAP_RECOVERY_CONFIRMED) && \
    MAC27_PAC_PROBE_TRAP_RECOVERY_CONFIRMED == 1
    struct mac27_pac_probe_observation tmp;
    uint64_t mpidr_after;
    clear_observation(&tmp);
    __asm__ volatile ("mrs %0, CurrentEL" : "=r"(tmp.current_el));
    if (tmp.current_el != MAC27_PAC_PROBE_EL1)
        return MAC27_PAC_PROBE_WRONG_EL;
    /*
     * STOP BEFORE ENABLING ON DIZI WITHOUT EXCEPTION RETURN ASSURANCE.
     * The following reads may synchronously trap due to EL2/EL3 controls.
     * No exception-table entries, per-core trap recovery, or EL2 cooperation
     * is installed here; this function CANNOT promise to return on a trap.
     * Existing Android cpu.txt / FDT prove NONE of these permissions.
     */
    __asm__ volatile ("mrs %0, MPIDR_EL1" : "=r"(tmp.mpidr_el1));
    __asm__ volatile ("mrs %0, ID_AA64ISAR1_EL1" : "=r"(tmp.id_aa64isar1_el1));
    __asm__ volatile ("mrs %0, ID_AA64ISAR2_EL1" : "=r"(tmp.id_aa64isar2_el1));
    /* Read again to reject migration to a different PE during collection.
     * The caller must also provide its own CPU pinning/interrupt discipline.
     * MPIDR alone does not prove the reads were unvirtualized. */
    __asm__ volatile ("mrs %0, MPIDR_EL1" : "=r"(mpidr_after));
    if (mpidr_after != tmp.mpidr_el1)
        return MAC27_PAC_PROBE_READ_FAILED;
    tmp.complete_mask = MAC27_PAC_PROBE_ALL_READS;
    tmp.source = MAC27_PAC_SOURCE_DIRECT_EL1;
    /* Reads only: does NOT test PAC instructions, keys, traps, or CPU0+SMP. */
    *out = tmp;
    return MAC27_PAC_PROBE_OK;
#else
    /* No MRS embedded in ordinary binary. Never use imaginary ISAR values. */
    return MAC27_PAC_PROBE_DISABLED;
#endif
}

int mac27_pac_probe_to_cpu_sample(
    const struct mac27_pac_probe_observation *observation,
    struct mac27_cpu_sample *out)
{
    if (!out) return MAC27_PAC_PROBE_BAD_ARGUMENT;
    clear_sample(out);
    if (!observation ||
        observation->source != MAC27_PAC_SOURCE_DIRECT_EL1 ||
        observation->complete_mask != MAC27_PAC_PROBE_ALL_READS ||
        observation->current_el != MAC27_PAC_PROBE_EL1 ||
        observation->native_boot_ready != 0)
        return MAC27_PAC_PROBE_NOT_ATTESTED;
    out->mpidr_el1 = observation->mpidr_el1;
    out->id_aa64isar1_el1 = observation->id_aa64isar1_el1;
    out->id_aa64isar2_el1 = observation->id_aa64isar2_el1;
    out->origin = MAC27_CPU_ORIGIN_DIRECT_EL1;
    out->isar1_observed = 1;
    out->isar2_observed = 1;
    return MAC27_PAC_PROBE_OK;
}
