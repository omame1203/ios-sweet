/* SPDX-License-Identifier: BSD-2-Clause
 * Opt-in, READ-ONLY SMMUv2 ownership observation.
 * Only PA/offsets already individually proven in saved dizi shim logs:
 *  ID0 @15000020, ID1 @15000024, sCR0 @15000000, SMR0 @15000800.
 * ID2 @15000028, S2CR and SMR1..119 are deliberately NOT read: no
 * successful per-register device evidence. So all route grants are UNKNOWN.
 * This must NOT be taken as a translation/CB/hypervisor authorization.
 * No SMMU/GPI/QUP register writes, TLB commands or DMA.
 */
#if defined(ARM64_BOARD_CONFIG_SWEET)
#include <sys/param.h>
#include <sys/systm.h>
#include <vm/vm_kern.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include "smmu_owner_0114.h"

extern vm_offset_t ml_io_map(vm_offset_t, vm_size_t);
#define DZ_0114_GR0_PA UINT64_C(0x15000000)
#define DZ_0114_GR0_LENGTH 4096u

static uint32_t
dz_0114_read32(vm_offset_t va, uint32_t off)
{
    uint32_t v;
    vm_offset_t addr = va + off;
    __asm__ volatile("ldr %w0, [%1]" : "=r"(v) : "r"(addr) : "memory");
    __asm__ volatile("dmb oshld" ::: "memory");
    return v;
}

void
dizi_smmu_owner_0114_boot_audit(void)
{
    uint32_t dizi = 0, observe = 0;
    (void)PE_parse_boot_argn("dizihw", &dizi, sizeof(dizi));
    (void)PE_parse_boot_argn("dizismmuownerro", &observe, sizeof(observe));
    if (dizi != 1 || observe != 1) return;
    vm_offset_t base = ml_io_map((vm_offset_t)DZ_0114_GR0_PA,
        DZ_0114_GR0_LENGTH);
    if (!base) {
        printf("DIZI SMMU 0114: read-only GR0 map unavailable; blocked\n");
        return;
    }
    struct dz_0114_snapshot s = {0};
    s.id0 = dz_0114_read32(base, 0x20u);
    s.id1 = dz_0114_read32(base, 0x24u);
    s.scr0 = dz_0114_read32(base, 0x00u);
    s.smr[0] = dz_0114_read32(base, 0x800u);
    s.id0_known = s.id1_known = s.scr0_known = s.smr_known[0] = true;
    /* ID2 and every S2CR deliberately UNKNOWN. No real owner attestation.
     * No path from this audit to dz_plan_routes or any hardware activation. */
    struct dz_0114_report r = dz_0114_evaluate(&s);
    printf("DIZI SMMU 0114 RO: ID0=0x%x ID1=0x%x sCR0=0x%x SMR0=0x%x\n",
        s.id0, s.id1, s.scr0, s.smr[0]);
    printf("DIZI SMMU 0114 RO: status=%u observed=%u/%u ID2/S2CR=UNREAD, owner=UNPROVEN, DMA=BLOCKED\n",
        (unsigned)r.result, r.observed_smrs, DZ_0114_SMRS);
}
#endif
