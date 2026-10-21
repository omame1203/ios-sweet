/** @file
  Source-complete post-grant real FD transfer; default build does NO RAM I/O.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include "DiziSecTransfer.h"
#include "DiziGkiHandoff.h"

#if defined(DIZI_SEC_ENABLE) && DIZI_SEC_ENABLE == 1 && \
    defined(DIZI_SEC_TRUSTED_OWNER_IMPLEMENTED) && \
    DIZI_SEC_TRUSTED_OWNER_IMPLEMENTED == 1
#define DIZI_SEC_ACTIVE 1
#else
#define DIZI_SEC_ACTIVE 0
#endif

#if DIZI_SEC_ACTIVE
static int disjoint(uint64_t a, uint64_t an, uint64_t b, uint64_t bn)
{
  if (!an || !bn || a > UINT64_MAX - an || b > UINT64_MAX - bn)
    return 0;
  return (a + an <= b || b + bn <= a);
}

/*  ARMv8 D-cache clean to Point of Coherency, then I-cache invalidate to
 *  Point of Unification before interpreting the copied FV as instructions.
 *  Hardware grants MUST permit CTR_EL0 and these maintenance operations.
 */
#if defined(__aarch64__)
static void sync_executable_fv(uint64_t pa, uint64_t bytes)
{
  uint64_t ctr, dline, iline, p, end = pa + bytes;
  __asm__ volatile ("mrs %0, ctr_el0" : "=r"(ctr));
  dline = UINT64_C(4) << ((ctr >> 16) & 15);
  iline = UINT64_C(4) << (ctr & 15);
  for (p = pa & ~(dline - 1); p < end; p += dline)
    __asm__ volatile ("dc cvac, %0" :: "r"(p) : "memory");
  __asm__ volatile ("dsb sy" ::: "memory");
  for (p = pa & ~(iline - 1); p < end; p += iline)
    __asm__ volatile ("ic ivau, %0" :: "r"(p) : "memory");
  __asm__ volatile ("dsb sy\nisb" ::: "memory");
}

static int safe_first_pc(void)
{
  uint64_t el, sctlr, daif;
  __asm__ volatile ("mrs %0, CurrentEL" : "=r"(el));
  if (el != 4) return 0; /* EL1 only; EL2 independently unverified. */
  __asm__ volatile ("mrs %0, SCTLR_EL1" : "=r"(sctlr));
  __asm__ volatile ("mrs %0, DAIF" : "=r"(daif));
  /* Linux ARM64 entry contract: stage-1 MMU and D-cache disabled.
   * I-cache may be on, but only after proper source PoC maintenance. */
  return (sctlr & UINT64_C(5)) == 0 && (daif & UINT64_C(0x3c0)) == 0x3c0;
}
#else
/* No host build may pretend to have executed architectural cache ops. */
static int safe_first_pc(void) { return 0; }
static void sync_executable_fv(uint64_t p, uint64_t n)
{ (void)p; (void)n; }
#endif

static int matches_source(const DIZI_SEC_INPUT *r,
                          const DIZI_SEC_GRANTED_MAPPING *g)
{
  uint64_t fdt = r->incoming_fdt_pa;
  if (g->abi_version != DIZI_SEC_TRANSFER_ABI ||
      g->fdt_readable == 0 || g->initrd_readable == 0 ||
      g->fd_writable == 0 || g->fdt_capacity < 40 ||
      g->fdt_capacity > DIZI_GKI_MAX_DTB ||
      g->fd_pa != DIZI_SEC_LOW_FV_PA ||
      g->fd_bytes != DIZI_SEC_LOW_FV_SIZE ||
      g->initrd_bytes != r->initrd_bytes ||
      (uint64_t)(uintptr_t)g->fdt_readable != fdt ||
      (uint64_t)(uintptr_t)g->initrd_readable != r->initrd_pa ||
      (uint64_t)(uintptr_t)g->fd_writable != DIZI_SEC_LOW_FV_PA ||
      !disjoint(fdt,g->fdt_capacity,DIZI_SEC_LOW_FV_PA,
                DIZI_SEC_EARLY_END-DIZI_SEC_LOW_FV_PA) ||
      !disjoint(fdt,g->fdt_capacity,
                r->kernel_image_base,r->kernel_image_bytes) ||
      !disjoint(fdt,g->fdt_capacity,
                r->initrd_pa,r->initrd_bytes) ||
      !disjoint(r->initrd_pa,r->initrd_bytes,
                DIZI_SEC_LOW_FV_PA,
                DIZI_SEC_EARLY_END - DIZI_SEC_LOW_FV_PA) ||
      !disjoint(r->kernel_image_base,r->kernel_image_bytes,
                DIZI_SEC_LOW_FV_PA,
                DIZI_SEC_EARLY_END - DIZI_SEC_LOW_FV_PA))
    return 0;
  return 1;
}
#endif

int DiziSecStageFirmware(const DIZI_SEC_INPUT *r)
{
#if DIZI_SEC_ACTIVE
  DIZI_SEC_GRANTED_MAPPING g = {0};
  DIZI_GKI_REQUEST fd_req = {0};
  DIZI_GKI_PLAN plan = {0};
  uint64_t i;
  if (!r || !r->incoming_fdt_pa || (r->incoming_fdt_pa & 7) ||
      !r->initrd_pa || r->initrd_bytes < DIZI_FD_SIZE ||
      r->initrd_bytes > DIZI_GKI_MAX_INITRD ||
      !r->kernel_image_base || !r->kernel_image_bytes ||
      r->incoming_fdt_pa > UINT64_MAX - DIZI_GKI_MAX_DTB ||
      !disjoint(r->initrd_pa,r->initrd_bytes,
                r->kernel_image_base,r->kernel_image_bytes) ||
      !safe_first_pc())
    return DIZI_SEC_BAD_REQUEST;

  /* The only transition allowing ANY physical read/write: independently
   * verified EL2/XPU grant, not FDT membership or a self-authored boolean. */
  if (DiziSecGetTrustedRuntimeGrant(r, &g) != 0)
    return DIZI_SEC_NO_OWNER;
  if (!matches_source(r, &g))
    return DIZI_SEC_OWNER_MISMATCH;

  fd_req.fdt = g.fdt_readable;
  fd_req.fdt_capacity = g.fdt_capacity;
  fd_req.initrd = g.initrd_readable;
  fd_req.initrd_bytes = (size_t)g.initrd_bytes;
  fd_req.initrd_physical = r->initrd_pa;
  for (i=0;i<32;i++)fd_req.exact_fd_sha256[i]=r->expected_fd_sha256[i];
  if (dizi_gki_fd_plan(&fd_req, &plan) != DIZI_GKI_LAYOUT_UNAUTHORIZED ||
      plan.authorized_to_copy_or_execute ||
      plan.fd_destination_pa != DIZI_SEC_LOW_FV_PA ||
      plan.fd_bytes != DIZI_SEC_LOW_FV_SIZE)
    return DIZI_SEC_FDT_OR_FV_INVALID;

  /* A trusted owner already excludes *all* live DMA, MMIO and ownership
   * conflicts. Stage and verify the exact source bytes, not a donor FV. */
  for (i=0;i<DIZI_SEC_LOW_FV_SIZE;i++)
    g.fd_writable[i] = g.initrd_readable[plan.source_offset + i];
  for (i=0;i<DIZI_SEC_LOW_FV_SIZE;i++)
    if (g.fd_writable[i] != g.initrd_readable[plan.source_offset + i])
      return DIZI_SEC_COPY_INVALID;
  sync_executable_fv(g.fd_pa,DIZI_SEC_LOW_FV_SIZE);
  return DIZI_SEC_STAGED_NOT_EXECUTED;
#else
  (void)r;
  return DIZI_SEC_NO_OWNER;
#endif
}

int DiziSecTryBoot(const DIZI_SEC_INPUT *request)
{
#if DIZI_SEC_ACTIVE
  int status = DiziSecStageFirmware(request);
  if (status != DIZI_SEC_STAGED_NOT_EXECUTED)
    return status;
  /* This branch is unreachable in production WITHOUT the separately
   * linked real owner implementation. It is a genuine AArch64 BR, not a
   * substitute for ABL/Gunyah/XPU memory evidence or a boot success claim. */
  DiziSecEnterPrePi(request->incoming_fdt_pa, DIZI_SEC_LOW_FV_PA);
  return DIZI_SEC_REFUSED;
#else
  (void)request;
  return DIZI_SEC_NO_OWNER;
#endif
}
