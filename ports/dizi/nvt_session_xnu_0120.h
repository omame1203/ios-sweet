/* BSD/XNU adapter for native Novatek firmware, reports and IOHID contacts.
 * This is an in-kernel API for a future VERIFIED DMA/SE9 backend only.
 * It is never callable from a boot argument/sysctl or userspace.
 */
#ifndef DIZI_NVT_SESSION_XNU_0120_H
#define DIZI_NVT_SESSION_XNU_0120_H
#include "nvt_session_0120.h"

/* No XNU backend has verified ownership and mapped both SIDs yet.
 * In particular, SID0x416 + SID0x403 may NOT use naked CPU physical PAs. */
#define DIZI_NVT0120_NATIVE_TRANSPORT_READY 0

int dizi_nvt0120_kernel_start(const struct dizi_nvt0120_lease *lease,
    const struct dizi_nvt0120_ops *bus,
    const uint8_t *firmware, size_t firmware_size);
int dizi_nvt0120_kernel_frame(const uint8_t *packet, size_t size);
void dizi_nvt0120_kernel_stop(void);
enum dizi_nvt0120_state dizi_nvt0120_kernel_state(void);
#endif
