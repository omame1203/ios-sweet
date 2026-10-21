/* SPDX-License-Identifier: MIT
 * Real XNU binding of the 0120 chip-SRAM packet protocol to native HID.
 * This requires a separate trusted GPI/QUP owner before any hardware IO;
 * no such attestation producer exists. Keep default implementation inert.
 */
#include "nvt_session_xnu_0120.h"

extern void sweet_hid_touch(int finger, int down, int x, int y);

static struct dizi_nvt0120_session dizi_nvt_session;
#if DIZI_NVT0120_NATIVE_TRANSPORT_READY
static struct dizi_nvt0120_ops dizi_nvt_bus;

static int
nvt_xnu_page(void *unused, uint32_t page)
{
    (void)unused;
    return dizi_nvt_bus.select_page ?
        dizi_nvt_bus.select_page(dizi_nvt_bus.context, page) : -1;
}

static int
nvt_xnu_sram(void *unused, uint8_t offset, const uint8_t *bytes, size_t length)
{
    (void)unused;
    return dizi_nvt_bus.write_sram ?
        dizi_nvt_bus.write_sram(dizi_nvt_bus.context, offset, bytes, length) : -1;
}

static int
nvt_xnu_boot(void *unused, uint8_t version)
{
    (void)unused;
    return dizi_nvt_bus.verify_boot ?
        dizi_nvt_bus.verify_boot(dizi_nvt_bus.context, version) : -1;
}

static void
nvt_xnu_hid(void *unused, unsigned finger, bool down, unsigned x, unsigned y)
{
    (void)unused;
    if (finger < DIZI_NVT0120_CONTACTS && x < 1600u && y < 2560u)
        sweet_hid_touch((int)finger, down ? 1 : 0, (int)x, (int)y);
}
#endif

int
dizi_nvt0120_kernel_start(const struct dizi_nvt0120_lease *lease,
    const struct dizi_nvt0120_ops *bus,
    const uint8_t *firmware, size_t firmware_size)
{
#if DIZI_NVT0120_NATIVE_TRANSPORT_READY
    if (!bus || !lease || dizi_nvt_session.state != DIZI_NVT0120_STOPPED)
        return -1;
    dizi_nvt_bus = *bus;
    const struct dizi_nvt0120_ops adapter = {
        .context = 0, .select_page = nvt_xnu_page,
        .write_sram = nvt_xnu_sram, .verify_boot = nvt_xnu_boot,
        .contact = nvt_xnu_hid
    };
    return dizi_nvt0120_start(&dizi_nvt_session, lease, &adapter,
        firmware, firmware_size);
#else
    (void)lease; (void)bus; (void)firmware; (void)firmware_size;
    return -1; /* no producer has proved both SID maps, SMMU/SE9/IRQ */
#endif
}

int dizi_nvt0120_kernel_frame(const uint8_t *packet, size_t size)
{
    return dizi_nvt0120_frame(&dizi_nvt_session, packet, size);
}

void dizi_nvt0120_kernel_stop(void)
{
    dizi_nvt0120_stop(&dizi_nvt_session);
}

enum dizi_nvt0120_state dizi_nvt0120_kernel_state(void)
{
    return dizi_nvt_session.state;
}
