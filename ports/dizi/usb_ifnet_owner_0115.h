/*
 * Dizi CDC-ECM ownership transfer policy for a FUTURE native IOKit driver.
 * Transport-independent and never wired into XNU by this file.
 *
 * Current XNU: sweet_usb.c allocates/attaches BSD ue0 and owns RX/TX.
 * Apple IONetworkingFamily-166 IONetworkInterface::attachToDataLinkLayer
 * allocates/attaches its OWN private ifnet. It cannot adopt BSD ue0.
 * Patch 0098 also defines a fake global IONetworkController metaclass,
 * which conflicts with Apple's genuine IONetworkController vtable.
 *
 * Do not create an IOKit interface or start a native controller until ALL
 * migration prerequisites are proven. Without them, default BSD continues;
 * explicit native requests fail closed. No shadow ifnet or fabricated MAC.
 *
 * Caller must protect these transitions with ONE lock used by BOTH owners.
 * release_complete requires a true ifnet_detach completion callback and
 * drained DWC3 RX/TX work. In particular, issuing ifnet_detach and immediately
 * re-registering is unsafe because XNU detach is asynchronous.
 */
#ifndef DIZI_USB_IFNET_OWNER_0115_H
#define DIZI_USB_IFNET_OWNER_0115_H
#include <stdint.h>
#include <stdbool.h>

#define DZ_USB_NATIVE_FAMILY_ABI_MATCH     (1u << 0) /* pinned Apple ABI/exports verified */
#define DZ_USB_NATIVE_FAKE_CLASS_REMOVED   (1u << 1) /* real IONetworkController only */
#define DZ_USB_NATIVE_BSD_CREATE_DISABLED  (1u << 2) /* before sweet_usb ifnet_allocate */
#define DZ_USB_NATIVE_DWC3_PACKET_BACKEND  (1u << 3) /* native TX/RX + mbuf ownership */
#define DZ_USB_NATIVE_STACK_REGISTERED     (1u << 4) /* real IONetworkStack + interface */
#define DZ_USB_NATIVE_TEARDOWN_VERIFIED    (1u << 5) /* no outstanding RX/TX / detached */
#define DZ_USB_NATIVE_ALL (DZ_USB_NATIVE_FAMILY_ABI_MATCH | \
    DZ_USB_NATIVE_FAKE_CLASS_REMOVED | DZ_USB_NATIVE_BSD_CREATE_DISABLED | \
    DZ_USB_NATIVE_DWC3_PACKET_BACKEND | DZ_USB_NATIVE_STACK_REGISTERED | \
    DZ_USB_NATIVE_TEARDOWN_VERIFIED)

enum dizi_usb_owner_kind {
    DZ_USB_OWNER_NONE = 0,
    DZ_USB_OWNER_BSD = 1,
    DZ_USB_OWNER_APPLE_IOKIT = 2
};

enum dizi_usb_owner_phase {
    DZ_USB_OWNER_IDLE = 0,
    DZ_USB_OWNER_RESERVED,
    DZ_USB_OWNER_ACTIVE,
    DZ_USB_OWNER_DRAINING,
    DZ_USB_OWNER_BLOCKED
};

struct dizi_usb_owner_state {
    uint64_t max_epoch;
    uint64_t epoch;
    uint32_t proof;
    enum dizi_usb_owner_kind owner;
    enum dizi_usb_owner_phase phase;
};

/* A native request with incomplete proof poisons this lifetime's attempt.
 * The code does not silently fall back after the user selects native mode. */
static inline bool
dizi_usb_owner_claim(struct dizi_usb_owner_state *s, bool native_opt_in,
    uint32_t proven_requirements, uint64_t epoch)
{
    if (!s || s->phase != DZ_USB_OWNER_IDLE || !epoch || epoch <= s->max_epoch)
        return false;
    if (native_opt_in && proven_requirements != DZ_USB_NATIVE_ALL) {
        s->phase = DZ_USB_OWNER_BLOCKED;
        return false;
    }
    s->max_epoch = s->epoch = epoch;
    s->proof = native_opt_in ? proven_requirements : 0;
    s->owner = native_opt_in ? DZ_USB_OWNER_APPLE_IOKIT : DZ_USB_OWNER_BSD;
    s->phase = DZ_USB_OWNER_RESERVED;
    return true;
}

/* Only the chosen owner can commit a real successful attach result. Failure
 * must abort the reserved owner without claiming an attached ifnet. */
static inline bool
dizi_usb_owner_attached(struct dizi_usb_owner_state *s,
    enum dizi_usb_owner_kind owner, uint64_t epoch)
{
    if (!s || s->phase != DZ_USB_OWNER_RESERVED || s->owner != owner ||
        s->epoch != epoch || owner == DZ_USB_OWNER_NONE)
        return false;
    s->phase = DZ_USB_OWNER_ACTIVE;
    return true;
}

static inline bool
dizi_usb_owner_abort_reserved(struct dizi_usb_owner_state *s,
    enum dizi_usb_owner_kind owner, uint64_t epoch)
{
    if (!s || s->phase != DZ_USB_OWNER_RESERVED || s->owner != owner ||
        s->epoch != epoch)
        return false;
    s->phase = DZ_USB_OWNER_IDLE;
    s->epoch = 0;
    s->proof = 0;
    s->owner = DZ_USB_OWNER_NONE;
    return true;
}

/* A disconnect or link-down event does NOT free an ifnet; network device
 * registration outlives carrier. Begin drain only on actual detach intent. */
static inline bool
dizi_usb_owner_detach_begin(struct dizi_usb_owner_state *s,
    enum dizi_usb_owner_kind owner, uint64_t epoch)
{
    if (!s || s->phase != DZ_USB_OWNER_ACTIVE || s->owner != owner ||
        s->epoch != epoch)
        return false;
    s->phase = DZ_USB_OWNER_DRAINING;
    return true;
}

static inline bool
dizi_usb_owner_detach_done(struct dizi_usb_owner_state *s,
    enum dizi_usb_owner_kind owner, uint64_t epoch, bool callbacks_drained)
{
    if (!s || s->phase != DZ_USB_OWNER_DRAINING || s->owner != owner ||
        s->epoch != epoch || !callbacks_drained)
        return false;
    s->phase = DZ_USB_OWNER_IDLE;
    s->epoch = 0;
    s->proof = 0;
    s->owner = DZ_USB_OWNER_NONE;
    return true;
}

static inline bool
dizi_usb_owner_transmits(const struct dizi_usb_owner_state *s,
    enum dizi_usb_owner_kind owner, uint64_t epoch)
{
    return s && s->phase == DZ_USB_OWNER_ACTIVE && s->owner == owner &&
        s->epoch == epoch;
}

#endif /* DIZI_USB_IFNET_OWNER_0115_H */
