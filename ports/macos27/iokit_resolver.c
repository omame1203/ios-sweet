/* SPDX-License-Identifier: MIT */
#include "iokit_resolver.h"

static bool valid_string(const char *s)
{
    if (!s || !*s) return false;
    /* Bounds are deliberately small; no unbounded scan of hostile strings. */
    for (size_t i = 0; i < 192; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!c) return true;
        if (c < 0x20 || c > 0x7e) return false;
    }
    return false;
}

static bool equal(const char *a, const char *b)
{
    if (!valid_string(a) || !valid_string(b)) return false;
    for (unsigned i = 0; i < 192; i++) {
        if (a[i] != b[i]) return false;
        if (!a[i]) return true;
    }
    return false;
}

static uint32_t missing_evidence(const struct m27_iokit_runtime_evidence *e)
{
    if (!e) return M27_IOKIT_ALL_BLOCKERS;
    uint32_t missing = 0;
    if (!e->arm64e_pac_verified) missing |= M27_IOKIT_NO_ARM64E_PAC;
    if (!e->kc_fixups_verified) missing |= M27_IOKIT_KC_FIXUPS_UNPROVEN;
    if (!e->metaclass_abi_verified) missing |= M27_IOKIT_OSMETACLASS_UNPROVEN;
    if (!e->driver_xnu27_abi_verified) missing |= M27_IOKIT_DRIVER_ABI_UNPROVEN;
    if (!e->provider_runtime_observed) missing |= M27_IOKIT_PROVIDER_NOT_LIVE;
    if (!e->exclusive_hardware_owner_verified) missing |= M27_IOKIT_HW_OWNERSHIP_UNPROVEN;
    if (!e->probe_and_start_observed) missing |= M27_IOKIT_PROBE_UNPROVEN;
    if (!e->platform_policy_verified) missing |= M27_IOKIT_PLATFORM_UNSUPPORTED;
    return missing;
}

struct m27_iokit_result m27_iokit_resolve(
    const struct m27_iokit_personality *d,
    const struct m27_iokit_provider *p,
    const struct m27_iokit_runtime_evidence *evidence)
{
    struct m27_iokit_result result = {
        .match = M27_IOKIT_INVALID,
        .blockers = missing_evidence(evidence),
        .metadata_candidate = false,
        .attach_authorized = false
    };
    if (!d || !p || !valid_string(d->bundle_id) ||
        !valid_string(d->personality) || !valid_string(d->io_class) ||
        !valid_string(d->provider_class) ||
        !valid_string(p->name) || !valid_string(p->class_name) ||
        d->names_count > M27_IOKIT_MAX_NAME_MATCH ||
        p->superclasses_count > M27_IOKIT_MAX_LINEAGE)
        return result;
    for (unsigned i = 0; i < d->names_count; i++) {
        if (!valid_string(d->names[i])) return result;
    }
    for (unsigned i = 0; i < p->superclasses_count; i++) {
        if (!valid_string(p->superclasses[i])) return result;
    }
    if ((d->resource_match && !valid_string(d->resource_match)) ||
        (d->match_category && !valid_string(d->match_category)) ||
        (p->resource && !valid_string(p->resource)) ||
        (p->match_category && !valid_string(p->match_category)))
        return result;

    bool cls = equal(d->provider_class, p->class_name);
    for (unsigned i = 0; i < p->superclasses_count; i++) {
        if (equal(d->provider_class, p->superclasses[i])) cls = true;
    }
    if (!cls) {
        result.match = M27_IOKIT_NO_PROVIDER_CLASS;
        return result;
    }
    if (d->names_count) {
        bool ok = false;
        for (unsigned i = 0; i < d->names_count; i++) {
            if (equal(d->names[i], p->name)) ok = true;
        }
        if (!ok) {
            result.match = M27_IOKIT_NO_NAME_MATCH;
            return result;
        }
    }
    if (d->resource_match && !equal(d->resource_match, p->resource)) {
        result.match = M27_IOKIT_NO_RESOURCE_MATCH;
        return result;
    }
    /* IOMatchCategory arbitrates driver competition. It is NOT a required
     * matching property on the provider; do not compare these strings. */
    if (d->property_match_present || d->other_unsupported_selectors) {
        result.match = M27_IOKIT_UNSUPPORTED_KEYS;
        return result;
    }
    result.match = M27_IOKIT_CANDIDATE_ONLY;
    result.metadata_candidate = true;
    return result;
}

struct m27_iokit_choice m27_iokit_choose(
    const struct m27_iokit_personality *drivers, size_t count,
    const struct m27_iokit_provider *provider)
{
    struct m27_iokit_choice c = {.selected_index = UINT16_MAX};
    if (!drivers || !provider || count > M27_IOKIT_MAX_CANDIDATES) return c;
    for (size_t i = 0; i < count; i++) {
        struct m27_iokit_result r = m27_iokit_resolve(&drivers[i], provider, 0);
        if (!r.metadata_candidate) continue;
        c.matching_count++;
        if (c.selected_index == UINT16_MAX || drivers[i].probe_score > c.best_score) {
            c.selected_index = (uint16_t)i;
            c.best_score = drivers[i].probe_score;
            c.tie_for_best = false;
        } else if (drivers[i].probe_score == c.best_score) {
            c.tie_for_best = true;
        }
    }
    if (c.tie_for_best) c.selected_index = UINT16_MAX;
    return c;
}

/* Existing XNU22 0058/0099/0116:
 * - SweetPlatformExpert matches IOPlatformExpertDevice/xiaomi,dizi;
 * - AppleCLCD matches IOPlatformDevice/sweet,display via /arm-io/disp0;
 * - SweetHIDTouch gets IOResources as mobile IOHIDEventService;
 * - GICv3 is configured directly in SWEET kernel machine routines;
 *   no AppleARMIODevice-nub in this XNU22 port.
 * Provider metadata is for explainability only. Not a runtime registry.
 */
static const struct m27_iokit_provider dizi_xnu22[M27_IOKIT_DIZI_COUNT] = {
    {"xiaomi,dizi", "IOPlatformExpertDevice", {0}, 0, 0, 0},
    {"dizi,cpu", "IOPlatformDevice", {"IOService"}, 1, 0, 0},
    {"sweet,display", "IOPlatformDevice", {"IOService"}, 1, 0, 0},
    {"IOResources", "IOResources", {"IOService"}, 1, 0, 0},
    {0, 0, {0}, 0, 0, 0}, /* GIC is in machine code, not an IOKit nub */
    {"IOResources", "IOResources", {"IOService"}, 1, "IOBSD", 0}
};

const struct m27_iokit_provider *
m27_iokit_dizi_xnu22_provider(enum m27_iokit_dizi_provider_id id)
{
    if ((unsigned)id >= M27_IOKIT_DIZI_COUNT || id == M27_IOKIT_DIZI_GIC) return 0;
    return &dizi_xnu22[(unsigned)id];
}
