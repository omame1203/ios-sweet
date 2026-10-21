/* SPDX-License-Identifier: MIT
 * Offline macOS 27 (26A434) IOKit provider/personality matching for dizi.
 * Never registers IOService, writes an ADT, maps MMIO or starts a driver.
 *
 * The caller consumes exact CFBundleIdentifier, IOClass, IOProviderClass,
 * IONameMatch, IOResourceMatch, IOPropertyMatch and IOMatchCategory fields
 * extracted from the *real* 26A434 fileset __PRELINK_INFO XML.
 * A "metadata candidate" is NOT a loadable or operational IOKit driver.
 */
#ifndef MACOS27_DIZI_IOKIT_RESOLVER_H
#define MACOS27_DIZI_IOKIT_RESOLVER_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define M27_IOKIT_MAX_NAME_MATCH 8u
#define M27_IOKIT_MAX_LINEAGE 6u
#define M27_IOKIT_MAX_CANDIDATES 64u

enum m27_iokit_match {
    M27_IOKIT_INVALID = 0,
    M27_IOKIT_NO_PROVIDER_CLASS,
    M27_IOKIT_NO_NAME_MATCH,
    M27_IOKIT_NO_RESOURCE_MATCH,
    M27_IOKIT_NO_CATEGORY_MATCH,
    M27_IOKIT_UNSUPPORTED_KEYS,
    M27_IOKIT_CANDIDATE_ONLY
};

enum m27_iokit_block {
    M27_IOKIT_NO_ARM64E_PAC         = 1u << 0,
    M27_IOKIT_KC_FIXUPS_UNPROVEN    = 1u << 1,
    M27_IOKIT_OSMETACLASS_UNPROVEN  = 1u << 2,
    M27_IOKIT_DRIVER_ABI_UNPROVEN   = 1u << 3,
    M27_IOKIT_PROVIDER_NOT_LIVE    = 1u << 4,
    M27_IOKIT_HW_OWNERSHIP_UNPROVEN = 1u << 5,
    M27_IOKIT_PROBE_UNPROVEN        = 1u << 6,
    M27_IOKIT_PLATFORM_UNSUPPORTED = 1u << 7
};
#define M27_IOKIT_ALL_BLOCKERS ((uint32_t)255u)

/* Shape is a safe normalized subset, not a plist decoder. The extractor
 * records unsupported selectors rather than dropping them to force a match.
 * NULL pointer means unspecified, not wildcard unless Apple IOKit allows
 * that key to be absent (IONameMatch / IOResourceMatch / category).
 */
struct m27_iokit_personality {
    const char *bundle_id;
    const char *personality;
    const char *io_class;
    const char *provider_class;
    const char *names[M27_IOKIT_MAX_NAME_MATCH];
    uint8_t names_count;
    const char *resource_match;
    const char *match_category;
    int32_t probe_score;
    bool property_match_present;
    bool other_unsupported_selectors;
};

/* Class lineage requires independently established runtime inheritance.
 * Do NOT synthesize 'AppleARMIODevice' from IOPlatformDevice just to match
 * a macOS AppleARMGIC or paravirtual GPU driver.
 */
struct m27_iokit_provider {
    const char *name;
    const char *class_name;
    const char *superclasses[M27_IOKIT_MAX_LINEAGE];
    uint8_t superclasses_count;
    const char *resource; /* IOResources named service, if applicable */
    const char *match_category;
};

/* These claims are diagnostic only. The resolver can never attest their
 * origin, so it never returns a ready-to-attach decision, even when all set.
 */
struct m27_iokit_runtime_evidence {
    bool arm64e_pac_verified;
    bool kc_fixups_verified;
    bool metaclass_abi_verified;
    bool driver_xnu27_abi_verified;
    bool provider_runtime_observed;
    bool exclusive_hardware_owner_verified;
    bool probe_and_start_observed;
    bool platform_policy_verified;
};

struct m27_iokit_result {
    enum m27_iokit_match match;
    uint32_t blockers;
    bool metadata_candidate;
    bool attach_authorized; /* Always false. No hardware side effects. */
};

struct m27_iokit_choice {
    uint16_t selected_index; /* UINT16_MAX when missing or tied */
    uint16_t matching_count;
    int32_t best_score;
    bool tie_for_best;
    bool attach_authorized; /* Always false. */
};

struct m27_iokit_result m27_iokit_resolve(
    const struct m27_iokit_personality *driver,
    const struct m27_iokit_provider *provider,
    const struct m27_iokit_runtime_evidence *evidence);
struct m27_iokit_choice m27_iokit_choose(
    const struct m27_iokit_personality *drivers, size_t driver_count,
    const struct m27_iokit_provider *provider);

/* Source-grounded dizi/XNU22 descriptors. These are legacy services only,
 * never equivalent to native macOS27 AppleARMPlatform, IOGraphics/IOHID ABI.
 */
enum m27_iokit_dizi_provider_id {
    M27_IOKIT_DIZI_PLATFORM = 0,
    M27_IOKIT_DIZI_CPU,
    M27_IOKIT_DIZI_DISPLAY,
    M27_IOKIT_DIZI_HID,
    M27_IOKIT_DIZI_GIC,
    M27_IOKIT_DIZI_IORESOURCES,
    M27_IOKIT_DIZI_COUNT
};
const struct m27_iokit_provider *m27_iokit_dizi_xnu22_provider(
    enum m27_iokit_dizi_provider_id id);
#endif
