/* SPDX-License-Identifier: BSD-2-Clause */
#include "storage_boot_gate.h"

#include <string.h>

#define APFS_CHECKSUM_MOD UINT64_C(0xffffffff)

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static int zero_bytes(const uint8_t *p, size_t length)
{
    size_t i;
    for (i = 0; i < length; i++)
        if (p[i] != 0)
            return 0;
    return 1;
}

static int checksum_valid(const uint8_t *block, size_t length)
{
    uint64_t first, sum1 = 0, sum2 = 0;
    size_t i;

    if (!block || length < 4096 || length > 65536 || (length & 3u))
        return 0;
    first = rd64(block);
    if (first == 0 || first == UINT64_MAX)
        return 0;
    /* APFS Fletcher-64, starting at offset 8, then including the two
     * stored checksum words. The checksum is non-cryptographic. */
    for (i = 8; i < length; i += 4) {
        sum1 = (sum1 + rd32(block + i)) % APFS_CHECKSUM_MOD;
        sum2 = (sum2 + sum1) % APFS_CHECKSUM_MOD;
    }
    for (i = 0; i < 8; i += 4) {
        sum1 = (sum1 + rd32(block + i)) % APFS_CHECKSUM_MOD;
        sum2 = (sum2 + sum1) % APFS_CHECKSUM_MOD;
    }
    return sum1 == 0 && sum2 == 0;
}

static int recognized_block_size(uint32_t size)
{
    return size == 4096u || size == 8192u || size == 16384u ||
           size == 32768u || size == 65536u;
}

int m27_storage_boot_parse_nxsb(const void *src, size_t length,
                               struct m27_storage_boot_nxsb *out)
{
    const uint8_t *b = (const uint8_t *)src;
    struct m27_storage_boot_nxsb parsed;
    unsigned i, populated = 0;

    if (!out)
        return M27_STORAGE_BOOT_INVALID;
    memset(out, 0, sizeof(*out));
    if (!b || length < 4096 || length > 65536)
        return M27_STORAGE_BOOT_INVALID;
    if (memcmp(b + 32, "NXSB", 4) != 0)
        return M27_STORAGE_BOOT_UNSUPPORTED;
    if (!recognized_block_size(rd32(b + 36)) || rd32(b + 36) != length)
        return M27_STORAGE_BOOT_UNSUPPORTED;
    if ((rd32(b + 24) & 0xffffu) != 1u || rd64(b + 8) != 1u ||
        rd64(b + 16) == 0 || !checksum_valid(b, length))
        return M27_STORAGE_BOOT_INVALID;
    memset(&parsed, 0, sizeof(parsed));
    parsed.block_size = rd32(b + 36);
    parsed.block_count = rd64(b + 40);
    parsed.xid = rd64(b + 16);
    memcpy(parsed.container_uuid, b + 72, 16);
    parsed.max_fs = rd32(b + 180);
    if (parsed.block_count < 256 || parsed.max_fs < 1 || parsed.max_fs > 100 ||
        zero_bytes(parsed.container_uuid, 16))
        return M27_STORAGE_BOOT_INVALID;
    for (i = 0; i < 100; i++) {
        parsed.fs_oids[i] = rd64(b + 184 + i * 8);
        if (i >= parsed.max_fs && parsed.fs_oids[i] != 0)
            return M27_STORAGE_BOOT_CONFLICT;
        if (parsed.fs_oids[i])
            populated++;
    }
    if (!populated)
        return M27_STORAGE_BOOT_MISSING;
    *out = parsed;
    return M27_STORAGE_BOOT_STRUCTURAL;
}

int m27_storage_boot_parse_apsb(const void *src, size_t length,
                               struct m27_storage_boot_apsb *out)
{
    const uint8_t *b = (const uint8_t *)src;
    struct m27_storage_boot_apsb parsed;

    if (!out)
        return M27_STORAGE_BOOT_INVALID;
    memset(out, 0, sizeof(*out));
    if (!b || length < 4096 || length > 65536 ||
        !recognized_block_size((uint32_t)length))
        return M27_STORAGE_BOOT_INVALID;
    if (memcmp(b + 32, "APSB", 4) != 0)
        return M27_STORAGE_BOOT_UNSUPPORTED;
    if ((rd32(b + 24) & 0xffffu) != 13u || rd64(b + 8) == 0 ||
        rd64(b + 16) == 0 || !checksum_valid(b, length))
        return M27_STORAGE_BOOT_INVALID;
    memset(&parsed, 0, sizeof(parsed));
    parsed.oid = rd64(b + 8);
    parsed.xid = rd64(b + 16);
    parsed.incompatible_features = rd64(b + 56);
    parsed.snapshot_count = rd64(b + 216);
    parsed.integrity_oid = rd64(b + 1024);
    parsed.role = (uint16_t)(b[964] | ((uint16_t)b[965] << 8));
    memcpy(parsed.uuid, b + 240, 16);
    memcpy(parsed.group_uuid, b + 1008, 16);
    if (zero_bytes(parsed.uuid, 16))
        return M27_STORAGE_BOOT_INVALID;
    *out = parsed;
    return M27_STORAGE_BOOT_STRUCTURAL;
}

static int valid_build(const char *s)
{
    size_t i, digits = 0;
    /* macOS 27 builds use Darwin train 26 (e.g. 26A434). Do not allow
     * older iOS 16 (20H...) or macOS 26 (25A...) build identifiers. */
    if (!s || !memchr(s, 0, M27_STORAGE_BOOT_BUILD_MAX) ||
        s[0] != '2' || s[1] != '6' || s[2] < 'A' || s[2] > 'Z')
        return 0;
    for (i = 3; i < M27_STORAGE_BOOT_BUILD_MAX && s[i] >= '0' && s[i] <= '9'; i++)
        digits++;
    if (digits < 3 || digits > 5)
        return 0;
    if (s[i] >= 'a' && s[i] <= 'z')
        i++;
    return i < M27_STORAGE_BOOT_BUILD_MAX && s[i] == 0;
}

static int valid_snapshot_name(const char *s)
{
    static const char prefix[] = "com.apple.os.update-";
    size_t i, n;
    if (!memchr(s, 0, M27_STORAGE_BOOT_SNAPSHOT_MAX))
        return 0;
    n = strlen(s);
    if (n <= sizeof(prefix) - 1 || n >= M27_STORAGE_BOOT_SNAPSHOT_MAX ||
        memcmp(s, prefix, sizeof(prefix) - 1) != 0)
        return 0;
    for (i = sizeof(prefix) - 1; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z') || c == '-'))
            return 0;
    }
    return 1;
}

static int listed_fs_oid(const struct m27_storage_boot_nxsb *nx, uint64_t oid)
{
    unsigned i;
    for (i = 0; i < nx->max_fs; i++) {
        if (nx->fs_oids[i] == oid)
            return 1;
    }
    return 0;
}

static int required_role(uint16_t role)
{
    return role == M27_STORAGE_ROLE_SYSTEM || role == M27_STORAGE_ROLE_DATA ||
           role == M27_STORAGE_ROLE_PREBOOT || role == M27_STORAGE_ROLE_VM ||
           role == M27_STORAGE_ROLE_RECOVERY;
}

static const struct m27_storage_boot_apsb *get_role(
    const struct m27_storage_boot_observation *obs, uint16_t role)
{
    unsigned i;
    for (i = 0; i < M27_STORAGE_BOOT_MAX_VOLUMES; i++)
        if (obs->volumes[i].role == role)
            return &obs->volumes[i];
    return NULL;
}

int m27_storage_boot_preflight(const struct m27_storage_boot_observation *obs)
{
    const struct m27_storage_boot_apsb *system, *data;
    uint32_t seen = 0;
    unsigned i, j;

    if (!obs || obs->abi != M27_STORAGE_BOOT_ABI_V1 ||
        obs->struct_size != sizeof(*obs))
        return M27_STORAGE_BOOT_INVALID;
    if (obs->macos_major != 27 || obs->architecture != 1u ||
        !valid_build(obs->build))
        return M27_STORAGE_BOOT_UNSUPPORTED;
    if (!recognized_block_size(obs->nx.block_size) ||
        obs->nx.block_count < 256 || obs->nx.xid == 0 ||
        obs->nx.max_fs < 5 || obs->nx.max_fs > 100 ||
        zero_bytes(obs->nx.container_uuid, 16))
        return M27_STORAGE_BOOT_INVALID;
    if (obs->volume_count != M27_STORAGE_BOOT_MAX_VOLUMES)
        return M27_STORAGE_BOOT_MISSING;
    if (zero_bytes(obs->volume_group_uuid, 16))
        return M27_STORAGE_BOOT_MISSING;
    for (i = 0; i < M27_STORAGE_BOOT_MAX_VOLUMES; i++) {
        const struct m27_storage_boot_apsb *v = &obs->volumes[i];
        if (!required_role(v->role))
            return M27_STORAGE_BOOT_UNSUPPORTED;
        if (seen & (uint32_t)v->role)
            return M27_STORAGE_BOOT_CONFLICT;
        seen |= v->role;
        if (!v->oid || !v->xid || v->xid > obs->nx.xid ||
            zero_bytes(v->uuid, 16) || !listed_fs_oid(&obs->nx, v->oid))
            return M27_STORAGE_BOOT_CONFLICT;
        for (j = 0; j < i; j++) {
            if (memcmp(v->uuid, obs->volumes[j].uuid, 16) == 0 ||
                v->oid == obs->volumes[j].oid)
                return M27_STORAGE_BOOT_CONFLICT;
        }
        if (v->role == M27_STORAGE_ROLE_SYSTEM ||
            v->role == M27_STORAGE_ROLE_DATA) {
            if (memcmp(v->group_uuid, obs->volume_group_uuid, 16) != 0)
                return M27_STORAGE_BOOT_CONFLICT;
        } else if (!zero_bytes(v->group_uuid, 16)) {
            return M27_STORAGE_BOOT_CONFLICT;
        }
    }
    if (seen != (M27_STORAGE_ROLE_SYSTEM | M27_STORAGE_ROLE_DATA |
                 M27_STORAGE_ROLE_PREBOOT | M27_STORAGE_ROLE_RECOVERY |
                 M27_STORAGE_ROLE_VM))
        return M27_STORAGE_BOOT_MISSING;
    system = get_role(obs, M27_STORAGE_ROLE_SYSTEM);
    data = get_role(obs, M27_STORAGE_ROLE_DATA);
    if (!system || !data || !(system->incompatible_features & 0x20u) ||
        system->snapshot_count == 0 || system->integrity_oid == 0)
        return M27_STORAGE_BOOT_MISSING;
    if (memcmp(system->uuid, obs->preboot_system_uuid, 16) != 0 ||
        memcmp(system->uuid, obs->snapshot_system_uuid, 16) != 0)
        return M27_STORAGE_BOOT_CONFLICT;
    if (!valid_snapshot_name(obs->snapshot_name))
        return M27_STORAGE_BOOT_UNSUPPORTED;
    if (obs->preboot_kernel_collection_present != 1u ||
        obs->preboot_localpolicy_present != 1u ||
        obs->recovery_artifact_present != 1u ||
        obs->system_version_plist_present != 1u ||
        obs->snapshot_selected != 1u ||
        obs->ufs_ro_block_reader_available != 1u)
        return M27_STORAGE_BOOT_MISSING;
    return M27_STORAGE_BOOT_STRUCTURAL;
}

static int digest_present(const uint8_t *digest, size_t size)
{
    return !zero_bytes(digest, size);
}

int m27_storage_boot_prepare(const struct m27_storage_boot_observation *obs,
                             const struct m27_storage_boot_trust_ops *trust,
                             struct m27_storage_boot_mount_plan *plan)
{
    struct m27_storage_boot_attestation attest;
    const struct m27_storage_boot_apsb *system, *data;
    int ret;

    if (!plan)
        return M27_STORAGE_BOOT_INVALID;
    memset(plan, 0, sizeof(*plan));
    ret = m27_storage_boot_preflight(obs);
    if (ret != M27_STORAGE_BOOT_STRUCTURAL)
        return ret;
    if (!trust || trust->abi != M27_STORAGE_BOOT_ABI_V1 ||
        trust->struct_size != sizeof(*trust) || !trust->verify)
        return M27_STORAGE_BOOT_NEEDS_TRUST;

    memset(&attest, 0, sizeof(attest));
    if (trust->verify(trust->ctx, obs, &attest) != 0)
        return M27_STORAGE_BOOT_AUTH_FAILED;
    system = get_role(obs, M27_STORAGE_ROLE_SYSTEM);
    data = get_role(obs, M27_STORAGE_ROLE_DATA);
    /* Reject unrecognized proof bits, caller-forged structural flags, and
     * attestations not bound to this specific VolumeGroup / root snapshot. */
    if (attest.abi != M27_STORAGE_BOOT_ABI_V1 ||
        attest.struct_size != sizeof(attest) || attest.reserved != 0 ||
        attest.proofs != M27_STORAGE_BOOT_REQUIRED_PROOFS ||
        attest.checkpoint_xid < obs->nx.xid ||
        memcmp(attest.container_uuid, obs->nx.container_uuid, 16) ||
        memcmp(attest.volume_group_uuid, obs->volume_group_uuid, 16) ||
        memcmp(attest.system_uuid, system->uuid, 16) ||
        memcmp(attest.snapshot_system_uuid, obs->snapshot_system_uuid, 16) ||
        memcmp(attest.snapshot_name, obs->snapshot_name,
               M27_STORAGE_BOOT_SNAPSHOT_MAX) != 0 ||
        !digest_present(attest.ssv_root_hash_sha256, 32) ||
        !digest_present(attest.signed_manifest_sha384, 48) ||
        !digest_present(attest.localpolicy_nsih_sha384, 48) ||
        /* LocalPolicy nsih is the SHA-384 of the boot Image4 manifest. The
         * trusted provider must validate its origin and this exact binding. */
        memcmp(attest.localpolicy_nsih_sha384,
               attest.signed_manifest_sha384, 48) != 0 ||
        !digest_present(attest.recovery_policy_measurement_sha384, 48) ||
        !digest_present(attest.cryptex_manifest_sha384, 48))
        return M27_STORAGE_BOOT_AUTH_FAILED;

    /* No device operations! The eventual consumer may only treat this as a
     * mount-intent plan after independently securing the verifier callback. */
    plan->abi = M27_STORAGE_BOOT_ABI_V1;
    plan->struct_size = sizeof(*plan);
    memcpy(plan->container_uuid, obs->nx.container_uuid, 16);
    memcpy(plan->volume_group_uuid, obs->volume_group_uuid, 16);
    memcpy(plan->system_uuid, system->uuid, 16);
    memcpy(plan->data_uuid, data->uuid, 16);
    plan->resolved_checkpoint_xid = attest.checkpoint_xid;
    plan->read_only = 1u;
    plan->apfs_sealed_snapshot = 1u;
    memcpy(plan->snapshot_name, obs->snapshot_name,
           M27_STORAGE_BOOT_SNAPSHOT_MAX);
    return M27_STORAGE_BOOT_DELEGATED_PLAN;
}
