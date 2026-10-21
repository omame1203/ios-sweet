/* SPDX-License-Identifier: BSD-2-Clause */
/* Synthetic source-only macOS27 APFS/SSV boot gate tests: no mount/MMIO. */
#define _POSIX_C_SOURCE 200809L
#include "storage_boot_gate.h"

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void wr64(uint8_t *p, uint64_t v)
{
    wr32(p, (uint32_t)v);
    wr32(p + 4, (uint32_t)(v >> 32));
}

static uint32_t rd32_test(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Inverse of the APFS Fletcher64 checking algorithm. Independent builder. */
static void seal_block(uint8_t *b, size_t length)
{
    const uint64_t mod = UINT64_C(0xffffffff);
    uint64_t s1 = 0, s2 = 0;
    size_t i;
    wr64(b, 0);
    for (i = 8; i < length; i += 4) {
        s1 = (s1 + rd32_test(b + i)) % mod;
        s2 = (s2 + s1) % mod;
    }
    wr32(b, (uint32_t)((mod - ((s1 + s2) % mod)) % mod));
    wr32(b + 4, (uint32_t)(s2 % mod));
}

static void make_nx(uint8_t b[4096])
{
    unsigned i;
    memset(b, 0, 4096);
    wr64(b + 8, 1);
    wr64(b + 16, 400);
    wr32(b + 24, 0x80000001u);
    memcpy(b + 32, "NXSB", 4);
    wr32(b + 36, 4096);
    wr64(b + 40, 2000);
    memset(b + 72, 0x77, 16);
    wr32(b + 180, 20);
    for (i = 0; i < 5; i++)
        wr64(b + 184 + i * 8, 1024 + i);
    seal_block(b, 4096);
}

static void make_apsb(uint8_t b[4096], unsigned i, uint16_t role)
{
    memset(b, 0, 4096);
    wr64(b + 8, 1024u + i);
    wr64(b + 16, 300);
    wr32(b + 24, 0x4000000du);
    memcpy(b + 32, "APSB", 4);
    if (role == M27_STORAGE_ROLE_SYSTEM) {
        wr64(b + 56, 0x20);
        wr64(b + 216, 2);
        wr64(b + 1024, 2001);
    }
    memset(b + 240, (int)(0x11 + i), 16);
    wr32(b + 964, role);
    if (role == M27_STORAGE_ROLE_SYSTEM || role == M27_STORAGE_ROLE_DATA)
        memset(b + 1008, 0x66, 16);
    seal_block(b, 4096);
}

static void fill(struct m27_storage_boot_observation *obs)
{
    static const uint16_t roles[5] = {
        M27_STORAGE_ROLE_SYSTEM, M27_STORAGE_ROLE_DATA,
        M27_STORAGE_ROLE_PREBOOT, M27_STORAGE_ROLE_RECOVERY,
        M27_STORAGE_ROLE_VM
    };
    uint8_t buf[4096];
    unsigned i;
    memset(obs, 0, sizeof(*obs));
    obs->abi = M27_STORAGE_BOOT_ABI_V1;
    obs->struct_size = sizeof(*obs);
    obs->macos_major = 27;
    obs->architecture = 1;
    strcpy(obs->build, "26A434");
    make_nx(buf);
    assert(m27_storage_boot_parse_nxsb(buf, sizeof(buf), &obs->nx) ==
           M27_STORAGE_BOOT_STRUCTURAL);
    for (i = 0; i < 5; i++) {
        make_apsb(buf, i, roles[i]);
        assert(m27_storage_boot_parse_apsb(buf, sizeof(buf), &obs->volumes[i]) ==
               M27_STORAGE_BOOT_STRUCTURAL);
    }
    obs->volume_count = 5;
    memset(obs->volume_group_uuid, 0x66, 16);
    memset(obs->preboot_system_uuid, 0x11, 16);
    memset(obs->snapshot_system_uuid, 0x11, 16);
    strcpy(obs->snapshot_name, "com.apple.os.update-1234");
    obs->preboot_kernel_collection_present = 1;
    obs->preboot_localpolicy_present = 1;
    obs->recovery_artifact_present = 1;
    obs->system_version_plist_present = 1;
    obs->snapshot_selected = 1;
    obs->ufs_ro_block_reader_available = 1;
}

static void assert_blank(const struct m27_storage_boot_mount_plan *p)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t i;
    for (i = 0; i < sizeof(*p); i++)
        assert(b[i] == 0);
}

static void preflight_negatives(void)
{
    struct m27_storage_boot_observation obs, edited;
    struct m27_storage_boot_mount_plan plan;
    unsigned i;

    assert(m27_storage_boot_preflight(NULL) == M27_STORAGE_BOOT_INVALID);
    fill(&obs);
    assert(m27_storage_boot_preflight(&obs) == M27_STORAGE_BOOT_STRUCTURAL);
    memset(&plan, 0xcc, sizeof(plan));
    assert(m27_storage_boot_prepare(&obs, NULL, &plan) ==
           M27_STORAGE_BOOT_NEEDS_TRUST);
    assert_blank(&plan);

#define REJECT(change, code) do { \
    edited = obs; change; \
    assert(m27_storage_boot_preflight(&edited) == (code)); \
    memset(&plan, 0xcc, sizeof(plan)); \
    assert(m27_storage_boot_prepare(&edited, NULL, &plan) == (code)); \
    assert_blank(&plan); \
} while (0)
    REJECT(edited.abi = 2, M27_STORAGE_BOOT_INVALID);
    REJECT(edited.struct_size = 0, M27_STORAGE_BOOT_INVALID);
    REJECT(edited.macos_major = 16, M27_STORAGE_BOOT_UNSUPPORTED);
    REJECT(edited.macos_major = 26, M27_STORAGE_BOOT_UNSUPPORTED);
    REJECT(edited.macos_major = 28, M27_STORAGE_BOOT_UNSUPPORTED);
    REJECT(edited.architecture = 2, M27_STORAGE_BOOT_UNSUPPORTED);
    REJECT(strcpy(edited.build, "20H392"), M27_STORAGE_BOOT_UNSUPPORTED);
    REJECT(strcpy(edited.build, "25A434"), M27_STORAGE_BOOT_UNSUPPORTED);
    REJECT(strcpy(edited.build, "27A434"), M27_STORAGE_BOOT_UNSUPPORTED);
    REJECT(strcpy(edited.build, "26A"), M27_STORAGE_BOOT_UNSUPPORTED);
    REJECT(memset(edited.build, 'A', sizeof(edited.build)), M27_STORAGE_BOOT_UNSUPPORTED);
    REJECT(edited.nx.block_size = 123, M27_STORAGE_BOOT_INVALID);
    REJECT(edited.nx.xid = 0, M27_STORAGE_BOOT_INVALID);
    REJECT(edited.nx.block_count = 255, M27_STORAGE_BOOT_INVALID);
    REJECT(edited.nx.max_fs = 4, M27_STORAGE_BOOT_INVALID);
    REJECT(memset(edited.nx.container_uuid, 0, 16), M27_STORAGE_BOOT_INVALID);
    REJECT(edited.volume_count = 1, M27_STORAGE_BOOT_MISSING);
    REJECT(edited.volume_count = 6, M27_STORAGE_BOOT_MISSING);
    REJECT(memset(edited.volume_group_uuid, 0, 16), M27_STORAGE_BOOT_MISSING);
    REJECT(edited.volumes[1].role = M27_STORAGE_ROLE_SYSTEM, M27_STORAGE_BOOT_CONFLICT);
    REJECT(edited.volumes[1].role = 0xffff, M27_STORAGE_BOOT_UNSUPPORTED);
    REJECT(edited.volumes[1].oid = edited.volumes[0].oid, M27_STORAGE_BOOT_CONFLICT);
    REJECT(edited.volumes[1].oid = 60000, M27_STORAGE_BOOT_CONFLICT);
    REJECT(edited.volumes[1].xid = edited.nx.xid + 1, M27_STORAGE_BOOT_CONFLICT);
    REJECT(edited.volumes[0].xid = 0, M27_STORAGE_BOOT_CONFLICT);
    REJECT(memset(edited.volumes[0].uuid, 0, 16), M27_STORAGE_BOOT_CONFLICT);
    REJECT(memcpy(edited.volumes[1].uuid, edited.volumes[0].uuid, 16),
           M27_STORAGE_BOOT_CONFLICT);
    REJECT(memset(edited.volumes[0].group_uuid, 0, 16), M27_STORAGE_BOOT_CONFLICT);
    REJECT(memset(edited.volumes[2].group_uuid, 0x66, 16), M27_STORAGE_BOOT_CONFLICT);
    REJECT(edited.volumes[0].incompatible_features = 0, M27_STORAGE_BOOT_MISSING);
    REJECT(edited.volumes[0].snapshot_count = 0, M27_STORAGE_BOOT_MISSING);
    REJECT(edited.volumes[0].integrity_oid = 0, M27_STORAGE_BOOT_MISSING);
    REJECT(memset(edited.preboot_system_uuid, 0x22, 16), M27_STORAGE_BOOT_CONFLICT);
    REJECT(memset(edited.snapshot_system_uuid, 0x22, 16), M27_STORAGE_BOOT_CONFLICT);
    REJECT(strcpy(edited.snapshot_name, "bad"), M27_STORAGE_BOOT_UNSUPPORTED);
    REJECT(strcpy(edited.snapshot_name, "com.apple.os.update-../../bad"),
           M27_STORAGE_BOOT_UNSUPPORTED);
    REJECT(memset(edited.snapshot_name, 'q', sizeof(edited.snapshot_name)),
           M27_STORAGE_BOOT_UNSUPPORTED);
    REJECT(edited.preboot_kernel_collection_present = 0, M27_STORAGE_BOOT_MISSING);
    REJECT(edited.preboot_localpolicy_present = 0, M27_STORAGE_BOOT_MISSING);
    REJECT(edited.recovery_artifact_present = 0, M27_STORAGE_BOOT_MISSING);
    REJECT(edited.system_version_plist_present = 0, M27_STORAGE_BOOT_MISSING);
    REJECT(edited.snapshot_selected = 0, M27_STORAGE_BOOT_MISSING);
    REJECT(edited.ufs_ro_block_reader_available = 0, M27_STORAGE_BOOT_MISSING);
    REJECT(edited.ufs_ro_block_reader_available = 2, M27_STORAGE_BOOT_MISSING);
#undef REJECT

    /* All five role slots are checked; reordering is permitted. */
    for (i = 0; i < 5; i++)
        assert(obs.volumes[i].oid != 0);
    edited = obs;
    { struct m27_storage_boot_apsb t = edited.volumes[0];
      edited.volumes[0] = edited.volumes[4]; edited.volumes[4] = t; }
    assert(m27_storage_boot_preflight(&edited) == M27_STORAGE_BOOT_STRUCTURAL);
}

static void parse_negatives(void)
{
    struct m27_storage_boot_nxsb nx;
    struct m27_storage_boot_apsb sb;
    uint8_t buf[4096];
    unsigned i;

    assert(m27_storage_boot_parse_nxsb(NULL, 4096, &nx) == M27_STORAGE_BOOT_INVALID);
    assert(m27_storage_boot_parse_nxsb(buf, 4096, NULL) == M27_STORAGE_BOOT_INVALID);
    assert(m27_storage_boot_parse_apsb(NULL, 4096, &sb) == M27_STORAGE_BOOT_INVALID);
    assert(m27_storage_boot_parse_apsb(buf, 4096, NULL) == M27_STORAGE_BOOT_INVALID);
    make_nx(buf);
    assert(m27_storage_boot_parse_nxsb(buf, 4095, &nx) == M27_STORAGE_BOOT_INVALID);
    assert(m27_storage_boot_parse_nxsb(buf, 4096, &nx) == M27_STORAGE_BOOT_STRUCTURAL);
    for (i = 0; i < 1024; i += 7) {
        buf[i] ^= 0x55;
        assert(m27_storage_boot_parse_nxsb(buf, 4096, &nx) != M27_STORAGE_BOOT_STRUCTURAL);
        buf[i] ^= 0x55;
    }
    buf[32] = 'H';
    assert(m27_storage_boot_parse_nxsb(buf, 4096, &nx) == M27_STORAGE_BOOT_UNSUPPORTED);
    make_nx(buf);
    wr32(buf + 36, 8192);
    seal_block(buf, 4096);
    assert(m27_storage_boot_parse_nxsb(buf, 4096, &nx) == M27_STORAGE_BOOT_UNSUPPORTED);
    make_nx(buf);
    wr64(buf + 184 + 25 * 8, 8888);
    seal_block(buf, 4096);
    assert(m27_storage_boot_parse_nxsb(buf, 4096, &nx) == M27_STORAGE_BOOT_CONFLICT);
    make_apsb(buf, 0, M27_STORAGE_ROLE_SYSTEM);
    assert(m27_storage_boot_parse_apsb(buf, 4096, &sb) == M27_STORAGE_BOOT_STRUCTURAL);
    for (i = 0; i < 1024; i += 5) {
        buf[i] ^= 0x21;
        assert(m27_storage_boot_parse_apsb(buf, 4096, &sb) != M27_STORAGE_BOOT_STRUCTURAL);
        buf[i] ^= 0x21;
    }
    make_apsb(buf, 0, M27_STORAGE_ROLE_SYSTEM);
    /* Never lie about the backing buffer's actual size to a C pointer API. */
    assert(m27_storage_boot_parse_apsb(buf, 2048, &sb) != M27_STORAGE_BOOT_STRUCTURAL);
    assert(m27_storage_boot_parse_apsb(buf, 1024, &sb) == M27_STORAGE_BOOT_INVALID);
}

struct callback_context { int mode; };

static int synthetic_trust(void *opaque, const struct m27_storage_boot_observation *obs,
                           struct m27_storage_boot_attestation *a)
{
    struct callback_context *ctx = (struct callback_context *)opaque;
    if (ctx->mode == 1)
        return -1;
    a->abi = M27_STORAGE_BOOT_ABI_V1;
    a->struct_size = sizeof(*a);
    a->proofs = M27_STORAGE_BOOT_REQUIRED_PROOFS;
    a->checkpoint_xid = obs->nx.xid;
    memcpy(a->container_uuid, obs->nx.container_uuid, 16);
    memcpy(a->volume_group_uuid, obs->volume_group_uuid, 16);
    memcpy(a->system_uuid, obs->volumes[0].uuid, 16);
    memcpy(a->snapshot_system_uuid, obs->snapshot_system_uuid, 16);
    memcpy(a->snapshot_name, obs->snapshot_name, sizeof(a->snapshot_name));
    memset(a->ssv_root_hash_sha256, 0x88, 32);
    memset(a->signed_manifest_sha384, 0x99, 48);
    memset(a->localpolicy_nsih_sha384, 0x99, 48);
    memset(a->recovery_policy_measurement_sha384, 0xbb, 48);
    memset(a->cryptex_manifest_sha384, 0xcc, 48);
    switch (ctx->mode) {
    case 2: a->proofs &= ~M27_STORAGE_PROOF_SSV_MERKLE_APPLE_SEAL; break;
    case 3: a->proofs |= 0x80u; break;
    case 4: a->checkpoint_xid = 1; break;
    case 5: a->system_uuid[0]++; break;
    case 6: a->volume_group_uuid[0]++; break;
    case 7: a->snapshot_name[0] = 'x'; break;
    case 8: memset(a->ssv_root_hash_sha256, 0, 32); break;
    case 9: memset(a->signed_manifest_sha384, 0, 48); break;
    case 10: memset(a->localpolicy_nsih_sha384, 0, 48); break;
    case 11: memset(a->recovery_policy_measurement_sha384, 0, 48); break;
    case 12: memset(a->cryptex_manifest_sha384, 0, 48); break;
    case 13: a->abi = 2; break;
    case 14: a->struct_size = 0; break;
    case 15: a->reserved = 1; break;
    case 16: a->snapshot_system_uuid[0]++; break;
    case 17: a->container_uuid[0]++; break;
    case 18: a->localpolicy_nsih_sha384[0]++; break;
    default: break;
    }
    return 0;
}

static void trust_negatives(void)
{
    struct m27_storage_boot_observation obs;
    struct m27_storage_boot_mount_plan plan;
    struct callback_context context;
    struct m27_storage_boot_trust_ops ops;
    int i;
    fill(&obs);
    memset(&ops, 0, sizeof(ops));
    assert(m27_storage_boot_prepare(&obs, &ops, &plan) ==
           M27_STORAGE_BOOT_NEEDS_TRUST);
    ops.abi = M27_STORAGE_BOOT_ABI_V1;
    ops.struct_size = sizeof(ops);
    context.mode = 0;
    ops.ctx = &context;
    assert(m27_storage_boot_prepare(&obs, &ops, &plan) ==
           M27_STORAGE_BOOT_NEEDS_TRUST);
    ops.verify = synthetic_trust;
    ops.abi = 0;
    assert(m27_storage_boot_prepare(&obs, &ops, &plan) ==
           M27_STORAGE_BOOT_NEEDS_TRUST);
    ops.abi = M27_STORAGE_BOOT_ABI_V1;
    ops.struct_size = 0;
    assert(m27_storage_boot_prepare(&obs, &ops, &plan) ==
           M27_STORAGE_BOOT_NEEDS_TRUST);
    ops.struct_size = sizeof(ops);
    for (i = 1; i <= 18; i++) {
        context.mode = i;
        memset(&plan, 0xA5, sizeof(plan));
        assert(m27_storage_boot_prepare(&obs, &ops, &plan) ==
               M27_STORAGE_BOOT_AUTH_FAILED);
        assert_blank(&plan);
    }
    /* No real trust check has occurred here. This only tests trusted-callback
     * ABI and output planning mechanics; it is NEVER a bootability claim. */
    context.mode = 0;
    memset(&plan, 0, sizeof(plan));
    assert(m27_storage_boot_prepare(&obs, &ops, &plan) ==
           M27_STORAGE_BOOT_DELEGATED_PLAN);
    assert(plan.read_only == 1 && plan.apfs_sealed_snapshot == 1);
    assert(plan.resolved_checkpoint_xid == obs.nx.xid);
    assert(memcmp(plan.data_uuid, obs.volumes[1].uuid, 16) == 0);
    assert(strcmp(plan.snapshot_name, obs.snapshot_name) == 0);
    assert(m27_storage_boot_prepare(&obs, &ops, NULL) ==
           M27_STORAGE_BOOT_INVALID);
}

/* Optional on-disk probe: reads only the first APFS block of an existing
 * offline image, no copy (even when the image is 14 GB). */
static int inspect_real_readonly(const char *filename)
{
    int fd;
    uint8_t block[4096];
    struct m27_storage_boot_nxsb nx;
    struct stat details;
    unsigned listed = 0, i;
    if (!filename)
        return 0;
    fd = open(filename, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
    if (fd < 0) {
        perror("offline APFS image open");
        return 1;
    }
    if (fstat(fd, &details) != 0 || !S_ISREG(details.st_mode)) {
        fputs("offline APFS probe: only regular files permitted\n", stderr);
        close(fd);
        return 1;
    }
    if (read(fd, block, sizeof(block)) != (ssize_t)sizeof(block)) {
        fputs("offline APFS image too short\n", stderr);
        close(fd);
        return 1;
    }
    close(fd);
    if (m27_storage_boot_parse_nxsb(block, sizeof(block), &nx) !=
        M27_STORAGE_BOOT_STRUCTURAL) {
        fputs("offline APFS image NXSB rejected (never mounted)\n", stderr);
        return 1;
    }
    for (i = 0; i < nx.max_fs; i++)
        if (nx.fs_oids[i] != 0)
            listed++;
    printf("offline NXSB: xid=%llu blocks=%llu block_size=%u fs_oids=%u; "
           "readonly=1 mount=never structural-only=1\n",
           (unsigned long long)nx.xid, (unsigned long long)nx.block_count,
           nx.block_size, listed);
    assert(listed < M27_STORAGE_BOOT_MAX_VOLUMES || listed <= nx.max_fs);
    return 0;
}

int main(int argc, char **argv)
{
    parse_negatives();
    preflight_negatives();
    trust_negatives();
    if (argc > 2) {
        fputs("usage: test-macos27-storage-boot [offline-raw-apfs-image]\n", stderr);
        return 2;
    }
    if (argc == 2 && inspect_real_readonly(argv[1]))
        return 1;
    puts("macOS27 storage boot: negative gate/parser/trust ABI tests PASSED");
    return 0;
}
