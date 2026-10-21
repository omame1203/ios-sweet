/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef MACOS27_STORAGE_BOOT_GATE_H
#define MACOS27_STORAGE_BOOT_GATE_H
/*
 * macOS 27 / arm64e APFS root pre-mount gate, freestanding ISO C11 ABI v1.
 * NO platform I/O, DMA, APFS mounting, Apple signatures or cryptography.
 * A structurally valid disk is NOT an authenticated/bootable disk.
 *
 * The platform is responsible for checkpoint/object-map traversal, block
 * reads, full snapshot and SSV Merkle proofs, Image4/Apple trust anchor,
 * Secure Enclave LocalPolicy/1TR and Cryptex measurements. A callback in
 * this ABI is a TRUST BOUNDARY, never a substitute for those primitives.
 *
 * Link into a future shim with -std=c11; no XNU-specific dependencies.
 */

#include <stddef.h>
#include <stdint.h>

#define M27_STORAGE_BOOT_ABI_V1 1u
#define M27_STORAGE_BOOT_MAX_VOLUMES 5u
#define M27_STORAGE_BOOT_BUILD_MAX 24u
#define M27_STORAGE_BOOT_SNAPSHOT_MAX 112u

enum m27_storage_boot_status {
    M27_STORAGE_BOOT_INVALID = -1,
    M27_STORAGE_BOOT_UNSUPPORTED = -2,
    M27_STORAGE_BOOT_CONFLICT = -3,
    M27_STORAGE_BOOT_MISSING = -4,
    M27_STORAGE_BOOT_AUTH_FAILED = -5,
    M27_STORAGE_BOOT_NEEDS_TRUST = 0,
    /* Indicates format/metadata consistency ONLY, not permission to mount. */
    M27_STORAGE_BOOT_STRUCTURAL = 1,
    /* Plan emitted only after FULL authoritative verifier callback; it has
     * not been mounted and does not establish native boot success. */
    M27_STORAGE_BOOT_DELEGATED_PLAN = 2
};

enum m27_storage_boot_apfs_role {
    M27_STORAGE_ROLE_SYSTEM = 0x0001u,
    M27_STORAGE_ROLE_RECOVERY = 0x0004u,
    M27_STORAGE_ROLE_VM = 0x0008u,
    M27_STORAGE_ROLE_PREBOOT = 0x0010u,
    M27_STORAGE_ROLE_DATA = 0x0040u
};

/* Zero-terminated UUIDs in these structures are RAW 16-byte UUID values,
 * not strings. Never compare SSV/system volume UUID to the VolumeGroup ID. */
struct m27_storage_boot_nxsb {
    uint8_t container_uuid[16];
    uint64_t xid;
    uint64_t block_count;
    uint64_t fs_oids[100];
    uint32_t block_size;
    uint32_t max_fs;
};

struct m27_storage_boot_apsb {
    uint8_t uuid[16];
    uint8_t group_uuid[16];
    uint64_t oid;
    uint64_t xid;
    uint64_t snapshot_count;
    uint64_t integrity_oid;
    uint64_t incompatible_features;
    uint16_t role;
};

/* Observed/preflight metadata is NEVER an authenticated security verdict.
 * For compactness, role entries may be in any order and the gate rejects
 * unknown/repeated roles. Missing proof of latest checkpoint is handled by
 * the delegated verifier, NOT inferred from one good NXSB or APSB checksum.
 */
struct m27_storage_boot_observation {
    uint32_t abi;
    uint32_t struct_size;
    uint32_t macos_major;             /* exactly 27 */
    uint32_t architecture;            /* 1 = arm64e */
    char build[M27_STORAGE_BOOT_BUILD_MAX]; /* canonical 26[A-Z][0-9]+suffix */
    struct m27_storage_boot_nxsb nx;
    struct m27_storage_boot_apsb volumes[M27_STORAGE_BOOT_MAX_VOLUMES];
    uint32_t volume_count;
    uint32_t preboot_kernel_collection_present;
    uint32_t preboot_localpolicy_present;
    uint32_t recovery_artifact_present;
    uint32_t system_version_plist_present;
    uint32_t snapshot_selected;
    uint32_t ufs_ro_block_reader_available;
    uint8_t preboot_system_uuid[16];
    uint8_t snapshot_system_uuid[16];
    uint8_t volume_group_uuid[16];
    char snapshot_name[M27_STORAGE_BOOT_SNAPSHOT_MAX];
};

/* Claims below must come from an independent, authenticated implementation.
 * The gate never infers any of them from APSB bits or a caller-supplied hash.
 */
enum m27_storage_boot_proof {
    M27_STORAGE_PROOF_APFS_CHECKPOINT_OMAP = 1u << 0,
    M27_STORAGE_PROOF_SSV_MERKLE_APPLE_SEAL = 1u << 1,
    M27_STORAGE_PROOF_IMAGE4_BOOTKC = 1u << 2,
    M27_STORAGE_PROOF_SEP_LOCALPOLICY_NSIH_VUID = 1u << 3,
    M27_STORAGE_PROOF_PAIRED_RECOVERY_1TR = 1u << 4,
    M27_STORAGE_PROOF_PREBOOT_BINDING = 1u << 5,
    M27_STORAGE_PROOF_CRYPTEX_SPIH = 1u << 6
};

#define M27_STORAGE_BOOT_REQUIRED_PROOFS ((uint32_t)0x7fu)

struct m27_storage_boot_attestation {
    uint32_t abi;
    uint32_t struct_size;
    uint32_t proofs;          /* issued by trusted backend, NEVER input JSON */
    uint32_t reserved;
    uint8_t container_uuid[16];
    uint8_t volume_group_uuid[16];
    uint8_t system_uuid[16];
    uint8_t snapshot_system_uuid[16];
    uint64_t checkpoint_xid;  /* actually resolved freshest valid checkpoint */
    uint8_t ssv_root_hash_sha256[32];
    uint8_t signed_manifest_sha384[48];
    uint8_t localpolicy_nsih_sha384[48];
    uint8_t recovery_policy_measurement_sha384[48];
    uint8_t cryptex_manifest_sha384[48];
    char snapshot_name[M27_STORAGE_BOOT_SNAPSHOT_MAX];
};

struct m27_storage_boot_trust_ops {
    uint32_t abi;
    uint32_t struct_size;
    /* MUST perform real checkpoint/OMAP/SSV/Image4/SEP/1TR/Cryptex trust
     * verification, measure authenticated values and fill *attestation.
     * Returning 0 means attestation fully initialized; nonzero fails closed.
     * For this port NO trusted implementation currently exists. */
    int (*verify)(void *ctx, const struct m27_storage_boot_observation *observed,
                  struct m27_storage_boot_attestation *attestation);
    void *ctx;
};

/* This is a description of the root mount request, not a mount operation. */
struct m27_storage_boot_mount_plan {
    uint32_t abi;
    uint32_t struct_size;
    uint8_t container_uuid[16];
    uint8_t volume_group_uuid[16];
    uint8_t system_uuid[16];
    uint8_t data_uuid[16];
    uint64_t resolved_checkpoint_xid;
    uint32_t read_only;
    uint32_t apfs_sealed_snapshot;
    char snapshot_name[M27_STORAGE_BOOT_SNAPSHOT_MAX];
};

/* Untrusted APFS parsing helpers: verify Fletcher64 and bounded headers,
 * not whether an APSB is the latest version or maps through current OMAP. */
int m27_storage_boot_parse_nxsb(const void *block, size_t length,
                               struct m27_storage_boot_nxsb *out);
int m27_storage_boot_parse_apsb(const void *block, size_t length,
                               struct m27_storage_boot_apsb *out);

/* Return STRUCTURAL on pass; no mount plan and no trust implied. */
int m27_storage_boot_preflight(const struct m27_storage_boot_observation *obs);

/* No verifier => NEEDS_TRUST and plan fully zeroed. All callback failures,
 * absent evidence, mismatched bindings, or unknown version/layout => reject.
 * DELEGATED_PLAN depends entirely on the trusted caller's verifier and must
 * NOT be reported as Apple hardware boot or seal validation by this library.
 */
int m27_storage_boot_prepare(const struct m27_storage_boot_observation *obs,
                             const struct m27_storage_boot_trust_ops *trust,
                             struct m27_storage_boot_mount_plan *plan);

#endif
