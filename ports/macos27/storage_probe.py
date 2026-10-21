#!/usr/bin/env python3
"""Offline read-only macOS 27 APFS VolumeGroup / Preboot readiness gate.

Only inspect ordinary files: raw APFS *container partition* (NXSB at byte 0),
caller-supplied APSB physical block offsets and extracted Preboot/Recovery
artifacts. No mounting, block-device access, security bypass, writes or boot.

APSB offsets are physical *hints*, not verified NX object-map resolutions.
SSV seal, snapshot selection, Image4 trust, LocalPolicy/SEP and paired 1TR are
not cryptographically verified by this code. Passing means structural evidence
was coherent; it NEVER means the disk can boot on Apple silicon or POCO Pad.

References: Apple File System Reference; Apple Platform Security (APFS roles,
SSV, LocalPolicy); preserved apfs-fuse/ApfsLib/DiskStruct.h and Util.cpp.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import struct
import sys
import uuid


ROLES = {"System": 0x0001, "Data": 0x0040, "Preboot": 0x0010,
         "Recovery": 0x0004, "VM": 0x0008}
NXSB_MAGIC = b"NXSB"
APSB_MAGIC = b"APSB"
BLOCK_MIN = 4096
BLOCK_MAX = 65536
MASK = 0xFFFFFFFF
MODULUS = 0xFFFFFFFF
SEALED_VOLUME_FEATURE = 0x20
MAX_MANIFEST = 65536
MAX_PLIST = 65536


class ReadinessError(ValueError):
    pass


def fail(message: str) -> None:
    raise ReadinessError(message)


def expect(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def exact_fields(obj: object, keys: set[str], label: str) -> dict:
    expect(type(obj) is dict, f"{label}: must be an object")
    expect(set(obj) == keys, f"{label}: unsupported or missing fields: {sorted(set(obj) ^ keys)}")
    return obj


def parse_uuid(value: object, label: str) -> uuid.UUID:
    expect(type(value) is str, f"{label}: UUID must be text")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        fail(f"{label}: malformed UUID")
    expect(str(parsed).upper() == value, f"{label}: UUID must be uppercase canonical")
    expect(parsed.int != 0, f"{label}: zero UUID forbidden")
    return parsed


def hex_digest(value: object, label: str) -> str:
    expect(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
           f"{label}: expected lowercase 64-hex SHA256")
    expect(value != "0" * 64, f"{label}: zero placeholder hash forbidden")
    return value


def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    output: dict = {}
    for key, value in pairs:
        if key in output:
            fail(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def regular_file(path: Path, label: str) -> int:
    """Refuse symlinks, directories, pipes and devices before opening."""
    expect(not path.is_symlink(), f"{label}: symlink forbidden")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        fail(f"{label}: cannot open read-only: {exc.strerror}")
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        fail(f"{label}: only regular offline files allowed")
    return fd


def safe_path(root: Path, relative: object, label: str) -> Path:
    expect(type(relative) is str and len(relative) <= 1024, f"{label}: invalid path")
    expect("\\" not in relative and "\x00" not in relative and "//" not in relative,
           f"{label}: malformed path")
    parts = PurePosixPath(relative)
    expect(not parts.is_absolute() and bool(parts.parts) and
           all(part not in ("..", ".", "") for part in parts.parts) and
           relative not in (".", ".."), f"{label}: path traversal / absolute path")
    child = root
    for part in parts.parts:
        child = child / part
        expect(not child.is_symlink(), f"{label}: symlink path forbidden")
    expect(child.resolve().is_relative_to(root.resolve()), f"{label}: path escaped root")
    return child


def read_regular(path: Path, label: str, limit: int) -> bytes:
    fd = regular_file(path, label)
    try:
        expect(os.fstat(fd).st_size <= limit, f"{label}: exceeds size limit")
        with os.fdopen(fd, "rb", closefd=False) as f:
            return f.read(limit + 1)
    finally:
        os.close(fd)


def sha256_regular(path: Path, expected: str, label: str) -> int:
    digest = hashlib.sha256()
    fd = regular_file(path, label)
    try:
        size = os.fstat(fd).st_size
        expect(size > 0, f"{label}: empty artifact")
        with os.fdopen(fd, "rb", closefd=False) as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        expect(digest.hexdigest() == hex_digest(expected, label),
               f"{label}: artifact SHA256 mismatch")
        return size
    finally:
        os.close(fd)


def u32(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<I", buf, offset)[0]


def u64(buf: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", buf, offset)[0]


def checksum_ok(data: bytes) -> bool:
    """APFS Fletcher64 modulo 2^32-1 including stored first eight bytes."""
    if len(data) < BLOCK_MIN or len(data) % 4:
        return False
    stored = u64(data, 0)
    if stored in (0, 0xFFFFFFFFFFFFFFFF):
        return False
    total1 = total2 = 0
    for (word,) in struct.iter_unpack("<I", data[8:]):
        total1 += word
        total2 += total1
    total1 %= MODULUS
    total2 %= MODULUS
    for word in (stored & MASK, stored >> 32):
        total1 = (total1 + word) % MODULUS
        total2 = (total2 + total1) % MODULUS
    return total1 == total2 == 0


def read_at(fd: int, offset: int, size: int, length: int, label: str) -> bytes:
    expect(type(offset) is int and offset >= 0 and type(size) is int and size > 0,
           f"{label}: invalid offset/length")
    expect(offset <= length and size <= length - offset,
           f"{label}: block outside partition image")
    data = os.pread(fd, size, offset)
    expect(len(data) == size, f"{label}: truncated block")
    return data


def object_header(block: bytes, magic: bytes, objtype: int, label: str) -> None:
    expect(block[32:36] == magic, f"{label}: incorrect APFS magic")
    expect((u32(block, 24) & 0xFFFF) == objtype, f"{label}: object type mismatch")
    expect(u64(block, 8) != 0 and u64(block, 16) != 0,
           f"{label}: null object ID or transaction ID")
    expect(checksum_ok(block), f"{label}: APFS Fletcher64 mismatch")


def inspect_image(path: Path, container_id: uuid.UUID, volumes: list[dict]) -> dict:
    fd = regular_file(path, "container image")
    try:
        size = os.fstat(fd).st_size
        expect(size >= 1024 * 1024, "container: too small to be APFS")
        head = read_at(fd, 0, BLOCK_MIN, size, "NXSB")
        expect(head[32:36] == NXSB_MAGIC, "container: HFS/unknown magic; APFS required")
        block_size = u32(head, 36)
        expect(block_size in (4096, 8192, 16384, 32768, 65536),
               "container: unsupported APFS block size")
        nx = read_at(fd, 0, block_size, size, "NXSB")
        object_header(nx, NXSB_MAGIC, 1, "NXSB")
        expect(u64(nx, 8) == 1, "NXSB: expected object ID 1")
        expect(u64(nx, 40) >= 256 and u64(nx, 40) <= size // block_size,
               "NXSB: invalid block count")
        expect(uuid.UUID(bytes=nx[72:88]) == container_id,
               "NXSB: container UUID differs from manifest")
        expect(u32(nx, 180) >= 5 and u32(nx, 180) <= 100,
               "NXSB: unsupported max file system count")
        oids = {u64(nx, 184 + i * 8) for i in range(100)} - {0}
        expect(len(oids) >= 5, "NXSB: fewer than five populated volume OIDs")
        found_roles: dict[str, dict] = {}
        used_offsets: set[int] = set()
        for volume in volumes:
            role = volume["role"]
            offset = volume["superblock_offset"]
            expect(type(offset) is int and offset > 0 and offset % block_size == 0,
                   f"{role}: APSB offset must be aligned and nonzero")
            expect(offset not in used_offsets, f"{role}: reused APSB physical block")
            used_offsets.add(offset)
            sb = read_at(fd, offset, block_size, size, f"{role} APSB")
            object_header(sb, APSB_MAGIC, 13, f"{role} APSB")
            expect(u64(sb, 8) in oids, f"{role}: APSB OID absent from NXSB volume list")
            expect(uuid.UUID(bytes=sb[240:256]) == parse_uuid(volume["uuid"], role),
                   f"{role}: volume UUID differs from APSB")
            expect(struct.unpack_from("<H", sb, 964)[0] == ROLES[role],
                   f"{role}: incorrect APFS role")
            group = uuid.UUID(bytes=sb[1008:1024])
            if role in ("System", "Data"):
                expect(group == parse_uuid(volume["group_uuid"], f"{role} group"),
                       f"{role}: APSB VolumeGroup UUID mismatch")
            else:
                expect(group.int == 0 and volume["group_uuid"] is None,
                       f"{role}: shared volume must not belong to OS volume group")
            if role == "System":
                expect(u64(sb, 56) & SEALED_VOLUME_FEATURE != 0,
                       "System: missing sealed-volume incompatible feature")
                expect(u64(sb, 216) > 0, "System: no snapshot metadata count")
                expect(u64(sb, 1024) != 0, "System: absent integrity metadata object")
            found_roles[role] = {"uuid": volume["uuid"], "oid": u64(sb, 8)}
        return {"block_size": block_size, "container_uuid": str(container_id).upper(),
                "apfs_roles": found_roles}
    finally:
        os.close(fd)


def validate(manifest: object, root: Path) -> dict:
    m = exact_fields(manifest, {"schema", "platform", "architecture", "container_image",
                                "container_uuid", "volume_group_uuid", "volumes",
                                "system_version_plist", "preboot", "recovery", "snapshot"},
                     "manifest")
    expect(type(m["schema"]) is int and m["schema"] == 1, "unsupported manifest schema")
    expect(m["platform"] == "macOS" and m["architecture"] == "arm64",
           "wrong platform or architecture (macOS arm64 required)")
    group = parse_uuid(m["volume_group_uuid"], "target VolumeGroup")
    container = parse_uuid(m["container_uuid"], "container")
    volumes = m["volumes"]
    expect(type(volumes) is list and len(volumes) == 5,
           "unsupported layout: require exactly five APFS roles")
    rolemap = {}
    all_uuids = set()
    for v in volumes:
        exact_fields(v, {"role", "uuid", "group_uuid", "superblock_offset"}, "volume")
        role = v["role"]
        expect(type(role) is str and role in ROLES, "unsupported APFS role")
        expect(role not in rolemap, f"duplicate role: {role}")
        vid = parse_uuid(v["uuid"], f"{role} UUID")
        expect(vid not in all_uuids, f"reused volume UUID: {role}")
        all_uuids.add(vid)
        if role in ("System", "Data"):
            expect(parse_uuid(v["group_uuid"], f"{role} group") == group,
                   "System/Data VolumeGroup mismatch")
        else:
            expect(v["group_uuid"] is None, f"{role}: group UUID must be null")
        rolemap[role] = v
    expect(set(rolemap) == set(ROLES), "missing essential APFS role")
    image = inspect_image(safe_path(root, m["container_image"], "container image"),
                          container, volumes)

    plistpath = safe_path(root, m["system_version_plist"], "SystemVersion.plist")
    plist = plistlib.loads(read_regular(plistpath, "SystemVersion.plist", MAX_PLIST))
    expect(type(plist) is dict, "SystemVersion.plist: not a dictionary")
    version, build = plist.get("ProductVersion"), plist.get("ProductBuildVersion")
    expect(plist.get("ProductName") == "macOS", "SystemVersion.plist: wrong product")
    expect(type(version) is str and re.fullmatch(r"27\.\d+(?:\.\d+)?", version) is not None,
           "SystemVersion.plist: macOS major must be exactly 27")
    expect(type(build) is str and re.fullmatch(r"26[A-Z][0-9]{3,5}[a-z]?", build) is not None,
           "SystemVersion.plist: unexpected macOS 27 build train")

    sn = exact_fields(m["snapshot"], {"system_uuid", "name", "seal_sha256"}, "snapshot")
    expect(parse_uuid(sn["system_uuid"], "snapshot volume") ==
           parse_uuid(rolemap["System"]["uuid"], "System"),
           "snapshot: incorrect System volume association")
    expect(type(sn["name"]) is str and
           re.fullmatch(r"com\.apple\.os\.update-[A-Za-z0-9-]{1,96}", sn["name"]),
           "snapshot: unsupported boot snapshot name")
    hex_digest(sn["seal_sha256"], "snapshot seal assertion")

    system_uuid = rolemap["System"]["uuid"]
    pb = exact_fields(m["preboot"], {"slot_uuid", "boot_kc", "boot_kc_sha256",
                                     "localpolicy", "localpolicy_sha256"}, "preboot")
    expect(parse_uuid(pb["slot_uuid"], "Preboot slot") ==
           parse_uuid(system_uuid, "System UUID"),
           "Preboot: slot does not identify System volume")
    prefix = f"preboot/{system_uuid}/"
    for key in ("boot_kc", "localpolicy"):
        expect(type(pb[key]) is str and pb[key].startswith(prefix),
               f"Preboot: {key} must be under exact System UUID slot")
    expect(pb["boot_kc"].endswith("/BootKernelExtensions.kc"),
           "Preboot: unsupported boot kernel collection layout")
    file_sizes = {}
    for key in ("boot_kc", "localpolicy"):
        file_sizes[key] = sha256_regular(safe_path(root, pb[key], f"preboot {key}"),
                                        pb[key + "_sha256"], f"preboot {key}")

    recovery = exact_fields(m["recovery"], {"artifact", "artifact_sha256"}, "recovery")
    expect(type(recovery["artifact"]) is str and
           recovery["artifact"].startswith("recovery/"),
           "Recovery artifact must be under extracted recovery root")
    file_sizes["recovery_artifact"] = sha256_regular(
        safe_path(root, recovery["artifact"], "Recovery artifact"),
        recovery["artifact_sha256"], "Recovery artifact")

    return {
        "result": "STRUCTURAL_EVIDENCE_ONLY",
        "macos_version": version,
        "build": build,
        "volume_group_uuid": str(group).upper(),
        "container": image,
        "verified_file_lengths": file_sizes,
        "bootable": False,
        "blockers": [
            "No APFS checkpoint/object-map resolution or full filesystem consistency proof",
            "Snapshot seal assertion is not a verified Merkle tree or Apple signature",
            "Image4 BootKC trust chain, LocalPolicy SEP signature/nsih and paired Recovery/1TR are not validated",
            "Offline extracted Preboot/Recovery files are not cryptographically tied to APFS container",
            "dizi has an HFS iPadOS root and no verified macOS 27 APFS/boot-security driver chain",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path,
                        help="JSON evidence manifest; offline regular file only")
    parser.add_argument("--root", required=True, type=Path,
                        help="directory of offline image and extracted artifacts")
    opts = parser.parse_args(argv)
    try:
        expect(opts.root.is_dir() and not opts.root.is_symlink(),
               "root must be an existing offline directory")
        fd = regular_file(opts.manifest, "manifest")
        try:
            expect(os.fstat(fd).st_size <= MAX_MANIFEST, "manifest oversized")
            with os.fdopen(fd, "rb", closefd=False) as f:
                raw = f.read(MAX_MANIFEST + 1)
        finally:
            os.close(fd)
        manifest = json.loads(raw, object_pairs_hook=no_duplicate_keys)
        print(json.dumps(validate(manifest, opts.root), indent=2, sort_keys=True))
        return 0
    except (ReadinessError, ValueError, plistlib.InvalidFileException,
            OSError, json.JSONDecodeError, struct.error) as exc:
        print(json.dumps({"result": "REJECTED", "bootable": False,
                          "reason": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
