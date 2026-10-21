#!/usr/bin/env python3
"""Synthetic APFS block fixtures: strict negative readiness/fail-closed tests."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid


SOURCE = Path(__file__).resolve().parents[1] / "ports/macos27/storage_probe.py"
sys.path.insert(0, str(SOURCE.parent))
import storage_probe as probe  # noqa: E402


SYSTEM = "11111111-1111-4111-8111-111111111111"
DATA = "22222222-2222-4222-8222-222222222222"
PREBOOT = "33333333-3333-4333-8333-333333333333"
RECOVERY = "44444444-4444-4444-8444-444444444444"
VM = "55555555-5555-4555-8555-555555555555"
GROUP = "66666666-6666-4666-8666-666666666666"
CONTAINER = "77777777-7777-4777-8777-777777777777"
ROLES = (("System", SYSTEM), ("Data", DATA), ("Preboot", PREBOOT),
         ("Recovery", RECOVERY), ("VM", VM))


def mark_checksum(data: bytearray) -> None:
    """Inverse APFS Fletcher checksum, independent from checker implementation."""
    struct.pack_into("<Q", data, 0, 0)
    sum1 = sum2 = 0
    for (word,) in struct.iter_unpack("<I", data[8:]):
        sum1 = (sum1 + word) % 0xFFFFFFFF
        sum2 = (sum2 + sum1) % 0xFFFFFFFF
    # APFS verifies the data words first, then the two checksum words;
    # choose a,b such that s1+a+b==0, s2+2*s1+2*a+b==0 modulo 2^32-1.
    c1 = (-sum1 - sum2) % 0xFFFFFFFF
    c2 = sum2 % 0xFFFFFFFF
    struct.pack_into("<II", data, 0, c1, c2)


def make_nx() -> bytes:
    b = bytearray(4096)
    struct.pack_into("<Q", b, 8, 1)
    struct.pack_into("<Q", b, 16, 10)
    struct.pack_into("<I", b, 24, 1)
    b[32:36] = b"NXSB"
    struct.pack_into("<I", b, 36, 4096)
    struct.pack_into("<Q", b, 40, 256)
    b[72:88] = uuid.UUID(CONTAINER).bytes
    struct.pack_into("<I", b, 180, 100)
    for i in range(5):
        struct.pack_into("<Q", b, 184 + i * 8, i + 1024)
    mark_checksum(b)
    return bytes(b)


def make_apsb(i: int, role: str, volume_uuid: str) -> bytes:
    b = bytearray(4096)
    struct.pack_into("<Q", b, 8, 1024 + i)
    struct.pack_into("<Q", b, 16, 10)
    struct.pack_into("<I", b, 24, 13)
    b[32:36] = b"APSB"
    if role == "System":
        struct.pack_into("<Q", b, 56, 0x20)
        struct.pack_into("<Q", b, 216, 1)
        struct.pack_into("<Q", b, 1024, 2121)
    b[240:256] = uuid.UUID(volume_uuid).bytes
    struct.pack_into("<H", b, 964, probe.ROLES[role])
    if role in ("System", "Data"):
        b[1008:1024] = uuid.UUID(GROUP).bytes
    mark_checksum(b)
    return bytes(b)


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        blocks = bytearray(4096 * 256)
        blocks[:4096] = make_nx()
        volumes = []
        for index, (role, ident) in enumerate(ROLES):
            offset = 4096 * (index + 1)
            blocks[offset:offset + 4096] = make_apsb(index, role, ident)
            volumes.append({"role": role, "uuid": ident,
                            "group_uuid": GROUP if role in ("System", "Data") else None,
                            "superblock_offset": offset})
        (root / "container.apfs").write_bytes(blocks)

        version = root / "system/System/Library/CoreServices/SystemVersion.plist"
        version.parent.mkdir(parents=True)
        version.write_bytes(plistlib.dumps({"ProductName": "macOS", "ProductVersion": "27.0.1",
                                            "ProductBuildVersion": "26A434"}))
        kc = root / f"preboot/{SYSTEM}/System/Library/KernelCollections/BootKernelExtensions.kc"
        kc.parent.mkdir(parents=True)
        kc.write_bytes(b"test kernel collection; no Apple signature")
        lp = root / f"preboot/{SYSTEM}/LocalPolicy/LocalPolicy.img4"
        lp.parent.mkdir(parents=True)
        lp.write_bytes(b"test local policy; no SEP signature")
        rec = root / "recovery/BaseSystem.dmg"
        rec.parent.mkdir(parents=True)
        rec.write_bytes(b"test recovery, not bootable")
        self.manifest = {
            "schema": 1, "platform": "macOS", "architecture": "arm64",
            "container_image": "container.apfs", "container_uuid": CONTAINER,
            "volume_group_uuid": GROUP, "volumes": volumes,
            "system_version_plist": str(version.relative_to(root)),
            "preboot": {"slot_uuid": SYSTEM,
                        "boot_kc": str(kc.relative_to(root)),
                        "boot_kc_sha256": hashlib.sha256(kc.read_bytes()).hexdigest(),
                        "localpolicy": str(lp.relative_to(root)),
                        "localpolicy_sha256": hashlib.sha256(lp.read_bytes()).hexdigest()},
            "recovery": {"artifact": str(rec.relative_to(root)),
                         "artifact_sha256": hashlib.sha256(rec.read_bytes()).hexdigest()},
            "snapshot": {"system_uuid": SYSTEM,
                         "name": "com.apple.os.update-1234",
                         "seal_sha256": "1" * 64},
        }

    def rewrite_block(self, offset: int, edit, *, recalc: bool = True):
        img = self.root / "container.apfs"
        with img.open("r+b") as f:
            f.seek(offset)
            block = bytearray(f.read(4096))
            edit(block)
            if recalc:
                mark_checksum(block)
            f.seek(offset)
            f.write(block)


class StorageProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="macos27-storage-")
        self.root = Path(self.tmp.name)
        self.f = Fixture(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def reject(self, message: str) -> None:
        with self.assertRaises(probe.ReadinessError) as error:
            probe.validate(self.f.manifest, self.root)
        self.assertIn(message.lower(), str(error.exception).lower())

    def test_valid_evidence_never_claims_bootability(self):
        result = probe.validate(self.f.manifest, self.root)
        self.assertEqual(result["macos_version"], "27.0.1")
        self.assertEqual(result["build"], "26A434")
        self.assertEqual(result["result"], "STRUCTURAL_EVIDENCE_ONLY")
        self.assertIs(result["bootable"], False)
        self.assertEqual(len(result["container"]["apfs_roles"]), 5)
        self.assertTrue(any("LocalPolicy" in b for b in result["blockers"]))

    def test_reject_hfs_as_apfs(self):
        self.f.rewrite_block(0, lambda b: b.__setitem__(slice(32, 36), b"HFS+"))
        self.reject("APFS required")

    def test_reject_superblock_checksum(self):
        self.f.rewrite_block(0, lambda b: b.__setitem__(128, 0xF1), recalc=False)
        self.reject("Fletcher64")

    def test_reject_volume_checksum(self):
        self.f.rewrite_block(4096, lambda b: b.__setitem__(128, 0xF1), recalc=False)
        self.reject("Fletcher64")

    def test_reject_wrong_container_uuid(self):
        self.f.rewrite_block(0, lambda b: b.__setitem__(slice(72, 88), uuid.UUID(GROUP).bytes))
        self.reject("container UUID differs")

    def test_reject_invalid_apfs_role(self):
        self.f.rewrite_block(4096, lambda b: struct.pack_into("<H", b, 964, 2))
        self.reject("incorrect APFS role")

    def test_reject_wrong_volume_group_on_disk(self):
        self.f.rewrite_block(4096, lambda b: b.__setitem__(slice(1008, 1024), uuid.UUID(CONTAINER).bytes))
        self.reject("VolumeGroup UUID mismatch")

    def test_reject_shared_volume_in_group(self):
        self.f.rewrite_block(4096 * 3,
                             lambda b: b.__setitem__(slice(1008, 1024), uuid.UUID(GROUP).bytes))
        self.reject("must not belong")

    def test_reject_unsealed_system(self):
        self.f.rewrite_block(4096, lambda b: struct.pack_into("<Q", b, 56, 0))
        self.reject("sealed-volume")

    def test_reject_missing_snapshot_count(self):
        self.f.rewrite_block(4096, lambda b: struct.pack_into("<Q", b, 216, 0))
        self.reject("snapshot metadata")

    def test_reject_missing_integrity_metadata(self):
        self.f.rewrite_block(4096, lambda b: struct.pack_into("<Q", b, 1024, 0))
        self.reject("integrity metadata")

    def test_reject_wrong_major(self):
        for version in ("16.7.16", "26.9", "28.0", "27beta", "127.1"):
            with self.subTest(version=version):
                plist = self.root / self.f.manifest["system_version_plist"]
                doc = plistlib.loads(plist.read_bytes())
                doc["ProductVersion"] = version
                plist.write_bytes(plistlib.dumps(doc))
                self.reject("major must be exactly 27")

    def test_reject_wrong_build_train(self):
        plist = self.root / self.f.manifest["system_version_plist"]
        doc = plistlib.loads(plist.read_bytes())
        doc["ProductBuildVersion"] = "20H392"
        plist.write_bytes(plistlib.dumps(doc))
        self.reject("build train")

    def test_reject_wrong_product(self):
        plist = self.root / self.f.manifest["system_version_plist"]
        doc = plistlib.loads(plist.read_bytes())
        doc["ProductName"] = "iPadOS"
        plist.write_bytes(plistlib.dumps(doc))
        self.reject("wrong product")

    def test_reject_wrong_arch(self):
        self.f.manifest["architecture"] = "x86_64"
        self.reject("wrong platform or architecture")

    def test_reject_wrong_manifest_platform(self):
        self.f.manifest["platform"] = "iPadOS"
        self.reject("wrong platform")

    def test_reject_extra_role(self):
        self.f.manifest["volumes"].append(copy.deepcopy(self.f.manifest["volumes"][0]))
        self.reject("exactly five")

    def test_reject_duplicate_role(self):
        self.f.manifest["volumes"][1]["role"] = "System"
        self.reject("duplicate role")

    def test_reject_duplicate_uuid(self):
        self.f.manifest["volumes"][1]["uuid"] = SYSTEM
        self.reject("reused volume UUID")

    def test_reject_missing_volume_group(self):
        self.f.manifest["volumes"][1]["group_uuid"] = CONTAINER
        self.reject("VolumeGroup mismatch")

    def test_reject_wrong_slot_uuid(self):
        self.f.manifest["preboot"]["slot_uuid"] = DATA
        self.reject("Preboot: slot")

    def test_reject_wrong_boot_kc_hash(self):
        self.f.manifest["preboot"]["boot_kc_sha256"] = "0" * 63 + "1"
        self.reject("SHA256 mismatch")

    def test_reject_missing_localpolicy(self):
        (self.root / self.f.manifest["preboot"]["localpolicy"]).unlink()
        self.reject("cannot open")

    def test_reject_missing_recovery(self):
        (self.root / self.f.manifest["recovery"]["artifact"]).unlink()
        self.reject("cannot open")

    def test_reject_path_traversal(self):
        self.f.manifest["preboot"]["localpolicy"] = f"preboot/{SYSTEM}/../../../../../etc/passwd"
        self.reject("path traversal")

    def test_reject_symlink(self):
        path = self.root / self.f.manifest["preboot"]["boot_kc"]
        backup = path.with_suffix(".original")
        path.rename(backup)
        path.symlink_to(backup)
        self.reject("symlink")

    def test_reject_duplicated_block_offset(self):
        self.f.manifest["volumes"][1]["superblock_offset"] = 4096
        self.reject("reused APSB")

    def test_reject_out_of_bounds_offset(self):
        self.f.manifest["volumes"][1]["superblock_offset"] = 4096 * 256
        self.reject("outside partition")

    def test_reject_unlisted_apfs_oid(self):
        self.f.rewrite_block(4096, lambda b: struct.pack_into("<Q", b, 8, 9001))
        self.reject("absent from NXSB")

    def test_reject_no_boot_snapshot_association(self):
        self.f.manifest["snapshot"]["system_uuid"] = DATA
        self.reject("incorrect System volume")

    def test_reject_fake_snapshot_seal(self):
        self.f.manifest["snapshot"]["seal_sha256"] = "0" * 64
        self.reject("placeholder hash")

    def test_reject_unknown_schema_and_keys(self):
        self.f.manifest["schema"] = 2
        self.reject("unsupported manifest schema")
        self.f.manifest["schema"] = 1
        self.f.manifest["bootable"] = True
        self.reject("unsupported or missing fields")

    def test_reject_container_not_regular_file(self):
        self.f.manifest["container_image"] = "/dev/null"
        self.reject("path traversal")

    def test_reject_duplicate_json_keys_in_cli(self):
        with self.assertRaises(probe.ReadinessError):
            json.loads('{"schema":1,"schema":2}', object_pairs_hook=probe.no_duplicate_keys)

    def test_cli_output_and_readonly(self):
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps(self.f.manifest), encoding="utf-8")
        original_hash = hashlib.sha256((self.root / "container.apfs").read_bytes()).hexdigest()
        run = subprocess.run([sys.executable, str(SOURCE), "--manifest", str(manifest),
                              "--root", str(self.root)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        doc = json.loads(run.stdout)
        self.assertIs(doc["bootable"], False)
        self.assertEqual(doc["result"], "STRUCTURAL_EVIDENCE_ONLY")
        self.assertEqual(hashlib.sha256((self.root / "container.apfs").read_bytes()).hexdigest(),
                         original_hash)
        manifest.write_text('{"schema":1,"schema":2}', encoding="utf-8")
        run = subprocess.run([sys.executable, str(SOURCE), "--manifest", str(manifest),
                              "--root", str(self.root)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertEqual(json.loads(run.stdout)["result"], "REJECTED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
