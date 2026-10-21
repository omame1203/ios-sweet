#!/usr/bin/env python3
"""No-device GKI boot-v4 packager tests; budgeted synthetic and real header checks."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import struct


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/macos27-temporary-image.py"
spec = importlib.util.spec_from_file_location("mac27_temporary_image", SOURCE)
assert spec is not None and spec.loader is not None
m27 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m27)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def synthetic_kc() -> bytes:
    return struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0xC0000002,
                       m27.MACHO_FILESET, 1, 256, 0, 0) + b"TEST-DATA-ONLY" * 300


class ImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mac27-review-test-")
        self.root = Path(self.temp.name)
        self.kc_bytes = synthetic_kc()
        self.kc = self.root / "kc.data"
        self.kc.write_bytes(self.kc_bytes)
        self.manifest_data = b"synthetic manifest, no Apple signature"
        self.manifest = self.root / "BuildManifest.plist"
        self.manifest.write_bytes(self.manifest_data)
        self.out = self.root / "review-v4.img"
        self.patches = [
            mock.patch.object(m27, "KC_SIZE", len(self.kc_bytes)),
            mock.patch.object(m27, "KC_SHA256", sha(self.kc_bytes)),
            mock.patch.object(m27, "MANIFEST_SHA256", sha(self.manifest_data)),
        ]
        for context in self.patches:
            context.start()

    def tearDown(self):
        for context in reversed(self.patches):
            context.stop()
        self.temp.cleanup()

    def test_real_preflight_elf_linker_linux_image(self):
        elf = m27.DEFAULT_ELF
        if not elf.is_file():
            self.skipTest("offline preflight ELF not present")
        image = self.root / "Image"
        result = m27.verify_elf(elf, image)
        raw = image.read_bytes()
        self.assertEqual(len(raw), result["image_size"])
        self.assertEqual(raw[56:60], b"ARM\x64")
        self.assertEqual(struct.unpack_from("<Q", raw, 24)[0], 0xA)
        self.assertEqual(struct.unpack_from("<Q", raw, 16)[0], len(raw))
        self.assertEqual((struct.unpack_from("<I", raw)[0] & 0x3FFFFFF) * 4,
                         result["entry_offset"])
        self.assertEqual(result["no_xnu_jump_verified_static_disassembly"], True)
        self.assertEqual(result["el1_diagnostics_may_access_hardware"], True)
        self.assertEqual(result["image_sha256"], sha(raw))

    def test_reject_modified_or_wrong_kc(self):
        self.assertEqual(m27.verify_kc(self.kc)["bytes"], len(self.kc_bytes))
        corrupted = self.root / "badkc"
        bad = bytearray(self.kc_bytes)
        bad[-1] ^= 1
        corrupted.write_bytes(bad)
        with self.assertRaisesRegex(m27.Rejected, "SHA256/size mismatch"):
            m27.verify_kc(corrupted)
        bad = bytearray(self.kc_bytes)
        struct.pack_into("<I", bad, 12, 2)
        corrupted.write_bytes(bad)
        with mock.patch.object(m27, "KC_SHA256", sha(bad)):
            with self.assertRaisesRegex(m27.Rejected, "MH_FILESET"):
                m27.verify_kc(corrupted)
        corrupted.write_bytes(b"x" * (len(self.kc_bytes) + 1))
        with self.assertRaisesRegex(m27.Rejected, "size mismatch"):
            m27.verify_kc(corrupted)

    def test_reject_manifest_mismatch(self):
        self.assertEqual(m27.verify_manifest(self.manifest)["sha256"], sha(self.manifest_data))
        self.manifest.write_bytes(b"wrong")
        with self.assertRaisesRegex(m27.Rejected, "provenance"):
            m27.verify_manifest(self.manifest)

    def test_refuse_symlink_and_device_inputs(self):
        link = self.root / "linkkc"
        link.symlink_to(self.kc)
        with self.assertRaises(m27.Rejected):
            m27.verify_kc(link)
        with self.assertRaises(m27.Rejected):
            m27.file_hash(Path("/dev/null"), 1024, "device")

    def test_no_gate_means_no_work_no_write(self):
        with mock.patch.object(m27, "command", side_effect=AssertionError("no subprocess permitted")):
            with self.assertRaisesRegex(m27.Rejected, "no-execute-review-gate"):
                m27.package(m27.DEFAULT_ELF, self.kc, self.manifest, self.out, enabled=False)
        self.assertFalse(self.out.exists())
        self.assertFalse(Path(str(self.out) + ".review.json").exists())

    def test_refuse_overwrite_preserves_exact_bytes(self):
        self.out.write_bytes(b"KNOWN IMAGE KEEP")
        with self.assertRaisesRegex(m27.Rejected, "already exists"):
            m27.package(m27.DEFAULT_ELF, self.kc, self.manifest, self.out, enabled=True)
        self.assertEqual(self.out.read_bytes(), b"KNOWN IMAGE KEEP")
        self.out.unlink()
        report = Path(str(self.out) + ".review.json")
        report.write_bytes(b"KEEP MANIFEST")
        with self.assertRaisesRegex(m27.Rejected, "already exists"):
            m27.package(m27.DEFAULT_ELF, self.kc, self.manifest, self.out, enabled=True)
        self.assertEqual(report.read_bytes(), b"KEEP MANIFEST")

    def test_refuse_output_symlink_and_invalid_parent(self):
        self.out.symlink_to(self.kc)
        with self.assertRaises(m27.Rejected):
            m27.package(m27.DEFAULT_ELF, self.kc, self.manifest, self.out, enabled=True)
        self.out.unlink()
        with self.assertRaisesRegex(m27.Rejected, "output parent"):
            m27.package(m27.DEFAULT_ELF, self.kc, self.manifest,
                        self.root / "nonexistent" / "review.img", enabled=True)

    def test_jump_gate_rejects_indirect_or_legacy_loader(self):
        code = """0000 <shim_main>:\n    0: aa0003e0 mov x0, x0\n    4: 94000010 bl 40 <mac27_dizi_probe_dtb>\n    8: 14000010 b 48 <bootlog_sync>\n"""
        start = """0000 <_start>:\n   0: 94000010 bl 40 <shim_main>\n   4: d503207f wfe\n"""
        with mock.patch.object(m27, "command", side_effect=[code, start]):
            m27.check_no_jump(m27.DEFAULT_ELF, {})
        for injected in ("   c: 94000010 bl 80 <loader_boot>\n",
                         "   c: d61f0000 br x0\n",
                         "   c: d63f0000 blr x0\n"):
            with self.subTest(injected=injected):
                with mock.patch.object(m27, "command", side_effect=[code + injected, start]):
                    with self.assertRaises(m27.Rejected):
                        m27.check_no_jump(m27.DEFAULT_ELF, {})

    def test_reject_modified_elf_architecture(self):
        if not m27.DEFAULT_ELF.is_file():
            self.skipTest("preflight ELF not present")
        badelf = self.root / "wrong-arch.elf"
        raw = bytearray(m27.DEFAULT_ELF.read_bytes())
        struct.pack_into("<H", raw, 18, 62)
        badelf.write_bytes(raw)
        with self.assertRaisesRegex(m27.Rejected, "AArch64"):
            m27.verify_elf(badelf, self.root / "outImage")

    def test_gki_v4_synthetic_roundtrip_validated_no_fastboot(self):
        if not m27.DEFAULT_ELF.is_file():
            self.skipTest("preflight ELF not present")
        allowed = {"aarch64-linux-gnu-nm", "aarch64-linux-gnu-objdump",
                   "aarch64-linux-gnu-objcopy", "mkbootimg"}
        real_command = m27.command
        observed_commands: list[str] = []

        def guarded_command(*argv: str) -> str:
            observed_commands.append(argv[0])
            self.assertIn(argv[0], allowed)
            return real_command(*argv)

        with mock.patch.object(m27, "command", side_effect=guarded_command):
            result = m27.package(m27.DEFAULT_ELF, self.kc, self.manifest,
                                 self.out, enabled=True)
        self.assertIn("mkbootimg", observed_commands)
        self.assertTrue(self.out.is_file())
        review = Path(str(self.out) + ".review.json")
        self.assertTrue(review.is_file())
        self.assertLess(self.out.stat().st_size, 1024 * 1024)
        self.assertTrue(result["no_xnu_jump"])
        self.assertFalse(result["native_macos27_boot_demonstrated"])
        self.assertFalse(result["apple_boot_trust_verified"])
        stored = json.loads(review.read_text())
        self.assertEqual(stored["kernel_collection_inert_data"]["sha256"], sha(self.kc_bytes))
        self.assertEqual(stored["android_gki_boot_v4"]["sha256"], sha(self.out.read_bytes()))
        self.assertEqual(stored["android_gki_boot_v4"]["header_version"], 4)
        self.assertEqual(stored["android_gki_boot_v4"]["ramdisk_size"], len(self.kc_bytes))
        before = (sha(self.kc.read_bytes()), sha(self.manifest.read_bytes()),
                  sha(m27.DEFAULT_ELF.read_bytes()))
        with self.assertRaisesRegex(m27.Rejected, "already exists"):
            m27.package(m27.DEFAULT_ELF, self.kc, self.manifest, self.out, enabled=True)
        after = (sha(self.kc.read_bytes()), sha(self.manifest.read_bytes()),
                 sha(m27.DEFAULT_ELF.read_bytes()))
        self.assertEqual(before, after)
        self.assertFalse(list(self.root.glob("mac27-nojump-*")))

    def test_reject_corrupted_gki_header_size_and_hash(self):
        image = self.root / "badboot.img"
        blob = bytearray(12288)
        blob[:8] = b"ANDROID!"
        struct.pack_into("<4I", blob, 8, 100, 130, 0, 1584)
        struct.pack_into("<I", blob, 40, 4)
        blob[44:44+len(b"mac27_diag_nojump=1")] = b"mac27_diag_nojump=1"
        image.write_bytes(blob[:-1])
        with self.assertRaisesRegex(m27.Rejected, "GKI v4 layout"):
            m27.verify_v4(image, 100, "a" * 64, 130, "b" * 64)
        struct.pack_into("<I", blob, 40, 3)
        image.write_bytes(blob)
        with self.assertRaisesRegex(m27.Rejected, "GKI boot v4"):
            m27.verify_v4(image, 100, "a" * 64, 130, "b" * 64)

    def test_cli_requires_explicit_review_gate(self):
        run = subprocess.run([sys.executable, str(SOURCE), "--preflight-elf", str(m27.DEFAULT_ELF),
                              "--kc", str(self.kc), "--output", str(self.out)],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertIn("no-execute-review-gate", run.stderr)
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
