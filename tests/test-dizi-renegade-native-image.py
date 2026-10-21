#!/usr/bin/env python3
"""Source-grounded host tests: actual GKI4/ARM64 stock header + EDK2 FD.

No USB/fastboot/flash, no fake Linux->UEFI trampoline. All generated fixtures
or genuine data are marked NONBOOTABLE and confined to disposable /tmp.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "tools/dizi-renegade-native-image.py"
SPEC = importlib.util.spec_from_file_location("dizi_native_stage", FILE)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def kernel_fixture() -> bytes:
    data = bytearray(4096)
    # Real Linux arm64 Image EFI-stub MZ instruction word + A64 branch.
    struct.pack_into("<IIQQQ", data, 0, 0x91005A4D, 0x1400000F, 0, 4096, 0xA)
    data[56:60] = b"ARM\x64"
    data[64:68] = struct.pack("<I", 0xD503201F)  # nop: structural only
    return bytes(data)


def fd_fixture() -> bytes:
    size = 0x10000
    data = bytearray(b"\xff" * size)
    data[:16] = bytes(16)
    struct.pack_into("<I", data, 0, 0x14000020)  # AArch64 B +0x80
    data[16:32] = bytes(range(16))
    struct.pack_into("<Q", data, 32, size)
    data[40:44] = b"_FVH"
    struct.pack_into("<H", data, 48, 72)
    struct.pack_into("<H", data, 50, 0)
    data[55] = 2
    struct.pack_into("<4I", data, 56, 1, size, 0, 0)
    struct.pack_into("<H", data, 50,
                     -sum(struct.unpack_from("<36H", data)) & 0xffff)
    # Synthetic FV bytes are NEVER machine-code SEC proof.
    return bytes(data)


def boot_fixture(kernel: bytes, ramdisk: bytes, signature: int = 4096) -> bytes:
    header = bytearray(4096)
    header[:8] = b"ANDROID!"
    struct.pack_into("<4I", header, 8, len(kernel), len(ramdisk), 0, 1584)
    struct.pack_into("<I", header, 40, 4)
    struct.pack_into("<I", header, 1580, signature)
    return (bytes(header) + kernel + bytes(tool.aligned(len(kernel)) - len(kernel)) +
            ramdisk + bytes(tool.aligned(len(ramdisk)) - len(ramdisk)) +
            bytes(tool.aligned(signature)))


def vendor_fixture() -> bytes:
    header = bytearray(4096)
    header[:8] = b"VNDRBOOT"
    struct.pack_into("<5I", header, 8, 4, 4096, 0x8000, 0x1000000, 100)
    struct.pack_into("<2I", header, 2096, 2128, 48)
    struct.pack_into("<Q", header, 2104, 0x1f00000)
    struct.pack_into("<4I", header, 2112, 108, 1, 108, 85)
    dtb = bytearray(48)
    dtb[:4] = b"\xd0\x0d\xfe\xed"
    return (bytes(header) + b"V" * 100 + bytes(4096 - 100) +
            bytes(dtb) + bytes(4096 - len(dtb)) +
            bytes(108) + bytes(4096 - 108) +
            bytes(85) + bytes(4096 - 85))


class DiziNativeImage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kernel = kernel_fixture()
        cls.fd = fd_fixture()
        cls.boot = boot_fixture(cls.kernel, b"INITRAMFS")
        cls.vendor = vendor_fixture()

    def test_actual_linux_efi_stub_image_header_is_not_sec(self):
        meta = tool.linux_image_header(self.kernel)
        self.assertTrue(meta["efi_stub_mz"])
        self.assertEqual(meta["initial_branch_at_offset"], 4)
        self.assertEqual(meta["arm64_magic"], "ARMd")
        self.assertFalse(meta["efi_sec_handoff_implemented"])
        for offset, new in ((56, b"XXXX"), (4, bytes(4)), (16, bytes(8)),
                            (24, struct.pack("<Q", 0x10000)), (32, b"ABCD")):
            with self.subTest(offset=offset):
                bad = bytearray(self.kernel)
                bad[offset:offset + len(new)] = new
                with self.assertRaises(tool.Reject):
                    tool.linux_image_header(bad)

    def test_real_android_boot_v4_and_vendor_v4_serializer_fields(self):
        desc, native, rd = tool.parse_boot_v4(self.boot, expected_sha=digest(self.boot))
        self.assertEqual(desc["header_version"], 4)
        self.assertEqual(desc["boot_signature_bytes"], 4096)
        self.assertEqual(desc["kernel_sha256"], digest(self.kernel))
        self.assertEqual(native, self.kernel)
        self.assertEqual(rd, b"INITRAMFS")
        v = tool.parse_vendor_v4(self.vendor, expected_sha=digest(self.vendor))
        self.assertEqual(v["header_bytes"], 2128)
        self.assertEqual(v["dtb_bytes"], 48)
        self.assertEqual(v["vendor_ramdisk_entries"], 1)
        self.assertFalse(v["vendor_ramdisk_merging_or_fd_offset_runtime_verified"])
        with self.assertRaisesRegex(tool.Reject, "pinned"):
            tool.parse_boot_v4(self.boot)
        with self.assertRaisesRegex(tool.Reject, "pin"):
            tool.parse_vendor_v4(self.vendor)

    def test_invalid_source_header_and_vendor_dtb_rejected(self):
        for offset, replacement in ((0, b"INVALID!"), (20, bytes(4)),
                                    (40, bytes(4)), (1580, b"\xff" * 4),
                                    (4096 + 56, b"BAD!")):
            with self.subTest(offset=offset):
                corrupted = bytearray(self.boot)
                corrupted[offset:offset + len(replacement)] = replacement
                with self.assertRaises(tool.Reject):
                    tool.parse_boot_v4(bytes(corrupted), expected_sha=digest(corrupted))
        for offset, replacement in ((0, b"INVALID!"), (8, bytes(4)),
                                    (2096, bytes(4)), (2112, b"\x01\0\0\0"),
                                    (4096 + 4096, bytes(4))):
            with self.subTest(offset=offset):
                corrupted = bytearray(self.vendor)
                corrupted[offset:offset + len(replacement)] = replacement
                with self.assertRaises(tool.Reject):
                    tool.parse_vendor_v4(bytes(corrupted), expected_sha=digest(corrupted))

    def test_exact_real_genfv_fv_header_and_checksum(self):
        desc = tool.edk2_fd_header(self.fd, expected_sha=digest(self.fd))
        self.assertEqual(desc["fv_length"], len(self.fd))
        self.assertTrue(desc["fv_checksum_valid"])
        self.assertFalse(desc["uefi_executable_ownership_verified"])
        for offset, new in ((0, bytes(4)), (40, b"NOPE"), (32, bytes(8)),
                            (50, b"\0\0"), (55, bytes([3])), (56, bytes(4))):
            with self.subTest(offset=offset):
                data = bytearray(self.fd)
                data[offset:offset + len(new)] = new
                with self.assertRaises(tool.Reject):
                    tool.edk2_fd_header(bytes(data), expected_sha=digest(data))

    def test_stage_gki4_is_structural_and_never_a_uefi_wrapper(self):
        raw, meta = tool.create_stage(self.kernel, self.fd)
        tool.verify_stage(raw, self.kernel, self.fd)
        self.assertEqual(raw[:8], b"ANDROID!")
        self.assertEqual(meta["boot_header_version"], 4)
        self.assertEqual(meta["ramdisk_start"], 4096 + 4096)
        self.assertEqual(meta["boot_signature_bytes"], 0)
        self.assertFalse(meta["actual_uefi_handoff"])
        for offset in (4, 8, 20, 40, 1580, 4096, 8192):
            broken = bytearray(raw)
            broken[offset] ^= 0x1
            with self.subTest(offset=offset), self.assertRaises(tool.Reject):
                tool.verify_stage(bytes(broken), self.kernel, self.fd)

    def test_destinations_refuse_symlinks_and_replacements(self):
        with tempfile.TemporaryDirectory(prefix="dizi-native-v4-") as tmp:
            folder = Path(tmp)
            link = folder / "link"
            link.symlink_to(folder, target_is_directory=True)
            # stage() uses captured pins; it must refuse our fixture before
            # any write, even with a synthetic perfectly valid header.
            a, b, c = folder / "boot", folder / "vendor", folder / "fd"
            a.write_bytes(self.boot)
            b.write_bytes(self.vendor)
            c.write_bytes(self.fd)
            with self.assertRaisesRegex(tool.Reject, "pinned source"):
                tool.stage(boot_path=a, vendor_path=b, fd_path=c, directory=folder)
            with self.assertRaisesRegex(tool.Reject, "regular input"):
                tool.regular_file(link, 1024)
            self.assertFalse((folder / tool.STAGE_BLOB).exists())

    def test_existing_upstream_allowlist_remains_empty(self):
        original = (ROOT / "tools/dizi-renegade-image.py").read_text()
        self.assertIn("VERIFIED_DIZI_WRAPPERS: dict[str, dict] = {}", original)
        handoff = (ROOT / "ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435/"
                   "DiziBootShim/DiziGkiHandoff.h").read_text()
        self.assertIn("DIZI_GKI_LAYOUT_UNAUTHORIZED = 1", handoff)
        self.assertIn("authorized_to_copy_or_execute", handoff)
        self.assertNotIn("fastboot", tool.__doc__.split("No fastboot")[-1])

    def test_worker8_genuine_native_elf_image_has_first_pc_and_no_transfer(self):
        if shutil.which("aarch64-linux-gnu-gcc") is None:
            self.skipTest("AArch64 compiler not installed")
        binary, meta = tool.build_native_entry_image()
        self.assertEqual(len(binary), 4096)
        self.assertEqual(struct.unpack_from("<IIQQQ", binary),
                         (0x14000010, 0, 0, 4096, 0xA))
        self.assertEqual(struct.unpack_from("<II", binary, 64),
                         (0xD53B422E, 0xD5034FDF))
        self.assertEqual(meta["first_pc"], 64)
        self.assertEqual(meta["native_image"]["sha256"], digest(binary))
        self.assertTrue(meta["parks_with_wfe_on_every_path"])
        self.assertFalse(meta["edk2_sec_transfer_permitted"])
        self.assertFalse(meta["native_image"]["efi_sec_handoff_implemented"])
        blob, desc = tool.create_stage(binary, self.fd)
        tool.verify_stage(blob, binary, self.fd)
        self.assertEqual(desc["bytes"], 4096 + 4096 + 0x10000)

    def test_real_captured_sources_stage_only_offline(self):
        boot = ROOT / "backup/dizi/boot_a.img"
        vendor = ROOT / "backup/dizi/vendor_boot_a.img"
        fd = Path("/tmp/dizi-edk2-msm-genuine-dizi-debug-20261021-w9/verify-cold/"
                  "Build/dizi/DEBUG_GCC5/FV/SM7435_UEFI.fd")
        if not all(p.is_file() for p in (boot, vendor, fd)):
            self.skipTest("captured boot/vendor and pinned compiled GenFv FD not installed")
        with tempfile.TemporaryDirectory(prefix="dizi-native-stage-") as d:
            where = Path(d)
            manifest = tool.stage(boot_path=boot, vendor_path=vendor,
                                  fd_path=fd, directory=where)
            output = where / tool.STAGE_BLOB
            saved = json.loads((where / tool.STAGE_MANIFEST).read_text())
            self.assertEqual(saved, manifest)
            self.assertEqual(manifest["source_boot"]["boot_signature_bytes"], 4096)
            self.assertEqual(manifest["source_vendor_boot"]["dtb_bytes"], 4886872)
            self.assertEqual(manifest["genuine_uefi_fd"]["sha256"],
                             tool.FD_COLD_20261021_SHA)
            self.assertEqual(manifest["gki_v4_structural_stage"]["bytes"], 51056640)
            self.assertFalse(manifest["safe_to_boot"])
            self.assertFalse(manifest["safe_to_flash"])
            self.assertFalse(manifest["bootshim_native_uefi_entry_implemented"])
            self.assertFalse(manifest["device_actions_performed"])
            with output.open("rb") as handle:
                self.assertEqual(hashlib.file_digest(handle, "sha256").hexdigest(),
                                 manifest["gki_v4_structural_stage"]["sha256"])
            self.assertFalse(any(p.name.endswith(".img") for p in where.iterdir()))
            with self.assertRaisesRegex(tool.Reject, "already exist"):
                tool.stage(boot_path=boot, vendor_path=vendor,
                           fd_path=fd, directory=where)

    def test_real_fd_with_worker8_native_first_pc_gki_v4_stage(self):
        boot = ROOT / "backup/dizi/boot_a.img"
        vendor = ROOT / "backup/dizi/vendor_boot_a.img"
        fd = Path("/tmp/dizi-edk2-msm-genuine-dizi-debug-20261021-w9/verify-commit-20261021/"
                  "Build/dizi/DEBUG_GCC5/FV/SM7435_UEFI.fd")
        if not all(p.is_file() for p in (boot, vendor, fd)):
            self.skipTest("authentic captured inputs unavailable")
        if shutil.which("aarch64-linux-gnu-gcc") is None:
            self.skipTest("AArch64 source assembler unavailable")
        with tempfile.TemporaryDirectory(prefix="dizi-native-worker8-") as d:
            directory = Path(d)
            result = tool.stage(boot_path=boot, vendor_path=vendor,
                                fd_path=fd, directory=directory, native_entry=True)
            native = directory / tool.STAGE_NATIVE_IMAGE
            image = directory / tool.STAGE_BLOB
            self.assertEqual(len(native.read_bytes()), 4096)
            self.assertEqual(image.stat().st_size, 4096 + 4096 + 4194304)
            self.assertEqual(result["native_entry_build"]["native_image"]["sha256"],
                             digest(native.read_bytes()))
            self.assertEqual(result["native_entry_build"]["native_image"]["sha256"],
                             tool.NATIVE_STAGE_IMAGE_SHA)
            self.assertEqual(result["genuine_uefi_fd"]["sha256"],
                             tool.FD_VERIFIED_20261021_SHA)
            self.assertEqual(result["gki_v4_structural_stage"]["sha256"],
                             digest(image.read_bytes()))
            self.assertIn("register-check-WFE", result["native_image_entry"])
            self.assertFalse(result["bootshim_native_uefi_entry_implemented"])
            self.assertFalse(result["safe_to_boot"])
            self.assertFalse(result["safe_to_flash"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
