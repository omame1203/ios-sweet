#!/usr/bin/env python3
"""Offline GKI-v4 Renegade packager tests. Synthetic wrapper is NOT real UEFI."""
from __future__ import annotations

import hashlib
import gzip
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/dizi-renegade-image.py"
SPEC = importlib.util.spec_from_file_location("dizi_renegade_image", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
rgi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rgi)


def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def make_fd() -> bytes:
    """Minimal FVH structural fixture: not a runnable EDK2 SEC/PrePi firmware."""
    fd = bytearray(b"\xff" * 0x10000)
    fd[:16] = b"\0" * 16
    fd[16:32] = bytes(range(1, 17))
    struct.pack_into("<Q", fd, 32, len(fd))
    fd[40:44] = b"_FVH"
    struct.pack_into("<HHH", fd, 48, 72, 0, 0)
    fd[54] = 0
    fd[55] = 2
    struct.pack_into("<II", fd, 56, 1, len(fd))
    struct.pack_into("<II", fd, 64, 0, 0)
    words = struct.unpack_from("<36H", fd)
    struct.pack_into("<H", fd, 50, -sum(words) & 0xFFFF)
    return bytes(fd)


def make_wrapper() -> bytes:
    """Valid Linux Image transport header with nonfunctional synthetic code."""
    wrapper = bytearray(4096)
    struct.pack_into("<IIQQQ", wrapper, 0, 0x14000020, 0, 0, len(wrapper), 0xA)
    wrapper[56:60] = b"ARM\x64"
    struct.pack_into("<I", wrapper, 0x80, 0x91000400)
    return bytes(wrapper)


def evidence(wrapper: bytes, fd: bytes, fd_base: int = rgi.RAM_BASE) -> dict:
    return {
        "schema": rgi.SCHEMA,
        "board": "dizi", "soc": "SM7435",
        "linux_entry_abi": "aarch64-linux-image-x0-physical-fdt",
        "fd_transport": "android-gki-v4-ramdisk-fv",
        "fd_image_layout": "one-uefi-firmware-volume-at-offset-0",
        "fd_sha256": digest(fd), "fd_size": len(fd),
        "fd_base_pa": hex(fd_base),
        "wrapper_sha256": digest(wrapper), "wrapper_entry_offset": 0x80,
        "initrd_vendor_prefix_handling_verified": True,
        "fd_copier_and_uefi_entry_machine_code_reviewed": True,
        "aarch64_cache_and_mmu_transition_reviewed": True,
        "runtime_ram_ownership_verified_out_of_band": True,
    }


class DiziRenegadeImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dizi-renegade-v4-tests-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.fd = self.base / "Renegade-UEFI.fd"
        self.wrapper = self.base / "BootShim-linux.Image"
        self.audit = self.base / "wrapper-review.json"
        self.output = self.base / "dizi-renegade-boot.img"
        self.raw_fd = make_fd()
        self.raw_wrapper = make_wrapper()
        self.fd.write_bytes(self.raw_fd)
        self.wrapper.write_bytes(self.raw_wrapper)
        self.save_audit()
        # Synthetic positive transport tests emulate a separate code-review
        # allowlist, never granting a release artifact actual EDK2 authority.
        self.allowlist = mock.patch.dict(
            rgi.VERIFIED_DIZI_WRAPPERS, {
                digest(self.raw_wrapper): {
                    "fd_sha256": digest(self.raw_fd),
                    "fd_base_pa": hex(rgi.RAM_BASE),
                    "wrapper_entry_offset": 0x80,
                }
            })
        self.allowlist.start()
        self.addCleanup(self.allowlist.stop)

    def save_audit(self, **change):
        data = evidence(self.raw_wrapper, self.raw_fd)
        data.update(change)
        self.audit.write_text(json.dumps(data))

    def package(self, *, approved_fd: str | None = None, approved_wrapper: str | None = None,
                fd_base: int = rgi.RAM_BASE, gate: bool = True) -> dict:
        return rgi.package(fd_path=self.fd, wrapper_path=self.wrapper,
                           contract_path=self.audit, output=self.output,
                           approved_fd_sha256=approved_fd or digest(self.raw_fd),
                           approved_wrapper_sha256=approved_wrapper or digest(self.raw_wrapper),
                           fd_base=fd_base, reviewed=gate)

    def assert_no_output(self):
        self.assertFalse(self.output.exists())
        self.assertFalse(Path(str(self.output) + ".review.json").exists())

    def test_synthetic_header_layout_hash_and_no_device_actions(self):
        # Verify the conditional transport code using synthetic inert inputs.
        # This test explicitly does NOT establish a real EDK2 entry wrapper.
        report = self.package()
        output = self.output.read_bytes()
        result = rgi.verify_v4_bytes(output, self.raw_wrapper, self.raw_fd)
        self.assertEqual(result, report["boot_v4"])
        self.assertEqual(result["kernel_offset"], 4096)
        self.assertEqual(result["fd_ramdisk_offset"], 8192)
        self.assertEqual(result["fd_ramdisk_bytes"], 65536)
        self.assertEqual(result["bytes"], 4096 + 4096 + 65536)
        self.assertEqual(result["sha256"], digest(output))
        self.assertEqual(output[:8], b"ANDROID!")
        self.assertEqual(struct.unpack_from("<I", output, 40)[0], 4)
        self.assertEqual(struct.unpack_from("<I", output, 1580)[0], 0)
        saved = json.loads(Path(str(self.output) + ".review.json").read_text())
        self.assertEqual(saved["boot_v4"]["sha256"], digest(output))
        self.assertFalse(saved["uefi_runtime_execution_verified"])
        self.assertFalse(saved["physical_fd_ram_exclusivity_verified_by_packager"])
        self.assertFalse(saved["safe_to_flash"])
        self.assertFalse(saved["device_actions_performed"])

    def test_missing_entry_wrapper_or_audit_rejected(self):
        self.wrapper.unlink()
        with self.assertRaisesRegex(rgi.Rejected, "no readable regular"):
            self.package()
        self.assert_no_output()
        self.wrapper.write_bytes(self.raw_wrapper)
        self.audit.unlink()
        with self.assertRaisesRegex(rgi.Rejected, "no readable regular"):
            self.package()
        self.assert_no_output()

    def test_mandatory_abi_review_gate_no_reads_or_writes(self):
        with mock.patch.object(rgi, "read_regular", side_effect=AssertionError("read invoked")):
            with self.assertRaisesRegex(rgi.Rejected, "independently reviewed"):
                self.package(gate=False)
        self.assert_no_output()

    def test_bad_wrapper_fields_and_offset_rejected(self):
        cases = [
            (56, b"BLAH", "Linux Image header"),
            (0, struct.pack("<I", 0xD61F0000), "code0"),
            (0, struct.pack("<I", 0x14001000), "branch entry"),
            (4, struct.pack("<I", 4), "Linux Image header"),
            (8, struct.pack("<Q", 0x80000), "text_offset"),
            (16, struct.pack("<Q", 8192), "size"),
            (24, struct.pack("<Q", 0), "flags"),
            (0x80, struct.pack("<I", 0xD65F03C0), "entry"),
        ]
        for offset, new, fragment in cases:
            with self.subTest(offset=offset, payload=new.hex()):
                tampered = bytearray(self.raw_wrapper)
                tampered[offset:offset + len(new)] = new
                with self.assertRaisesRegex(rgi.Rejected, fragment):
                    rgi.check_arm64_wrapper(bytes(tampered), expected_sha256=digest(tampered))
        for size in (63, 4095, rgi.MAX_WRAPPER + 1):
            with self.subTest(size=size), self.assertRaises(rgi.Rejected):
                rgi.check_arm64_wrapper(b"\0" * size, expected_sha256=digest(b"\0" * size))
        self.assert_no_output()

    def test_upstream_bootshim_fd_gzip_plus_dtb_is_not_a_gki_linux_image(self):
        # Renegade's real upstream pipeline uses BootShim.bin + FD, gzips the
        # result and appends DTB. That is neither an uncompressed Linux Image
        # with declared size nor a dizi-audited FD-to-SEC loader.
        pseudo_bootshim = bytearray(make_wrapper())
        struct.pack_into("<Q", pseudo_bootshim, 16, 0)  # upstream size=0
        struct.pack_into("<Q", pseudo_bootshim, 24, 0)  # upstream flags=0
        with self.assertRaisesRegex(rgi.Rejected, "size/flags"):
            rgi.check_arm64_wrapper(bytes(pseudo_bootshim),
                                    expected_sha256=digest(pseudo_bootshim))
        upstream_kernel = gzip.compress(make_wrapper() + self.raw_fd) + b"DTB"
        with self.assertRaises(rgi.Rejected):
            rgi.check_arm64_wrapper(upstream_kernel,
                                    expected_sha256=digest(upstream_kernel))
        self.assert_no_output()

    def test_fd_header_checksum_length_and_block_mapping(self):
        scenarios = [
            (40, b"XXXX", "_FVH"),
            (32, struct.pack("<Q", 0x20000), "FV length"),
            (55, b"\x01", "revision"),
            (48, struct.pack("<H", 4097), "FV length"),
            (56, struct.pack("<I", 2), "checksum"),
            (50, b"nope", "checksum"),
        ]
        for offset, change, text in scenarios:
            with self.subTest(offset=offset):
                b = bytearray(self.raw_fd)
                b[offset:offset + len(change)] = change
                with self.assertRaisesRegex(rgi.Rejected, text):
                    rgi.check_uefi_fd(bytes(b), expected_sha256=digest(b),
                                     fd_base=rgi.RAM_BASE)
        with self.assertRaisesRegex(rgi.Rejected, "outside dizi"):
            rgi.check_uefi_fd(self.raw_fd, expected_sha256=digest(self.raw_fd),
                             fd_base=0xCE000000)
        with self.assertRaisesRegex(rgi.Rejected, "outside dizi"):
            rgi.check_uefi_fd(self.raw_fd, expected_sha256=digest(self.raw_fd),
                             fd_base=rgi.RAM_BASE + rgi.RAM_SIZE)
        self.assert_no_output()

    def test_self_declared_contract_without_audited_binary_allowlist_fails_closed(self):
        with mock.patch.dict(rgi.VERIFIED_DIZI_WRAPPERS, {}, clear=True):
            with self.assertRaisesRegex(rgi.Rejected, "no audited dizi EDK2 Linux Image"):
                self.package()
        self.assert_no_output()

    def test_digest_pins_detect_modified_fd_wrapper_and_contract(self):
        with self.assertRaisesRegex(rgi.Rejected, "allowlisted wrapper"):
            self.package(approved_fd="0" * 64)
        with self.assertRaisesRegex(rgi.Rejected, "no audited"):
            self.package(approved_wrapper="0" * 64)
        with self.assertRaisesRegex(rgi.Rejected, "SHA-256 pin"):
            self.package(approved_wrapper="abc")
        original = self.fd.read_bytes()
        self.fd.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaisesRegex(rgi.Rejected, "FD SHA-256"):
            self.package()
        self.fd.write_bytes(original)
        original = self.wrapper.read_bytes()
        self.wrapper.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaisesRegex(rgi.Rejected, "wrapper SHA-256"):
            self.package()
        self.wrapper.write_bytes(original)
        self.save_audit(board="pipa")
        with self.assertRaisesRegex(rgi.Rejected, "contract mismatches"):
            self.package()
        self.save_audit(fd_size=len(self.raw_fd) + 1)
        with self.assertRaisesRegex(rgi.Rejected, "contract mismatches"):
            self.package()
        self.save_audit(aarch64_cache_and_mmu_transition_reviewed=False)
        with self.assertRaisesRegex(rgi.Rejected, "contract mismatches"):
            self.package()
        self.assert_no_output()

    def test_output_already_exists_is_byte_identical(self):
        self.output.write_bytes(b"RETAIN SAVED BOOT")
        with self.assertRaisesRegex(rgi.Rejected, "already exists"):
            self.package()
        self.assertEqual(self.output.read_bytes(), b"RETAIN SAVED BOOT")
        self.output.unlink()
        review = Path(str(self.output) + ".review.json")
        review.write_bytes(b"RETAIN AUDIT")
        with self.assertRaisesRegex(rgi.Rejected, "already exists"):
            self.package()
        self.assertEqual(review.read_bytes(), b"RETAIN AUDIT")
        review.unlink()
        self.output.symlink_to(self.fd)
        with self.assertRaisesRegex(rgi.Rejected, "already exists"):
            self.package()
        self.assertEqual(self.fd.read_bytes(), self.raw_fd)
        self.output.unlink()
        review.symlink_to(self.wrapper)
        with self.assertRaisesRegex(rgi.Rejected, "already exists"):
            self.package()
        self.assertEqual(self.wrapper.read_bytes(), self.raw_wrapper)

    def test_symlink_device_and_uncreated_output_directory_rejected(self):
        link = self.base / "fake-wrapper"
        link.symlink_to(self.wrapper)
        with self.assertRaises(rgi.Rejected):
            rgi.read_regular(link, rgi.MAX_WRAPPER, "wrapper")
        with self.assertRaises(rgi.Rejected):
            rgi.read_regular(Path("/dev/null"), rgi.MAX_WRAPPER, "wrapper")
        with self.assertRaisesRegex(rgi.Rejected, "output directory"):
            rgi.package(fd_path=self.fd, wrapper_path=self.wrapper,
                        contract_path=self.audit,
                        output=self.base / "missing" / "foo.img",
                        approved_fd_sha256=digest(self.raw_fd),
                        approved_wrapper_sha256=digest(self.raw_wrapper),
                        fd_base=rgi.RAM_BASE, reviewed=True)

    def test_corrupted_boot_header_sections_padding_and_extra_signature(self):
        boot, _ = rgi.build_v4(self.raw_wrapper, self.raw_fd)
        alterations = [
            (0, b"NOTBOOT!", "magic"),
            (8, struct.pack("<I", 3), "sizes"),
            (12, struct.pack("<I", 0), "sizes"),
            (20, struct.pack("<I", 1580), "header"),
            (40, struct.pack("<I", 3), "version"),
            (44, b"x", "command"),
            (1580, struct.pack("<I", 8), "signature"),
            (4096 + 0x80, b"X", "content"),
            (8192 + 0x55, b"X", "content"),
        ]
        for offset, new, fragment in alterations:
            with self.subTest(offset=offset):
                changed = bytearray(boot)
                changed[offset:offset + len(new)] = new
                with self.assertRaisesRegex(rgi.Rejected, fragment):
                    rgi.verify_v4_bytes(bytes(changed), self.raw_wrapper, self.raw_fd)
        with self.assertRaisesRegex(rgi.Rejected, "trailing"):
            rgi.verify_v4_bytes(boot + b"not-an-AVB-signature",
                                self.raw_wrapper, self.raw_fd)
        with self.assertRaises(rgi.Rejected):
            rgi.verify_v4_bytes(boot[:-1], self.raw_wrapper, self.raw_fd)
        self.assert_no_output()

    def test_upstream_missing_sm7435_and_bootshim_contract_not_fabricated(self):
        overlay = ROOT / "ports/renegade/edk2-overlay/configs"
        device = (overlay / "devices/dizi.conf").read_text()
        soc = (overlay / "sm7435.conf").read_text()
        self.assertIn('SOC_PLATFORM="SM7435"', device)
        self.assertIn("BOOTIMG_HEADER_VERSION=4", device)
        self.assertIn('PLATFORM_NAME="dizi"', device)
        self.assertNotIn("FD_BASE=", "\n".join(line for line in soc.splitlines()
                                                if line.lstrip().startswith("FD_BASE=")))
        upstream = Path("/tmp/dizi-edk2-msm-audit-20261021")
        if upstream.is_dir():
            self.assertFalse((upstream / "Silicon/Qualcomm/sm7435").exists())
            self.assertFalse((upstream / "Platform/Xiaomi/sm7435/dizi.dsc").exists())
            # Another audit worker may populate upstream's generic BootShim
            # during our run. Presence of its 144-byte size=0,flags=0
            # diagnostic stub cannot establish a full ARM64 GKI-v4 wrapper.
            bootshim = upstream / "tools/BootShim/BootShim.bin"
            if bootshim.is_file():
                raw = bootshim.read_bytes()
                with self.assertRaises(rgi.Rejected):
                    rgi.check_arm64_wrapper(raw, expected_sha256=digest(raw))
            check = subprocess.run(["bash", "-c", 'source "$1"', "_", str(overlay / "sm7435.conf")],
                                   env={**os.environ, "ROOTDIR": str(upstream)},
                                   capture_output=True, text=True)
            self.assertNotEqual(check.returncode, 0)
            self.assertIn("unimplemented", check.stderr)
        self.assert_no_output()

    def test_cli_must_have_explicit_review_and_no_flash(self):
        command = [
            sys.executable, str(SCRIPT), "--fd", str(self.fd),
            "--wrapper-image", str(self.wrapper), "--wrapper-audit-contract", str(self.audit),
            "--approved-fd-sha256", digest(self.raw_fd),
            "--approved-wrapper-sha256", digest(self.raw_wrapper),
            "--fd-base-pa", hex(rgi.RAM_BASE), "--output", str(self.output),
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("independently reviewed", result.stderr)
        self.assert_no_output()


if __name__ == "__main__":
    unittest.main(verbosity=2)
