#!/usr/bin/env python3
"""Genuine ARM64 SEC branch implementation, default denied until real owner."""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435/DiziBootShim"
C = SOURCES / "DiziSecTransfer.c"
ASM = SOURCES / "DiziSecTransfer.S"
FD = Path("/tmp/dizi-edk2-msm-genuine-dizi-debug-20261021-w9/verify-commit-20261021/Build/dizi/DEBUG_GCC5/FV/SM7435_UEFI.fd")


class SecTransferTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cc = shutil.which("aarch64-linux-gnu-gcc")
        cls.nm = shutil.which("aarch64-linux-gnu-nm")
        cls.dump = shutil.which("aarch64-linux-gnu-objdump")
        if not all((cls.cc, cls.nm, cls.dump)):
            raise unittest.SkipTest("AArch64 GNU compiler/binutils not installed")

    def test_default_disabled_c_compiles_and_does_not_refer_to_ownership(self):
        with tempfile.TemporaryDirectory(prefix="dizi-sec-transfer-") as td:
            obj = Path(td) / "default.o"
            subprocess.run([self.cc, "-std=gnu17", "-ffreestanding",
                            "-fno-builtin", "-fno-stack-protector", "-Wall",
                            "-Wextra", "-Werror", "-c", str(C), "-o", str(obj)],
                           check=True)
            unresolved = subprocess.check_output([self.nm, "-u", str(obj)], text=True)
            self.assertEqual(unresolved.strip(), "")
            dump = subprocess.check_output([self.dump, "-d", str(obj)], text=True)
            self.assertNotIn("dc\tcvac", dump)
            self.assertNotIn("ic\tivau", dump)

    def test_gated_arm64_copy_cache_branch_real_machine_code(self):
        opts = ["-DDIZI_SEC_ENABLE=1", "-DDIZI_SEC_TRUSTED_OWNER_IMPLEMENTED=1"]
        with tempfile.TemporaryDirectory(prefix="dizi-sec-transfer-") as td:
            code = Path(td) / "active.o"
            entry = Path(td) / "entry.o"
            subprocess.run([self.cc, *opts, "-std=gnu17", "-ffreestanding",
                            "-fno-builtin", "-fno-stack-protector", "-mgeneral-regs-only",
                            "-Wall", "-Wextra", "-Werror", "-c", str(C),
                            "-o", str(code)], check=True)
            subprocess.run([self.cc, *opts, "-c", str(ASM), "-o", str(entry)], check=True)
            unresolved = subprocess.check_output([self.nm, "-u", str(code)], text=True)
            self.assertIn("DiziSecGetTrustedRuntimeGrant", unresolved)
            self.assertIn("dizi_gki_fd_plan", unresolved)
            self.assertIn("DiziSecEnterPrePi", unresolved)
            dump = subprocess.check_output([self.dump, "-d", str(code)], text=True)
            self.assertRegex(dump, r"dc\s+cvac")
            self.assertRegex(dump, r"ic\s+ivau")
            self.assertRegex(dump, r"dsb\s+sy")
            asm = subprocess.check_output([self.dump, "-d", str(entry)], text=True)
            self.assertRegex(asm, r"br\s+x16")
            self.assertRegex(asm, r"mov\s+x1, xzr")
            self.assertRegex(asm, r"mov\s+x2, xzr")
            self.assertRegex(asm, r"mov\s+x3, xzr")
            self.assertNotIn("0xce000000", C.read_text().lower())

    def test_active_link_fails_without_real_owner_provider(self):
        # Both explicit compile switches are NOT sufficient to create a
        # bootable EFI handoff: a genuine platform owner object is mandatory.
        with tempfile.TemporaryDirectory(prefix="dizi-sec-link-negative-") as td:
            td = Path(td)
            opts = ["-DDIZI_SEC_ENABLE=1", "-DDIZI_SEC_TRUSTED_OWNER_IMPLEMENTED=1"]
            build = [(C, "transfer_c.o"), (ASM, "transfer_s.o"),
                     (SOURCES / "DiziGkiHandoff.c", "planner.o")]
            objects = []
            for src, name in build:
                obj = td / name
                subprocess.run([self.cc, *opts, "-std=gnu17", "-ffreestanding",
                                "-fno-builtin", "-fno-stack-protector",
                                "-mgeneral-regs-only", "-c", str(src),
                                "-o", str(obj)], check=True)
                objects.append(str(obj))
            result = subprocess.run(
                [self.cc, "-nostdlib", "-static", "-Wl,-e,DiziSecTryBoot",
                 *objects, "-o", str(td / "active.elf")],
                capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("undefined reference to `DiziSecGetTrustedRuntimeGrant'",
                          result.stderr)
            self.assertFalse((td / "active.elf").exists())

    def test_default_arm64_branch_is_park_only(self):
        with tempfile.TemporaryDirectory(prefix="dizi-sec-transfer-") as td:
            obj = Path(td) / "default-entry.o"
            subprocess.run([self.cc, "-c", str(ASM), "-o", str(obj)], check=True)
            dump = subprocess.check_output([self.dump, "-d", str(obj)], text=True)
            self.assertRegex(dump, r"wfe")
            self.assertNotRegex(dump, r"\sbr\s+x")
            self.assertNotRegex(dump, r"\sstr\s+")

    def test_current_saved_real_fd_is_not_an_android_linux_image(self):
        if not FD.is_file():
            self.skipTest("Genuine EDK2 FV artifact unavailable in this container")
        f = FD.read_bytes()
        self.assertEqual(len(f), 0x400000)
        self.assertEqual(f[40:44], b"_FVH")
        self.assertNotEqual(f[56:60], b"ARM\x64")
        self.assertEqual(hashlib.sha256(f).hexdigest(),
                         "7bb217aebee2d79910ea9e9d2bb204cb6375a6d6bcb637fb9e7dd81cf2e78ec8")

    def test_trust_boundary_is_external_and_no_fake_device_actions(self):
        code = C.read_text()
        hdr = (SOURCES / "DiziSecTransfer.h").read_text()
        native = ASM.read_text()
        self.assertIn("DiziSecGetTrustedRuntimeGrant(r, &g)", code)
        self.assertIn("dizi_gki_fd_plan(&fd_req, &plan)", code)
        self.assertIn("DiziSecEnterPrePi(request->incoming_fdt_pa", code)
        self.assertNotRegex(code, r"\b(?:MmioWrite\w*|ArmWriteHcr|fastboot|flash|UfsHc)\s*\(")
        self.assertIn("NO implementation", hdr)
        self.assertIn("DIZI_SEC_TRUSTED_OWNER_IMPLEMENTED", native)
        self.assertIn("return DIZI_SEC_NO_OWNER;", code)


if __name__ == "__main__":
    unittest.main(verbosity=2)
