#!/usr/bin/env python3
"""Native first-PC ARM64 Linux Image: real assembler, linker and binary tests.

No QEMU, fastboot, device, flash, output to repo or firmware execution. The
result is an executable *AArch64 entry that parks*, NOT a UEFI/SEC loader.
"""
from __future__ import annotations

import ctypes
import hashlib
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DIR = ROOT / "ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435/DiziBootShim"


def run(*cmd: str) -> str:
    cp = subprocess.run(cmd, check=True, text=True, capture_output=True)
    return cp.stdout


class NativeEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ("aarch64-linux-gnu-gcc", "aarch64-linux-gnu-ld",
                     "aarch64-linux-gnu-objcopy", "aarch64-linux-gnu-objdump",
                     "aarch64-linux-gnu-readelf", "aarch64-linux-gnu-nm",
                     "gcc"):
            if not shutil.which(tool):
                raise unittest.SkipTest(f"cross compilation unavailable: {tool}")

        cls.tmp = tempfile.TemporaryDirectory(prefix="dizi-renegade-native-")
        dst = Path(cls.tmp.name)
        cls.obj = dst / "DiziNativeEntry.o"
        cls.elf = dst / "DiziNativeEntry.elf"
        cls.image = dst / "Image"
        cls.lib = dst / "libdizi-native-validator.so"
        cls.cobj = dst / "DiziNativeEntry.c.o"

        run("aarch64-linux-gnu-gcc", "-c", "-x", "assembler-with-cpp",
            "-nostdlib", "-ffreestanding", "-Wall", "-Wextra", "-Werror",
            "-I", str(DIR), str(DIR / "DiziNativeEntry.S"),
            "-o", str(cls.obj))
        run("aarch64-linux-gnu-ld", "-nostdlib", "-static",
            "-T", str(DIR / "DiziNativeEntry.ld"),
            "-o", str(cls.elf), str(cls.obj))
        run("aarch64-linux-gnu-objcopy", "-O", "binary",
            str(cls.elf), str(cls.image))
        run("gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra",
            "-Werror", "-std=c11", str(DIR / "DiziNativeEntry.c"),
            "-o", str(cls.lib))
        run("aarch64-linux-gnu-gcc", "-c", "-O2", "-std=c11",
            "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
            "-Wall", "-Wextra", "-Werror",
            str(DIR / "DiziNativeEntry.c"), "-o", str(cls.cobj))

        cls.raw = cls.image.read_bytes()
        cls.disasm = run("aarch64-linux-gnu-objdump", "-d", "-j",
                         ".text", str(cls.elf))
        cls.sections = run("aarch64-linux-gnu-readelf", "-SW", str(cls.elf))
        cls.relocations = run("aarch64-linux-gnu-readelf", "-Wr", str(cls.elf))
        cls.symbols = run("aarch64-linux-gnu-nm", "-n", str(cls.elf))
        cls.shared = ctypes.CDLL(str(cls.lib))
        cls.validator = cls.shared.dizi_native_image_header_valid
        cls.validator.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        cls.validator.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def validate(self, raw: bytes) -> tuple[int, int]:
        value = (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw)
        entry = ctypes.c_uint32(0xFFFFFFFF)
        valid = self.validator(value, len(raw), ctypes.byref(entry))
        return valid, entry.value

    def test_real_image_has_exact_4096_bytes_and_kernel_header(self):
        self.assertEqual(len(self.raw), 4096)
        self.assertEqual(self.raw[56:60], b"ARM\x64")
        self.assertEqual(struct.unpack_from("<IIQQQ", self.raw, 0),
                         (0x14000010, 0, 0, 4096, 0xA))
        self.assertEqual(self.raw[32:56], b"\0" * 24)
        self.assertEqual(self.raw[60:64], b"\0" * 4)
        self.assertFalse(self.raw[:2] == b"MZ")
        self.assertEqual(self.validate(self.raw), (1, 64))

    def test_first_image_instruction_really_branches_into_native_code(self):
        self.assertIn("0 <dizi_native_image_header>:", self.disasm)
        self.assertRegex(self.disasm, r"0:\s+14000010\s+b\s+40 <dizi_native_first_pc>")
        self.assertRegex(self.disasm, r"40:\s+d53b422e\s+mrs\s+x14, daif")
        self.assertRegex(self.disasm, r"44:\s+d5034fdf\s+msr\s+daifset, #0xf")
        self.assertEqual(struct.unpack_from("<I", self.raw, 64)[0], 0xD53B422E)
        self.assertEqual(struct.unpack_from("<I", self.raw, 68)[0], 0xD5034FDF)

    def test_linker_has_no_external_relocations_stack_or_globals(self):
        self.assertIn("There are no relocations in this file.", self.relocations)
        self.assertFalse(run("aarch64-linux-gnu-nm", "-u", str(self.elf)).strip())
        self.assertFalse(run("aarch64-linux-gnu-nm", "-u", str(self.cobj)).strip())
        self.assertIn("0000000000000040 T dizi_native_first_pc", self.symbols)
        self.assertIn("0000000000000000 T dizi_native_image_header", self.symbols)
        self.assertIn("0000000000001000 T __dizi_native_image_end", self.symbols)
        # Header is executable at offset zero. No .bss heap, .data or stack.
        self.assertNotRegex(self.sections, r"\s\.(?:bss|data|got|plt)\s")

    def test_only_reviewed_register_and_control_flow_opcodes(self):
        instructions = []
        for line in self.disasm.splitlines():
            match = re.match(r"\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+([a-z.]+)\s*(.*)$", line)
            if match is None:
                continue
            address = int(match.group(1), 16)
            opcode = match.group(3)
            operands = match.group(4)
            if address < 64:
                continue
            instructions.append((address, opcode, operands))
        self.assertGreater(len(instructions), 20)
        self.assertEqual([x[1] for x in instructions[:2]], ["mrs", "msr"])
        allowed = {"mrs", "msr", "mov", "cbz", "cbnz", "tst", "cmp",
                   "b", "b.ne", "tbz", "tbnz", "wfe"}
        self.assertTrue(all(m in allowed for _, m, _ in instructions),
                        instructions)
        self.assertEqual([(op, args) for _, op, args in instructions if op == "msr"],
                         [("msr", "daifset, #0xf")])
        # No load/store (nor LDP/STP, cache operations, TLBI, barriers,
        # HVC/SMC/ERET, calls or data-dependent BR/BLR).
        for forbidden in ("ldr", "str", "ldp", "stp", "br", "blr", "ret",
                          "svc", "hvc", "smc", "eret", "tlbi", "dc",
                          "ic", "adr", "adrp", "bl", "msr sctlr"):
            self.assertTrue(all(op != forbidden for _, op, _ in instructions),
                            forbidden)
        for address, opcode, operands in instructions:
            if opcode == "mov":
                self.assertTrue(operands.startswith("x16, #"), (address, operands))
            if opcode == "mrs":
                self.assertRegex(operands, r"^x(14|15|17), ")
            if opcode == "b" and address != 0:
                # All reachable B instructions land on the park label.
                self.assertIn("<dizi_native_park>", operands)

    def test_sctlr_reads_are_gated_by_el1_and_entry_daif(self):
        self.assertIn("mrs\tx17, currentel", self.disasm)
        self.assertIn("mrs\tx15, sctlr_el1", self.disasm)
        self.assertIn("tbz\tw14, #7", self.disasm)
        self.assertIn("tbz\tw14, #6", self.disasm)
        self.assertIn("tbnz\tw15, #0", self.disasm)
        self.assertIn("tbnz\tw15, #2", self.disasm)
        self.assertIn("tbnz\tw15, #12", self.disasm)
        self.assertIn("cbz\tx0", self.disasm)
        self.assertIn("cbnz\tx1", self.disasm)
        self.assertIn("cbnz\tx2", self.disasm)
        self.assertIn("cbnz\tx3", self.disasm)

    def test_every_path_ends_in_wfe_park_without_prepi(self):
        wfe = [(address, operand) for address, code, operand
               in self._decoded() if code == "wfe"]
        self.assertEqual(len(wfe), 1)
        park = wfe[0][0]
        self.assertEqual(park, 0xB8)
        last_address, last_code, last_operands = self._decoded()[-1]
        self.assertEqual(last_address, park + 4)
        self.assertEqual(last_code, "b")
        self.assertIn("<dizi_native_park>", last_operands)
        # A reviewer can tell apart entry reached from actual SEC started:
        # x16 == 12 (NO_OWNER), not an asserted firmware-ready condition.
        self.assertRegex(self.disasm, r"mov\s+x16, #0xc\b")
        self.assertTrue(self.raw[0xC0:] == b"\0" * (4096 - 0xC0))

    def _decoded(self):
        decoded = []
        for line in self.disasm.splitlines():
            match = re.match(r"\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+([a-z.]+)\s*(.*)$", line)
            if match and int(match.group(1), 16) >= 64:
                decoded.append((int(match.group(1), 16), match.group(3), match.group(4)))
        return decoded

    def test_host_validator_rejects_mutated_linux_image_header(self):
        edits = [(0, struct.pack("<I", 0xd503201f)),  # NOP
                 (0, struct.pack("<I", 0x14000011)),  # wrong branch
                 (4, b"FAIL"), (8, struct.pack("<Q", 0x1000)),
                 (16, struct.pack("<Q", 0)), (24, struct.pack("<Q", 0)),
                 (32, b"X"), (40, b"X"), (48, b"X"), (55, b"X"),
                 (56, b"BAD!"), (60, b"X"), (64, b"\0" * 4)]
        for offset, data in edits:
            with self.subTest(offset=offset, patch=data.hex()):
                raw = bytearray(self.raw)
                raw[offset:offset+len(data)] = data
                self.assertEqual(self.validate(raw), (0, 0))
        for raw in (self.raw[:63], self.raw[:4095], self.raw + b"EXTRA"):
            self.assertEqual(self.validate(raw), (0, 0))

    def test_real_dizi_stock_android_image_is_not_this_entry(self):
        saved = ROOT / "backup/dizi/boot_a.img"
        vendor = ROOT / "backup/dizi/vendor_boot_a.img"
        abl = ROOT / "backup/dizi/abl_a.img"
        if not all(p.is_file() for p in (saved, vendor, abl)):
            self.skipTest("ignored actual dizi ABL/GKI-v4 backup unavailable")
        with saved.open("rb") as f:
            boot = f.read(4096)
            stock_image = f.read(4096)
        with vendor.open("rb") as f:
            vendor_header = f.read(4096)
        with abl.open("rb") as f:
            abl_header = f.read(64)
        self.assertEqual(boot[:8], b"ANDROID!")
        self.assertEqual(struct.unpack_from("<I", boot, 40)[0], 4)
        self.assertEqual(struct.unpack_from("<I", boot, 20)[0], 1584)
        self.assertEqual(struct.unpack_from("<I", boot, 1580)[0], 4096)
        self.assertEqual(stock_image[56:60], b"ARM\x64")
        self.assertEqual(vendor_header[:8], b"VNDRBOOT")
        self.assertEqual(struct.unpack_from("<I", vendor_header, 8)[0], 4)
        self.assertEqual(abl_header[:4], b"\x7fELF")
        self.assertEqual(struct.unpack_from("<H", abl_header, 18)[0], 40)
        self.assertNotEqual(stock_image, self.raw)
        self.assertEqual(self.validate(stock_image), (0, 0))

    def test_binary_no_fd_or_bootloader_address_constants(self):
        # The immediate signature of a real FD transport is deliberately
        # absent. These byte checks are supplemental to disassembly audit.
        self.assertEqual(len(self.raw), 0x1000)
        self.assertNotIn(struct.pack("<Q", 0x90000000), self.raw)
        self.assertNotIn(struct.pack("<Q", 0x90400000), self.raw)
        self.assertNotIn(struct.pack("<Q", 0x90fc0000), self.raw)
        self.assertEqual(len(hashlib.sha256(self.raw).digest()), 32)


if __name__ == "__main__":
    unittest.main(verbosity=2)
