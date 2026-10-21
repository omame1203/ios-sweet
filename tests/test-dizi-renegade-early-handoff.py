#!/usr/bin/env python3
"""Strict offline pre-SEC guard tests: no writes, jumps, or fake XPU proof.

No edit, no device, no boot, no git actions. The saved dizi FDT is read-only.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "ports/renegade/edk2-overlay/Silicon/Qualcomm/sm7435/Library/DiziEarlyHandoffGuard"
HEADER = ROOT / "ports/renegade/edk2-overlay/Silicon/Qualcomm/sm7435/Include"
FDT = ROOT / "backup/dizi/fdt"
UPSTREAM = Path("/tmp/dizi-edk2-msm-audit-20261021/Silicon/Qualcomm/QcomPkg/PrePi")


class EarlyHandoffTests(unittest.TestCase):
    def test_actual_unpatched_prepi_writes_before_C_and_requires_new_entry(self):
        assembler = (UPSTREAM / "ModuleEntryPoint.S").read_text()
        startup = assembler.split("_ModuleEntryPoint:", 1)[1]
        self.assertLess(startup.index("str x0, [x10]"), startup.index("bl CEntryPoint"))
        self.assertLess(startup.index("_FillVectors:"), startup.index("bl CEntryPoint"))
        self.assertLess(startup.index("_ClearStack:"), startup.index("bl CEntryPoint"))
        self.assertIn("FixedPcdGet64 (PcdDeviceTreeStore)", startup)
        self.assertIn("FixedPcdGet64(PcdCpuVectorBaseAddress)", startup)
        self.assertIn("FixedPcdGet32(PcdPrePiStackBase)", assembler)
        self.assertIn("FixedPcdGet32(PcdPrePiStackSize)", assembler)
        c_entry = (UPSTREAM / "Pi.c").read_text()
        self.assertIn("HobConstructor", c_entry)
        self.assertIn("ArmEnableVFP();", c_entry)
        self.assertIn("ArmWriteHcr(ARM_HCR_TGE)", c_entry)
        self.assertIn("ArmWriteCntHctl(", c_entry)
        self.assertIn("InvalidateDataCacheRange(", c_entry)
        self.assertIn("MemoryPeim(UefiMemoryBase, UefiMemorySize)", c_entry)
        # Exact upstream control flow: PlatformInitialize is before
        # PrePiMain (and therefore before the HCR/CNTHCTL/HOB/cache/MMU),
        # BUT pre-C assembly FDT/VBAR/stack stores are already too early.
        last = c_entry.split("CEntryPoint(", 1)[1]
        self.assertLess(last.index("PlatformInitialize();"),
                        last.index("PrePiMain(StackBase, StackSize);"))

    def test_guard_assembly_is_default_deny_and_never_dereferences_x0(self):
        self.assertTrue(shutil.which("aarch64-linux-gnu-gcc"))
        with tempfile.TemporaryDirectory(prefix="dizi-early-entry-") as d:
            obj = Path(d) / "guard.o"
            subprocess.run(["aarch64-linux-gnu-gcc", "-c", "-x", "assembler-with-cpp",
                            str(GUARD / "DiziEarlyHandoffGuardEntry.S"), "-o", str(obj)],
                           check=True)
            dis = subprocess.check_output(["aarch64-linux-gnu-objdump", "-dr", str(obj)],
                                          text=True)
            section = dis.split("<DiziEarlyHandoffGuardEntry>:", 1)[1]
            ops = []
            for line in section.splitlines():
                matched = re.search(r"^\s*[0-9a-f]+:\s+[0-9a-f]{8}\s+([a-z0-9]+)", line)
                if matched:
                    ops.append(matched.group(1))
            self.assertTrue(ops)
            self.assertIn("wfe", ops)
            self.assertIn("mrs", ops)
            self.assertTrue(set(ops).issubset({"cbz", "tst", "b.ne", "mrs", "cmp", "b.eq", "b", "wfe"}), ops)
            for forbidden in ("ldr", "str", "stp", "ldp", "bl", "blr", "br", "ret",
                              "smc", "hvc", "svc", "msr", "dc", "ic"):
                self.assertNotIn(forbidden, ops)
            self.assertNotIn("_ModuleEntryPoint", dis)
            self.assertNotIn("CEntryPoint", dis)
            self.assertEqual(ops[-2:], ["wfe", "b"])
            self.assertNotIn("R_AARCH64", dis)  # no unresolved trusted verifier shim

    def test_actual_dizi_fdt_readonly_under_sanitizers_and_aarch64_build(self):
        self.assertEqual(hashlib.sha256(FDT.read_bytes()).hexdigest(),
                         "13107fc680b51539989ecd86127edd9d50b77af22afe384ffc7956c3c2f8a944")
        silicon = HEADER.parents[0] / "Library/PlatformMemoryMapLib/DiziSm7435Memory.c"
        self.assertTrue(silicon.is_file())
        with tempfile.TemporaryDirectory(prefix="dizi-early-guard-test-") as d:
            out = Path(d)
            common = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                      "-I", str(GUARD), "-I", str(HEADER)]
            source = [str(GUARD / "DiziEarlyHandoffGuard.c"), str(silicon)]
            executable = out / "test-early"
            subprocess.run(["clang", *common, "-O1", "-g", "-fsanitize=address,undefined",
                            "-fno-omit-frame-pointer", *source,
                            str(ROOT / "tests/test-dizi-renegade-early-handoff.c"),
                            "-o", str(executable)], check=True)
            subprocess.run([str(executable), str(FDT)], check=True)
            cc = shutil.which("aarch64-linux-gnu-gcc")
            self.assertTrue(cc)
            for path in source:
                subprocess.run([cc, *common, "-ffreestanding", "-fno-builtin", "-O2",
                                "-c", path, "-o", str(out / (Path(path).stem + ".o"))],
                               check=True)

    def test_guard_source_includes_no_fake_owner_allow_or_entry_call(self):
        c = (GUARD / "DiziEarlyHandoffGuard.c").read_text()
        h = (GUARD / "DiziEarlyHandoffGuard.h").read_text()
        asm = (GUARD / "DiziEarlyHandoffGuardEntry.S").read_text()
        self.assertIn("DiziEarlyStructureOnly", c)
        self.assertIn("DiziSm7435ExpectedDdr", c)
        self.assertIn("DiziSm7435ExpectedFixed", c)
        self.assertIn("ExclusiveMemoryOwnershipVerified", h)
        self.assertIn("CanEnterRenegadePrePi", h)
        self.assertIn("WFE", h.upper())
        self.assertIn(".Ldizi_early_deny:", asm)
        self.assertNotIn("_ModuleEntryPoint:", asm)
        self.assertNotRegex(c, r"\b(?:MmioRead|MmioWrite|memcpy\s*\(|malloc\s*\(|fastboot)\b")
        self.assertNotIn("Gunyah proof acquired", h)

    def test_early_guard_edk2_package_is_self_contained_not_integrated(self):
        dec = (GUARD / "DiziEarlyHandoffGuard.dec").read_text()
        inf = (GUARD / "DiziEarlyHandoffGuard.inf").read_text()
        self.assertIn("DiziEarlyHandoffGuardLib|DiziEarlyHandoffGuard.h", dec)
        self.assertIn("LIBRARY_CLASS = DiziEarlyHandoffGuardLib", inf)
        self.assertIn("DiziEarlyHandoffGuardEntry.S | GCC", inf)
        self.assertIn("DiziEarlyHandoffGuard.c", inf)
        self.assertIn("Silicon/Qualcomm/sm7435/Library/DiziEarlyHandoffGuard/DiziEarlyHandoffGuard.dec", inf)
        self.assertIn("PlatformMemoryMapLib", inf)
        parent = ROOT / "ports/renegade/edk2-overlay/Platform/Qualcomm/sm7435/sm7435.dsc"
        board = ROOT / "ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435/dizi.dsc"
        # Intentional fail-closed lack of integration: no claim of entry guard
        # protection for the actual FD until loader/FV/linker changes reviewed.
        self.assertNotIn("DiziEarlyHandoffGuardLib|", parent.read_text())
        self.assertNotIn("DiziEarlyHandoffGuardEntry", board.read_text())

    def test_standalone_linker_entry_is_guard_not_unsafe_prepi(self):
        """Synthetic, unbootable layout proving proper linker -e plumbing.

        Real QcomPkg PrePi.inf remains unmodified and does not use this
        entry. This specifically does NOT demonstrate actual FD routing.
        """
        with tempfile.TemporaryDirectory(prefix="dizi-guard-link-entry-") as tmp:
            work = Path(tmp)
            guard = work / "guard.o"
            donor = work / "unsafe-original.o"
            image = work / "synthetic.elf"
            assembly = work / "fake-prepi.S"
            assembly.write_text(""".text
.global _ModuleEntryPoint
_ModuleEntryPoint:
  str x0, [x10]     // deliberately dangerous simulated upstream first write
  ret
.section .note.GNU-stack,"",%progbits
""")
            subprocess.run(["aarch64-linux-gnu-gcc", "-c",
                            str(GUARD / "DiziEarlyHandoffGuardEntry.S"),
                            "-o", str(guard)], check=True)
            subprocess.run(["aarch64-linux-gnu-gcc", "-c", str(assembly),
                            "-o", str(donor)], check=True)
            subprocess.run(["aarch64-linux-gnu-ld", "-e", "DiziEarlyHandoffGuardEntry",
                            "-Ttext=0x90000000", str(guard), str(donor),
                            "-o", str(image)], check=True)
            hdr = subprocess.check_output(["aarch64-linux-gnu-readelf", "-h", str(image)],
                                          text=True)
            self.assertRegex(hdr, r"Entry point address:\s*0x90000000")
            symbols = subprocess.check_output(["aarch64-linux-gnu-nm", "-n", str(image)],
                                              text=True)
            self.assertRegex(symbols, r"(?m)^0000000090000000 T DiziEarlyHandoffGuardEntry$")
            self.assertIn("_ModuleEntryPoint", symbols)
            dis = subprocess.check_output(["aarch64-linux-gnu-objdump", "-d", str(image)],
                                          text=True)
            safe = dis.split("<DiziEarlyHandoffGuardEntry>:", 1)[1]
            safe = safe.split("<_ModuleEntryPoint>:", 1)[0]
            self.assertIn("wfe", safe)
            self.assertNotIn("<_ModuleEntryPoint>", safe)
            self.assertNotRegex(safe, r"\b(?:str|ldr|br|blr|ret|bl)\b")


if __name__ == "__main__":
    unittest.main(verbosity=2)
