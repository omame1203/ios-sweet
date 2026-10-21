#!/usr/bin/env python3
"""Source-only Renegade EDK2 SM7435 overlay verification (never touches device).

Uses host Clang ASan/UBSan plus a MINIMAL EDK2 ABI type shim exclusively in
TemporaryDirectory; compiles pure silicon code for AArch64. FDT is READ-ONLY.
The shim is not an EDK2 firmware build. No fake ACPI/XBL binaries.
"""

from pathlib import Path
import hashlib
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SILICON = ROOT / "ports/renegade/edk2-overlay/Silicon/Qualcomm/sm7435"
MEMORY = SILICON / "Library/PlatformMemoryMapLib"
HEADER = SILICON / "Include"
HOST = ROOT / "tests/test-dizi-renegade-silicon.c"
FDT = ROOT / "backup/dizi/fdt"
UPSTREAM = Path("/tmp/dizi-edk2-msm-audit-20261021")

EDK2_SHIM = """#ifndef FAKE_PLATFORM_MEMORY_MAP_LIB_H
#define FAKE_PLATFORM_MEMORY_MAP_LIB_H
#include <stdint.h>
typedef struct {
  char Name[32]; uint64_t Address; uint64_t Length;
  int HobOption; int ResourceType; uint64_t ResourceAttribute;
  int MemoryType; int ArmAttributes;
} ARM_MEMORY_REGION_DESCRIPTOR_EX;
enum { NoHob = 0, AddMem = 1, AddDev = 2 };
enum { SYS_MEM = 1, MMAP_IO = 2, MEM_RES = 3 };
enum { Conv = 1, Reserv = 2, MmIO = 3 };
enum { SYS_MEM_CAP = 15, WRITE_BACK_XN = 16, WRITE_BACK = 16, INITIALIZED = 32 };
ARM_MEMORY_REGION_DESCRIPTOR_EX *GetPlatformMemoryMap(void);
#endif
"""


def run(*args):
    subprocess.run(args, check=True, cwd=ROOT)


def fdt_property(node: str, prop: str):
    out = subprocess.check_output(["fdtget", "-t", "x", str(FDT), node, prop], text=True)
    return [int(c, 16) for c in out.split()]


def tuples(cells):
    assert len(cells) % 4 == 0
    return [(cells[n] << 32 | cells[n+1], cells[n+2] << 32 | cells[n+3])
            for n in range(0, len(cells), 4)]


def parse_constants(name: str, source: str):
    start = re.search(rf"static const DIZI_SM7435_RANGE m{name}\[[^]]+\] = \{{", source)
    if not start:
        raise AssertionError(f"Missing source {name} FDT array")
    body = source[start.end():source.index("};", start.end())]
    return [(int(a, 16), int(b, 16)) for a, b in
            re.findall(r"\{\s*UINT64_C\(0x([0-9a-fA-F]+)\),\s*UINT64_C\(0x([0-9a-fA-F]+)\)\s*\}", body)]


class TestDiziRenegadeSilicon(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (MEMORY / "DiziSm7435Memory.c").read_text()

    def test_real_fdt_ddr_7_and_fixed_35(self):
        if not FDT.exists() or not shutil.which("fdtget"):
            self.skipTest("Saved FDT or fdtget absent")
        self.assertEqual(hashlib.sha256(FDT.read_bytes()).hexdigest(),
                         "13107fc680b51539989ecd86127edd9d50b77af22afe384ffc7956c3c2f8a944")
        ddr = [v for v in tuples(fdt_property("/memory", "reg")) if v[1]]
        self.assertEqual(len(ddr), 7)
        self.assertCountEqual(parse_constants("Ddr", self.text), ddr)
        children = subprocess.check_output(["fdtget", "-l", str(FDT), "/reserved-memory"],
                                           text=True).splitlines()
        fixed, dynamic = [], []
        for name in children:
            path = "/reserved-memory/" + name
            props = subprocess.check_output(["fdtget", "-p", str(FDT), path], text=True).splitlines()
            if "reg" in props:
                fixed.extend(tuples(fdt_property(path, "reg")))
            else:
                dynamic.append(name)
        self.assertEqual((len(fixed), len(dynamic)), (35, 10))
        self.assertCountEqual(parse_constants("Fixed", self.text), fixed)
        self.assertIn((0xb8000000, 0x2b00000), fixed)

    def test_edk2_overlay_inf_decs_and_source_provenance(self):
        names = ["Library/PlatformMemoryMapLib/PlatformMemoryMapLib.inf",
                 "Library/PlatformPrePiLib/PlatformPrePiLib.inf",
                 "Library/PlatformPeiLib/PlatformPeiLib.inf"]
        for name in names:
            text = (SILICON / name).read_text()
            self.assertIn("[Defines]", text)
            self.assertIn("[Packages]", text)
            self.assertIn("Silicon/Qualcomm/sm7435/sm7435.dec", text)
            self.assertNotIn("sm7325.dec", text)
        self.assertTrue((SILICON / "sm7435.dec").is_file())
        upstream_header = (UPSTREAM / "Silicon/Qualcomm/QcomPkg/Include/Library/PlatformMemoryMapLib.h")
        if upstream_header.exists():
            self.assertIn("ARM_MEMORY_REGION_DESCRIPTOR_EX", upstream_header.read_text())
            self.assertIn("GetPlatformMemoryMap", upstream_header.read_text())
        self.assertNotIn("0xb0400000", self.text.lower())  # never donor heap
        self.assertNotIn("0x9ffff000", self.text.lower())  # never donor EFI info

    def test_no_hardware_writes_in_silicon_source(self):
        # The pre-SEC/PEI libraries must remain MMIO-free in all builds.
        # New separately gated DXE device drivers have their own full-source
        # default-disabled/owner-proof test; reject their accidental
        # inclusion in the PrePi libraries instead of banning any source
        # code that correctly implements an opt-in interrupt controller.
        sources = list((SILICON / "Library").rglob("*.c"))
        self.assertGreaterEqual(len(sources), 4)
        bad = re.compile(r"\b(?:MmioWrite\w*|MmioRead\w*|SerialPortInitialize|"
                         r"RFSLocateAndProtectSharedArea|GICR_WAKER_CURRENT_CPU|"
                         r"fastboot|UfsHc|ActivateSmmu)\s*\(")
        for path in sources:
            self.assertIsNone(bad.search(path.read_text()), f"Unsafe MMIO call in {path}")

    def test_prep_i_and_pei_compile_without_donor_libs(self):
        # For the actual EDK2 libraries, full upstream BaseTools/DSC + device
        # firmware inputs are needed. Here we at least type-check the exported
        # PlatformInitialize/PlatformPeim APIs under a tiny explicit ABI shim.
        cross = shutil.which("aarch64-linux-gnu-gcc")
        if not cross:
            self.skipTest("AArch64 cross compiler unavailable")
        with tempfile.TemporaryDirectory(prefix="sm7435-pei-abi-") as tmp:
            d = Path(tmp)
            lib = d / "Library"
            lib.mkdir()
            (lib / "BaseLib.h").write_text('''#include <stdint.h>
typedef void VOID;
typedef uint64_t UINT64;
typedef uint32_t UINT32;
typedef uintptr_t UINTN;
void CpuDeadLoop(void);
''')
            (d / "PiPei.h").write_text('''#include <stdint.h>
typedef uint64_t UINT64;
typedef uint32_t UINT32;
typedef uint64_t EFI_STATUS;
#define EFIAPI
#define VOID void
#define EFI_NOT_READY 6ULL
#define EFI_UNSUPPORTED 3ULL
#define EFI_SUCCESS 0ULL
''')
            (lib / "HobLib.h").write_text('''#include <stdint.h>
void BuildFvHob(uint64_t base,uint64_t length);
''')
            (lib / "PcdLib.h").write_text('''#include <stdint.h>
#define PcdFvBaseAddress 1
#define PcdFvSize 2
#define PcdGet64(x) ((uint64_t)0x90000000)
#define PcdGet32(x) ((uint32_t)0x00100000)
''')
            prep = SILICON / "Library/PlatformPrePiLib/PlatformUtils.c"
            pei = SILICON / "Library/PlatformPeiLib/PlatformPeiLib.c"
            base = [cross, "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-ffreestanding", "-O2", "-I", str(d), "-I", str(HEADER)]
            run(*base, "-c", str(prep), "-o", str(d / "PrePi.o"))
            run(*base, "-c", str(pei), "-o", str(d / "Pei.o"))
            # Disabled-by-default FB diagnostic must not appear without BOTH
            # explicit opt-ins. Compile only (never run) the diagnostic path.
            denied = subprocess.run([*base, "-DDIZI_EDK2_PREPI_DIAGNOSTIC=1",
                                     "-c", str(prep), "-o", str(d / "bad.o")],
                                    cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("explicit framebuffer review opt-in", denied.stderr)
            run(*base, "-DDIZI_EDK2_PREPI_DIAGNOSTIC=1",
                "-DDIZI_EDK2_PREPI_FB_REVIEWED=1", "-c", str(prep),
                "-o", str(d / "PrePi-pixel-opt-in.o"))

    def test_host_sanitizers_map_abi_and_cross_target(self):
        with tempfile.TemporaryDirectory(prefix="dizi-renegade-sm7435-") as temp:
            work = Path(temp)
            fake = work / "Library"
            fake.mkdir()
            (fake / "PlatformMemoryMapLib.h").write_text(EDK2_SHIM)
            binary = work / "test-silicon"
            run("clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-Wpedantic", "-O1", "-g", "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer", "-I", str(work), "-I", str(HEADER),
                str(MEMORY / "DiziSm7435Memory.c"),
                str(MEMORY / "PlatformMemoryMapLib.c"), str(HOST), "-o", str(binary))
            run(str(binary))
            cc = shutil.which("aarch64-linux-gnu-gcc")
            if cc:
                for path in (MEMORY / "DiziSm7435Memory.c",
                             MEMORY / "PlatformMemoryMapLib.c"):
                    run(cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-ffreestanding", "-fno-builtin", "-O2",
                        "-I", str(work), "-I", str(HEADER), "-c", str(path),
                        "-o", str(work / (path.stem + ".o")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
