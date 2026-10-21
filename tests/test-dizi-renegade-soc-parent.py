#!/usr/bin/env python3
"""Offline minimal SM7435 Renegade parent DSC/FDF static integration tests.

Uses the preexisting read-only /tmp edk2-msm audit checkout only for source
paths; never edits a third-party checkout and never invokes boot/fastboot.
Static assertions are NOT proof that DSC builds, firmware runs or memory is
owned by EDK2. Missing EDK2 libraries and firmware entry remain blockers.
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "ports/renegade/edk2-overlay"
PARENT = OVERLAY / "Platform/Qualcomm/sm7435"
BOARD = OVERLAY / "Platform/Xiaomi/sm7435/dizi.dsc"
SILICON = OVERLAY / "Silicon/Qualcomm/sm7435"
UPSTREAM = Path("/tmp/dizi-edk2-msm-audit-20261021")
MEMORY_MAP = SILICON / "Library/PlatformMemoryMapLib/PlatformMemoryMapLib.c"
MEMORY_GATE = SILICON / "Library/PlatformMemoryMapLib/DiziSm7435Memory.c"
PREPI_ASM = UPSTREAM / "Silicon/Qualcomm/QcomPkg/PrePi/ModuleEntryPoint.S"
PREPI_C = UPSTREAM / "Silicon/Qualcomm/QcomPkg/PrePi/Pi.c"
DSC = PARENT / "sm7435.dsc"
FDF = PARENT / "sm7435.fdf"


def active_lines(source: str):
    for lineno, raw in enumerate(source.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if line:
            yield lineno, line


def dsc_sections(source: str):
    section = None
    for number, line in active_lines(source):
        if line.startswith("[") and line.endswith("]"):
            section = line
        yield number, section, line


def pcd_map(source: str):
    result = {}
    for num, section, line in dsc_sections(source):
        if section != "[PcdsFixedAtBuild.common]" or not line.startswith("g"):
            continue
        m = re.fullmatch(r"(g\w+\.Pcd\w+)\|(0x[0-9a-fA-F]+|[0-9]+|L?\"[^\"]*\"|TRUE|FALSE)", line)
        if not m:
            raise AssertionError(f"unexpected PCD line {num}: {line}")
        key, value = m.groups()
        if key in result:
            raise AssertionError(f"duplicate SoC PCD {key}")
        result[key] = value
    return result


def memory_descriptors(source: str):
    """Parse explicit attested descriptors; refuse expressions/hidden ranges.

    This is a HOST-ONLY source contract checker, not an EDK2 runtime verifier.
    """
    body = source.split("static ARM_MEMORY_REGION_DESCRIPTOR_EX mAuthorized[] = {", 1)[1]
    body = body.split("};", 1)[0]
    pattern = re.compile(r'\{"([^"\n]+)",\s*UINT64_C\(0x([0-9a-fA-F]+)\),\s*'
                         r'UINT64_C\(0x([0-9a-fA-F]+)\),\s*'
                         r'(AddMem|AddDev|NoHob),\s*(SYS_MEM|MEM_RES),\s*'
                         r'(\w+),\s*(Conv|Reserv),\s*(WRITE_BACK)\}')
    return [(name, int(base, 16), int(length, 16), hob, res, mem)
            for name, base, length, hob, res, _, mem, _ in pattern.findall(body)]


def validate_memory_partition(pcd: dict[str, str], descriptors):
    """Raises AssertionError for *any* FD/metadata/heap/stack overlap or gap."""
    def val(name):
        return int(pcd[name], 0)

    grant_base = val("gArmTokenSpaceGuid.PcdSystemMemoryBase")
    grant_size = val("gArmTokenSpaceGuid.PcdSystemMemorySize")
    pool_base = val("gQcomTokenSpaceGuid.PcdUefiMemPoolBase")
    pool_size = val("gQcomTokenSpaceGuid.PcdUefiMemPoolSize")
    stack_base = val("gEmbeddedTokenSpaceGuid.PcdPrePiStackBase")
    stack_size = val("gEmbeddedTokenSpaceGuid.PcdPrePiStackSize")
    vector = val("gArmTokenSpaceGuid.PcdCpuVectorBaseAddress")
    fdt_pointer = val("gSimpleInitTokenSpaceGuid.PcdDeviceTreeStore")

    expected = [
        (grant_base, 0x00400000, "AddDev", "MEM_RES", "Reserv"),
        (grant_base + 0x00400000, 0x00010000, "AddDev", "MEM_RES", "Reserv"),
        (pool_base, stack_base - pool_base, "AddMem", "SYS_MEM", "Conv"),
        (stack_base, stack_size, "NoHob", "MEM_RES", "Reserv"),
    ]
    assert len(descriptors) == 4, "unexpected number of published descriptors"
    assert grant_base == 0x90000000 and grant_size == 0x01000000
    assert pool_base == 0x90410000 and pool_size == 0x00bf0000
    assert stack_base == 0x90fc0000 and stack_size == 0x00040000
    assert fdt_pointer == 0x90400000 and vector == 0x90401000
    assert fdt_pointer + 8 <= vector, "FDT pointer clobbered by vector write"
    assert vector + 0x800 <= pool_base, "exception vectors inside free HOB pool"
    assert pool_base + pool_size - stack_size == stack_base
    assert pool_base + pool_size == grant_base + grant_size
    assert descriptors[0][1] == grant_base
    for i, entry in enumerate(descriptors):
        _, base, length, hob, resource, memory = entry
        assert (base, length, hob, resource, memory) == expected[i], (
            "wrong or unsafe EDK2 memory descriptor", i, entry, expected[i])
        assert base % 0x1000 == 0 and length % 0x1000 == 0 and length > 0
        assert base >= grant_base and base + length <= grant_base + grant_size
        if i:
            assert descriptors[i - 1][1] + descriptors[i - 1][2] == base, (
                "adjacent descriptors have a gap or overlap", i)
    assert descriptors[-1][1] + descriptors[-1][2] == grant_base + grant_size


class Sm7435ParentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsc = DSC.read_text(encoding="utf-8")
        cls.fdf = FDF.read_text(encoding="utf-8")

    def test_upstream_style_and_dizi_board_include(self):
        self.assertIn("SOC_PLATFORM                  = SM7435", self.dsc)
        self.assertIn("USE_PHYSICAL_TIMER            = FALSE", self.dsc)
        self.assertIn("!include MdePkg/MdeLibs.dsc.inc", self.dsc)
        board = BOARD.read_text()
        self.assertIn("!include Platform/Qualcomm/sm7435/sm7435.dsc", board)
        self.assertIn("FLASH_DEFINITION               = Platform/Qualcomm/sm7435/sm7435.fdf", board)
        self.assertIn("DEVICE_DXE_FV_COMPONENTS       = Platform/Xiaomi/sm7435/dizi.fdf.inc", board)
        self.assertIn("!include $(DEVICE_DXE_FV_COMPONENTS)", self.fdf)

    def test_firmware_ram_layout_silicon_contract(self):
        p = pcd_map(self.dsc)
        asint = lambda key: int(p[key], 0)
        grant = (asint("gArmTokenSpaceGuid.PcdSystemMemoryBase"),
                 asint("gArmTokenSpaceGuid.PcdSystemMemorySize"))
        pool = (asint("gQcomTokenSpaceGuid.PcdUefiMemPoolBase"),
                asint("gQcomTokenSpaceGuid.PcdUefiMemPoolSize"))
        self.assertEqual(grant, (0x90000000, 0x01000000))
        self.assertEqual(pool, (0x90410000, 0x00BF0000))
        self.assertEqual(pool[0] + pool[1], grant[0] + grant[1])
        self.assertEqual(pool[0] - grant[0], 0x00410000)
        self.assertEqual(asint("gEmbeddedTokenSpaceGuid.PcdPrePiStackBase"), 0x90FC0000)
        self.assertEqual(asint("gEmbeddedTokenSpaceGuid.PcdPrePiStackSize"), 0x00040000)
        self.assertEqual(asint("gSimpleInitTokenSpaceGuid.PcdDeviceTreeStore"), 0x90400000)
        self.assertEqual(asint("gArmTokenSpaceGuid.PcdCpuVectorBaseAddress"), 0x90401000)
        self.assertEqual(pool[0] + pool[1] - 0x40000, 0x90FC0000)
        self.assertEqual(asint("gArmTokenSpaceGuid.PcdCpuVectorBaseAddress") + 0x800, 0x90401800)
        self.assertLess(asint("gArmTokenSpaceGuid.PcdCpuVectorBaseAddress") + 0x800, pool[0])
        self.assertEqual(asint("gArmPlatformTokenSpaceGuid.PcdCoreCount"), 1)
        self.assertNotIn("0xB0400000", self.dsc)
        self.assertNotIn("0xCE000000", self.dsc)
        self.assertNotIn("0x8c0000000", "\n".join(
            line for _, line in active_lines(self.dsc) if "Pcd" in line))
        # Parent RAM PCD must match immutable strict owner checker.
        h = (SILICON / "Include/Library/DiziSm7435Memory.h").read_text()
        self.assertRegex(h, r"DIZI_SM7435_GRANT_BASE\s+UINT64_C\(0x90000000\)")
        self.assertRegex(h, r"DIZI_SM7435_GRANT_BYTES\s+UINT64_C\(0x01000000\)")

    def test_fdt_psci_gic_timer_and_framebuffer_pcds(self):
        p = pcd_map(self.dsc)
        b = pcd_map(BOARD.read_text())
        addr = "gArmTokenSpaceGuid."
        for field, value in (("PcdGicDistributorBase", 0x17200000),
                             ("PcdGicRedistributorsBase", 0x17260000),
                             ("PcdArmArchTimerFreqInHz", 19200000),
                             ("PcdArmArchTimerVirtIntrNum", 27),
                             ("PcdArmArchTimerIntrNum", 30),
                             ("PcdArmArchTimerSecIntrNum", 29)):
            self.assertEqual(int(p[addr + field], 0), value)
            if addr + field in b:
                self.assertEqual(int(b[addr + field], 0), value)
        for key, value in (("Address", 0xB8000000), ("Width", 1600),
                           ("Height", 2560), ("PixelBpp", 32)):
            full = "gQcomTokenSpaceGuid.PcdMipiFrameBuffer" + key
            self.assertEqual(int(p[full], 0), value)
            self.assertEqual(int(b[full], 0), value)
        if (ROOT / "backup/dizi/fdt").is_file():
            dtb = str(ROOT / "backup/dizi/fdt")
            try:
                psci = subprocess.check_output(
                    ["fdtget", "-t", "s", dtb, "/soc/psci", "method"], text=True).strip()
                self.assertEqual(psci, "smc")
            except FileNotFoundError:
                self.skipTest("fdtget unavailable")

    def test_fdf_valid_blocks_fv_and_compression_structure(self):
        text = self.fdf
        self.assertRegex(text, r"(?m)^\[FD\.sm7435_UEFI\]$")
        self.assertRegex(text, r"(?m)^\[FV\.FvMain\]$")
        self.assertRegex(text, r"(?m)^\[FV\.FVMAIN_COMPACT\]$")
        self.assertIn("BaseAddress   = $(FD_BASE)|gArmTokenSpaceGuid.PcdFdBaseAddress", text)
        self.assertIn("Size          = $(FD_SIZE)|gArmTokenSpaceGuid.PcdFdSize", text)
        self.assertIn("0x00000000|0x00400000", text)
        self.assertRegex(text, r"(?m)^BlockSize\s+=\s+0x00001000$")
        self.assertRegex(text, r"(?m)^NumBlocks\s+=\s+0x400$")
        self.assertEqual(0x1000 * 0x400, 0x00400000)
        self.assertIn("INF Silicon/Qualcomm/QcomPkg/PrePi/PrePi.inf", text)
        self.assertIn("SECTION FV_IMAGE = FVMAIN", text)
        self.assertIn("EE4E5898-3914-4259-9D6E-DC7BD79403CF", text)
        self.assertIn("!include Silicon/Qualcomm/QcomPkg/QcomCommonFdf.inc", text)
        self.assertNotIn("!include Platform/Qualcomm/sm7325/", text)

    def test_open_source_only_modules_match_dsc_and_fdf(self):
        self.assertNotIn("!include Silicon/Qualcomm/QcomPkg/QcomCommonDsc.inc", self.dsc)
        dscrefs = set()
        fdfrefs = set()
        for source, output in ((self.dsc, dscrefs), (self.fdf, fdfrefs)):
            for _, line in active_lines(source):
                m = re.match(r"(?:INF\s+)?((?:MdePkg|MdeModulePkg|ArmPkg|"
                             r"ArmPlatformPkg|EmbeddedPkg|ShellPkg|Silicon/Qualcomm)/\S+\.inf)", line)
                if m:
                    output.add(m.group(1))
                if line.startswith("INF "):
                    output.add(line.split()[1])
                self.assertFalse(line.startswith("FILE DRIVER") and ".efi" in line)
                self.assertNotIn("Platform/EFI_Binaries/", line)
                self.assertNotIn("AcpiTables/", line)
                self.assertNotIn("sm7325/", line)
                self.assertNotIn("sm8550/", line)
        self.assertEqual(fdfrefs - dscrefs, set())
        self.assertNotIn("ArmPkg/Drivers/ArmGic/ArmGicDxe.inf", fdfrefs)
        self.assertNotIn("ArmPkg/Drivers/TimerDxe/TimerDxe.inf", fdfrefs)
        self.assertNotIn("Silicon/Qualcomm/QcomPkg/Drivers/SimpleFbDxe/SimpleFbDxe.inf", fdfrefs)
        self.assertIn("ShellPkg/Application/Shell/Shell.inf", fdfrefs)
        self.assertIn("DEFINE DIZI_SM7435_ENABLE_CONSOLE_SHELL = FALSE", self.dsc)
        self.assertIn("!if $(DIZI_SM7435_ENABLE_CONSOLE_SHELL) == TRUE", self.fdf)
        for path in fdfrefs:
            expected = (OVERLAY / path) if path.startswith("Silicon/Qualcomm/sm7435/") else (
                UPSTREAM / path if path.startswith("Silicon/") else
                UPSTREAM / "Common/edk2" / path)
            self.assertTrue(expected.is_file(), f"missing referenced source INF: {path}")
        for path in (
            "Library/PlatformMemoryMapLib/PlatformMemoryMapLib.inf",
            "Library/PlatformPeiLib/PlatformPeiLib.inf",
            "Library/PlatformPrePiLib/PlatformPrePiLib.inf",
        ):
            self.assertIn("Silicon/Qualcomm/sm7435/" + path, self.dsc)

    def test_unresolved_fd_and_live_ownership_remain_fail_closed(self):
        config = (OVERLAY / "configs/sm7435.conf").read_text()
        self.assertIn('"SM7435 FD_BASE/FD_SIZE unknown', config)
        self.assertNotRegex(config, r"(?m)^(?:FD_BASE|FD_SIZE)\s*=")
        self.assertIn("CpuDeadLoop", (
            SILICON / "Library/PlatformPrePiLib/PlatformUtils.c").read_text())
        self.assertIn("DiziSm7435PlatformMemoryAuthorized", (
            SILICON / "Library/PlatformMemoryMapLib/PlatformMemoryMapLib.c").read_text())
        self.assertIn("!include $(DEVICE_DXE_FV_COMPONENTS)", self.fdf)

    def test_early_entry_pcm_memory_grant_is_disjoint(self):
        descriptors = memory_descriptors(MEMORY_MAP.read_text())
        validate_memory_partition(pcd_map(self.dsc), descriptors)
        gates = MEMORY_MAP.read_text()
        self.assertIn("mMemoryAuthorized ? mAuthorized : mDenied", gates)
        self.assertIn("mMemoryAuthorized = 0;", gates)
        self.assertIn("DiziSm7435PlanMemory(Observation, TrustedCheck, Context, &Plan)", gates)
        self.assertIn("DiziSm7435ApprovedByExternalVerifier", gates)
        self.assertIn("DiziSm7435PlatformMemoryAuthorized", gates)
        pure = MEMORY_GATE.read_text()
        self.assertIn("ProtectedLayoutCoversGrant(&Grant)", pure)
        self.assertIn("if (TrustedCheck(Context, O) != 1)", pure)
        self.assertIn("O->DynamicCount", pure)

    def test_qcom_prepi_actual_heap_hob_and_early_write_assumptions(self):
        if not (PREPI_C.is_file() and PREPI_ASM.is_file()):
            self.skipTest("current upstream sparse checkout unavailable")
        pi = PREPI_C.read_text()
        entry = PREPI_ASM.read_text()
        self.assertIn("FixedPcdGet32(PcdUefiMemPoolBase)", pi)
        self.assertIn("FixedPcdGet32(PcdUefiMemPoolSize)", pi)
        self.assertIn("UefiMemoryBase + UefiMemorySize - StackSize", pi)
        self.assertIn("HobConstructor(", pi)
        self.assertIn("BuildStackHob", pi)
        self.assertIn("FixedPcdGet64 (PcdDeviceTreeStore)", entry)
        self.assertIn("str x0, [x10]", entry)
        self.assertIn("FixedPcdGet64(PcdCpuVectorBaseAddress)", entry)
        self.assertIn("add x2, x0, #0x800", entry)
        self.assertIn("FixedPcdGet32(PcdPrePiStackBase)", entry)
        self.assertIn("FixedPcdGet32(PcdPrePiStackSize)", entry)
        self.assertLess(entry.index("str x0, [x10]"), entry.index("bl CEntryPoint"))
        # The Silicon gate is reached by C PlatformInitialize only after
        # these writes. Static memory partitioning cannot attest PA ownership.
        self.assertIn("CpuDeadLoop", (
            SILICON / "Library/PlatformPrePiLib/PlatformUtils.c").read_text())

    def test_negative_static_memory_overlap_mutations_fail(self):
        fixed = pcd_map(self.dsc)
        original = memory_descriptors(MEMORY_MAP.read_text())
        validate_memory_partition(fixed, original)

        bad_pcds = [
            ("gQcomTokenSpaceGuid.PcdUefiMemPoolBase", "0x90400000"),  # vector in HOB
            ("gQcomTokenSpaceGuid.PcdUefiMemPoolSize", "0x00c00000"),  # overlap stack
            ("gEmbeddedTokenSpaceGuid.PcdPrePiStackBase", "0x90fb0000"),
            ("gEmbeddedTokenSpaceGuid.PcdPrePiStackSize", "0x00020000"),
            ("gArmTokenSpaceGuid.PcdCpuVectorBaseAddress", "0x90fb0000"),
            ("gSimpleInitTokenSpaceGuid.PcdDeviceTreeStore", "0x90001000"),
            ("gArmTokenSpaceGuid.PcdSystemMemorySize", "0x01100000"),
        ]
        for key, malicious in bad_pcds:
            with self.subTest(pcd=key):
                changed = dict(fixed, **{key: malicious})
                with self.assertRaises(AssertionError):
                    validate_memory_partition(changed, original)

        bad_descriptors = [
            (0, ("FD made conventional", 0x90000000, 0x00400000,
                 "AddMem", "SYS_MEM", "Conv")),
            (1, ("VBAR made conventional", 0x90400000, 0x00010000,
                 "AddMem", "SYS_MEM", "Conv")),
            (2, ("Heap covers metadata", 0x90400000, 0x00bc0000,
                 "AddMem", "SYS_MEM", "Conv")),
            (2, ("Heap overlaps stack", 0x90410000, 0x00bc0000,
                 "AddMem", "SYS_MEM", "Conv")),
            (3, ("Stack made conventional", 0x90fc0000, 0x00040000,
                 "AddMem", "SYS_MEM", "Conv")),
            (3, ("Stack shrunk", 0x90fd0000, 0x00030000,
                 "NoHob", "MEM_RES", "Reserv")),
        ]
        for at, mutated in bad_descriptors:
            with self.subTest(mutation=mutated[0]):
                changed = list(original)
                changed[at] = mutated
                with self.assertRaises(AssertionError):
                    validate_memory_partition(fixed, changed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
