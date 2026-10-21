#!/usr/bin/env python3
"""Offline Renegade EDK2 SM7435/dizi platform/FDF and real FDT provenance audit.

This test never builds, boots, flashes, invokes a storage driver or changes an
upstream EDK2 checkout. Correct DSC/FDF syntax + PCDs != working UEFI on dizi.
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import re
import shutil
import struct
import subprocess
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
BOARD = ROOT / 'ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435'
DSC = BOARD / 'dizi.dsc'
FDF = BOARD / 'dizi.fdf.inc'
EVIDENCE = BOARD / 'BoardEvidence.txt'
PROFILE = ROOT / 'boards/dizi.json'
FDT = ROOT / 'backup/dizi/fdt'
EDK2 = Path('/tmp/dizi-edk2-msm-audit-20261021')
SILICON = ROOT / 'ports/renegade/edk2-overlay/Platform/Qualcomm/sm7435'
DIAG = BOARD / 'DiziDiagDxe/DiziDiagDxe.c'
DIAG_INF = BOARD / 'DiziDiagDxe/DiziDiagDxe.inf'
# Worker-9 isolated DEBUG build; READ ONLY. Not a device or user repo build.
ISOLATED_BUILD = Path('/tmp/dizi-edk2-msm-genuine-dizi-debug-20261021-w9')
DIAG_OUTPUT = (ISOLATED_BUILD / 'Build/dizi/DEBUG_GCC5/AARCH64/Platform/Xiaomi/'
               'sm7435/DiziDiagDxe/DiziDiagDxe/OUTPUT')


def pcds(source: str) -> dict[str, str]:
    """Extract board DSC's fixed PCD overrides, rejecting silent duplicates."""
    current = None
    result = {}
    for lineno, raw in enumerate(source.splitlines(), 1):
        text = raw.split('#', 1)[0].strip()
        if text.startswith('[') and text.endswith(']'):
            current = text
            continue
        if current == '[PcdsFixedAtBuild.common]' and text.startswith('g'):
            match = re.fullmatch(r'([A-Za-z0-9_]+\.[A-Za-z0-9_]+)\|(.+)', text)
            if not match:
                raise AssertionError(f'bad PCD syntax line {lineno}: {text}')
            key, val = match.groups()
            if key in result:
                raise AssertionError(f'duplicate PCD {key} line {lineno}')
            result[key] = val.strip()
    return result


def fdt_words(path: str, prop: str) -> list[int]:
    return [int(x, 16) for x in subprocess.check_output(
        ['fdtget', '-t', 'x', str(FDT), path, prop],
        stderr=subprocess.STDOUT, text=True).split()]


class RenegadeDiziPlatformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsc = DSC.read_text()
        cls.fdf = FDF.read_text()
        cls.evidence = EVIDENCE.read_text()
        cls.profile = json.loads(PROFILE.read_text())
        cls.fixed = pcds(cls.dsc)

    def test_genuine_board_dsc_and_unique_paths(self):
        txt = self.dsc
        self.assertIn('VENDOR_NAME                    = Xiaomi', txt)
        self.assertIn('PLATFORM_NAME                  = dizi', txt)
        self.assertRegex(txt, r'(?m)^\s*SUPPORTED_ARCHITECTURES\s*=\s*AARCH64\s*$')
        self.assertIn('FLASH_DEFINITION               = Platform/Qualcomm/sm7435/sm7435.fdf', txt)
        self.assertIn('DEVICE_DXE_FV_COMPONENTS       = Platform/Xiaomi/sm7435/dizi.fdf.inc', txt)
        self.assertRegex(txt, r'(?m)^!include Platform/Qualcomm/sm7435/sm7435\.dsc\s*$')
        match = re.search(r'(?m)^\s*PLATFORM_GUID\s*=\s*([0-9a-fA-F-]+)\s*$', txt)
        self.assertIsNotNone(match)
        self.assertEqual(uuid.UUID(match.group(1)).version, 4)
        self.assertIn('GCC:*_*_AARCH64_CC_FLAGS = -DENABLE_SIMPLE_INIT', txt)
        self.assertNotIn('ENABLE_LINUX_SIMPLE_MASS_STORAGE', '\n'.join(
            line for line in txt.splitlines()
            if not line.lstrip().startswith('#')))

    def test_gop_pc_d_layout_matches_physical_reservation(self):
        fixed = self.fixed
        prefix = 'gQcomTokenSpaceGuid.PcdMipiFrameBuffer'
        expected = self.profile['framebuffer']
        self.assertEqual(int(fixed[prefix + 'Address'], 0), int(expected['base'], 0))
        self.assertEqual(int(fixed[prefix + 'Width']), expected['width'])
        self.assertEqual(int(fixed[prefix + 'Height']), expected['height'])
        self.assertEqual(int(fixed[prefix + 'PixelBpp']), 32)
        self.assertEqual(int(fixed[prefix + 'VisibleWidth']), expected['width'])
        self.assertEqual(int(fixed[prefix + 'VisibleHeight']), expected['height'])
        self.assertEqual(expected['stride'], 4 * expected['width'])
        footprint = expected['height'] * expected['stride']
        reservation = int(expected['reserved_size'], 0)
        self.assertEqual(footprint, 1600 * 2560 * 4)
        self.assertLessEqual(footprint, reservation)
        self.assertEqual(footprint, 0xFA0000)
        self.assertLessEqual(int(expected['base'], 0) + reservation, 1 << 32)
        # Qcom SimpleFbDxe uses PcdMipiFrameBufferAddress (UINT32),
        # Width, Height, and advertises PixelBlueGreenRedReserved8BitPerColor.
        if EDK2.is_dir():
            gfx = (EDK2 / 'Silicon/Qualcomm/QcomPkg/Drivers/SimpleFbDxe/SimpleFbDxe.c')
            self.assertTrue(gfx.is_file())
            text = gfx.read_text()
            self.assertIn('FixedPcdGet32(PcdMipiFrameBufferAddress)', text)
            self.assertIn('PixelBlueGreenRedReserved8BitPerColor', text)
            self.assertIn('InstallMultipleProtocolInterfaces(', text)
            # SIMPLE_FB IS NOT A SAFE PIXEL FORMAT CONVERSION DRIVER.
            self.assertIn('ZeroMem((void *)FrameBufferAddress, FrameBufferSize)', text)

    def test_gic_timer_from_saved_board_and_not_another_soc(self):
        p = self.fixed
        a = 'gArmTokenSpaceGuid.'
        self.assertEqual(int(p[a + 'PcdGicDistributorBase'], 0), 0x17200000)
        self.assertEqual(int(p[a + 'PcdGicRedistributorsBase'], 0), 0x17260000)
        self.assertEqual(int(p[a + 'PcdArmArchTimerFreqInHz']), 19200000)
        self.assertEqual(int(p[a + 'PcdArmArchTimerIntrNum']), 30)
        self.assertEqual(int(p[a + 'PcdArmArchTimerVirtIntrNum']), 27)
        self.assertEqual(int(p[a + 'PcdGicDistributorBase'], 0), int(self.profile['gic'][0], 0))
        self.assertEqual(int(p[a + 'PcdGicRedistributorsBase'], 0), int(self.profile['gic'][2], 0))
        self.assertEqual(int(p[a + 'PcdArmArchTimerVirtIntrNum']), self.profile['virtual_timer_intid'])
        self.assertEqual(int(p[a + 'PcdArmArchTimerIntrNum']), self.profile['physical_timer_intid'])
        self.assertEqual(self.profile['timer_frequency'], 19200000)

    def test_vendor_model_and_host_gui_only(self):
        p = self.fixed
        for unconsumed in ('PcdDeviceVendor', 'PcdDeviceProduct', 'PcdDeviceCodeName'):
            self.assertNotIn('gRenegadePkgTokenSpaceGuid.' + unconsumed, p)
        self.assertIn('Xiaomi POCO Pad dizi SM7435', self.evidence)
        self.assertEqual(int(p['gSimpleInitTokenSpaceGuid.PcdGuiDefaultDPI']), 240)
        self.assertIn('UI preference', self.dsc)
        self.assertNotRegex(self.dsc, r'(?mi)^\s*INF\s+.*(UFSDxe|UFS|Acpi)')

    def test_fdf_is_real_freeform_and_no_foreign_bsp_or_acpi(self):
        text = self.fdf
        self.assertRegex(text, r'(?m)^FILE FREEFORM = [0-9a-fA-F-]{36} \{')
        self.assertRegex(text, r'(?m)^\s*SECTION RAW = Platform/Xiaomi/sm7435/BoardEvidence\.txt\s*$')
        self.assertRegex(text, r'(?m)^\s*SECTION UI = "DiziBoardEvidence"\s*$')
        active = '\n'.join(line for line in text.splitlines()
                           if line.strip() and not line.lstrip().startswith('#'))
        self.assertNotRegex(active, r'(?i)sm7325|lisa|mona|UFSDxe|Acpi|DSDT|SMI|Button|ClockDxe|PMIC|Platform/EFI_Binaries')
        # A single genuine, open-source dizi GOP diagnostics DXE is allowed;
        # imported vendor binary DXEs/depex and arbitrary providers are not.
        self.assertEqual(re.findall(r'(?mi)^\s*INF\s+([^\s]+)\s*$', active),
                         ['Platform/Xiaomi/sm7435/DiziDiagDxe/DiziDiagDxe.inf'])
        self.assertNotRegex(active, r'(?i)\b(SECTION PE32|SECTION DXE_DEPEX)\b')
        self.assertNotIn('bootable', self.evidence.splitlines()[0])
        self.assertIn('NOT prove a bootable', self.evidence)

    def test_actual_saved_fdt_resources_and_precise_limits(self):
        if not (FDT.is_file() and shutil.which('fdtget')):
            self.skipTest('original captured live dizi FDT or fdtget not present')
        self.assertEqual(fdt_words('/soc/interrupt-controller@17200000', 'reg'),
                         [0x17200000, 0x10000, 0x17260000, 0x100000])
        self.assertEqual(fdt_words('/soc/timer', 'clock-frequency'), [19200000])
        self.assertEqual(fdt_words('/reserved-memory/splash_region', 'reg'),
                         [0, 0xb8000000, 0, 0x2b00000])
        timer = fdt_words('/soc/timer', 'interrupts')
        self.assertEqual((timer[6], timer[7]), (1, 27 - 16))
        self.assertEqual((timer[3], timer[4]), (1, 30 - 16))
        # The display and graphics memory layout are inherited only.
        self.assertIn('inherited', self.dsc.lower())

    def test_upstream_edk2_fdf_dsc_conventions(self):
        if not EDK2.is_dir():
            self.skipTest('pinned edk2-msm source checkout not mounted')
        lisa = (EDK2 / 'Platform/Xiaomi/sm7325/lisa.dsc').read_text()
        silicon_dsc = (EDK2 / 'Platform/Qualcomm/sm7325/sm7325.dsc').read_text()
        silicon_fdf = (EDK2 / 'Platform/Qualcomm/sm7325/sm7325.fdf').read_text()
        self.assertIn('!include Platform/Qualcomm/sm7325/sm7325.dsc', lisa)
        self.assertIn('DEVICE_DXE_FV_COMPONENTS', lisa)
        self.assertIn('PlatformMemoryMapLib|Silicon/Qualcomm/sm7325/', silicon_dsc)
        self.assertIn('!include $(DEVICE_DXE_FV_COMPONENTS)', silicon_fdf)
        self.assertIn('Silicon/Qualcomm/QcomPkg/Drivers/SimpleFbDxe/SimpleFbDxe.inf', silicon_fdf)
        # A new sm7435-specific Silicon implementation MUST replace the donor.
        self.assertNotIn('Platform/Qualcomm/sm7325', self.dsc)
        self.assertNotIn('Silicon/Qualcomm/sm7325', self.fdf)

    def test_silicon_contract_only_when_worker_artifacts_exist(self):
        # Never pronounce the OVERALL firmware buildable because this board
        # DSC is valid. The SoC .dsc/.fdf, prebinaries, memory ownership,
        # and EDK2 toolchain must be separately checked by the prime.
        parent_dsc = SILICON / 'sm7435.dsc'
        parent_fdf = SILICON / 'sm7435.fdf'
        if not (parent_dsc.is_file() and parent_fdf.is_file()):
            self.skipTest('worker-6 Silicon parent not yet present; build readiness BLOCKED')
        parent_text = parent_dsc.read_text() + parent_fdf.read_text()
        contents = '\n'.join(line.split('#', 1)[0] for line in parent_text.splitlines()
                             if not line.lstrip().startswith('#'))
        for foreign in ('sm7325', 'sm8250', 'sm8550', 'UFSDxe.efi'):
            self.assertNotIn(foreign, contents)
        self.assertIn('DEVICE_DXE_FV_COMPONENTS', contents)
        self.assertIn('!include $(DEVICE_DXE_FV_COMPONENTS)', contents)
        self.assertIn('USE_PHYSICAL_TIMER', contents)
        self.assertIn('gArmTokenSpaceGuid.PcdArmArchTimerVirtIntrNum|27', contents)
        # SimpleFbDxe is optional: it ZeroMem()s the inherited framebuffer.
        # Do not require device access until the SoC has established a safe
        # writable scanout mapping and graphics handoff contract.
        active_infs = re.findall(r'(?m)^\s*INF\s+(\S+)', contents)
        self.assertNotIn('Silicon/Qualcomm/QcomPkg/Drivers/SimpleFbDxe/SimpleFbDxe.inf',
                         active_infs)
        self.assertNotIn('ArmPkg/Drivers/ArmGic/ArmGicDxe.inf', active_infs)
        self.assertNotIn('ArmPkg/Drivers/TimerDxe/TimerDxe.inf', active_infs)
        # Inactive diagnostics: GOP depex cannot become TRUE when no driver
        # in the sealed FV produces graphics output protocol.

    def test_dizi_diag_true_module_wiring_and_no_unsafe_gop_activation(self):
        path = 'Platform/Xiaomi/sm7435/DiziDiagDxe/DiziDiagDxe.inf'
        driver = DIAG.read_text()
        inf = DIAG_INF.read_text()
        self.assertRegex(self.dsc, r'(?m)^\s*' + re.escape(path) + r'\s*$')
        self.assertEqual(re.findall(r'(?m)^\s*INF\s+(\S+)', self.fdf), [path])
        self.assertIn('MODULE_TYPE                    = DXE_DRIVER', inf)
        self.assertIn('ENTRY_POINT                    = DiziDiagEntry', inf)
        self.assertRegex(inf, r'(?s)\[Depex\]\s+gEfiGraphicsOutputProtocolGuid')
        self.assertIn('gEfiGraphicsOutputProtocolGuid', driver)
        self.assertIn('LocateProtocol(', driver)
        self.assertIn('PixelBlueGreenRedReserved8BitPerColor', driver)
        self.assertIn('FrameBufferBase != DIZI_FB_PHYSICAL_ADDRESS', driver)
        self.assertIn('FrameBufferSize < DIZI_FB_MIN_BYTES', driver)
        self.assertIn('FrameBufferSize > DIZI_FB_RESERVED_BYTES', driver)
        for forbidden in ('InstallMultipleProtocolInterfaces', 'MmioWrite',
                          'FrameBufferBlt(', 'ZeroMem((void *)FrameBufferAddress',
                          'Ufs', 'SmcCall', 'Stall('):
            self.assertNotIn(forbidden, driver)
        self.assertIn('gEfiGraphicsOutputProtocolGuid', inf)

    def test_actual_edk2_dxe_binary_build_link_and_gop_depex(self):
        # Test actual linked EFI and dependency expression, not just a
        # freestanding .o: link success is distinct from genuine device boot.
        efi_path = DIAG_OUTPUT / 'DiziDiagDxe.efi'
        depex_path = DIAG_OUTPUT / 'DiziDiagDxe.depex'
        staged = ISOLATED_BUILD / 'Platform/Xiaomi/sm7435/DiziDiagDxe/DiziDiagDxe.c'
        if not all(path.is_file() for path in (efi_path, depex_path, staged)):
            self.skipTest('isolated worker-9 GCC5 EDK2 artifact unavailable')
        self.assertEqual(hashlib.sha256(staged.read_bytes()).digest(),
                         hashlib.sha256(DIAG.read_bytes()).digest(),
                         'staged EFI was built from a DIFFERENT driver revision')
        data = efi_path.read_bytes()
        self.assertGreaterEqual(len(data), 4096)
        self.assertEqual(data[:2], b'MZ')
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        self.assertLess(pe + 128, len(data))
        self.assertEqual(data[pe:pe+4], b'PE\0\0')
        self.assertEqual(struct.unpack_from('<H', data, pe+4)[0], 0xAA64)
        self.assertEqual(struct.unpack_from('<H', data, pe+24)[0], 0x20B)
        self.assertEqual(struct.unpack_from('<H', data, pe+24+68)[0], 11)
        self.assertEqual(len(data), 12288)
        # The linker merges declared GOP dependency with UefiDriverEntryPoint
        # library's EFI PCD dependency. Decode real binary bytecode.
        raw = depex_path.read_bytes()
        self.assertEqual(len(raw), 36)
        self.assertEqual(raw[0], 2)  # PUSH
        self.assertEqual(str(uuid.UUID(bytes_le=raw[1:17])),
                         '9042a9de-23dc-4a38-96fb-7aded080516a')  # GOP
        self.assertEqual(raw[17], 2)  # PUSH
        self.assertEqual(str(uuid.UUID(bytes_le=raw[18:34])),
                         '13a3f0f6-264a-3ef0-f2e0-dec512342f34')  # PCD
        self.assertEqual(raw[-2:], b'\x03\x08')  # AND, END


if __name__ == '__main__':
    unittest.main(verbosity=2)
