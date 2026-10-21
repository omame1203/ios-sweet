#!/usr/bin/env python3
"""Safe, read-only Renegade SM7435 GOP build/ABI and host BLT regression suite.

Uses pinned PUBLIC EDK2 headers, no device, no fastboot, no hardware mapping.
The enabled EDK2 EFI still requires independent ownership grant integration.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
OVERLAY = ROOT / 'ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435'
DXE = OVERLAY / 'DiziSafeGopDxe'
EDK2 = Path('/tmp/dizi-edk2-msm-audit-20261021/Common/edk2')
SOURCE = DXE / 'DiziSafeGopDxe.c'
BLT = DXE / 'DiziSafeGopBlt.c'


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs)


class TestSafeInheritedGop(unittest.TestCase):
    def test_board_strict_default_and_efi_gop_fdf(self):
        board = (OVERLAY / 'dizi.dsc').read_text()
        fdf = (OVERLAY / 'dizi.fdf.inc').read_text()
        opt_fdf = (DXE / 'DiziSafeGop.fdf.inc').read_text()
        inf = (DXE / 'DiziSafeGopDxe.inf').read_text()
        self.assertRegex(board, r'(?m)^\s*DEFINE DIZI_ENABLE_SAFE_GOP = FALSE\s*$')
        self.assertRegex(board, r'(?s)!if \$\(DIZI_ENABLE_SAFE_GOP\) == TRUE'
                                   r'.*?DiziSafeGopDxe/DiziSafeGopDxe.inf')
        self.assertRegex(fdf, r'(?s)!if \$\(DIZI_ENABLE_SAFE_GOP\) == TRUE'
                                 r'.*?!include Platform/Xiaomi/sm7435/'
                                 r'DiziSafeGopDxe/DiziSafeGop.fdf.inc')
        self.assertIn('INF Platform/Xiaomi/sm7435/DiziSafeGopDxe/DiziSafeGopDxe.inf', opt_fdf)
        self.assertIn('MODULE_TYPE                    = DXE_DRIVER', inf)
        self.assertIn('ENTRY_POINT                    = DiziSafeGopEntry', inf)
        self.assertIn('UefiBootServicesTableLib', inf)
        self.assertIn('UefiDriverEntryPoint', inf)
        self.assertRegex(inf, r'(?s)\[Depex\]\s+TRUE')
        self.assertNotRegex(fdf, r'(?mi)^\s*INF\s+.*SimpleFbDxe')
        self.assertNotIn('Platform/EFI_Binaries', board + fdf + inf + opt_fdf)

    def test_fail_closed_ownership_and_no_untrusted_writes(self):
        src = SOURCE.read_text()
        h = (DXE / 'DiziSafeGopDxe.h').read_text()
        blt = BLT.read_text()
        for token in ('DIZI_SAFE_GOP_ENABLE', 'DIZI_SAFE_GOP_GRANT_INTEGRATED',
                      'DIZI_SAFE_GOP_ACTIVE', 'DIZI_SAFE_GOP_GRANT_GUID',
                      'DIZI_SAFE_GOP_REQUIRED_ACCESS', 'DIZI_SAFE_GOP_GRANT_CLEAR'):
            self.assertIn(token, src + h)
        self.assertIn('return EFI_UNSUPPORTED;', src)
        self.assertIn('mGrant->Validate(', src)
        self.assertIn('InstallMultipleProtocolInterfaces(', src)
        self.assertIn('gEfiGraphicsOutputProtocolGuid', src)
        self.assertIn('PixelBlueGreenRedReserved8BitPerColor', src)
        self.assertIn('DIZI_GOP_FB_PA             0xB8000000ULL',
                      (DXE / 'DiziSafeGopBlt.h').read_text())
        self.assertIn('DIZI_GOP_VISIBLE_BYTES     0x00FA0000ULL',
                      (DXE / 'DiziSafeGopBlt.h').read_text())
        self.assertIn('DIZI_GOP_RESERVED_BYTES    0x02B00000ULL',
                      (DXE / 'DiziSafeGopBlt.h').read_text())
        for token in ('ZeroMem', 'MmioWrite', 'MmioRead', 'SmcCall', 'HvcCall',
                      'Ufs', 'Pmic', 'Dsi', 'InitializeDisplay', 'FrameBufferBltLib'):
            self.assertNotIn(token, blt)
        self.assertNotIn('ZeroMem(', src)
        self.assertIn('if (EFI_ERROR(Status))', src)
        self.assertIn('Access = Operation == EfiBltVideoToBltBuffer', src)
        self.assertIn('ReadPixel', blt)
        self.assertIn('WritePixel', blt)
        self.assertIn('Height - 1 - Y', blt)  # overlapping rows
        self.assertIn('Width - 1 - X', blt)   # overlapping columns

    def test_real_edk2_headers_host_sanitizers_and_mock_grants(self):
        if not EDK2.is_dir():
            self.skipTest('pinned EDK2 header checkout unavailable')
        cc = shutil.which('clang')
        self.assertTrue(cc)
        incl = ['-I' + str(EDK2 / 'MdePkg/Include'),
                '-I' + str(EDK2 / 'MdePkg/Include/X64')]
        common = [cc, '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
                  '-Werror', '-fshort-wchar', '-fsanitize=address,undefined',
                  '-fno-omit-frame-pointer', *incl]
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                   UBSAN_OPTIONS='halt_on_error=1')
        with tempfile.TemporaryDirectory(prefix='renegade-safe-gop-') as temp:
            temp = Path(temp)
            suite = temp / 'gop-blt'
            run(*common, str(BLT), str(ROOT / 'tests/test-dizi-renegade-gop.c'),
                '-o', str(suite))
            self.assertRegex(run(str(suite), env=env).stdout,
                             r'PASS \d+ genuine GOP BGRA BLT host assertions')
            mock = temp / 'gop-entry'
            run(*common, '-DDIZI_SAFE_GOP_ENABLE=1',
                '-DDIZI_SAFE_GOP_GRANT_INTEGRATED=1',
                str(SOURCE), str(BLT), str(ROOT / 'tests/test-dizi-renegade-gop-entry.c'),
                '-o', str(mock))
            self.assertRegex(run(str(mock), env=env).stdout,
                             r'PASS \d+ synthetic GOP entry assertions')

    def test_aarch64_real_uefi_headers_both_flags_and_no_libc(self):
        cross = shutil.which('aarch64-linux-gnu-gcc')
        nm = shutil.which('aarch64-linux-gnu-nm')
        self.assertTrue(cross and nm)
        with tempfile.TemporaryDirectory(prefix='renegade-safe-gop-arm64-') as temp:
            temp = Path(temp)
            inc = ['-I' + str(EDK2 / 'MdePkg/Include'),
                   '-I' + str(EDK2 / 'MdePkg/Include/AArch64')]
            for case, defines in enumerate((
                [],
                ['-DDIZI_SAFE_GOP_ENABLE=1'],
                ['-DDIZI_SAFE_GOP_GRANT_INTEGRATED=1'],
                ['-DDIZI_SAFE_GOP_ENABLE=1',
                 '-DDIZI_SAFE_GOP_GRANT_INTEGRATED=1'],
            )):
                name = temp / f'gop{case}.o'
                run(cross, '-std=c11', '-Os', '-Wall', '-Wextra', '-Werror',
                    '-ffreestanding', '-fshort-wchar', '-fno-builtin',
                    '-mgeneral-regs-only', *inc, *defines,
                    '-c', str(SOURCE), '-o', str(name))
                symbols = run(nm, '-u', str(name)).stdout
                if case < 3:
                    self.assertFalse(symbols.strip(), symbols)
                else:
                    self.assertIn('DiziSafeBlt', symbols)
                    self.assertIn('gBS', symbols)
                    self.assertIn('gEfiGraphicsOutputProtocolGuid', symbols)
                    self.assertNotRegex(symbols, r'\b(memcpy|memset|malloc|free|ZeroMem)\b')
            out = temp / 'blt.o'
            run(cross, '-std=c11', '-Os', '-Wall', '-Wextra', '-Werror',
                '-ffreestanding', '-fshort-wchar', '-fno-builtin',
                '-mgeneral-regs-only', *inc, '-c', str(BLT), '-o', str(out))
            self.assertFalse(run(nm, '-u', str(out)).stdout.strip())


if __name__ == '__main__':
    unittest.main(verbosity=2)
