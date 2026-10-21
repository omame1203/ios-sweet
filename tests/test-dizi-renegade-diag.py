#!/usr/bin/env python3
"""Build and execute the real dizi DXE with mocked UEFI services and ASan."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_EDK2 = Path('/tmp/dizi-edk2-msm-audit-20261021/Common/edk2')
DXE = ROOT / 'ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435/DiziDiagDxe/DiziDiagDxe.c'
TEST = ROOT / 'tests/test-dizi-renegade-diag.c'


class TestDiziDiag(unittest.TestCase):
    def test_actual_tianocore_header_abi(self):
        if not (UPSTREAM_EDK2 / 'MdePkg/Include/Uefi.h').exists():
            self.skipTest('Pinned TianoCore source not installed')
        flags = [
            '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-fshort-wchar', '-I' + str(UPSTREAM_EDK2 / 'MdePkg/Include'),
        ]
        with tempfile.TemporaryDirectory(prefix='dizi-uefi-diag-') as temp:
            temp = Path(temp)
            for arch, compiler in [('host', 'clang'), ('arm64', 'aarch64-linux-gnu-gcc')]:
                if not shutil.which(compiler):
                    self.skipTest(f'{compiler} missing')
                args = [compiler, *flags,
                        '-I' + str(UPSTREAM_EDK2 / ('MdePkg/Include/AArch64'
                                                         if arch == 'arm64' else 'MdePkg/Include/X64'))]
                if arch == 'host':
                    exe = temp / 'host'
                    subprocess.run([*args, '-fsanitize=address,undefined',
                                    '-fno-omit-frame-pointer', str(DXE), str(TEST),
                                    '-o', str(exe)], check=True)
                    subprocess.run([str(exe)], check=True)
                else:
                    obj = temp / 'diag.o'
                    subprocess.run([*args, '-ffreestanding', '-fno-builtin',
                                    '-c', str(DXE), '-o', str(obj)], check=True)
                    unresolved = subprocess.check_output(['aarch64-linux-gnu-nm', '-u', str(obj)],
                                                         text=True)
                    self.assertIn('gEfiGraphicsOutputProtocolGuid', unresolved)
        text = (ROOT / 'ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435/DiziDiagDxe/DiziDiagDxe.inf').read_text()
        self.assertIn('MODULE_TYPE                    = DXE_DRIVER', text)
        self.assertIn('gEfiGraphicsOutputProtocolGuid', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
