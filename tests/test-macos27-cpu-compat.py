#!/usr/bin/env python3
"""Offline source provenance and host/freestanding test runner; no device I/O."""
from __future__ import annotations

import os
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'ports/macos27/cpu_compat_gate.c'
HEADER = ROOT / 'ports/macos27/cpu_compat_gate.h'
TEST = ROOT / 'tests/test-macos27-cpu-compat.c'
SAVED_CPU = ROOT / 'backup/dizi/cpu.txt'
SAVED_FDT = ROOT / 'backup/dizi/fdt'
SAVED_KC = ROOT / 'research/macos27-26A434/preflight-vma2.json'
VENDOR_SYSREG = ROOT / 'research/xiaomi-ruan/arch/arm64/include/asm/sysreg.h'


class CPUCompatTests(unittest.TestCase):
    def test_observations_are_not_raw_isar(self):
        if not SAVED_CPU.is_file():
            self.skipTest('local saved cpu.txt absent; never invent hardware observations')
        raw = SAVED_CPU.read_text()
        blocks = re.findall(r'(?m)^processor\s*:\s*\d+.*?(?=\n\s*\n|\Z)', raw, re.S)
        self.assertEqual(len(blocks), 8)
        parts = []
        for block in blocks:
            features = re.search(r'(?m)^Features\s*:\s*(.*)$', block)
            part = re.search(r'(?m)^CPU part\s*:\s*(0x[0-9a-f]+)$', block)
            self.assertIsNotNone(features)
            self.assertIsNotNone(part)
            words = set(features.group(1).split())
            self.assertFalse({'paca', 'pacg'} & words)
            parts.append(int(part.group(1), 16))
        self.assertEqual(parts, [0xd05] * 4 + [0xd41] * 4)
        self.assertNotIn('id_aa64isar1_el1', raw.lower())
        self.assertNotIn('id_aa64isar2_el1', raw.lower())

    def test_fdt_is_topology_not_feature_proof(self):
        if not SAVED_FDT.is_file() or not shutil.which('dtc'):
            self.skipTest('saved FDT or dtc not available on this host')
        output = subprocess.run(['dtc', '-I', 'dtb', '-O', 'dts', str(SAVED_FDT)],
                                capture_output=True, text=True, check=True).stdout
        self.assertIn('compatible = "qcom,kryo"', output)
        self.assertIn('enable-method = "psci"', output)
        self.assertEqual(output.count('device_type = "cpu";'), 8)
        self.assertNotIn('id_aa64isar1_el1', output.lower())

    def test_saved_26a434_kc_abi_not_x1_userland(self):
        if not SAVED_KC.is_file():
            self.skipTest('original artifact preflight unavailable; no guessed KC identity')
        data = json.loads(SAVED_KC.read_text())
        self.assertEqual(data['system_version']['build'], '26A434')
        self.assertEqual(data['kernel']['darwin_major'], 27)
        self.assertEqual(data['kernel']['cpu_subtype'], 0xc0000002)
        self.assertTrue(data['kernel']['arm64e'])
        self.assertEqual(data['kernel']['format'], 'MH_FILESET')
        self.assertIn('root:xnu-13432.1.9~1/', data['kernel']['version_string'])
        # This does NOT validate an Apple signing chain or prove bootability.

    def test_fields_match_saved_vendor_architecture_definitions(self):
        if not VENDOR_SYSREG.is_file():
            self.skipTest('vendor Linux register definition unavailable')
        data = VENDOR_SYSREG.read_text()
        for field, shift in [('APA', 4), ('API', 8), ('GPA', 24), ('GPI', 28)]:
            self.assertRegex(data, rf'#define ID_AA64ISAR1_{field}_SHIFT\s+{shift}\b')

    def test_no_claim_or_device_operations_in_portable_gate(self):
        raw = SOURCE.read_text()
        forbidden = ('fastboot', 'adb ', 'system(', 'open(', 'fopen(', 'popen(',
                     'msr ', 'str ', 'stp ', 'pacga ', 'xpaci ', 'autia ', 'nopauth')
        for value in forbidden:
            self.assertNotIn(value, raw)
        self.assertIn('mrs %0, ID_AA64ISAR1_EL1', raw)
        self.assertIn('mrs %0, ID_AA64ISAR2_EL1', raw)
        self.assertIn('out->native_mac27_ready = 0', raw)
        self.assertIn('MAC27_CPU_ORIGIN_DIRECT_EL1', HEADER.read_text())

    def test_compilation_sanitized_host_and_aarch64_freestanding(self):
        compiler = shutil.which('clang') or shutil.which('cc')
        cross = shutil.which('aarch64-linux-gnu-gcc')
        self.assertIsNotNone(compiler)
        self.assertIsNotNone(cross)
        with tempfile.TemporaryDirectory(prefix='mac27-cpu-compat-') as tmp:
            test_exe = Path(tmp) / 'test'
            flags = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                     '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            subprocess.run([compiler, *flags, str(SOURCE), str(TEST),
                            '-o', str(test_exe)], check=True)
            env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1')
            run = subprocess.run([str(test_exe)], capture_output=True, text=True,
                                 env=env, check=True)
            self.assertRegex(run.stdout, r'PASS \d+ macOS27 PAC/ISAR1\+ISAR2')
            for enabled in (0, 1):
                obj = Path(tmp) / ('gate%d.o' % enabled)
                subprocess.run([cross, '-std=c11', '-Os', '-Wall', '-Wextra',
                                '-Werror', '-ffreestanding', '-fno-builtin',
                                '-DMAC27_CPU_ENABLE_EL1_READ=%d' % enabled,
                                '-c', str(SOURCE), '-o', str(obj)], check=True)
                self.assertGreater(obj.stat().st_size, 100)
                undefined = subprocess.run(['aarch64-linux-gnu-nm', '-u', str(obj)],
                                           capture_output=True, text=True, check=True)
                self.assertFalse(undefined.stdout.strip(), undefined.stdout)
                disassembly = subprocess.run(['aarch64-linux-gnu-objdump', '-d', str(obj)],
                                            capture_output=True, text=True, check=True).stdout
                if enabled:
                    self.assertRegex(disassembly, r'mrs\s+x\d+, id_aa64isar1_el1')
                    self.assertRegex(disassembly, r'mrs\s+x\d+, id_aa64isar2_el1')
                else:
                    self.assertNotIn('id_aa64isar1_el1', disassembly)


if __name__ == '__main__':
    unittest.main(verbosity=2)
