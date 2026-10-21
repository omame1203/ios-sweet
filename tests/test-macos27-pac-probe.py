#!/usr/bin/env python3
"""Host mock + AArch64 freestanding passive MRS audit (no device commands)."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'shim/macos27_pac_probe.c'
HEADER = ROOT / 'shim/macos27_pac_probe.h'
TEST = ROOT / 'tests/test-macos27-pac-probe.c'


class PacProbeTests(unittest.TestCase):
    def test_scope_and_trap_precautions(self):
        source = SOURCE.read_text()
        header = HEADER.read_text()
        for token in ('MAC27_PAC_PROBE_ENABLE_EL1_READ',
                      'MAC27_PAC_PROBE_TRAP_RECOVERY_CONFIRMED',
                      'MAC27_PAC_SOURCE_DIRECT_EL1'):
            self.assertIn(token, source + header)
        self.assertIn('MAC27_CPU_ORIGIN_DIRECT_EL1', source)
        self.assertIn('MAC27_PAC_SOURCE_MOCK', source)
        self.assertIn('CANNOT promise to return on a trap', source)
        self.assertIn('if (mpidr_after != tmp.mpidr_el1)', source)
        self.assertIn('out->native_boot_ready = 0', source)
        # All MRS statements must be inside the explicit opt-in gate.
        gate = source.index('#if defined(__aarch64__)')
        end = source.index('#else', gate)
        for match in re.finditer(r'__asm__ volatile', source):
            self.assertGreater(match.start(), gate)
            self.assertLess(match.start(), end)
        for token in ('mrs %0, CurrentEL', 'mrs %0, MPIDR_EL1',
                      'mrs %0, ID_AA64ISAR1_EL1',
                      'mrs %0, ID_AA64ISAR2_EL1'):
            self.assertIn(token, source)
        for forbidden in ('fastboot ', 'adb ', 'system(', 'fopen(', 'popen(',
                          'msr ', 'smc ', 'hvc ', 'pacib', 'nopauth',
                          'EITHER_PAC_OR_ISAR'):
            self.assertNotIn(forbidden, source)

    def test_sanitizers_and_aarch64_no_runtime_dependencies(self):
        cc = shutil.which('clang')
        cross = shutil.which('aarch64-linux-gnu-gcc')
        objdump = shutil.which('aarch64-linux-gnu-objdump')
        nm = shutil.which('aarch64-linux-gnu-nm')
        self.assertTrue(cc and cross and objdump and nm)
        with tempfile.TemporaryDirectory(prefix='mac27-pac-probe-') as tmp:
            tmp = Path(tmp)
            exe = tmp / 'pac-probe-test'
            subprocess.run([cc, '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
                            '-Werror', '-fsanitize=address,undefined',
                            '-fno-omit-frame-pointer', str(SOURCE), str(TEST),
                            '-o', str(exe)], check=True)
            env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1')
            result = subprocess.run([str(exe)], capture_output=True, text=True,
                                    env=env, check=True)
            self.assertRegex(result.stdout, r'PASS \d+ macOS27 passive PAC mock assertions')
            for macro_args, expected_mrs in (
                ([], False),
                (['-DMAC27_PAC_PROBE_ENABLE_EL1_READ=1'], False),
                (['-DMAC27_PAC_PROBE_TRAP_RECOVERY_CONFIRMED=1'], False),
                (['-DMAC27_PAC_PROBE_ENABLE_EL1_READ=0',
                  '-DMAC27_PAC_PROBE_TRAP_RECOVERY_CONFIRMED=1'], False),
                (['-DMAC27_PAC_PROBE_ENABLE_EL1_READ=1',
                  '-DMAC27_PAC_PROBE_TRAP_RECOVERY_CONFIRMED=1'], True),
            ):
                obj = tmp / ('probe-%d.o' % len(list(tmp.glob('probe-*.o'))))
                subprocess.run([cross, '-std=c11', '-O2', '-Wall', '-Wextra',
                                '-Werror', '-ffreestanding', '-fno-builtin',
                                '-fno-stack-protector', '-mgeneral-regs-only',
                                '-mstrict-align', *macro_args, '-c', str(SOURCE),
                                '-o', str(obj)], check=True)
                undefined = subprocess.run([nm, '-u', str(obj)], capture_output=True,
                                           text=True, check=True).stdout
                self.assertFalse(undefined.strip(), undefined)
                disas = subprocess.run([objdump, '-d', str(obj)], capture_output=True,
                                       text=True, check=True).stdout.lower()
                for reg in ('currentel', 'mpidr_el1', 'id_aa64isar1_el1',
                            'id_aa64isar2_el1'):
                    if expected_mrs:
                        self.assertRegex(disas, rf'mrs\s+x\d+,\s*{reg}')
                    else:
                        self.assertNotIn(reg, disas)
                # No writes to privileged sysregs; MRS-only when opt-in.
                self.assertNotRegex(disas, r'\bmsr\s+')
            # Using both macros on a HOST still must not read MRS.
            dual = subprocess.run([
                cc, '-std=c11', '-O2',
                '-DMAC27_PAC_PROBE_ENABLE_EL1_READ=1',
                '-DMAC27_PAC_PROBE_TRAP_RECOVERY_CONFIRMED=1',
                str(SOURCE), str(TEST), '-o', str(tmp / 'host-both')],
                check=True)
            self.assertEqual(dual.returncode, 0)
            subprocess.run([str(tmp / 'host-both')], check=True, capture_output=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
