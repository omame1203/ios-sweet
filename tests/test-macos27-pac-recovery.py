#!/usr/bin/env python3
"""Fail-closed host mock and AArch64 ELF disassembly audit; never executes MRS."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
C = ROOT / 'shim/macos27_pac_recovery.c'
H = ROOT / 'shim/macos27_pac_recovery.h'
ASM = ROOT / 'shim/macos27_pac_recovery.S'
TEST = ROOT / 'tests/test-macos27-pac-recovery.c'


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)


class Mac27PacRecoveryTests(unittest.TestCase):
    def test_source_scope_and_exception_discipline(self):
        source = C.read_text()
        asm = ASM.read_text()
        header = H.read_text()
        for marker in ('MAC27_PAC_RECOVERY_ENABLE',
                       'MAC27_PAC_RECOVERY_HANDLER_WIRED'):
            self.assertIn(marker, source)
            self.assertIn(marker, asm)
        self.assertIn('slot 4', header)
        self.assertIn('slot 5', header)
        self.assertIn('ESR_EL1', source)
        self.assertIn('ELR_EL1', source)
        self.assertIn('msr ELR_EL1, %0', source)
        self.assertIn('if (!mac27_pac_recovery_plan', source)
        self.assertIn('p->trap_mask |= bit', source)
        self.assertIn('MAC27_PAC_RECOVERY_ESR_SYSREG_EC', source)
        self.assertIn('MAC27_PAC_RECOVERY_ESR_IL', source)
        for token in ('pacib', 'pacia', 'pacga', 'nopauth',
                      'fastboot', 'adb ', 'smc #', 'hvc #',
                      'msr AP', 'msr SCTLR', 'msr HCR'):
            self.assertNotIn(token, source + asm)
        for target in ('ID_AA64ISAR1_EL1', 'ID_AA64ISAR2_EL1'):
            self.assertIn('mrs     x10, ' + target, asm)
        self.assertIn('tbnz    w11, #0, 1f', asm)
        self.assertIn('tbnz    w11, #1, 2f', asm)

    def test_host_mock_asans_and_all_compiler_modes(self):
        cc = shutil.which('clang')
        cross = shutil.which('aarch64-linux-gnu-gcc')
        nm = shutil.which('aarch64-linux-gnu-nm')
        objdump = shutil.which('aarch64-linux-gnu-objdump')
        self.assertTrue(cc and cross and nm and objdump)
        with tempfile.TemporaryDirectory(prefix='mac27-pac-recovery-') as td:
            tmp = Path(td)
            host = tmp / 'host'
            run(cc, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                str(C), str(TEST), '-o', str(host))
            env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1')
            result = run(str(host), env=env)
            self.assertRegex(result.stdout, r'PASS \d+ PAC EL1 exception-planner assertions')

            for index, (defines, enabled) in enumerate([
                ([], False),
                (['-DMAC27_PAC_RECOVERY_ENABLE=1'], False),
                (['-DMAC27_PAC_RECOVERY_HANDLER_WIRED=1'], False),
                (['-DMAC27_PAC_RECOVERY_ENABLE=0',
                  '-DMAC27_PAC_RECOVERY_HANDLER_WIRED=1'], False),
                (['-DMAC27_PAC_RECOVERY_ENABLE=1',
                  '-DMAC27_PAC_RECOVERY_HANDLER_WIRED=1'], True),
            ]):
                obj_c = tmp / f'c{index}.o'
                obj_asm = tmp / f'asm{index}.o'
                joined = tmp / f'joined{index}.o'
                common = ['-Wall', '-Wextra', '-Werror', '-ffreestanding',
                          '-fno-builtin', '-fno-stack-protector',
                          '-fno-pic', '-fno-pie', '-mgeneral-regs-only',
                          '-mstrict-align', *defines]
                run(cross, '-std=c11', '-O2', *common, '-c', str(C), '-o', str(obj_c))
                run(cross, *common, '-c', str(ASM), '-o', str(obj_asm))
                run(cross, '-nostdlib', '-r', str(obj_c), str(obj_asm),
                    '-o', str(joined))
                undefined = run(nm, '-u', str(joined)).stdout
                self.assertFalse(undefined.strip(), undefined)
                defined = run(nm, '-n', str(joined)).stdout
                disasm = run(objdump, '-d', str(joined)).stdout.lower()
                if not enabled:
                    self.assertNotIn('id_aa64isar1_el1', disasm)
                    self.assertNotIn('id_aa64isar2_el1', disasm)
                    self.assertNotIn('elr_el1', disasm)
                    self.assertNotIn('mac27_pac_recovery_mrs_isar1', defined)
                else:
                    self.assertRegex(disasm, r'mrs\s+x10, id_aa64isar1_el1')
                    self.assertRegex(disasm, r'mrs\s+x10, id_aa64isar2_el1')
                    self.assertRegex(disasm, r'msr\s+elr_el1, x\d+')
                    for label, sysreg, bit in [
                        ('mac27_pac_recovery_mrs_isar1', 'id_aa64isar1_el1', 0),
                        ('mac27_pac_recovery_mrs_isar2', 'id_aa64isar2_el1', 1),
                    ]:
                        # The precise label must point to the MRS itself.
                        pattern = rf'<{label}>:\n\s*[0-9a-f]+:\s+[0-9a-f ]+\s+mrs\s+x10, {sysreg}'
                        self.assertRegex(disasm, pattern)
                        # The instruction immediately after the MRS must
                        # load the trap flag, and then branch on that flag;
                        # no store from a faulted (unknown) x10 may occur
                        # before this check.
                        lines = disasm.splitlines()
                        label_at = next(i for i, line in enumerate(lines)
                                        if f'<{label}>:' in line)
                        following = [line.strip() for line in lines[label_at + 1:]
                                     if re.match(r'^\s*[0-9a-f]+:', line)][:4]
                        self.assertRegex(following[0], rf'mrs\s+x10, {sysreg}$')
                        self.assertRegex(following[1], r'ldr\s+w11, \[x0, #24\]')
                        self.assertRegex(following[2], rf'tbnz\s+w11, #{bit},')
                        self.assertNotIn('str\tx10', '\n'.join(following[:3]))
                    self.assertEqual(len(re.findall(r'\bmrs\s+x10, id_aa64isar[12]_el1', disasm)), 2)
                    # No AP* key writes, no attempt to modify XNU entry.
                    self.assertNotRegex(disasm, r'msr\s+ap[ia-z]')
            # Even two opt-ins on the non-AArch64 HOST produce no MRS or ELR.
            host_both = tmp / 'host_both'
            run(cc, '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                '-DMAC27_PAC_RECOVERY_ENABLE=1',
                '-DMAC27_PAC_RECOVERY_HANDLER_WIRED=1',
                str(C), str(TEST), '-o', str(host_both))
            run(str(host_both))


if __name__ == '__main__':
    unittest.main(verbosity=2)
