#!/usr/bin/env python3
"""Read-only 26A434 first-B / dizi FDT provenance, sanitizer and AArch64 tests."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'ports/macos27/execution_platform_guard.c'
HEADER = ROOT / 'ports/macos27/execution_platform_guard.h'
HOST = ROOT / 'tests/test-macos27-execution-platform-guard.c'
FDT = ROOT / 'backup/dizi/fdt'
KC = ROOT / 'research/macos27-26A434/kernel.vma2.macho/kernelcache.release.vma2.decompressed'
REAL_KC_HASH = 'ca55ea8c4c86170e870380ae5501b8b43adb2d2d3db28be4531b3040653be203'


class ExecutionPlatformGuardTests(unittest.TestCase):
    def test_readonly_scope(self):
        text = SOURCE.read_text() + HEADER.read_text()
        self.assertIn('M27_XG_B_RAM_OWNERSHIP_UNKNOWN', text)
        self.assertIn('M27_XG_B_EXECUTE_UNATTESTED', text)
        self.assertIn('M27_XG_B_BRK_EXCEPTION_UNKNOWN', text)
        self.assertIn('M27_XG_B_DYNAMIC_RESERVATION', text)
        self.assertIn('M27_XG_ENTRY_PA', text)
        self.assertIn('M27_XG_DEST_PA', text)
        self.assertIn('native_entry_allowed = 0', text)
        # Source must not execute, modify KC/BRK, ask firmware, or touch a device.
        forbidden = (r'\basm\b', r'\b__asm__\b', r'\bfastboot\b',
                     r'\badb\b', r'\bfopen\s*\(', r'\bfwrite\s*\(',
                     r'\bmemcpy\s*\(', r'\bmemmove\s*\(',
                     r'\bmsr\s+', r'\bsmc\s+', r'\bhvc\s+',
                     r'\bbr\s+x[0-9]+', r'\bretab\b', r'\bblr\b')
        for pat in forbidden:
            self.assertNotRegex(SOURCE.read_text(), pat)

    def test_actual_26a434_pc_relative_branch_and_original_unchanged(self):
        if not KC.is_file():
            self.skipTest('genuine ignored KC unavailable; cannot fabricate Apple source bytes')
        self.assertEqual(KC.stat().st_size, 81444864)
        with KC.open('rb') as fd:
            h = hashlib.file_digest(fd, 'sha256').hexdigest()
        self.assertEqual(h, REAL_KC_HASH)
        with KC.open('rb') as fd:
            fd.seek(48956544)
            first = int.from_bytes(fd.read(4), 'little')
            fd.seek(48971888)
            target = int.from_bytes(fd.read(4), 'little')
        self.assertEqual(first, 0x14000efc)  # B +0x3bf0
        self.assertEqual(target, 0xd510109f)  # genuine OS lock access, NOT BRK
        self.assertNotEqual(target, 0xd429c4e0)
        self.assertEqual(48971888 - 48956544, 0x3bf0)

    def test_real_dizi_fdt_and_host_malformed_sanitizers(self):
        clang = shutil.which('clang')
        self.assertIsNotNone(clang)
        with tempfile.TemporaryDirectory(prefix='m27-platform-guard-') as tmp:
            exe = Path(tmp) / 'test-platform'
            cmd = [clang, '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
                   '-Werror', '-pedantic', '-fsanitize=address,undefined',
                   '-fno-omit-frame-pointer', str(SOURCE), str(HOST), '-o', str(exe)]
            subprocess.run(cmd, check=True)
            env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1')
            args = [str(exe)]
            if FDT.is_file():
                args.append(str(FDT))
            out = subprocess.run(args, capture_output=True, text=True,
                                 env=env, check=True).stdout
            self.assertRegex(out, r'PASS \d+ platform guard assertions')
            if FDT.is_file():
                self.assertRegex(out, r'PASS saved dizi FDT: \d+ DDR banks, \d+ fixed reservations, \d+ dynamic/unbounded children')
                self.assertIn('exec BLOCKED', out)

    def test_freestanding_aarch64_link_and_no_exec_insn(self):
        gcc = shutil.which('aarch64-linux-gnu-gcc')
        nm = shutil.which('aarch64-linux-gnu-nm')
        dis = shutil.which('aarch64-linux-gnu-objdump')
        self.assertTrue(gcc and nm and dis)
        with tempfile.TemporaryDirectory(prefix='m27-platform-aarch64-') as tmp:
            obj = Path(tmp) / 'platform.o'
            subprocess.run([gcc, '-std=c11', '-O2', '-Wall', '-Wextra',
                            '-Werror', '-pedantic', '-ffreestanding',
                            '-fno-builtin', '-fno-stack-protector',
                            '-mgeneral-regs-only', '-mstrict-align',
                            '-c', str(SOURCE), '-o', str(obj)], check=True)
            self.assertGreater(obj.stat().st_size, 1000)
            self.assertFalse(subprocess.run([nm, '-u', str(obj)],
                                            capture_output=True, text=True,
                                            check=True).stdout.strip())
            code = subprocess.run([dis, '-d', str(obj)], capture_output=True,
                                  text=True, check=True).stdout.lower()
            for pat in (r'\bmsr\s+', r'\bsmc\s+', r'\bhvc\s+',
                        r'\bbr\s+x\d+', r'\bblr\s+',
                        r'\bbrk\s+', r'\bretab\b'):
                self.assertNotRegex(code, pat)


if __name__ == '__main__':
    unittest.main(verbosity=2)
