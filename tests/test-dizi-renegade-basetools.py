#!/usr/bin/env python3
"""Isolated host-side sanity checks for Renegade BaseTools GCC compatibility."""

from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/dizi-renegade-basetools.sh'


class TestRenegadeBaseTools(unittest.TestCase):
    def test_only_explicit_build_and_isolated_source(self):
        with tempfile.TemporaryDirectory(prefix='dizi-edk2-basetools-') as d:
            root = Path(d)
            edk2 = root / 'EDK2'
            edk2.mkdir()
            first = subprocess.run(['bash', str(SCRIPT), str(edk2)],
                                   text=True, capture_output=True)
            self.assertEqual(first.returncode, 2)
            (edk2 / 'edksetup.sh').write_text('#!/bin/sh\n')
            build = edk2 / 'BaseTools/Source/C'
            build.mkdir(parents=True)
            (edk2 / 'BaseTools/Makefile').write_text(
                'all:\n\t@cc -Wall -Wextra -c -o probe.o probe.c\n'
                '\t@printf OK > built.txt\n')
            (edk2 / 'BaseTools/probe.c').write_text('int test(void) { return 0; }\n')
            second = subprocess.run(['bash', str(SCRIPT), str(edk2)],
                                    text=True, capture_output=True)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn('pass --build', second.stdout)
            self.assertFalse((edk2 / 'BaseTools/built.txt').exists())
            # The compatibility wrapper must really compile a host C source.
            third = subprocess.run(['bash', str(SCRIPT), str(edk2), '--build'],
                                   text=True, capture_output=True)
            self.assertEqual(third.returncode, 0, third.stdout + third.stderr)
            self.assertTrue((edk2 / 'BaseTools/probe.o').exists())
            self.assertEqual((edk2 / 'BaseTools/built.txt').read_text(), 'OK')


if __name__ == '__main__':
    unittest.main(verbosity=2)
