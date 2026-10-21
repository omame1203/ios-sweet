#!/usr/bin/env python3
"""Host-only upstream Renegade dizi config fail-closed / path regression."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / 'ports/renegade/edk2-overlay/configs/sm7435.conf'


class DiziConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dizi-renegade-conf-')
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)
        self.prepi = self.source / 'Silicon/Qualcomm/sm7435/Library/PlatformPrePiLib/PlatformPrePiLib.inf'
        self.board = self.source / 'Platform/Xiaomi/sm7435/dizi.dsc'
        self.parent = self.source / 'Platform/Qualcomm/sm7435/sm7435.fdf'

    def run_config(self, fd_base='', fd_size=''):
        env = dict(os.environ, ROOTDIR=str(self.source), FD_BASE=fd_base,
                   FD_SIZE=fd_size)
        return subprocess.run(
            ['bash', '-c', 'source "$1"; rc=$?; [ "$rc" -eq 0 ] || exit "$rc"; printf "%s/%s\n" "$SOC_VENDOR" "$FD_BASE"',
             'dizi-config-test', str(CONFIG)],
            capture_output=True, text=True, env=env, check=False)

    def create_inputs(self):
        for path in (self.prepi, self.board, self.parent):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic existence marker only\n')

    def test_missing_parent_fdf_refuses_even_with_fd_fields(self):
        self.create_inputs()
        self.parent.unlink()
        result = self.run_config('0x90000000', '0x00400000')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('silicon/platform', result.stderr)

    def test_present_parent_does_not_invent_fd_or_ownership(self):
        self.create_inputs()
        result = self.run_config()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('FD_BASE/FD_SIZE unknown', result.stderr)

    def test_explicit_fd_candidate_can_pass_presence_check_only(self):
        # Success here tests a shell guard, NOT Gunyah/XPU owner evidence,
        # valid FD contents, a Linux Image ABI or an on-device boot permit.
        self.create_inputs()
        result = self.run_config('0x90000000', '0x00400000')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Qualcomm/0x90000000', result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
