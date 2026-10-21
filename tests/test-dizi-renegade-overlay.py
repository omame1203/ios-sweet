#!/usr/bin/env python3
"""Non-device tests of isolated modern Renegade EDK2 integration workflow."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'renegade_overlay', ROOT / 'tools/dizi-renegade-overlay.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def git(repo: Path, *args: str):
    return subprocess.check_output(['git', '-C', str(repo), *args],
                                   text=True, stderr=subprocess.STDOUT).strip()


class TestRenegadeOverlay(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='renegade-dizi-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'upstream'
        self.repo.mkdir()
        git(self.repo, 'init', '-q')
        git(self.repo, 'config', 'user.name', 'Test')
        git(self.repo, 'config', 'user.email', 'test@example.invalid')
        (self.repo / 'README.md').write_text('Synthetic upstream EDK2 stub\n')
        git(self.repo, 'add', 'README.md')
        git(self.repo, 'commit', '-qm', 'Initial upstream stub')
        self.head = git(self.repo, 'rev-parse', 'HEAD')
        self.saved_pin = m.PINNED_RENEGADE_COMMIT
        m.PINNED_RENEGADE_COMMIT = self.head
        self.addCleanup(lambda: setattr(m, 'PINNED_RENEGADE_COMMIT', self.saved_pin))
        self.overlay = self.root / 'overlay'
        self.overlay.mkdir()

    def add_file(self, name: str, text='device-specific test source\n'):
        path = self.overlay / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def complete(self):
        for name in m.REQUIRED:
            self.add_file(name)

    def test_empty_review_cannot_be_declared_buildable(self):
        output = m.review(self.repo, self.overlay)
        self.assertEqual(output['upstream_commit'], self.head)
        self.assertEqual(len(output['missing_platform_inputs']), len(m.REQUIRED))
        self.assertFalse(output['generated_uefi_fd'])
        self.assertFalse(output['temporary_boot_performed'])
        with self.assertRaisesRegex(m.NotReady, 'incomplete'):
            m.prepare(self.repo, self.overlay, self.root / 'new')
        self.assertFalse((self.root / 'new').exists())

    def test_complete_stage_uses_new_git_checkout_only(self):
        self.complete()
        dest = self.root / 'new'
        out = m.prepare(self.repo, self.overlay, dest)
        self.assertEqual(out['missing_platform_inputs'], [])
        self.assertEqual(git(dest, 'rev-parse', 'HEAD'), self.head)
        for name in m.REQUIRED:
            self.assertEqual((dest / name).read_bytes(), (self.overlay / name).read_bytes())
        self.assertFalse((self.repo / 'configs').exists())
        self.assertTrue((dest / '.git').exists())
        with self.assertRaisesRegex(m.NotReady, 'already exists'):
            m.prepare(self.repo, self.overlay, dest)
        with self.assertRaisesRegex(m.NotReady, 'submodules not yet initialized'):
            m.build(dest, out)

    def test_unreviewed_upstream_rejected(self):
        m.PINNED_RENEGADE_COMMIT = '0' * 40
        with self.assertRaisesRegex(m.NotReady, 'unreviewed'):
            m.review(self.repo, self.overlay)

    def test_overlay_protects_wrong_board_and_symlinks(self):
        self.complete()
        self.add_file('Silicon/Qualcomm/sm7325/unsafe.inf')
        with self.assertRaisesRegex(m.NotReady, 'another board'):
            m.review(self.repo, self.overlay)
        (self.overlay / 'Silicon/Qualcomm/sm7325/unsafe.inf').unlink()
        (self.overlay / 'configs/secret.bin').write_bytes(b'proprietary donor')
        with self.assertRaisesRegex(m.NotReady, 'unsupported'):
            m.review(self.repo, self.overlay)
        (self.overlay / 'configs/secret.bin').unlink()
        (self.overlay / 'configs/evil.conf').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(m.NotReady, 'symlink'):
            m.review(self.repo, self.overlay)

    def test_build_finds_case_sensitive_edk2_workspace_fv_and_never_boots(self):
        # This mock does NOT build EDK2 or claim executable firmware. It checks
        # exactly where the real pinned upstream stores its compiled FD.
        dest = self.root / 'isolated'
        (dest / 'Common/edk2').mkdir(parents=True)
        (dest / 'tools/BootShim').mkdir(parents=True)
        (dest / 'Common/edk2/edksetup.sh').write_text('')
        (dest / 'tools/BootShim/Makefile').write_text('')
        output = dest / 'workspace/Build/dizi/DEBUG_GCC5/FV/SM7435_UEFI.fd'
        output.parent.mkdir(parents=True)
        fd = bytearray(0x00400000)
        fd[0x20:0x28] = len(fd).to_bytes(8, 'little')
        fd[0x28:0x2c] = b'_FVH'
        output.write_bytes(fd)
        report = {'generated_uefi_fd': False, 'temporary_boot_performed': False}
        calls = []

        def capture(*args, **kwargs):
            calls.append((args, kwargs))
            return ''

        with mock.patch.object(m.shutil, 'which', return_value='/mock/gcc'), \
             mock.patch.object(m, 'command', side_effect=capture):
            result = m.build(dest, report)
        self.assertTrue(result['generated_uefi_fd'])
        self.assertFalse(result['verified_bootable_uefi'])
        self.assertFalse(result['temporary_boot_performed'])
        self.assertEqual(len(result['firmware']), 1)
        self.assertEqual(result['firmware'][0]['bytes'], len(fd))
        argv, kwargs = calls[0]
        self.assertEqual(argv[:2], ('bash', './build.sh'))
        self.assertIn('--skip-rootfs-gen', argv)
        for dangerous in ('--boot', '--installer-zip', '--clean', '--distclean'):
            self.assertNotIn(dangerous, argv)
        self.assertEqual(kwargs['cwd'], dest)

        output.write_bytes(b'not an EDK2 firmware FD')
        with mock.patch.object(m.shutil, 'which', return_value='/mock/gcc'), \
             mock.patch.object(m, 'command', side_effect=capture):
            with self.assertRaisesRegex(m.NotReady, 'unexpected/non-FV'):
                m.build(dest, {'generated_uefi_fd': False})


if __name__ == '__main__':
    unittest.main(verbosity=2)
