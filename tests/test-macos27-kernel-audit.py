#!/usr/bin/env python3
"""Offline adversarial tests for the macOS27 XNU source/SDK rebase audit."""
import importlib.util
import json
import plistlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
AUDITOR = ROOT / 'tools/macos27-kernel-audit.py'
spec = importlib.util.spec_from_file_location('macos27_kernel_audit', AUDITOR)
assert spec and spec.loader
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def release(version='27.2', tag='xnu-13000.1.2', major='macOS 27'):
    return json.dumps({'release': 'macOS ' + version,
                       'major_release': major,
                       'projects': [{'project': 'xnu', 'tag': tag},
                                    {'project': 'Libsystem', 'tag': 'Libsystem-1337'}]}).encode()


REFS = ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/tags/xnu-13000.1.2\n'
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/tags/xnu-13000.1.2^{}\n')
BLACKTOP_OLD = "case ${MACOS_VERSION} in\n  '26.5') RELEASE_URL=old ;;\nesac\n"
BLACKTOP_NEW = "case ${MACOS_VERSION} in\n  '26.5') RELEASE_URL=old ;;\n  '27.2') RELEASE_URL=new ;;\nesac\n"


class AuditTests(unittest.TestCase):
    def test_public_build_identity_and_immutable_sources(self):
        self.assertEqual(audit.BUILD_TARGETS['27.0.1']['build'], '26A434')
        self.assertEqual(audit.BUILD_TARGETS['27.2']['build'], '26B118')
        self.assertEqual(audit.release_url('27.0.1').split('/')[-2], 'macos-270')
        self.assertEqual(audit.release_url('27.2').split('/')[-2], 'macos-272')
        self.assertEqual(audit.parse_release(release(), '27.2')['tag'], 'xnu-13000.1.2')
        self.assertFalse(audit.parse_release(release(), '27.2')['build_specific_proven'])

    def test_release_ambiguity_and_corruption_rejected(self):
        for version, tag, major in [
            ('26.5', 'xnu-13000.1.2', 'macOS 27'),
            ('27.0', 'xnu-13000.1.2', 'macOS 27'),
            ('27.2', 'xnu-12377.121.6', 'macOS 27'),
            ('27.2', 'xnu-13000', 'macOS 27'),
            ('27.2', 'xnu-13000.1.2; rm -rf /', 'macOS 27'),
            ('27.2', 'xnu-13000.1.2', 'macOS 26'),
        ]:
            with self.subTest(version=version, tag=tag, major=major):
                with self.assertRaises(ValueError):
                    audit.parse_release(release(version, tag, major), '27.2')
        for obj in [
            {}, [], {'release': 'macOS 27.2', 'major_release': 'macOS 27'},
            {'release': 'macOS 27.2', 'major_release': 'macOS 27',
             'projects': [{'project': 'xnu', 'tag': 'xnu-13000.1.2'}] * 2},
        ]:
            with self.assertRaises(ValueError):
                audit.parse_release(json.dumps(obj).encode(), '27.2')
        for invalid in [b'garbage', b'[]', b'x' * (audit.MAX_MANIFEST_BYTES + 1)]:
            with self.assertRaises(ValueError):
                audit.parse_release(invalid, '27.2')

    def test_ref_parser_prefers_peeled_and_ignores_lookalikes(self):
        refs = REFS + ('cccccccccccccccccccccccccccccccccccccccc\trefs/tags/xnu-13000.1.2/evil\n'
                       'dddddddddddddddddddddddddddddddddddddddd\trefs/heads/xnu-13000.1.2\n'
                       'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\trefs/tags/xnu-13000.1.2-bogus\n')
        self.assertEqual(audit.parse_xnu_refs(refs), {'xnu-13000.1.2': 'b' * 40})

    def test_blacktop_actual_case_not_just_readme(self):
        self.assertFalse(audit.script_supports_version(BLACKTOP_OLD, '27.2'))
        self.assertTrue(audit.script_supports_version(BLACKTOP_NEW, '27.2'))
        self.assertFalse(audit.script_supports_version("# macOS 27.2 supported\n", '27.2'))
        self.assertFalse(audit.script_supports_version("case ${MACOS_VERSION} in\n '27.20') : ;;\nesac", '27.2'))

    def test_local_sdk_plist_required_and_versioned(self):
        with tempfile.TemporaryDirectory() as directory:
            sdk = Path(directory)
            self.assertFalse(audit.check_sdk(sdk, '27.2')['installed_verified'])
            for version, expected in [('26.5', False), ('27.0', False),
                                      ('27.1', False), ('27.2', True),
                                      ('27.3', True), ('28.0', False)]:
                (sdk / 'SDKSettings.plist').write_bytes(plistlib.dumps({'Version': version}))
                self.assertEqual(audit.check_sdk(sdk, '27.2')['installed_verified'],
                                 expected, version)
            (sdk / 'SDKSettings.plist').write_text('not a plist')
            self.assertFalse(audit.check_sdk(sdk, '27.2')['installed_verified'])

    def test_confident_tag_not_exact_build_and_never_build_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            patchdir = repo / 'xnu/patches'
            patchdir.mkdir(parents=True)
            (patchdir / '0001-board.patch').write_text(
                'diff --git a/osfmk/arm64/start.s b/osfmk/arm64/start.s\n'
                '--- a/osfmk/arm64/start.s\n+++ b/osfmk/arm64/start.s\n')
            (patchdir / '0002-drivers.patch').write_text(
                'diff --git a/bsd/dev/sweet_touch.c b/bsd/dev/sweet_touch.c\n')
            wf = repo / '.github/workflows'
            wf.mkdir(parents=True)
            (wf / 'xnu.yml').write_text('''env:
  DXB_SHA: 663906528d1cd5ea8fde7de6f16de73db9511549
  MACOS_VERSION: ${{ inputs.macos_version || '13.5' }}
jobs:
  build:
    runs-on: macos-14
    # Xcode 15
    run: cp xnu/patches/*.patch elsewhere
''')
            report = audit.collect(repo, '27.2', release(), REFS, BLACKTOP_NEW, None)
            self.assertEqual(report['selected_xnu_tag'], 'xnu-13000.1.2')
            self.assertEqual(report['source']['upstream_peeled_sha'], 'b' * 40)
            self.assertFalse(report['source']['build_specific_source_proven'])
            self.assertFalse(report['ready_for_macos27_kernel_build'])
            self.assertEqual(report['patches']['total_patch_files'], 2)
            self.assertEqual(report['patches']['categories']['arm64_boot_mmu_pmap']['patch_count'], 1)
            self.assertEqual(report['patches']['categories']['bsd_vfs_drivers']['patch_count'], 1)
            self.assertEqual(report['workflow']['default_macos_version'], '13.5')
            self.assertTrue(report['workflow']['macos14_runner'])
            self.assertTrue(report['builder']['target_case_supported'])
            missing = audit.collect(repo, '27.2', None, REFS, BLACKTOP_OLD, None)
            self.assertIsNone(missing['selected_xnu_tag'])
            self.assertFalse(missing['ready_for_macos27_kernel_build'])
            mismatched = audit.collect(repo, '27.2', release(), '', BLACKTOP_NEW, None)
            self.assertIsNone(mismatched['selected_xnu_tag'])

    def test_real_repository_source_only_and_strict_cli(self):
        current = audit.collect(ROOT, '27.2', None, None, BLACKTOP_OLD, None)
        self.assertGreater(current['patches']['total_patch_files'], 60)
        self.assertFalse(current['ready_for_macos27_kernel_build'])
        self.assertTrue(current['workflow']['macos14_runner'])
        self.assertEqual(current['workflow']['default_macos_version'], '13.5')
        self.assertGreater(current['patches']['categories']['arm64_boot_mmu_pmap']['patch_count'], 0)
        self.assertGreater(current['patches']['categories']['platform_expert_machine']['patch_count'], 0)
        run = subprocess.run([sys.executable, str(AUDITOR), '--strict', '--target', '27.2',
                              '--repo', str(ROOT)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2, run.stderr)
        parsed = json.loads(run.stdout)
        self.assertIsNone(parsed['selected_xnu_tag'])
        self.assertFalse(parsed['device_runtime_verified'])
        self.assertNotIn('assumed_xnu_tag', parsed)

    def test_plain_unified_patches_and_new_files_are_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'plain.patch').write_text(
                '--- a/bsd/dev/sweet_touch.c\n'
                '+++ b/bsd/dev/sweet_touch.c\n'
                '@@ -1 +1 @@\n-old\n+new\n'
                '--- /dev/null\n+++ b/pexpert/arm/new_board.c\n'
                '@@ -0,0 +1 @@\n+new\n')
            inv = audit.patch_inventory(root)
            self.assertFalse(inv['malformed_or_renames'])
            self.assertEqual(inv['categories']['bsd_vfs_drivers']['patch_count'], 1)
            self.assertEqual(inv['categories']['platform_expert_machine']['patch_count'], 1)
            (root / 'invalid-body.patch').write_bytes(
                b'--- a/iokit/Kernel/arm/SweetDisplay.cpp\n'
                b'+++ b/iokit/Kernel/arm/SweetDisplay.cpp\n'
                b'@@ -1 +1 @@\n-old\n+\xff\n')
            inv = audit.patch_inventory(root)
            self.assertEqual(inv['non_utf8_patch_files'], ['invalid-body.patch'])
            self.assertEqual(inv['categories']['iokit_libkern']['patch_count'], 1)

    def test_allowlist_no_unsafe_network(self):
        with self.assertRaises(ValueError):
            audit.get_small_https('https://example.com/firmware.ipsw')


if __name__ == '__main__':
    unittest.main(verbosity=2)
