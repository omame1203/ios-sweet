#!/usr/bin/env python3
"""macOS27 target identity and fail-closed no-fake-boot regression suite."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = ROOT / 'tools/macos27-preflight.py'
spec = importlib.util.spec_from_file_location('dizi_macos27_preflight', PREFLIGHT)
preflight = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(preflight)


class Macos27PreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.profile = ROOT/'boards/dizi-macos27.json'

    def plist(self, name='macOS', version='27.0.1', build='26A434', fmt=plistlib.FMT_XML):
        p = self.root/'SystemVersion.plist'
        p.write_bytes(plistlib.dumps({'ProductName': name, 'ProductVersion': version,
                                      'ProductBuildVersion': build}, fmt=fmt))
        return p

    def kernel(self, major=26, cpu=preflight.ARM64, filetype=2):
        p = self.root/'kernel'
        # Metadata-only synthetic Mach-O; NEVER a bootable kernel.
        b = bytearray(256)
        struct.pack_into('<4I',b,0,preflight.MACHO64,cpu,0,filetype)
        b.extend(f'Darwin Kernel Version {major}.0.0: SYNTHETIC SOURCE TEST'.encode())
        p.write_bytes(b)
        return p

    def assess(self, **kwargs):
        return preflight.assess(self.profile, kwargs.get('plist'), kwargs.get('kernel'))

    def test_missing_assets_never_ready(self):
        r = self.assess()
        self.assertEqual(r['verdict'],'BLOCKED')
        self.assertEqual(r['system_version']['status'],'missing')
        self.assertEqual(r['kernel']['status'],'missing')

    def test_mac_27_metadata_may_match_but_still_blocked(self):
        for fmt in (plistlib.FMT_XML,plistlib.FMT_BINARY):
            with self.subTest(format=fmt):
                r = self.assess(plist=self.plist(fmt=fmt),kernel=self.kernel(major=26))
                self.assertEqual(r['system_version']['status'],'identity_only')
                self.assertEqual(r['kernel']['status'],'identity_only')
                self.assertEqual(r['verdict'],'BLOCKED')
                self.assertIn('SEP',str(r['hard_blockers']))

    def test_rejects_ipados_and_macos_26_userland(self):
        for data in (('iPadOS','27.0.1','26A434'),
                     ('macOS','26.7.1','25G241'),
                     ('macOS','27.0.1','25A354'),
                     ('macOS','27.0.1','24A446'),
                     ('macOS','99.0','26A434'),
                     ('macOS','27.0.1','26A434 EVIL')):
            with self.subTest(identity=data):
                r=self.assess(plist=self.plist(*data),kernel=self.kernel())
                self.assertEqual(r['system_version']['status'],'rejected')
                self.assertEqual(r['verdict'],'BLOCKED')

    def test_rejects_legacy_kernel_regardless_of_plist(self):
        for k in (22,23,24,25,27):
            self.assertEqual(self.assess(plist=self.plist(),kernel=self.kernel(k))['kernel']['status'],'rejected')

    def test_rejects_non_arm64_and_userspace_macho(self):
        self.assertEqual(self.assess(kernel=self.kernel(cpu=0x01000007))['kernel']['status'],'rejected')
        self.assertEqual(self.assess(kernel=self.kernel(filetype=6))['kernel']['status'],'rejected')

    def test_rejects_broken_and_oversized_metadata(self):
        p=self.root/'SystemVersion.plist'
        p.write_bytes(b'<?xml version="1.0"?><arbitrary>broken')
        self.assertEqual(self.assess(plist=p)['system_version']['status'],'rejected')
        p.write_bytes(b'x'*(preflight.MAX_PLIST_BYTES+1))
        self.assertEqual(self.assess(plist=p)['system_version']['status'],'rejected')

    def test_never_believes_modified_profile_or_false_approval(self):
        profile_data=json.loads(self.profile.read_text())
        for field,value in (('target_os','iPadOS'),('target_version_major',16),
                            ('official_apple_device_supported',True),('status','bootable')):
            with self.subTest(field=field):
                modified={**profile_data,field:value}
                p=self.root/'forged.json';p.write_text(json.dumps(modified))
                self.assertEqual(preflight.assess(p,None,None)['verdict'],'BLOCKED')
                self.assertIn('profile_error',preflight.assess(p,None,None))

    def test_executed_cli_returns_nonzero_even_for_matching_metadata(self):
        r=subprocess.run([sys.executable,str(PREFLIGHT),'--json',
                          '--system-version',str(self.plist()),
                          '--kernel',str(self.kernel())],text=True,capture_output=True)
        self.assertEqual(r.returncode,2)
        self.assertEqual(json.loads(r.stdout)['verdict'],'BLOCKED')
        self.assertNotIn('bootable',r.stdout)

    def test_real_existing_ipados_xnu_fails_if_available(self):
        path=ROOT/'xnu/out-0120/kernel.development.sweet'
        if not path.exists():
            self.skipTest('Ignored native CI0120 artifact not in clean checkout')
        r=self.assess(plist=self.plist(),kernel=path)
        self.assertEqual(r['verdict'],'BLOCKED')
        self.assertEqual(r['kernel']['status'],'rejected')
        self.assertIn('Darwin 22',r['kernel']['reason'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
