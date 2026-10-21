#!/usr/bin/env python3
"""Structural corruption tests and optional real Apple macOS27 input checks."""
from pathlib import Path
import hashlib
import importlib.util
import plistlib
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ports.macos27.kernel_collection import inspect, read_regular
spec = importlib.util.spec_from_file_location('preflight', ROOT / 'tools/macos27-preflight.py')
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)

BASE = 0xFFFFFE0007004000


def header(kind, commands, subtype=0xC0000002):
    return struct.pack('<8I', 0xFEEDFACF, 0x100000C, subtype, kind,
                       len(commands), sum(map(len, commands)), 0, 0) + b''.join(commands)


def segment(name, va, size, offset, length):
    return struct.pack('<II16s4Q4I', 0x19, 72, name, va, size, offset, length, 5, 5, 0, 0)


def thread(pc):
    out = bytearray(288)
    struct.pack_into('<4I', out, 0, 5, 288, 6, 68)
    struct.pack_into('<Q', out, 16 + 32 * 8, pc)
    return out


def fixture(major=27):
    out = bytearray(8192)
    name = b'com.apple.kernel\0'
    entry = bytearray(56)
    struct.pack_into('<IIQQII', entry, 0, 0x80000035, len(entry), BASE + 4096, 4096, 32, 0)
    entry[32:32+len(name)] = name
    outer = header(12, [segment(b'__TEXT', BASE, 8192, 0, 8192), thread(BASE+4608), entry])
    out[:len(outer)] = outer
    inner = header(2, [segment(b'__TEXT', BASE+4096, 4096, 4096, 4096)])
    out[4096:4096+len(inner)] = inner
    version = f'Darwin Kernel Version {major}.0.0: TEST; root:xnu-13432.1.9~1/RELEASE_ARM64_VMAPPLE'.encode()
    out[4608:4608+len(version)] = version
    return out


class KernelCollectionTests(unittest.TestCase):
    def test_collection_relative_kernel_segments(self):
        k = inspect(bytes(fixture()))
        self.assertEqual((k['format'], k['darwin'], k['observed_xnu_tag']),
                         ('MH_FILESET', '27.0.0', 'xnu-13432.1.9'))
        self.assertTrue(k['arm64e'])
        self.assertEqual(k['fileset_entries'][0]['fileoff'], 4096)
        self.assertEqual(k['entry_va'], BASE+4608)

    def test_x1_is_pac_and_full_subtype_is_preserved(self):
        for subtype, arch, pac in ((0xC0000002,'arm64e',True),
                                    (0x8000000C,'arm64e.x1',True),
                                    (0,'arm64',False),
                                    (0xC0000102,'arm64.subtype258',False)):
            with self.subTest(subtype=subtype):
                data=fixture()
                struct.pack_into('<I',data,8,subtype)
                struct.pack_into('<I',data,4096+8,subtype)
                k=inspect(bytes(data))
                self.assertEqual(k['cpu_arch'],arch)
                self.assertEqual(k['arm64e'],pac)
                self.assertEqual(k['cpu_subtype'],subtype)

    def test_rejects_malformed_commands_ranges_and_entry(self):
        for offset, fmt, value in (
            (16, '<I', 4097), (20, '<I', 7), (36, '<I', 0),
            (36, '<I', 71), (36, '<I', 0xFFFFFFF8),
            (32+48, '<Q', 8193), (32+24, '<Q', (1<<64)-1),
            (32+72+16+32*8, '<Q', BASE+8192),
            (32+72+288+16, '<Q', 8192),
            (32+72+288+24, '<I', 0),
            (4096+12, '<I', 6), (4096+32+40, '<Q', 8192),
        ):
            with self.subTest(offset=offset,value=value):
                data=fixture(); struct.pack_into(fmt,data,offset,value)
                with self.assertRaises(ValueError): inspect(bytes(data))

    def test_does_not_use_version_string_in_an_unrelated_file_region(self):
        data=fixture(); data[4608:4800]=b'\0'*192
        fake=b'Darwin Kernel Version 27.0.0: FAKE'
        data[512:512+len(fake)]=fake
        with self.assertRaisesRegex(ValueError,'version missing'): inspect(bytes(data))

    def test_rejects_multiple_different_native_versions(self):
        data=fixture(); other=b'Darwin Kernel Version 26.0.0: UNRELATED'
        data[4800:4800+len(other)]=other
        with self.assertRaisesRegex(ValueError,'ambiguous'): inspect(bytes(data))

    def test_fixup_starts_bounds_and_segment_vm_relationship(self):
        data=fixture()
        oldsize=struct.unpack_from('<I',data,20)[0]
        pos=32+oldsize
        struct.pack_into('<4I',data,pos,0x80000034,16,6000,62)
        struct.pack_into('<I',data,16,4)
        struct.pack_into('<I',data,20,oldsize+16)
        struct.pack_into('<7I',data,6000,0,28,62,62,0,1,0)
        struct.pack_into('<2I',data,6028,1,8)
        struct.pack_into('<IHHQIHHH',data,6036,26,4096,8,0,0,2,0xFFFF,0xFFFF)
        self.assertEqual(inspect(bytes(data))['chained_fixups'][0]['pointer_format'],8)
        for offset,fmt,value in ((6000,'<I',1),(6004,'<I',61),(6016,'<I',1),
                                  (6028,'<I',2),(6032,'<I',0xFFFFFFF0),
                                  (6036,'<I',25),(6040,'<H',0),(6044,'<Q',8192),
                                  (6056,'<H',65535)):
            with self.subTest(offset=offset,value=value):
                bad=bytearray(data);struct.pack_into(fmt,bad,offset,value)
                with self.assertRaises(ValueError): inspect(bytes(bad))

    def test_manifest_digest_uses_wrapped_bytes_and_does_not_attest_signatures(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp); wrapped=p/'kernelcache'; manifest=p/'BuildManifest.plist'
            data=b'NOT REAL IMG4: synthetic digest fixture'; wrapped.write_bytes(data)
            obj=dict(ProductVersion='27.0.1',ProductBuildVersion='26A434',
                     SupportedProductTypes=['VirtualMac2,1'],BuildIdentities=[
                dict(Info={'DeviceClass':'test'},Manifest={'KernelCache':{
                    'Info':{'Path':'kernelcache.release.test'},'Digest':hashlib.sha384(data).digest()}})])
            manifest.write_bytes(plistlib.dumps(obj))
            def check(): return preflight.manifest_identity(manifest,wrapped,'kernelcache.release.test')
            result=check()
            self.assertEqual(result['status'],'digest_matched')
            self.assertFalse(result['apple_signature_verified'])
            self.assertFalse(result['decompressed_kernel_link_verified'])
            wrapped.write_bytes(data+b'changed')
            self.assertEqual(check()['status'],'rejected')
            obj['BuildIdentities'][0]['Manifest']['KernelCache']['Digest']=b'bad length'
            manifest.write_bytes(plistlib.dumps(obj)); self.assertEqual(check()['status'],'rejected')
            obj['BuildIdentities'][0]['Manifest']['KernelCache']['Digest']=hashlib.sha384(wrapped.read_bytes()).digest()
            obj['SupportedProductTypes']=['iPhone15,2']
            manifest.write_bytes(plistlib.dumps(obj)); self.assertEqual(check()['status'],'rejected')

    def test_real_local_apple_components_if_available(self):
        root=ROOT/'research/macos27-26A434'
        if not (root/'26A434__MacOS/BuildManifest.plist').exists():
            self.skipTest('Private Apple artifacts absent from clean checkout')
        for name, entries in (('vma2',216),('mac13g',342)):
            with self.subTest(component=name):
                path=root/f'kernel.{name}.macho/kernelcache.release.{name}.decompressed'
                k=inspect(read_regular(path))
                self.assertEqual(k['darwin'],'27.0.0')
                self.assertEqual(k['observed_xnu_tag'],'xnu-13432.1.9')
                self.assertEqual(len(k['fileset_entries']),entries)
                self.assertEqual({c['pointer_format'] for c in k['chained_fixups']},{8})
                result=preflight.manifest_identity(root/'26A434__MacOS/BuildManifest.plist',
                    root/f'26A434__MacOS/kernelcache.release.{name}',f'kernelcache.release.{name}')
                self.assertEqual(result['status'],'digest_matched')


if __name__=='__main__':
    unittest.main(verbosity=2)
