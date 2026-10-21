#!/usr/bin/env python3
"""READ-ONLY provenance tests for saved dizi Android→EDK2 native entry.

No fastboot, device, writes, image replacement, or firmware entry. Negative
tests validate parsing/ABI claims rather than inventing EL2/XPU ownership.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import struct
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
BACKUP = ROOT / 'backup/dizi'
SILICON = ROOT / 'ports/renegade/edk2-overlay/Silicon/Qualcomm/sm7435'
QCOM = Path('/tmp/dizi-edk2-msm-audit-20261021')
DOC = ROOT / 'docs/DIZI_RENEGADE_NATIVE_ENTRY_AUDIT.md'
PINS = {
    'abl_a.img': '1b7e88d890d7a836a393a075628c9546b6f70e6501943261445283a643d1c1eb',
    'boot_a.img': 'b599bfbdc0ee336dba7de26e6f3e970e6888a7d839097be954b4b31594846dae',
    'vendor_boot_a.img': 'f053adc7d6f5aaead81f16be16d5275185ebddedb769adbb837bfef435422b08',
    'fdt': '13107fc680b51539989ecd86127edd9d50b77af22afe384ffc7956c3c2f8a944',
}


def read_range(path: Path, offset: int, n: int) -> bytes:
    with path.open('rb') as fp:
        fp.seek(offset)
        data = fp.read(n)
    if len(data) != n:
        raise ValueError('short file')
    return data


def read_pinned(path: Path, sha256: str) -> None:
    with path.open('rb') as fp:
        actual = hashlib.file_digest(fp, 'sha256').hexdigest()
    if actual != sha256:
        raise ValueError(f'{path.name}: unknown capture digest {actual}')


def parse_boot_header(raw: bytes) -> dict:
    if len(raw) < 1584 or raw[:8] != b'ANDROID!':
        raise ValueError('not Android boot v4')
    kernel_size, ramdisk_size, _, header_size = struct.unpack_from('<4I', raw, 8)
    version = struct.unpack_from('<I', raw, 40)[0]
    signature_size = struct.unpack_from('<I', raw, 1580)[0]
    if version != 4 or header_size != 1584 or kernel_size == 0:
        raise ValueError('incompatible or empty boot image')
    return dict(version=version, kernel_size=kernel_size,
                ramdisk_size=ramdisk_size, signature_size=signature_size)


def parse_linux_arm64_header(data: bytes) -> dict:
    if len(data) < 68 or data[56:60] != b'ARMd':
        raise ValueError('not an ARM64 Image')
    text_offset, image_size, flags = struct.unpack_from('<3Q', data, 8)
    pe_offset = struct.unpack_from('<I', data, 60)[0]
    if image_size == 0 or flags & ~0xf:
        raise ValueError('invalid Image extent/flags')
    if data[32:56] != bytes(24):
        raise ValueError('nonzero ARM64 reserved header')
    if pe_offset != 64 or data[64:68] != b'PE\0\0':
        raise ValueError('not the observed PE-stub Image variant')
    return dict(text_offset=text_offset, image_size=image_size,
                flags=flags, pe_offset=pe_offset)


def parse_vendor_header(data: bytes) -> dict:
    if len(data) < 2128 or data[:8] != b'VNDRBOOT':
        raise ValueError('not Android vendor_boot')
    v, page, kernel_addr, ramdisk_addr, ramdisk_size = struct.unpack_from(
        '<5I', data, 8)
    header_size, dtb_size = struct.unpack_from('<II', data, 2096)
    dtb_addr = struct.unpack_from('<Q', data, 2104)[0]
    table_size, table_num, table_entry_size, bootconfig_size = struct.unpack_from(
        '<4I', data, 2112)
    if v != 4 or page != 4096 or header_size != 2128 or not dtb_size:
        raise ValueError('unsupported vendor boot v4')
    return dict(version=v, page_size=page, kernel_addr=kernel_addr,
                ramdisk_addr=ramdisk_addr, ramdisk_size=ramdisk_size,
                dtb_size=dtb_size, dtb_addr=dtb_addr, table_size=table_size,
                table_num=table_num, table_entry_size=table_entry_size,
                bootconfig_size=bootconfig_size)


def parse_abl_elf32(data: bytes) -> tuple[int, tuple[int, int, int]]:
    if len(data) < 4096 or data[:6] != b'\x7fELF\x01\x01':
        raise ValueError('not little-endian ELF32 envelope')
    typ, machine, version = struct.unpack_from('<HHI', data, 16)
    entry, phoff, _, _, ehsize, phentsize, phnum = struct.unpack_from(
        '<IIIIHHH', data, 24)
    if (typ, machine, version, ehsize, phentsize) != (2, 40, 1, 52, 32):
        raise ValueError('unexpected ABL ELF32 ARM envelope')
    regions = []
    for n in range(phnum):
        off = phoff + n * phentsize
        if off + 32 > len(data):
            raise ValueError('truncated program header')
        kind, p_offset, vaddr, paddr, filesz, memsz, flags, align = struct.unpack_from(
            '<8I', data, off)
        if kind == 1:
            regions.append((p_offset, vaddr, paddr, filesz, memsz, flags, align))
    if len(regions) != 1:
        raise ValueError('unexpected ABL program headers')
    return entry, (regions[0][0], regions[0][2], regions[0][3])


class NativeAbiAudit(unittest.TestCase):
    def test_saved_artifact_integrity(self):
        for name, sha in PINS.items():
            with self.subTest(name=name):
                read_pinned(BACKUP / name, sha)

    def test_actual_boot_v4_and_real_arm64_image_not_fd(self):
        hdr = read_range(BACKUP / 'boot_a.img', 0, 4096)
        info = parse_boot_header(hdr)
        self.assertEqual(info, {
            'version': 4, 'kernel_size': 46854828,
            'ramdisk_size': 1380093, 'signature_size': 4096,
        })
        raw = read_range(BACKUP / 'boot_a.img', 4096, 256)
        img = parse_linux_arm64_header(raw)
        self.assertEqual(img, {'text_offset': 0, 'image_size': 0x2a90000,
                               'flags': 0xa, 'pe_offset': 64})
        self.assertLess(img['image_size'], info['kernel_size'])
        self.assertEqual(raw[:2], b'MZ')
        self.assertEqual(struct.unpack_from('<H', raw, 68)[0], 0xaa64)
        # EFI PE header does not turn the Linux Image into a raw FD.
        self.assertNotEqual(raw[40:44], b'_FVH')
        self.assertNotIn(b'FD_BASE', raw)

    def test_malformed_android_and_linux_header_rejections(self):
        hdr = bytearray(read_range(BACKUP / 'boot_a.img', 0, 4096))
        linux = bytearray(read_range(BACKUP / 'boot_a.img', 4096, 256))
        for off, blob in [(0, b'NOTANDRO'), (40, struct.pack('<I', 3)),
                          (20, struct.pack('<I', 0)),
                          (8, struct.pack('<I', 0))]:
            mutated = hdr.copy()
            mutated[off:off + len(blob)] = blob
            with self.assertRaises(ValueError):
                parse_boot_header(mutated)
        for off, blob in [(56, b'FAKE'), (16, bytes(8)),
                          (24, struct.pack('<Q', 0x100)),
                          (60, struct.pack('<I', 0)),
                          (64, b'XXXX'), (32, b'NOPE')]:
            mutated = linux.copy()
            mutated[off:off + len(blob)] = blob
            with self.assertRaises(ValueError):
                parse_linux_arm64_header(mutated)

    def test_vendor_boot_v4_fields_are_not_actual_live_pas(self):
        vendor = read_range(BACKUP / 'vendor_boot_a.img', 0, 4096)
        v = parse_vendor_header(vendor)
        self.assertEqual(v, {
            'version': 4, 'page_size': 4096,
            'kernel_addr': 0x8000, 'ramdisk_addr': 0x1000000,
            'ramdisk_size': 13848188, 'dtb_size': 4886872,
            'dtb_addr': 0x1f00000, 'table_size': 0x6c, 'table_num': 1,
            'table_entry_size': 0x6c, 'bootconfig_size': 0x55,
        })
        with self.assertRaises(ValueError):
            parse_vendor_header(b'UEFIBOOT' + vendor[8:])
        corrupted = bytearray(vendor)
        struct.pack_into('<I', corrupted, 8, 3)
        with self.assertRaises(ValueError):
            parse_vendor_header(corrupted)

    def test_abl_elf32_envelope_is_not_linux_entry_proof(self):
        image = read_range(BACKUP / 'abl_a.img', 0, 4096)
        entry, load = parse_abl_elf32(image)
        self.assertEqual(entry, 0x9fa00000)
        self.assertEqual(load, (0x1000, 0x9fa00000, 0x30000))
        self.assertEqual(read_range(BACKUP / 'abl_a.img', 0x1028, 4), b'_FVH')
        self.assertNotEqual(entry, 0x8000)  # vendor header field differs
        with self.assertRaises(ValueError):
            parse_abl_elf32(b'\0' * len(image))

    def test_captured_fdt_topology_reservations_and_gunyah(self):
        import shutil
        if not shutil.which('fdtget'):
            self.skipTest('fdtget unavailable for read-only saved FDT analysis')

        def prop(path, name):
            data = subprocess.check_output(
                ['fdtget', '-t', 'x', str(BACKUP / 'fdt'), path, name],
                text=True).split()
            return [int(v, 16) for v in data]

        def intervals(words):
            self.assertEqual(len(words) % 4, 0)
            return [(words[i] << 32 | words[i + 1],
                     words[i + 2] << 32 | words[i + 3])
                    for i in range(0, len(words), 4)]

        fdt_bytes = (BACKUP / 'fdt').read_bytes()
        self.assertEqual(struct.unpack_from('>I', fdt_bytes)[0], 0xd00dfeed)
        self.assertEqual(struct.unpack_from('>I', fdt_bytes, 4)[0], 851726)
        self.assertEqual((len(fdt_bytes), len([v for v in intervals(
            prop('/memory', 'reg')) if v[1]])), (851726, 7))
        initrd_start = prop('/chosen', 'linux,initrd-start')
        initrd_end = prop('/chosen', 'linux,initrd-end')
        self.assertEqual((initrd_start, initrd_end),
                         ([0, 0xb719f000], [0, 0xb7ffe6c4]))
        children = subprocess.check_output(
            ['fdtget', '-l', str(BACKUP / 'fdt'), '/reserved-memory'],
            text=True).split()
        fixed, dynamic = [], []
        for child in children:
            node = '/reserved-memory/' + child
            properties = subprocess.check_output(
                ['fdtget', '-p', str(BACKUP / 'fdt'), node],
                text=True).split()
            if 'reg' in properties:
                fixed += intervals(prop(node, 'reg'))
            else:
                dynamic.append(child)
        self.assertEqual((len(fixed), len(dynamic)), (35, 10))
        self.assertIn((0xb8000000, 0x2b00000), fixed)
        self.assertIn((0x80d00000, 0x200000), fixed)
        self.assertIn('linux,cma', dynamic)
        self.assertIn('non_secure_display_region', dynamic)
        self.assertIn('qseecom_ta_region', dynamic)
        # Saved DT explicit hypervisor descriptor, not stage-2 access proof.
        hv = subprocess.check_output(
            ['fdtget', '-t', 's', str(BACKUP / 'fdt'),
             '/hypervisor', 'compatible'], text=True)
        self.assertIn('qcom,gunyah-hypervisor', hv)
        candidate = (0x90000000, 0x1000000)
        self.assertTrue(any(start <= candidate[0] and
                            candidate[0] + candidate[1] <= start + size
                            for start, size in intervals(prop('/memory', 'reg')) if size))
        self.assertFalse(any(
            start < candidate[0] + candidate[1] and
            candidate[0] < start + size for start, size in fixed))
        # Intentionally DO NOT assert ownership/exclusive-PA from this.

    def test_true_linux_boot_abi_vs_unverified_qcom_prepi_early_writes(self):
        booting = (ROOT / 'research/xiaomi-ruan/Documentation/arm64/booting.rst').read_text()
        for expected in ('x0 = physical address of device tree blob',
                         'x1 = 0', 'x2 = 0', 'x3 = 0',
                         'The MMU must be off', 'DAIF',
                         'EL2 (RECOMMENDED', 'non-secure EL1'):
            self.assertIn(expected, booting)
        asm = (QCOM / 'Silicon/Qualcomm/QcomPkg/PrePi/ModuleEntryPoint.S').read_text()
        pi = (QCOM / 'Silicon/Qualcomm/QcomPkg/PrePi/Pi.c').read_text()
        self.assertLess(asm.index('str x0, [x10]'),
                        asm.index('ArmDisableCachesAndMmu'))
        self.assertLess(asm.index('str x0, [x10]'),
                        asm.index('ArmWriteVBar'))
        self.assertLess(asm.index('_FillVectors:'),
                        asm.index('bl CEntryPoint'))
        self.assertLess(asm.index('_ClearStack:'),
                        asm.index('bl CEntryPoint'))
        self.assertLess(asm.index('mov x10, FixedPcdGet64'),
                        asm.index('str x0, [x10]'))
        self.assertIn('FixedPcdGet32(PcdUefiMemPoolBase)', pi)
        self.assertIn('FixedPcdGet32(PcdUefiMemPoolSize)', pi)
        self.assertIn('FixedPcdGet32(PcdSystemMemoryBase)', pi)
        self.assertIn('FixedPcdGet32(PcdSystemMemorySize)', pi)

    def test_current_silicon_deny_by_default_and_wrapper_not_approved(self):
        memory = (SILICON / 'Library/PlatformMemoryMapLib/PlatformMemoryMapLib.c').read_text()
        init = (SILICON / 'Library/PlatformPrePiLib/PlatformUtils.c').read_text()
        early = (SILICON / 'Library/DiziEarlyHandoffGuard/DiziEarlyHandoffGuardEntry.S').read_text()
        sm7435 = (ROOT / 'ports/renegade/edk2-overlay/Platform/Qualcomm/sm7435/sm7435.dsc').read_text()
        packager = (ROOT / 'tools/dizi-renegade-image.py').read_text()
        for needle in ('mMemoryAuthorized', 'mDenied', 'DiziSm7435InstallTrustedMemoryEvidence'):
            self.assertIn(needle, memory)
        self.assertIn('CpuDeadLoop();', init)
        self.assertIn('b .Ldizi_early_deny', early)
        self.assertIn('gQcomTokenSpaceGuid.PcdUefiMemPoolBase|0x90410000', sm7435)
        self.assertIn('gEmbeddedTokenSpaceGuid.PcdPrePiStackBase|0x90fc0000', sm7435)
        self.assertIn('gArmTokenSpaceGuid.PcdCpuVectorBaseAddress|0x90401000', sm7435)
        self.assertIn('gSimpleInitTokenSpaceGuid.PcdDeviceTreeStore|0x90400000', sm7435)
        self.assertRegex(packager, r'(?m)^VERIFIED_DIZI_WRAPPERS: dict\[str, dict\] = \{\}$')
        shim = (QCOM / 'tools/BootShim/BootShim.S').read_text()
        for needle in ('adr\tx1, _Payload', 'ldp\tx2, x3, [x4], #16',
                       'stp\tx2, x3, [x5], #16', 'br\tx5'):
            self.assertIn(needle, shim)
        # Parallel source-only workers are adding a *real first PC* Image,
        # but it ALWAYS PARKS; a future post-grant BR is compiled out.
        native = (ROOT / 'ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435/'
                  'DiziBootShim/DiziNativeEntry.S')
        transfer = (ROOT / 'ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435/'
                    'DiziBootShim/DiziSecTransfer.S')
        if native.is_file():
            text = native.read_text()
            self.assertIn('b       dizi_native_park', text)
            self.assertIn('msr     DAIFSet, #0xf', text)
            self.assertNotIn('bl      DiziSecEnterPrePi', text)
        if transfer.is_file():
            text = transfer.read_text()
            self.assertIn('DIZI_SEC_TRUSTED_OWNER_IMPLEMENTED', text)
            self.assertIn('.Ldizi_sec_park:', text)
            self.assertIn('br x16', text)  # only inside the guarded #if

    def test_document_rejects_fabricated_ownership_and_contains_sources(self):
        doc = DOC.read_text()
        for word in ('**Disposition: BLOCKED**', '0x9fa00000',
                     '0x02a90000', '0x90000000', '0x90fc0000',
                     'str x0,[x10]', '35', '10',
                     'EL2', 'XPU', 'Linux Image allocation',
                     'before the first', 'no additional fastboot'):
            self.assertIn(word.lower(), doc.lower())
        self.assertIn('DiziNativeEntry.S', doc)
        self.assertIn('DiziSecGetTrustedRuntimeGrant', doc)
        self.assertNotIn('safe to flash', doc.lower())


if __name__ == '__main__':
    unittest.main(verbosity=2)
