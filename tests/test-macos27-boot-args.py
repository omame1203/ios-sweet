#!/usr/bin/env python3
"""Compile the loader serializer; compare with real 26A434 entry instructions."""
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ports.macos27.kernel_collection import inspect, read_regular


def check_real_entry(encoded: bytes) -> None:
    path = ROOT / 'research/macos27-26A434/kernel.vma2.macho/kernelcache.release.vma2.decompressed'
    if not path.is_file():
        print('SKIP private actual 26A434 KC absent; host/target compiles still checked')
        return
    data = read_regular(path)
    image = inspect(data)
    assert image['darwin'] == '27.0.0' and image['observed_xnu_tag'] == 'xnu-13432.1.9'

    def offset(va):
        segment = next(s for s in image['segments'] if s['vmaddr'] <= va < s['vmaddr'] + s['filesize'])
        return segment['fileoff'] + va - segment['vmaddr']

    pc = image['entry_va']
    word = struct.unpack_from('<I', data, offset(pc))[0]
    assert word >> 26 == 5, 'Actual 26A434 entry must be the observed direct B'
    immediate = word & ((1 << 26) - 1)
    if immediate & (1 << 25): immediate -= 1 << 26
    pc += 4 * immediate
    found = {}
    # Decode LDR Xt,[x20,#imm] from the real boot entry, not C offsetof.
    for word in struct.unpack_from('<24I', data, offset(pc)):
        if word & 0xFFC00000 == 0xF9400000 and (word >> 5) & 31 == 20:
            target = word & 31
            field = ((word >> 10) & 0xFFF) * 8
            found[target] = (field, struct.unpack_from('<Q', encoded, field)[0])
    assert found == {22: (8, 0xFFFFFE0007000000), 23: (16, 0x8C0000000),
                     24: (24, 0xB0000000), 26: (0x470, 1)}, found
    assert found[26][0] + 8 > 736, 'Legacy iPadOS boot_args must not be accepted as this layout'
    print('PASS actual 26A434 entry reads encoded values; legacy struct does not populate the 0x470 field')


def main():
    compiler = shutil.which('clang')
    cross = shutil.which('aarch64-linux-gnu-gcc')
    if not compiler or not cross:
        raise SystemExit('clang and aarch64-linux-gnu-gcc are required for this test')
    source = ROOT / 'ports/macos27/boot_args.c'
    with tempfile.TemporaryDirectory(prefix='mac27-boot-args-') as temp:
        temp = Path(temp)
        binary, encoded = temp / 'test', temp / 'args.bin'
        subprocess.run([compiler, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(source),
                        str(ROOT / 'tests/test-macos27-boot-args.c'), '-o', str(binary)], check=True)
        subprocess.run([str(binary), str(encoded)], check=True)
        subprocess.run([cross, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-ffreestanding',
                        '-fno-builtin', '-fno-stack-protector', '-mgeneral-regs-only', '-mstrict-align',
                        '-c', str(source), '-o', str(temp / 'boot-args.o')], check=True)
        undefined = subprocess.check_output(['aarch64-linux-gnu-nm', '-u', str(temp / 'boot-args.o')], text=True)
        assert not undefined.strip(), f'Freestanding encoder has unresolved runtime calls: {undefined}'
        assert encoded.stat().st_size == 1152
        check_real_entry(encoded.read_bytes())
    print('PASS freestanding AArch64 encoder object; no kernel compile, fileset fixup, device access or boot')


if __name__ == '__main__':
    main()
