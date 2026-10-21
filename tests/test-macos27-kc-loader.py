#!/usr/bin/env python3
"""Exercise the freestanding loader with malformed fixtures and real Apple KCs."""
from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ports.macos27.kernel_collection import inspect, read_regular


def main():
    compiler = shutil.which('clang')
    cross = shutil.which('aarch64-linux-gnu-gcc')
    if not compiler or not cross:
        raise SystemExit('clang and aarch64-linux-gnu-gcc required')
    sources = [ROOT / 'ports/macos27/kc_loader.c', ROOT / 'ports/macos27/boot_args.c']
    with tempfile.TemporaryDirectory(prefix='mac27-kc-loader-') as temp:
        temp = Path(temp); exe = temp / 'test'
        subprocess.run([compiler, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        *map(str, sources), str(ROOT / 'tests/test-macos27-kc-loader.c'),
                        '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
        obj = temp / 'kc-loader.o'
        subprocess.run([cross, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-ffreestanding',
                        '-fno-builtin', '-fno-stack-protector', '-mgeneral-regs-only', '-mstrict-align',
                        '-c', str(sources[0]), '-o', str(obj)], check=True)
        assert not subprocess.check_output(['aarch64-linux-gnu-nm', '-u', str(obj)], text=True).strip()
        tested = 0
        for name in ('vma2', 'mac13g'):
            path = ROOT / f'research/macos27-26A434/kernel.{name}.macho/kernelcache.release.{name}.decompressed'
            if not path.is_file(): continue
            mapped, report = temp / 'mapped.bin', temp / 'plan.json'
            subprocess.run([str(exe), str(path), str(mapped), str(report)], check=True)
            original = read_regular(path); image = inspect(original)
            memory = mapped.read_bytes(); plan = json.loads(report.read_text())
            base = min(s['vmaddr'] for s in image['segments']) & ~0x1FFFFFF
            assert plan['virt_base'] == base
            assert plan['entry_pa'] == 0x8C0000000 + image['entry_va'] - base
            assert plan['providers'] == len(image['fileset_entries'])
            assert plan['segments'] == len(image['segments'])
            for segment in image['segments']:
                dst = segment['vmaddr'] - base; src = segment['fileoff']; length = segment['filesize']
                assert memory[dst:dst+length] == original[src:src+length], segment['name']
                assert not any(memory[dst+length:dst+segment['vmsize']]), segment['name']
            first = min(s['vmaddr'] for s in image['segments']) - base
            assert memory[:first] == b'\xa5' * first
            # The complete mapped __LINKEDIT comparison above includes raw auth
            # chain metadata. No bind/rebase/PAC fixup is performed by this test.
            print(f'PASS {name}: {plan["providers"]} fileset providers, every segment byte preserved; entry PA {plan["entry_pa"]:#x}')
            tested += 1
        if not tested: print('SKIP ignored Apple KCs absent; synthetic loader tests and AArch64 object checked')
    print('PASS freestanding KC loader; this is host RAM loading, not a native macOS boot')


if __name__ == '__main__':
    main()
