#!/usr/bin/env python3
"""Validate patch0108 source equality, XNU default-disable, and ARM64 syntax.

No device access, no writes outside ephemeral /tmp paths, no MMIO backend.
Usage: python3 tests/test-dizi-se9-xnu.py
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
PATCH = ROOT / 'xnu/patches/0108-dizi-se9-clock.patch'
DESTS = ['bsd/dev/se9_clock.c', 'bsd/dev/se9_clock.h',
         'bsd/dev/dizi_se9_xnu.c', 'bsd/dev/dizi_se9_xnu.h']
PREFIX = '#define SE9_XNU_PUBLISH_PLAN 0 /* hard-disabled XNU policy */\n'


def run(*args, **kw):
    subprocess.run(args, check=True, **kw)


def extract_new_files(contents):
    result = {name: [] for name in DESTS}
    selected = None
    for line in contents.splitlines(keepends=True):
        if line.startswith('diff --git '):
            selected = None
        elif line.startswith('+++ b/'):
            candidate = line[6:].strip()
            selected = candidate if candidate in result else None
        elif line.startswith('@@ '):
            continue
        elif selected is not None:
            if line.startswith('+') and not line.startswith('+++'):
                result[selected].append(line[1:])
            elif line.startswith((' ', '-')):
                raise AssertionError('Expected exclusively new XNU source files')
    assert all(result.values()), 'missing new XNU source'
    return {name: ''.join(lines) for name, lines in result.items()}


def main():
    patch_text = PATCH.read_text()
    assert patch_text.count('bsd/dev/se9_clock.c\t\tstandard') == 1
    assert patch_text.count('bsd/dev/dizi_se9_xnu.c\t\tstandard') == 1
    mirror = extract_new_files(patch_text)
    assert mirror['bsd/dev/se9_clock.c'] == PREFIX + (ROOT / 'ports/dizi/se9_clock.c').read_text()
    assert mirror['bsd/dev/se9_clock.h'] == (ROOT / 'ports/dizi/se9_clock.h').read_text()
    bridge = mirror['bsd/dev/dizi_se9_xnu.c']
    assert 'return 0; /* no platform/hypervisor ownership handoff */' in bridge
    for content in mirror.values():
        for forbidden in ('ml_io_map(', 'writel(', 'ioremap(', '__asm__',
                          'phys_to_virt(', 'memcpy_toio('):
            assert forbidden not in content, forbidden
    print('PASS patch source byte-for-byte mirror, XNU compile-time no-plan gate, no MMIO')

    clang = os.getenv('CLANG', 'clang')
    with tempfile.TemporaryDirectory(prefix='dizi-se9-xnu-') as tmp:
        target = Path(tmp)
        for name, body in mirror.items():
            (target / Path(name).name).write_text(body)
        c = str(target / 'se9_clock.c')
        bridge_c = str(target / 'dizi_se9_xnu.c')
        test_c = str(ROOT / 'tests/dizi_se9_xnu_bridge_test.c')
        comp = [clang, '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic']
        run(*(comp + ['-O1', '-g', '-fsanitize=address,undefined',
              '-fno-omit-frame-pointer', '-I', str(target),
              c, bridge_c, test_c, '-o', str(target / 'bridge-test')]))
        run(str(target / 'bridge-test'),
            env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1'})
        run(*(comp + ['--target=aarch64-linux-gnu', '-c', c,
                     '-o', str(target / 'se9_clock.arm64.o')]))
        run(*(comp + ['--target=aarch64-linux-gnu', '-c', bridge_c,
                     '-o', str(target / 'dizi_se9_xnu.arm64.o')]))
        print('PASS exact 0108 sources cross-compile AArch64')

        # Prefer both older pre-0108 trees; no write/apply to either.
        for rel in ('research/bt0099/xnu', 'research/dizi-stage0104/xnu'):
            if (ROOT / rel / 'bsd/conf/files').is_file():
                run('git', 'apply', '--check', '--whitespace=error',
                    f'--directory={rel}', str(PATCH.relative_to(ROOT)), cwd=ROOT)
                print('PASS git apply --check', rel)
        flagdir = ROOT / 'research/bt0099/build/xnu.obj/DEVELOPMENT_ARM64_SWEET/bsd/DEVELOPMENT'
        flagsfile = flagdir / '.CFLAGS'
        if flagsfile.is_file():
            lib = ROOT / 'tools/xnu-buildtree-cc.py'
            spec = importlib.util.spec_from_file_location('xnu_cc', lib)
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            flags = module.flags(flagsfile, ROOT / 'research/bt0099')
            for source in (c, bridge_c):
                run(clang, '--target=arm64-apple-macos14.0', '-fsyntax-only',
                    *flags, source, cwd=flagdir)
                obj = str(target / (Path(source).stem + '.macho.o'))
                run(clang, '--target=arm64-apple-macos14.0', '-c', '-o', obj,
                    *flags, source, cwd=flagdir)
                # LLVM can emit Mach-O objects without linking a kernel.
                assert (target / (Path(source).stem + '.macho.o')).stat().st_size > 0
            print(f'PASS XNU native ARM64 syntax and Mach-O objects ({len(flags)} recorded flags)')
        else:
            print('SKIP: native XNU .CFLAGS unavailable')
    with tempfile.TemporaryDirectory(prefix='dizi-se9-portable-') as td:
        executable = str(Path(td) / 'portable-test')
        run(clang, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
            str(ROOT / 'ports/dizi/se9_clock.c'),
            str(ROOT / 'ports/dizi/se9_clock_test.c'), '-o', executable)
        run(executable)
    print('PASS complete portable fake-MMIO suite')


if __name__ == '__main__':
    main()
