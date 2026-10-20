#!/usr/bin/env python3
"""Offline 0102 SMMUv2/GPI test: extracts EXACT patch sources and tests them.
No device access, no MMIO, no code patch application to tracked sources.
"""
from pathlib import Path
import os
import importlib.util
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'xnu/patches/0102-dizi-smmu-dma-foundation.patch'
TEST = ROOT / 'tests/dizi_smmu_dma_test.c'


def sources(text):
    desired = {'bsd/dev/dizi_smmu_dma.h', 'bsd/dev/dizi_smmu_dma.c'}
    out = {p: [] for p in desired}
    current = None
    for line in text.splitlines(keepends=True):
        if line.startswith('diff --git '):
            current = None
        elif line.startswith('+++ b/'):
            candidate = line[6:].strip()
            current = candidate if candidate in desired else None
        elif current and line.startswith('+') and not line.startswith('+++'):
            out[current].append(line[1:])
        elif current and line.startswith('@@'):
            pass
        elif current and line.startswith((' ', '-')):
            raise AssertionError('Found edited rather than added source')
    assert all(out.values()), 'Missing new files in patch'
    return {p: ''.join(lines) for p, lines in out.items()}


def run(args, **kw):
    subprocess.run(args, check=True, **kw)


def main():
    files = sources(PATCH.read_text())
    assert 'volatile' not in files['bsd/dev/dizi_smmu_dma.c']
    for forbidden in ('ml_io_map', 'arm_smmu_gr0_write', 'fastboot', 'writel(', 'ioremap('):
        assert forbidden not in files['bsd/dev/dizi_smmu_dma.c'], forbidden
    with tempfile.TemporaryDirectory(prefix='dizi-smmu-offline-') as temp:
        p = Path(temp)
        for name, data in files.items():
            (p / Path(name).name).write_text(data)
        clang = os.getenv('CLANG', 'clang')
        host = [clang, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        src = str(p / 'dizi_smmu_dma.c')
        run(host + [src, str(TEST), '-I', str(p), '-o', str(p / 'test')])
        run([str(p / 'test')], env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1'})
        run([clang, '--target=aarch64-linux-gnu', '-std=c11', '-Wall', '-Wextra',
             '-Werror', '-c', src, '-o', str(p / 'dizi_smmu_dma.arm64.o')])
        print('PASS: exact 0102 patch C compiles for Linux AArch64')
        # Check 0102 applies to a real previously patched XNU working tree.
        buildtree = ROOT / 'research/bt0099/xnu'
        if (buildtree / 'bsd/conf/files').exists():
            run(['git', 'apply', '--check', '--directory=research/bt0099/xnu',
                 'xnu/patches/0102-dizi-smmu-dma-foundation.patch'], cwd=ROOT)
            print('PASS: git apply --check on staged XNU (through 0099)')
        else:
            print('SKIP: staged XNU tree not available for git apply --check')
        flags_file = (buildtree.parent / 'build/xnu.obj/DEVELOPMENT_ARM64_SWEET/bsd/DEVELOPMENT/.CFLAGS')
        if flags_file.exists():
            spec = importlib.util.spec_from_file_location('xnu_cc', ROOT / 'tools/xnu-buildtree-cc.py')
            assert spec and spec.loader
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            options = mod.flags(flags_file, buildtree.parent)
            run([clang, '--target=arm64-apple-macos14.0', '-fsyntax-only',
                 *options, src], cwd=flags_file.parent)
            print(f'PASS: {len(options)} recorded native XNU build flags, ARM64 syntax')
        else:
            print('SKIP: recorded XNU build flags unavailable')


if __name__ == '__main__':
    main()
