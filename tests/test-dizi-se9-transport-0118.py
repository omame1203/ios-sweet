#!/usr/bin/env python3
"""Offline 0118 GPI/SE9 XNU patch, ownership, sanitizer and Mach-O checks."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
PATCH = ROOT / 'xnu/patches/0118-dizi-se9-spi-transport.patch'
PREFIX = '#define DIZI_SE9_0118_XNU_BACKEND_ALLOWED 0 /* no verified GPI/SMMU owner */\n'
SOURCES = ('se9_transport_0118.h', 'se9_transport_0118.c',
           'dizi_se9_spi_xnu_0118.h', 'dizi_se9_spi_xnu_0118.c')


def run(*argv, **kw):
    subprocess.run(argv, check=True, **kw)


def new_files(body):
    selected = None
    out = {}
    for line in body.splitlines(keepends=True):
        if line.startswith('diff --git '):
            selected = None
        elif line.startswith('+++ b/bsd/dev/'):
            name = line.split('/')[-1].strip()
            if name in SOURCES:
                out[name] = []
                selected = name
        elif line.startswith('@@ '):
            continue
        elif selected:
            assert line.startswith('+') and not line.startswith('+++'), line
            out[selected].append(line[1:])
    assert set(out) == set(SOURCES)
    return {name: ''.join(lines) for name, lines in out.items()}


def main():
    patch = PATCH.read_text()
    assert patch.count('bsd/dev/se9_transport_0118.c\tstandard') == 1
    assert patch.count('bsd/dev/dizi_se9_spi_xnu_0118.c\tstandard') == 1
    sources = new_files(patch)
    assert sources['se9_transport_0118.h'] == PREFIX + (
        ROOT / 'ports/dizi/se9_transport_0118.h').read_text()
    assert sources['se9_transport_0118.c'] == (
        ROOT / 'ports/dizi/se9_transport_0118.c').read_text()
    assert 'dizi_se9_xnu_enabled() && DIZI_SE9_0118_XNU_BACKEND_ALLOWED' in (
        sources['dizi_se9_spi_xnu_0118.c'])
    for file in sources.values():
        for unsafe in ('ml_io_map(', '__asm__', 'writel(', 'ioremap(',
                       'dma_map_single(', 'geni_write_reg(', 'memcpy_toio('):
            assert unsafe not in file, unsafe
    print('PASS 0118 source mirror, 0108 gate, and NO MMIO/GPI writes')

    # CI stage contains 0108, allowing a true staged precondition check.
    stage = ROOT / 'research/dizi-ci0106/xnu'
    assert (stage / 'bsd/dev/dizi_se9_xnu.h').is_file()
    run('git', 'apply', '--check', '--whitespace=error',
        '--directory=research/dizi-ci0106/xnu', str(PATCH.relative_to(ROOT)),
        cwd=ROOT)
    print('PASS 0118 patch applies after 0108')

    clang = os.environ.get('CLANG', 'clang')
    comp = [clang, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-pedantic']
    san = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    portable = ROOT / 'ports/dizi'
    testcase = portable / 'se9_transport_0118_test.c'
    with tempfile.TemporaryDirectory(prefix='dizi-se9-0118-') as path:
        tmp = Path(path)
        for name, source in sources.items():
            (tmp / name).write_text(source)
        host = [str(portable / 'se9_transport_0118.c'), str(testcase)]
        run(*(comp + san + ['-I', str(portable), *host, '-o', str(tmp / 'host')]))
        run(str(tmp / 'host'))

        # Quoted includes first consult the source's containing directory;
        # copy the fixture so the genuine XNU-prefixed header is selected.
        (tmp / testcase.name).write_bytes(testcase.read_bytes())
        native = [str(tmp / 'se9_transport_0118.c'),
                  str(tmp / 'dizi_se9_spi_xnu_0118.c'),
                  str(tmp / testcase.name)]
        run(*(comp + san + ['-I', str(tmp), '-I', str(stage / 'bsd/dev'),
                          '-DDIZI_SE9_0118_TEST_NATIVE_BRIDGE=1', *native,
                          '-o', str(tmp / 'native')]))
        run(str(tmp / 'native'))
        for source in host[:1]:
            run(clang, '--target=aarch64-linux-gnu', '-std=c11', '-Wall',
                '-Wextra', '-Werror', '-pedantic', '-I', str(portable), '-c',
                source, '-o', str(tmp / 'portable.aarch64.o'))
        for source in native[:2]:
            run(clang, '--target=aarch64-linux-gnu', '-std=c11', '-Wall',
                '-Wextra', '-Werror', '-pedantic', '-I', str(tmp),
                '-I', str(stage / 'bsd/dev'), '-c', source,
                '-o', str(tmp / (Path(source).stem + '.aarch64.o')))
        print('PASS 0118 portable and XNU-disabled mock sanitizer + AArch64 TU')

        flagdir = ROOT / 'research/bt0099/build/xnu.obj/DEVELOPMENT_ARM64_SWEET/bsd/DEVELOPMENT'
        flagsfile = flagdir / '.CFLAGS'
        if flagsfile.is_file():
            tool = ROOT / 'tools/xnu-buildtree-cc.py'
            spec = importlib.util.spec_from_file_location('xnu_cc', tool)
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            flags = module.flags(flagsfile, ROOT / 'research/bt0099')
            for source in native[:2]:
                run(clang, '--target=arm64-apple-macos14.0', '-c',
                    '-o', str(tmp / (Path(source).stem + '.macho.o')),
                    '-I', str(tmp), '-I', str(stage / 'bsd/dev'),
                    *flags, source, cwd=flagdir)
                assert (tmp / (Path(source).stem + '.macho.o')).stat().st_size
            print('PASS 0118 native XNU ARM64 Mach-O using recorded kernel flags')
        else:
            print('SKIP native XNU Mach-O (recorded .CFLAGS unavailable)')


if __name__ == '__main__':
    main()
