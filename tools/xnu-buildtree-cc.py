#!/usr/bin/env python3
"""Compile selected XNU sources using a CI buildtree's recorded .FLAGS.

Unlike xnu-cc.py this does not require authenticated access to Actions logs.
It uses the original compiler options and does not emulate Apple builtins.
This is a translation-unit check, not a complete kernel build/link test.
"""
import argparse
from pathlib import Path
import re
import shlex
import subprocess
import sys

CI_ROOT = '/Users/runner/work/ios-sweet/ios-sweet/dxb'


def flags(path, tree):
    tokens = shlex.split(path.read_text().strip('\0\n'))[1:]
    result = []
    i = 0
    while i < len(tokens):
        arg = tokens[i]
        i += 1
        # REPLACECONTENTS records macro expressions without shell quoting.
        if arg.startswith('-D') and '=' in arg:
            depth = arg.count('(') - arg.count(')')
            while depth > 0 and i < len(tokens):
                more = tokens[i]
                i += 1
                arg += ' ' + more
                depth += more.count('(') - more.count(')')
            if depth != 0:
                raise ValueError('unbalanced macro in recorded flags')
        if arg == '-arch':
            i += 1
            continue
        if arg == '-g':
            continue
        arg = arg.replace(CI_ROOT, str(tree))
        arg = re.sub(r'/Applications/.*?\.sdk/+System/Library/Frameworks/Kernel\.framework/Versions/A/PrivateHeaders/platform',
                     str(tree / 'sdk-kernel-platform/platform'), arg)
        result.append(arg)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('buildtree', type=Path)
    ap.add_argument('sources', nargs='+')
    ap.add_argument('--clang', default='clang')
    ap.add_argument('--objects', type=Path, help='Emit Mach-O objects instead of syntax checks')
    ap.add_argument('--syntax-compat', action='store_true',
                    help='Syntax only: model unavailable Apple allocator builtins; cannot emit objects')
    ap.add_argument('--config', default='DEVELOPMENT_ARM64_SWEET')
    args = ap.parse_args()
    if args.syntax_compat and args.objects:
        ap.error('--syntax-compat cannot produce bootable objects')
    tree = args.buildtree.resolve()
    config = tree / 'build/xnu.obj' / args.config
    failed = False
    if args.objects:
        args.objects = args.objects.resolve()
        args.objects.mkdir(parents=True, exist_ok=True)
    for name in args.sources:
        source = tree / 'xnu' / name
        if not source.is_file():
            raise SystemExit(f'No source: {source}')
        component = name.split('/')[0]
        builddir = config / component / 'DEVELOPMENT'
        kind = 'S' if source.suffix in ('.s', '.S') else 'CXX' if source.suffix == '.cpp' else 'C'
        options = flags(builddir / ('.' + ('C' if kind == 'CXX' else kind) + 'FLAGS'), tree)
        if kind == 'CXX':
            # XNU's C++ rule uses CFLAGS plus the language-only CXXFLAGS.
            options += flags(builddir / '.CXXFLAGS', tree)
        if args.syntax_compat and kind != 'S':
            options += ['-D__builtin_xnu_type_signature(...)=""',
                        '-D__builtin_xnu_type_summary(...)=0',
                        '-D__builtin_xnu_types_compatible(...)=1']
        mode = ['-c', '-o', str(args.objects / (name.replace('/', '__') + '.o'))] if args.objects else ['-fsyntax-only']
        # An assembler must actually assemble to diagnose operand/immediate errors.
        if kind == 'S' and not args.objects:
            mode = ['-c', '-o', '/dev/null']
        cmd = [args.clang, '--target=arm64-apple-macos14.0', *mode, *options, str(source)]
        result = subprocess.run(cmd, cwd=builddir, capture_output=True, text=True)
        print(('PASS ' if result.returncode == 0 else 'FAIL ') + name, flush=True)
        if result.stderr:
            sys.stderr.write(result.stderr)
        failed |= result.returncode != 0
    return int(failed)


if __name__ == '__main__':
    sys.exit(main())
