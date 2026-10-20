#!/usr/bin/env python3
"""Run genuine portable UFS/GPT bounds code under sanitizers; never use a device."""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'xnu/patches/0111-dizi-ufs-gpt-bounds.patch'

patch = PATCH.read_text()
header_marker = '+++ b/bsd/dev/dizi_ufs_gpt_bounds.h\n'
start = patch.index(header_marker) + len(header_marker)
mirror = []
for line in patch[start:].splitlines(keepends=True):
    if line.startswith('@@') or line.startswith('\\ No newline'):
        continue
    if line.startswith('+') and not line.startswith('+++'):
        mirror.append(line[1:])
    elif line.startswith(('--- ', '+++ ', 'diff --git ')):
        break
assert ''.join(mirror) == (ROOT / 'ports/dizi/ufs_gpt_bounds.h').read_text(), (
    'The XNU header must be byte-identical to the sanitizer-tested helper')
for source_call in ('dizi_ufs_gpt_table_bounds(', 'dizi_ufs_gpt_partition_bounds(',
                    'dizi_ufs_partition_offset(', 'dizi_ufs_lba10_bounds('):
    assert source_call in patch, source_call
print('PASS XNU 0111 header is byte-identical to host-tested code; all four guard paths wired')

with tempfile.TemporaryDirectory(prefix='dizi-ufs-gpt-') as scratch:
    binary = str(Path(scratch) / 'ufs-gpt-test')
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra',
                    '-Werror', '-pedantic', '-O1', '-g',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    'ports/dizi/ufs_gpt_bounds_test.c', '-o', binary],
                   cwd=ROOT, check=True)
    subprocess.run([binary], check=True, cwd=ROOT)
