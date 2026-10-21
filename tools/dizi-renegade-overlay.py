#!/usr/bin/env python3
"""Stage an independently reviewable dizi Renegade EDK2 worktree.

Never edit the user's edk2 checkout, any existing source, or a device.
Default mode is an audit; --prepare clones the exact upstream git HEAD into a
NEW destination and adds only the bounded dizi overlay. --build additionally
attempts a native EDK2 build in the new copy (never --boot/--clean/--flash).
No claim that successfully producing an FD makes it safe for fastboot boot.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = Path('/tmp/dizi-edk2-msm-audit-20261021')
DEFAULT_OVERLAY = ROOT / 'ports/renegade/edk2-overlay'
PINNED_RENEGADE_COMMIT = 'e1952621f419f8db60ed28271264e1b5184c571d'
ALLOWED_EXT = {'.conf', '.dsc', '.dec', '.fdf', '.inc', '.inf', '.h', '.c', '.S', '.asl', '.txt'}
MAX_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 12 * 1024 * 1024
REQUIRED = (
    'configs/sm7435.conf', 'configs/devices/dizi.conf',
    'Platform/Xiaomi/sm7435/dizi.dsc',
    'Platform/Xiaomi/sm7435/dizi.fdf.inc',
    'Platform/Qualcomm/sm7435/sm7435.dsc',
    'Platform/Qualcomm/sm7435/sm7435.fdf',
    'Silicon/Qualcomm/sm7435/Library/PlatformMemoryMapLib/PlatformMemoryMapLib.inf',
    'Silicon/Qualcomm/sm7435/Library/PlatformPrePiLib/PlatformPrePiLib.inf',
    'Silicon/Qualcomm/sm7435/Library/PlatformPeiLib/PlatformPeiLib.inf',
)


class NotReady(RuntimeError):
    pass


def command(*args: str, cwd: Path | None = None, env: dict | None = None) -> str:
    try:
        completed = subprocess.run(args, cwd=cwd, env=env,
                                   text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, check=True)
        return completed.stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise NotReady(f'command failed: {args[0]}: {exc}') from exc


def source_files(overlay: Path) -> list[tuple[Path, str]]:
    if not overlay.is_dir() or overlay.is_symlink():
        raise NotReady('missing safe dizi overlay directory')
    files = []
    total = 0
    for path in sorted(overlay.rglob('*')):
        relative = path.relative_to(overlay)
        if path.is_symlink() or any(part.startswith('.') for part in relative.parts):
            raise NotReady(f'symlink/hidden overlay path: {relative}')
        if path.is_dir():
            continue
        if not path.is_file() or path.suffix not in ALLOWED_EXT:
            raise NotReady(f'unsupported overlay file: {relative}')
        if not relative.parts or relative.parts[0] not in ('Silicon', 'Platform', 'configs'):
            raise NotReady(f'unexpected overlay destination: {relative}')
        if path.stat().st_size > MAX_BYTES:
            raise NotReady(f'oversize source file: {relative}')
        total += path.stat().st_size
        if total > MAX_TOTAL_BYTES:
            raise NotReady('dizi overlay exceeds source-only budget')
        files.append((path, relative.as_posix()))
    return files


def review(source: Path, overlay: Path) -> dict:
    if not (source / '.git').exists() or source.is_symlink():
        raise NotReady('upstream must be a real git checkout')
    head = command('git', 'rev-parse', 'HEAD', cwd=source)
    if head != PINNED_RENEGADE_COMMIT:
        raise NotReady(f'unreviewed edk2-msm revision: {head}')
    files = source_files(overlay)
    paths = {name for _, name in files}
    missing = sorted(set(REQUIRED) - paths)
    incompatible = sorted(name for name in paths if
                          (name.startswith('Silicon/Qualcomm/') and not name.startswith('Silicon/Qualcomm/sm7435/')) or
                          (name.startswith('Platform/Qualcomm/') and not name.startswith('Platform/Qualcomm/sm7435/')) or
                          (name.startswith('Platform/Xiaomi/') and not name.startswith('Platform/Xiaomi/sm7435/')) or
                          (name.startswith('configs/devices/') and name != 'configs/devices/dizi.conf') or
                          (name.startswith('configs/') and name.count('/') == 1 and name != 'configs/sm7435.conf'))
    if incompatible:
        raise NotReady(f'overlay includes another board: {incompatible}')
    digest = hashlib.sha256()
    for path, name in files:
        data = path.read_bytes()
        digest.update(name.encode('utf-8') + b'\0')
        digest.update(hashlib.sha256(data).digest())
    return {
        'upstream': 'edk2-porting/edk2-msm', 'upstream_commit': head,
        'platform': 'SM7435/dizi', 'files': [name for _, name in files],
        'missing_platform_inputs': missing,
        'overlay_sha256': digest.hexdigest(), 'buildable_claim': False,
        'generated_uefi_fd': False, 'temporary_boot_performed': False,
        'needs_dynamic_fdt_reservation_and_el2_ownership_proof': True,
    }


def prepare(source: Path, overlay: Path, destination: Path) -> dict:
    report = review(source, overlay)
    if report['missing_platform_inputs']:
        raise NotReady(f'EDK2 dizi implementation is incomplete: {report["missing_platform_inputs"]}')
    if destination.exists() or destination.is_symlink():
        raise NotReady('destination already exists; refusing to overwrite')
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise NotReady('destination parent must be an existing directory')
    if destination.resolve() == source.resolve() or destination.resolve() == overlay.resolve():
        raise NotReady('destination aliases protected input')
    # A fresh checkout is required because upstream build.sh mutates its
    # own BaseTools, configuration, FD outputs, and boot shim in place.
    command('git', 'clone', '--quiet', '--shared', '--no-hardlinks',
            str(source), str(destination))
    if command('git', 'rev-parse', 'HEAD', cwd=destination) != PINNED_RENEGADE_COMMIT:
        raise NotReady('prepared copy has mismatched upstream commit')
    for path, name in source_files(overlay):
        output = destination / name
        if output.exists() or output.is_symlink():
            raise NotReady(f'upstream path already occupied; no overwrite: {name}')
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, output, follow_symlinks=False)
        if hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(output.read_bytes()).digest():
            raise NotReady(f'staged source bytes differ: {name}')
    report['prepared_workspace'] = str(destination)
    report['generated_uefi_fd'] = False
    return report


def build(destination: Path, report: dict) -> dict:
    if not (destination / 'Common/edk2/edksetup.sh').is_file():
        raise NotReady('EDK2 submodules not yet initialized in isolated workspace')
    if not (destination / 'tools/BootShim/Makefile').is_file():
        raise NotReady('Renegade BootShim source missing from isolated workspace')
    if not shutil.which('aarch64-linux-gnu-gcc'):
        raise NotReady('AARCH64 GCC cross compiler is missing')
    env = dict(os.environ)
    env['GCC5_AARCH64_PREFIX'] = 'aarch64-linux-gnu-'
    # --boot, --installer-zip, --clean and --distclean are never invoked.
    # The SimpleInit rootfs requires a separate runtime compatibility audit;
    # do not implicitly build/pack one as part of a firmware compilation.
    command('bash', './build.sh', '--device', 'dizi', '--release', 'DEBUG',
            '--toolchain', 'GCC5', '--skip-rootfs-gen', cwd=destination, env=env)
    # Renegade build.sh sets OUTDIR=$PWD and WORKSPACE=$OUTDIR/workspace;
    # this tool runs it from the new destination. The direct EDK2 debug audit
    # uses a different WORKSPACE (its root), so its output path is different.
    # The FD filename preserves DSC SOC_PLATFORM=SM7435 case.
    firmware = sorted((destination / 'workspace/Build/dizi').glob(
        '**/FV/SM7435_UEFI.fd'))
    if not firmware:
        raise NotReady('EDK2 returned success but workspace/Build/dizi/**/FV/SM7435_UEFI.fd is absent')
    for p in firmware:
        data = p.read_bytes()
        # The physical layout is a *provisional* 4 MiB FV. Validate at least
        # the fundamental EDK2 FV header before reporting an FD was produced.
        # This is not a signature, verified memory ownership or boot permit.
        if len(data) != 0x00400000 or len(data) < 0x48 or data[0x28:0x2c] != b'_FVH':
            raise NotReady(f'EDK2 produced an unexpected/non-FV output: {p}')
        if int.from_bytes(data[0x20:0x28], 'little') != len(data):
            raise NotReady(f'EDK2 FV header size mismatch: {p}')
    report['generated_uefi_fd'] = True
    report['verified_bootable_uefi'] = False
    report['firmware'] = [{'path': str(p), 'bytes': p.stat().st_size,
                           'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                          for p in firmware]
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=DEFAULT_SOURCE)
    parser.add_argument('--overlay', type=Path, default=DEFAULT_OVERLAY)
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--build', action='store_true')
    opts = parser.parse_args(argv)
    try:
        if opts.build and not opts.prepare:
            raise NotReady('--build requires --prepare')
        if opts.prepare and opts.destination is None:
            raise NotReady('--prepare requires --destination')
        report = (prepare(opts.source, opts.overlay, opts.destination)
                  if opts.prepare else review(opts.source, opts.overlay))
        if opts.build:
            report = build(opts.destination, report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if not report['missing_platform_inputs'] else 3
    except NotReady as exc:
        print(f'REFUSED: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
