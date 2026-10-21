#!/usr/bin/env python3
"""Reproduce dizi AArch64 EDK2 FV from pinned PUBLIC source in an isolated /tmp tree.

Default mode only audits inputs. --build creates a NEW isolated EDK2 WORKSPACE
under the explicitly selected stage and compiles one firmware-volume artifact.
The low PA is an unverified *compile-time candidate*, NEVER a boot permit.
Does not use upstream build.sh (which boot-packages and auto-initializes
unreviewed vendor submodules), Fastboot, installer, flash, or user-repo writes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "ports/renegade/edk2-overlay"
MAIN_PIN = "e1952621f419f8db60ed28271264e1b5184c571d"
PINNED_PUBLIC = {
    "Common/edk2": "e7aac7fc137e247edad22f7ee53b9a1fba227397",
    "Common/edk2-platforms": "982212662c71b6c734b7578526071d6b78da3bcc",
    "GPLDrivers/Library/SimpleInit": "29e062805776db5ab7a61d07ef040d43aed71161",
    "Common/edk2/BaseTools/Source/C/BrotliCompress/brotli":
        "f4153a09f87cbb9c826d8fc12c74642bb2d879ea",
    "Common/edk2/MdeModulePkg/Library/BrotliCustomDecompressLib/brotli":
        "f4153a09f87cbb9c826d8fc12c74642bb2d879ea",
    "Common/edk2/CryptoPkg/Library/OpensslLib/openssl":
        "129058165d195e43a0ad10111b0c2e29bdf65980",
    "Common/edk2/ArmPkg/Library/ArmSoftFloatLib/berkeley-softfloat-3":
        "b64af41c3276f97f0e181920400ee056b9c88037",
    "GPLDrivers/Library/SimpleInit/libs/freetype":
        "6a2b3e4007e794bfc6c91030d0ed987f925164a8",
}
FD_SIZE = 0x00400000
FD_BASE = 0x90000000  # Build diagnostic ONLY; no live RAM/XPU grant.


class Refused(RuntimeError):
    pass


def check_git(path: Path, expected: str) -> None:
    if not path.is_dir() or not (path / ".git").exists():
        raise Refused(f"missing pinned public git checkout: {path}")
    try:
        result = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Refused(f"unreadable public git checkout: {path}") from exc
    if result != expected:
        raise Refused(f"unreviewed public git revision: {path}: {result}")


def audit(stage: Path, overlay: Path = OVERLAY) -> dict:
    stage = stage.resolve(strict=True)
    if not stage.is_dir() or not stage.is_relative_to(Path("/tmp").resolve()):
        raise Refused("build stage MUST be an independent directory under /tmp")
    if stage == Path("/tmp") or stage == ROOT.resolve() or stage.is_symlink():
        raise Refused("unsafe stage location")
    check_git(stage, MAIN_PIN)
    for relative, pin in PINNED_PUBLIC.items():
        check_git(stage / relative, pin)
    tools = stage / "Common/edk2/BaseTools"
    for relative in ("Source/C/bin", "Source/Python/build/build.py"):
        if not (tools / relative).exists():
            raise Refused(f"BaseTools was not built: {relative}")
    for rel in ("Common/edk2/Conf/tools_def.txt",
                "Common/edk2/Conf/build_rule.txt"):
        if not (stage / rel).is_file():
            raise Refused(f"missing pinned build configuration: {rel}")
    source = tuple(sorted(p for p in overlay.rglob("*") if p.is_file()))
    if not source:
        raise Refused("no dizi board overlay")
    source_digests = {}
    for path in source:
        rel = path.relative_to(overlay).as_posix()
        staged = stage / rel
        if path.is_symlink() or staged.is_symlink() or not staged.is_file():
            raise Refused(f"missing unsafe/missing copied source: {rel}")
        expected = hashlib.sha256(path.read_bytes()).hexdigest()
        if hashlib.sha256(staged.read_bytes()).hexdigest() != expected:
            raise Refused(f"overlay source digest mismatch: {rel}")
        source_digests[rel] = expected
    report = {
        "stage": str(stage),
        "edk2_msm_revision": MAIN_PIN,
        "source_files_sha256": source_digests,
        "public_submodules_pinned": len(PINNED_PUBLIC),
        "compile_fd_candidate_pa": hex(FD_BASE),
        "compile_fd_candidate_bytes": FD_SIZE,
        "runtime_ram_ownership_proven": False,
        "prepi_entry_abi_proven": False,
        "bootable": False,
        "fastboot_performed": False,
        "firmware_generated": False,
    }
    return report


def prepare_wrappers(workspace: Path) -> Path:
    gcc = shutil.which("gcc")
    cross = shutil.which("aarch64-linux-gnu-gcc")
    if not gcc or not cross:
        raise Refused("host or AArch64 cross GCC missing")
    gcc = str(Path(gcc).resolve(strict=True))
    cross = str(Path(cross).resolve(strict=True))
    directory = workspace / "compat-tools"
    directory.mkdir()
    host_code = '#!/bin/sh\nexec "' + gcc + '" -std=gnu17 -Wno-error=unused-but-set-variable "$@"\n'
    target_code = ('#!/bin/sh\nfor arg in "$@"; do\n case "$arg" in\n'
                   ' *.c|*.i) exec "' + cross + '" -std=gnu17 "$@" ;;\n'
                   ' esac\ndone\nexec "' + cross + '" "$@"\n')
    for name, contents in (("gcc", host_code), ("cc", host_code),
                           ("aarch64-linux-gnu-gcc", target_code)):
        p = directory / name
        p.write_text(contents)
        p.chmod(0o700)
    return directory


def build(stage: Path, report: dict, *, workspace_name: str = "verify-reproduce") -> dict:
    stage = Path(report["stage"])
    if not workspace_name.startswith("verify-") or len(workspace_name) > 60 or not all(
        char.isalnum() or char in "-_" for char in workspace_name
    ):
        raise Refused("workspace name must be a simple verify-* label")
    workspace = stage / workspace_name
    if workspace.exists() or workspace.is_symlink():
        raise Refused("verification workspace already exists; no overwrite")
    workspace.mkdir()
    wrapper_dir = prepare_wrappers(workspace)
    env = dict(os.environ)
    edk2 = stage / "Common/edk2"
    env.update({
        "WORKSPACE": str(workspace),
        "EDK_TOOLS_PATH": str(edk2 / "BaseTools"),
        "PACKAGES_PATH": ":".join(map(str, (
            stage, edk2, stage / "Common/edk2-platforms",
            stage / "GPLDrivers/Library/SimpleInit", stage / "GPLDrivers"))),
        "PYTHON_COMMAND": "python3",
        "GCC5_AARCH64_PREFIX": "aarch64-linux-gnu-",
        "PATH": str(wrapper_dir) + os.pathsep + env["PATH"],
    })
    # Static trusted command string: no source path, FD address, user input or
    # arbitrary shell fragment is ever interpolated into the executed script.
    script = (
        # Pinned EDK2 BaseTools/BuildEnv uses unset-option probes such as
        # CONF_PATH without ${...:-}; bash `set -u` breaks edksetup itself.
        'set -eo pipefail\n'
        '. "$EDK_TOOLS_PATH/../edksetup.sh" BaseTools >/dev/null\n'
        'cd "$WORKSPACE"\n'
        'build -p Platform/Xiaomi/sm7435/dizi.dsc -a AARCH64 -t GCC5 '
        '-b DEBUG -n 4 -D FD_BASE=0x90000000 -D FD_SIZE=0x00400000\n'
    )
    log = workspace / "genuine-edk2-debug.log"
    with log.open("w") as fp:
        try:
            result = subprocess.run(
                ["bash", "-c", script], cwd=edk2, env=env,
                text=True, stdout=fp, stderr=subprocess.STDOUT, check=False)
        except OSError as exc:
            raise Refused(f"could not execute EDK2 tooling: {exc}") from exc
    if result.returncode:
        raise Refused(f"genuine EDK2 build failed ({result.returncode}); inspect {log}")
    fd = workspace / "Build/dizi/DEBUG_GCC5/FV/SM7435_UEFI.fd"
    if not fd.is_file():
        raise Refused("EDK2 returned 0 but expected genuine FD is missing")
    data = fd.read_bytes()
    if len(data) != FD_SIZE or data[40:44] != b"_FVH" or +            int.from_bytes(data[32:40], "little") != FD_SIZE:
        raise Refused("unexpected EDK2 FD size/FV header")
    report.update({"firmware_generated": True, "bootable": False,
                   "firmware": str(fd), "firmware_sha256": hashlib.sha256(data).hexdigest(),
                   "firmware_bytes": len(data), "build_log": str(log)})
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--workspace-name", default="verify-reproduce")
    args = parser.parse_args(argv)
    try:
        report = audit(args.stage)
        if args.build:
            report = build(args.stage, report, workspace_name=args.workspace_name)
        print(json.dumps(report, indent=2))
        return 0
    except (Refused, FileNotFoundError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
