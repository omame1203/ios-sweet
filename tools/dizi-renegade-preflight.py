#!/usr/bin/env python3
"""Read-only dizi FDT/board preflight for Renegade edk2-msm UEFI porting.

Reports hardware source facts and missing EDK2 drivers. NEVER edits firmware,
creates a boot image, accesses fastboot, claims UEFI works, or writes files.
The old SDM845 guide is NOT a binary/ACPI donor for SM7435.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


class Rejected(ValueError):
    pass


def fdtget(dtb: Path, *args: str) -> str:
    if args[:1] == ("-l",):
        command = ["fdtget", "-l", str(dtb), *args[1:]]
    elif args[:1] == ("-p",):
        command = ["fdtget", "-p", str(dtb), *args[1:]]
    elif len(args) >= 4 and args[:1] == ("-t",):
        command = ["fdtget", "-t", args[1], str(dtb), *args[2:]]
    else:
        raise Rejected("unsupported FDT access")
    try:
        return subprocess.check_output(
            command,
            text=True, stderr=subprocess.PIPE, timeout=10,
        ).strip()
    except (FileNotFoundError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        raise Rejected(f"missing or invalid FDT property {args}: {exc}") from exc


def cells(dtb: Path, node: str, name: str) -> list[int]:
    raw = fdtget(dtb, "-t", "x", node, name)
    try:
        values = [int(v, 16) for v in raw.split()]
    except ValueError as exc:
        raise Rejected(f"invalid cells: {node}/{name}") from exc
    if not values or any(v < 0 or v > 0xFFFFFFFF for v in values):
        raise Rejected(f"empty/overflow cells: {node}/{name}")
    return values


def u64(pair: list[int]) -> int:
    if len(pair) != 2:
        raise Rejected("expected #address-cells/#size-cells 2/2")
    return (pair[0] << 32) | pair[1]


def ranges(raw: list[int]) -> list[tuple[int, int]]:
    if len(raw) % 4:
        raise Rejected("truncated 64-bit FDT reg")
    result = []
    for i in range(0, len(raw), 4):
        pa = u64(raw[i:i+2])
        length = u64(raw[i+2:i+4])
        if length and pa + length <= 1 << 64:
            result.append((pa, length))
        elif length:
            raise Rejected("FDT reg wraparound")
    if not result:
        raise Rejected("no usable DDR banks")
    return result


def overlaps(a: int, n: int, b: int, m: int) -> bool:
    return n > 0 and m > 0 and a < b + m and b < a + n


def analyze(board_path: Path, dtb_path: Path, candidate_conf: Path) -> dict:
    for path in (board_path, dtb_path, candidate_conf):
        if not path.is_file() or path.is_symlink():
            raise Rejected(f"missing/not regular source: {path}")
    board = json.loads(board_path.read_text(encoding="utf-8"))
    if board.get("board") != "dizi" or board.get("soc") != "SM7435":
        raise Rejected("not an observed dizi/SM7435 board")
    conf = candidate_conf.read_text(encoding="utf-8")
    for token in ('SOC_PLATFORM="SM7435"', 'PLATFORM_NAME="dizi"',
                  'BOOTIMG_HEADER_VERSION=4'):
        if token not in conf:
            raise Rejected(f"Renegade candidate missing {token}")
    if len(dtb_path.read_bytes()) > 2 * 1024 * 1024:
        raise Rejected("unexpectedly large FDT")
    compatible = fdtget(dtb_path, "-t", "s", "/", "compatible")
    if "qcom,parrot" not in compatible:
        raise Rejected("FDT incompatible with observed Qualcomm parrot board")
    if cells(dtb_path, "/", "#address-cells") != [2] or \
       cells(dtb_path, "/", "#size-cells") != [2]:
        raise Rejected("expected 64-bit DDR map")
    memory = ranges(cells(dtb_path, "/memory", "reg"))
    kernel_pa, kernel_len = [int(v, 0) for v in board["kernel_ram"]]
    if not kernel_len or kernel_pa + kernel_len > 1 << 64:
        raise Rejected("bad requested kernel RAM region")
    inside = any(kernel_pa >= start and kernel_pa + kernel_len <= start + size
                 for start, size in memory)
    if not inside:
        raise Rejected("kernel_ram absent from captured DDR map")

    children = fdtget(dtb_path, "-l", "/reserved-memory").splitlines()
    fixed = []
    dynamic = []
    for name in children:
        node = "/reserved-memory/" + name.strip()
        if not name.strip():
            continue
        props = fdtget(dtb_path, "-p", node).splitlines()
        if "reg" in props:
            fixed.extend(ranges(cells(dtb_path, node, "reg")))
        else:
            # A reserved child without reg can be a CMA/dynamically assigned
            # region: it must not be omitted from runtime ownership audit.
            dynamic.append(name.strip())
    fixed_conflicts = [(start, size) for start, size in fixed
                       if overlaps(start, size, kernel_pa, kernel_len)]
    if fixed_conflicts:
        raise Rejected("kernel_ram intersects fixed reserved-memory")
    fb = board["framebuffer"]
    frame_pa = int(fb["base"], 0)
    frame_size = int(fb["reserved_size"], 0)
    fb_nodes = [(pa, size) for pa, size in fixed
                if pa == frame_pa and size == frame_size]
    if not fb_nodes:
        raise Rejected("framebuffer reservation differs from captured FDT")
    if fb["width"] * 4 != fb["stride"] or fb["height"] <= 0:
        raise Rejected("invalid framebuffer stride/dimensions")
    return {
        "board": "dizi", "soc": "SM7435", "target": "Renegade edk2-msm UEFI",
        "renegade_platform_ready": False, "uefi_buildable": False,
        "status": "SOURCE_ONLY_BLOCKED",
        "provenance": {
            "fdt_sha256": hashlib.sha256(dtb_path.read_bytes()).hexdigest(),
            "board_json_sha256": hashlib.sha256(board_path.read_bytes()).hexdigest(),
            "hardware_snapshot_not_live_attestation": True,
        },
        "observed": {
            "compatible": compatible.split(),
            "ddr_banks": len(memory),
            "candidate_kernel_ram": [hex(kernel_pa), hex(kernel_len)],
            "kernel_ram_in_captured_ddr": inside,
            "fixed_reserved_regions": len(fixed),
            "unlocated_reserved_children": len(dynamic),
            "framebuffer": [hex(frame_pa), fb["width"], fb["height"], fb["stride"]],
            "boot_header_version": board["boot_header_version"],
            "gic": board["gic"], "ufs": board["ufs"],
        },
        "unresolved": [
            "edk2-msm master has no Silicon/Qualcomm/sm7435 backend",
            "No Platform/Xiaomi/sm7435/dizi DSC/FDF or verified PCD memory map",
            "UEFI runtime memory ownership/EL2 and dynamic FDT reservations unverified",
            "No SM7435 ACPI/DT handoff, UFS DXE, clocks, PMIC, USB or GPU drivers",
            "Vendor XBL EFI binaries from SDM845/SM7325 are not ABI-compatible proof",
            "No dizi UEFI image or native macOS27/XNU27 boot created",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--board", type=Path, default=ROOT / "boards/dizi.json")
    parser.add_argument("--fdt", type=Path, default=ROOT / "backup/dizi/fdt")
    parser.add_argument("--config", type=Path, default=ROOT / "ports/renegade/dizi.conf")
    args = parser.parse_args()
    try:
        print(json.dumps(analyze(args.board, args.fdt, args.config), indent=2,
                         ensure_ascii=False))
    except (Rejected, OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
