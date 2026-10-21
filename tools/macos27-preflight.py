#!/usr/bin/env python3
"""Read-only macOS 27 migration artifact identity preflight for POCO Pad.

Never installs, converts, re-signs, patches, flashes or starts any OS.
Even fully matching VERSION METADATA cannot establish Apple signature,
macOS bootability, APFS SSV verification, working graphics, or ownership.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import plistlib
import re
import struct
from xml.parsers.expat import ExpatError

REPO = Path(__file__).resolve().parents[1]
MAX_PLIST_BYTES = 8 * 1024 * 1024
MAX_KERNEL_SCAN_BYTES = 64 * 1024 * 1024
MACHO64 = 0xFEEDFACF
ARM64 = 0x0100000C
DARWIN_MARKER = re.compile(rb"Darwin Kernel Version\s+(\d+)\.(\d+)\.(\d+)(?:[^\x00\r\n]{0,300})")
BUILD_TRAIN = re.compile(r"^26[A-Z][0-9]{1,6}[a-z]?$", re.ASCII)


def system_identity(path: Path | None) -> dict:
    if path is None:
        return {"status": "missing", "reason": "No macOS SystemVersion.plist supplied"}
    try:
        if path.stat().st_size > MAX_PLIST_BYTES:
            raise ValueError("SystemVersion.plist exceeds size limit")
        data = plistlib.loads(path.read_bytes())
        if not isinstance(data, dict):
            raise ValueError("SystemVersion.plist must contain a dictionary")
        name, version, build = (data.get(k) for k in
                                ("ProductName", "ProductVersion", "ProductBuildVersion"))
        if not all(isinstance(x, str) for x in (name, version, build)):
            raise ValueError("Missing string product identity fields")
        if name not in ("macOS", "Mac OS X"):
            raise ValueError("Not a macOS system image")
        if not re.fullmatch(r"27\.[0-9]{1,3}(?:\.[0-9]{1,3})?", version):
            raise ValueError("ProductVersion is not macOS 27")
        if not BUILD_TRAIN.fullmatch(build):
            raise ValueError("Build does not match the verified macOS 27 Darwin 26 train")
        return {"status": "identity_only", "product": name,
                "version": version, "build": build,
                "reason": "Plist identity is consistent but can be copied or edited"}
    except (OSError, ValueError, TypeError, OverflowError, ExpatError,
            plistlib.InvalidFileException) as exc:
        return {"status": "rejected", "reason": str(exc)}


def kernel_identity(path: Path | None) -> dict:
    if path is None:
        return {"status": "missing", "reason": "No matching macOS 27 kernel supplied"}
    try:
        size = path.stat().st_size
        if size < 64 or size > MAX_KERNEL_SCAN_BYTES:
            raise ValueError("Unsupported or oversized standalone kernel image")
        data = path.read_bytes()
        magic, cpu, _, filetype = struct.unpack_from("<4I", data)
        if magic != MACHO64 or cpu != ARM64:
            raise ValueError("Not a standalone ARM64 Mach-O kernel (kernel collections need separate handling)")
        if filetype != 2:  # MH_EXECUTE: existing dizi development-kernel input
            raise ValueError("Expected a standalone Mach-O executable, not a userland binary")
        match = DARWIN_MARKER.search(data)
        if not match:
            raise ValueError("Cannot determine the native kernel's Darwin version")
        major, minor, patch = (int(x) for x in match.groups())
        if major != 26:
            raise ValueError(f"Darwin {major}.{minor}.{patch} does not match macOS 27 (Darwin 26)")
        return {"status": "identity_only", "darwin": f"{major}.{minor}.{patch}",
                "reason": "Mach-O/header/version match is not source provenance or boot compatibility"}
    except (OSError, ValueError, struct.error, OverflowError) as exc:
        return {"status": "rejected", "reason": str(exc)}


def assess(profile: Path, system_version: Path | None, kernel: Path | None) -> dict:
    try:
        profile_obj = json.loads(profile.read_text(encoding="utf-8"))
        if (profile_obj["board"] != "dizi" or profile_obj["soc"] != "SM7435" or
            profile_obj["target_os"] != "macOS" or profile_obj["target_version_major"] != 27 or
            profile_obj["expected_darwin_major"] != 26 or
            profile_obj["official_apple_device_supported"] is not False or
            profile_obj["status"] != "not_bootable"):
            raise ValueError("Not the explicit fail-closed dizi/macOS27 profile")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {"target": "dizi/macOS27", "verdict": "BLOCKED", "profile_error": str(exc)}
    system = system_identity(system_version)
    version = kernel_identity(kernel)
    return {
        "target": "dizi/macOS27", "verdict": "BLOCKED",
        "system_version": system, "kernel": version,
        "retained_legacy_system": "iPadOS 16.7.16 / Darwin 22 baseline (unchanged)",
        "hard_blockers": [
            "No authenticated macOS27 kernelcache/ABI and complete OS payload verified",
            "APFS sealed System/Data volume group, Preboot and trust chain unimplemented",
            "Qualcomm SM7435 cannot satisfy Apple Silicon iBoot/SEP/AGX/WindowServer contracts yet",
            "No authorized non-destructive macOS27 boot image can be generated from version strings"
        ],
        "actions_performed": "Read-only local metadata inspection only"
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=REPO / "boards/dizi-macos27.json")
    parser.add_argument("--system-version", type=Path,
                        help="Genuine extracted macOS /System/Library/CoreServices/SystemVersion.plist")
    parser.add_argument("--kernel", type=Path,
                        help="Genuine candidate standalone ARM64 macOS kernel, NOT iOS or iPadOS")
    parser.add_argument("--json", action="store_true", help="Machine-readable blocked checks")
    args = parser.parse_args()
    report = assess(args.profile, args.system_version, args.kernel)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("macOS 27 on POCO Pad (dizi): BLOCKED / no boot attempt")
        for key in ("profile_error", "system_version", "kernel"):
            if key in report:
                print(f"{key}: {report[key]}")
        for blocker in report.get("hard_blockers", ()):
            print("- " + blocker)
    return 2  # fail closed for any automation treating a preflight as readiness


if __name__ == "__main__":
    raise SystemExit(main())
