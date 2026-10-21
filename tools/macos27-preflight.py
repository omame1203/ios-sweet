#!/usr/bin/env python3
"""Read-only macOS 27 migration artifact identity preflight for POCO Pad.

Never installs, converts, re-signs, patches, flashes or starts any OS.
Even fully matching VERSION METADATA cannot establish Apple signature,
macOS bootability, APFS SSV verification, working graphics, or ownership.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import sys
from xml.parsers.expat import ExpatError

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from ports.macos27.kernel_collection import inspect, read_regular, MAX_BYTES, ARM64

MAX_PLIST_BYTES = 8 * 1024 * 1024
MAX_KERNEL_SCAN_BYTES = MAX_BYTES
MACHO64 = 0xFEEDFACF
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
            raise ValueError("Build does not match the macOS 27 26A/26B build train")
        return {"status": "identity_only", "product": name,
                "version": version, "build": build,
                "role": "restore_environment" if data.get('ReleaseType') == 'Restore' else "system_metadata",
                "reason": "Plist identity is consistent but can be copied or edited"}
    except (OSError, ValueError, TypeError, OverflowError, ExpatError,
            plistlib.InvalidFileException) as exc:
        return {"status": "rejected", "reason": str(exc)}


def kernel_identity(path: Path | None) -> dict:
    if path is None:
        return {"status": "missing", "reason": "No matching macOS 27 kernel supplied"}
    try:
        data = read_regular(path)
        image = inspect(data)
        if image['darwin_major'] != 27:
            raise ValueError(f"Darwin {image['darwin']} does not match the observed macOS 27 kernel (Darwin 27)")
        return {"status": "identity_only", **image,
                "sha256": hashlib.sha256(data).hexdigest(),
                "reason": "Mach-O/header/version match is not source provenance or boot compatibility"}
    except (OSError, ValueError, OverflowError) as exc:
        return {"status": "rejected", "reason": str(exc)}


def manifest_identity(manifest: Path | None, wrapped: Path | None,
                      component: str | None) -> dict:
    """Check the downloaded IMG4/IM4P bytes against their BuildManifest entry.

    This is an integrity link, not a signature check. In particular a supplied
    manifest could be forged. Decompression is a separate step: the digest is
    over the ORIGINAL wrapped component, not the decompressed Mach-O.
    """
    if manifest is None or wrapped is None or component is None:
        return {'status': 'missing', 'reason': 'BuildManifest, wrapped kernelcache and component name required'}
    try:
        raw = read_regular(manifest, 32 * 1024 * 1024)
        metadata = plistlib.loads(raw)
        version, build = metadata.get('ProductVersion'), metadata.get('ProductBuildVersion')
        products = metadata.get('SupportedProductTypes')
        if (not isinstance(products, list) or not products or
                not all(isinstance(p, str) and p.startswith(('Mac', 'iMac', 'VirtualMac')) for p in products)):
            raise ValueError('BuildManifest is not a Mac product distribution')
        if (not isinstance(version, str) or not re.fullmatch(r'27\.[0-9]+(?:\.[0-9]+)?', version)
                or not isinstance(build, str) or not BUILD_TRAIN.fullmatch(build)):
            raise ValueError('BuildManifest is not a macOS 27 build train')
        matches = []
        for identity in metadata.get('BuildIdentities', []):
            item = identity.get('Manifest', {}).get('KernelCache', {})
            if item.get('Info', {}).get('Path') == component:
                digest = item.get('Digest')
                if not isinstance(digest, bytes) or len(digest) != 48:
                    raise ValueError('Expected a SHA-384 KernelCache digest')
                matches.append((identity.get('Info', {}).get('DeviceClass'), digest))
        if not matches or len({d for _, d in matches}) != 1:
            raise ValueError('KernelCache component missing or has conflicting digests')
        data = read_regular(wrapped)
        if hashlib.sha384(data).digest() != matches[0][1]:
            raise ValueError('Wrapped KernelCache SHA-384 differs from BuildManifest')
        return dict(status='digest_matched', version=version, build=build, component=component,
                    manifest_sha256=hashlib.sha256(raw).hexdigest(),
                    component_sha256=hashlib.sha256(data).hexdigest(),
                    component_sha384=matches[0][1].hex(),
                    device_classes=sorted({str(c) for c, _ in matches}),
                    apple_signature_verified=False,
                    decompressed_kernel_link_verified=False,
                    reason='Manifest integrity only; original source and decompression must be recorded separately')
    except (OSError, ValueError, TypeError, AttributeError, OverflowError, ExpatError,
            plistlib.InvalidFileException) as exc:
        return {'status': 'rejected', 'reason': str(exc)}


def assess(profile: Path, system_version: Path | None, kernel: Path | None,
           manifest: Path | None = None, wrapped: Path | None = None,
           component: str | None = None) -> dict:
    try:
        profile_obj = json.loads(profile.read_text(encoding="utf-8"))
        if (profile_obj["board"] != "dizi" or profile_obj["soc"] != "SM7435" or
            profile_obj["target_os"] != "macOS" or profile_obj["target_version_major"] != 27 or
            profile_obj["expected_darwin_major"] != 27 or
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
        "build_manifest": manifest_identity(manifest, wrapped, component),
        "retained_legacy_system": "iPadOS 16.7.16 / Darwin 22 baseline (unchanged)",
        "hard_blockers": [
            "Matching portable XNU source/build, CPU ABI and complete macOS OS payload not verified",
            "Stock arm64e filesets cannot use the legacy standalone SWEET loader or have PAC stripped",
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
                        help="Decompressed ARM64 macOS kernel or kernel collection, NOT the wrapped IM4P")
    parser.add_argument("--build-manifest", type=Path, help="Original IPSW BuildManifest.plist")
    parser.add_argument("--wrapped-kernel", type=Path, help="Original wrapped KernelCache component")
    parser.add_argument("--component", help="Exact KernelCache Info.Path in BuildManifest")
    parser.add_argument("--json", action="store_true", help="Machine-readable blocked checks")
    args = parser.parse_args()
    report = assess(args.profile, args.system_version, args.kernel,
                    args.build_manifest, args.wrapped_kernel, args.component)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("macOS 27 on POCO Pad (dizi): BLOCKED / no boot attempt")
        for key in ("profile_error", "system_version", "kernel", "build_manifest"):
            if key in report:
                value = report[key]
                if isinstance(value, dict):
                    value = {k: v for k, v in value.items() if k in
                             ('status', 'product', 'version', 'build', 'role', 'format',
                              'darwin', 'observed_xnu_tag', 'arm64e', 'reason')}
                print(f"{key}: {value}")
        for blocker in report.get("hard_blockers", ()):
            print("- " + blocker)
    return 2  # fail closed for any automation treating a preflight as readiness


if __name__ == "__main__":
    raise SystemExit(main())
