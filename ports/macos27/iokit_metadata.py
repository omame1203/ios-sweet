#!/usr/bin/env python3
"""Read-only 26A434 macOS27 fileset IOKit personality extractor.

Parses the actual embedded __PRELINK_INFO XML of the *decompressed* vma2
MH_FILESET, not strings guessed from bundle names, and intersects with real
LC_FILESET_ENTRY entries. Outputs normalized JSON or C initializer data
for ports/macos27/iokit_resolver.{c,h}. No fake IOService registration.

  python3 ports/macos27/iokit_metadata.py --format json
  python3 ports/macos27/iokit_metadata.py --format c

The C output is REVIEW DATA, not a compiled or trusted provider shim. It
contains no pointers, MMIO addresses, driver binaries or patched code.
The version, PAC and fixup requirements are separately enforced at runtime.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from ports.macos27.kernel_collection import inspect as kc_inspect

MAX_KC_BYTES = 256 * 1024 * 1024
MAX_PRELINK_BYTES = 16 * 1024 * 1024
# Local 26A434 vma2 81,444,864-byte decompressed fileset observed and
# hashed by the earlier KC preflight. A hash match is NOT an Apple signature.
EXPECTED_VMA2_SHA256 = "ca55ea8c4c86170e870380ae5501b8b43adb2d2d3db28be4531b3040653be203"
TARGET_BUNDLES = (
    "com.apple.driver.AppleARMGIC",
    "com.apple.driver.AppleARMPlatform",
    "com.apple.driver.AppleVirtualPlatform",
    "com.apple.iokit.IOGraphicsFamily",
    "com.apple.iokit.IOHIDFamily",
    "com.apple.iokit.IOGPUFamily",
    "com.apple.driver.AppleParavirtGPUIOGPUFamily",
)
TARGET_PERSONALITIES = (
    ("com.apple.driver.AppleARMGIC", "AppleARMGICv3"),
    ("com.apple.driver.AppleARMPlatform", "AppleARMPE"),
    ("com.apple.driver.AppleARMPlatform", "AppleARMCPU"),
    ("com.apple.driver.AppleARMPlatform", "AppleARMBacklight"),
    ("com.apple.driver.AppleVirtualPlatform", "AppleVirtualPlatformARMPE"),
    ("com.apple.driver.AppleVirtualPlatform", "ApplePSCI"),
    ("com.apple.iokit.IOGraphicsFamily", "AppleDisplay"),
    ("com.apple.iokit.IOGraphicsFamily", "IODisplayWrangler"),
    ("com.apple.iokit.IOHIDFamily", "IOHIDSystem"),
    ("com.apple.iokit.IOHIDFamily", "IOHIDEventServiceUserClient"),
    ("com.apple.driver.AppleParavirtGPUIOGPUFamily", "AppleParavirtGPUARM"),
)
# Only these fields can affect the conservative C resolver. Other matching
# selectors must be surfaced as unsupported, never silently ignored.
KNOWN_MATCH_KEYS = {
    "IOProviderClass", "IOClass", "IONameMatch", "IOResourceMatch",
    "IOMatchCategory", "IOProbeScore", "IOPropertyMatch",
}
UNSUPPORTED_MATCH_KEYS = {
    "IOPropertyExistsMatch", "IOPathMatch", "IOParentMatch", "IOPCIPrimaryMatch",
    "IOPCISecondaryMatch", "IOPCIClassMatch", "IOPCIMatch",
    "IOLocationMatch", "IODTMatch", "IOUserClientClassMatch", "IOServiceMatch",
    "IODefaultMatchCategory", "IOHIDDeviceUsagePairs", "IOHIDPrimaryUsagePage",
    "IOHIDPrimaryUsage", "IOIDMatch", "IOProbeScoreMatch",
}


def _checked_bytes(path: Path) -> bytes:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > MAX_KC_BYTES:
            raise ValueError("KC must be a bounded regular file, not a symlink/device")
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError("KC file is unavailable") from exc
    if len(raw) != info.st_size:
        raise ValueError("KC was modified while reading")
    return raw


def parse_prelink_xml(data: bytes) -> list[dict]:
    """Parse a single complete XML plist containing _PrelinkInfoDictionary.

    Avoid accepting arbitrary '<?xml' strings embedded in executable text.
    The genuine 26A434 KC contains several unrelated XML documents.
    """
    marker = b"<key>_PrelinkInfoDictionary</key>"
    pos = data.find(marker)
    if pos < 0 or data.find(marker, pos + len(marker)) >= 0:
        raise ValueError("missing or ambiguous _PrelinkInfoDictionary XML")
    begin = data.rfind(b"<?xml", max(0, pos - 4096), pos)
    if begin < 0 or pos - begin > 4096:
        raise ValueError("no bounded XML prelink header")
    close = data.find(b"</plist>", pos, min(len(data), begin + MAX_PRELINK_BYTES))
    if close < 0 or close + len(b"</plist>") - begin > MAX_PRELINK_BYTES:
        raise ValueError("prelink plist missing bounded terminator")
    tail = close + len(b"</plist>")
    if b"<!DOCTYPE plist " not in data[begin:pos]:
        raise ValueError("not a normal Apple plist XML")
    try:
        root = plistlib.loads(data[begin:tail])
    except (plistlib.InvalidFileException, TypeError, ValueError) as exc:
        raise ValueError("unparseable KC prelink metadata") from exc
    if type(root) is not dict or root.get("OSPrelinkInfoContainsUUIDs") is not True:
        raise ValueError("unexpected prelink document shape")
    entries = root.get("_PrelinkInfoDictionary")
    if type(entries) is not list or not 100 <= len(entries) <= 4096:
        raise ValueError("invalid KC kext metadata count")
    bundle_names = set()
    for entry in entries:
        if type(entry) is not dict:
            raise ValueError("non-dictionary prelink kext")
        ident = entry.get("CFBundleIdentifier")
        if type(ident) is not str or not ident or len(ident) > 192:
            raise ValueError("bad KC bundle identifier")
        if ident in bundle_names:
            raise ValueError("ambiguous repeated KC bundle")
        bundle_names.add(ident)
        pers = entry.get("IOKitPersonalities", {})
        if type(pers) is not dict or len(pers) > 2048:
            raise ValueError("bad IOKitPersonality container")
    return entries


def normalize(entry: dict, personality: str, raw: dict) -> dict:
    if type(personality) is not str or not 1 <= len(personality) <= 192:
        raise ValueError("bad personality name")
    if type(raw) is not dict:
        raise ValueError("personality must be a dictionary")
    bundle = entry["CFBundleIdentifier"]
    io_class = raw.get("IOClass")
    provider_class = raw.get("IOProviderClass")
    if not all(type(x) is str and 1 <= len(x) <= 192
               for x in (io_class, provider_class)):
        raise ValueError(f"no exact class/provider in {bundle} {personality}")
    names = raw.get("IONameMatch", [])
    if type(names) is str:
        names = [names]
    supported_names = type(names) is list and len(names) <= 8 and all(
        type(x) is str and 1 <= len(x) <= 192 for x in names)
    resource = raw.get("IOResourceMatch")
    supported_resource = resource is None or (
        type(resource) is str and 1 <= len(resource) <= 192)
    category = raw.get("IOMatchCategory")
    supported_category = category is None or (
        type(category) is str and 1 <= len(category) <= 192)
    probe_score = raw.get("IOProbeScore", 0)
    supported_score = type(probe_score) is int and -(1 << 31) <= probe_score < (1 << 31)
    # Unknown keys that affect device matching are not treated as "optional".
    # The prefix approach is conservative. Arbitrary properties such as
    # "driver-type" may be *payload* for a matched device, not match selectors.
    extra = sorted(k for k in raw if k in UNSUPPORTED_MATCH_KEYS or
                   (k.startswith(("IO", "IODT")) and k.endswith(("Match", "Matches")) and
                    k not in KNOWN_MATCH_KEYS))
    if not supported_names: extra.append("IONameMatch:unsupported-type-or-count")
    if not supported_resource: extra.append("IOResourceMatch:unsupported-type")
    if not supported_category: extra.append("IOMatchCategory:unsupported-type")
    if not supported_score: extra.append("IOProbeScore:unsupported-type")
    if type(raw.get("IOPropertyMatch", {})) is not dict:
        extra.append("IOPropertyMatch:unsupported-type")
    return {
        "bundle_id": bundle, "personality": personality, "io_class": io_class,
        "provider_class": provider_class, "name_match": names if supported_names else [],
        "resource_match": resource if supported_resource else None,
        "match_category": category if supported_category else None,
        "probe_score": probe_score if supported_score else 0,
        "property_match_present": "IOPropertyMatch" in raw,
        "unsupported_match_keys": extra,
        "metadata_only": True,
        "attach_authorized": False,
    }


def extract(raw: bytes, pinned: bool = True) -> dict:
    kc = kc_inspect(raw)
    if (kc.get("format") != "MH_FILESET" or kc.get("darwin") != "27.0.0" or
        kc.get("observed_xnu_tag") != "xnu-13432.1.9" or
        kc.get("cpu_arch") not in ("arm64e", "arm64e.x1") or not kc.get("arm64e")):
        raise ValueError("not actual Darwin27 arm64e xnu-13432.1.9 fileset")
    sha = hashlib.sha256(raw).hexdigest()
    if pinned and sha != EXPECTED_VMA2_SHA256:
        raise ValueError("unrecognized fileset digest: never import as 26A434")
    entries = parse_prelink_xml(raw)
    file_ids = {f["name"] for f in kc["fileset_entries"]}
    by_bundle = {e["CFBundleIdentifier"]: e for e in entries}
    records = []
    for bundle, name in TARGET_PERSONALITIES:
        if bundle not in by_bundle or bundle not in file_ids:
            raise ValueError(f"required fileset bundle missing: {bundle}")
        pers = by_bundle[bundle].get("IOKitPersonalities", {})
        if name not in pers:
            raise ValueError(f"verified KC personality missing: {bundle}/{name}")
        records.append(normalize(by_bundle[bundle], name, pers[name]))
    return {
        "kind": "KC prelink personality extraction, NOT runnable drivers",
        "product_build": "26A434" if pinned else "not verified by this test",
        "darwin": kc["darwin"], "cpu_arch": kc["cpu_arch"],
        "cpu_subtype": kc["cpu_subtype"], "xnu": kc["observed_xnu_tag"],
        "kc_sha256": sha, "fileset_entries": len(file_ids),
        "prelink_bundles": len(by_bundle),
        "target_present": {k: k in by_bundle and k in file_ids for k in TARGET_BUNDLES},
        "personalities": records,
        "shim_contract": {
            "kind": "read-only candidate table",
            "source": "exact decompressed vma2 LC_FILESET_ENTRY + __PRELINK_INFO",
            "driver_binding_allowed": False,
            "hardware_claims_made": False,
            "required_before_native_use": [
                "native arm64e PAC keys, EL1 instruction support and CPU feature ABI",
                "complete chained fixups and bind visibility for linked KC drivers",
                "correct xnu-13432.1.9 OSMetaClass/vtable layouts and KPI",
                "real macOS27 IOKit provider services, not XNU22 stub classes",
                "exclusive hardware ownership, safe MMIO/IOMMU, IRQ and reset",
                "driver probe/start with runtime evidence and platform boot policy",
            ],
        },
    }


def _c_string(value: str | None) -> str:
    if value is None:
        return "NULL"
    if not value or len(value) > 192 or any(not 32 <= ord(c) <= 126 for c in value):
        raise ValueError("unsafe C metadata")
    return json.dumps(value, ensure_ascii=True)


def as_c_catalogue(manifest: dict) -> str:
    """For an explicitly reviewed shim build pipeline to consume as DATA."""
    out = [
        "/* Read-only personality metadata from actual 26A434 vma2 KC.",
        " * Not IOKit registration and NOT a driver ABI/hardware attestation. */",
        '#include "iokit_resolver.h"',
        "static const struct m27_iokit_personality m27_26a434_personalities[] = {",
    ]
    for r in manifest["personalities"]:
        names = ", ".join(_c_string(x) for x in r["name_match"]) or "NULL"
        out += [
            "    {",
            f'      .bundle_id = {_c_string(r["bundle_id"])},',
            f'      .personality = {_c_string(r["personality"])},',
            f'      .io_class = {_c_string(r["io_class"])},',
            f'      .provider_class = {_c_string(r["provider_class"])},',
            f'      .names = {{ {names} }},',
            f'      .names_count = {len(r["name_match"])},',
            f'      .resource_match = {_c_string(r["resource_match"])},',
            f'      .match_category = {_c_string(r["match_category"])},',
            f'      .probe_score = {r["probe_score"]},',
            f'      .property_match_present = {"true" if r["property_match_present"] else "false"},',
            f'      .other_unsupported_selectors = {"true" if r["unsupported_match_keys"] else "false"},',
            "    },"
        ]
    out += [
        "};",
        "static const size_t m27_26a434_personality_count =",
        "    sizeof(m27_26a434_personalities)/sizeof(m27_26a434_personalities[0]);",
    ]
    return "\n".join(out) + "\n"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kc", type=Path, default=ROOT /
                   "research/macos27-26A434/kernel.vma2.macho/"
                   "kernelcache.release.vma2.decompressed")
    p.add_argument("--format", choices=("json", "c"), default="json")
    args = p.parse_args()
    try:
        manifest = extract(_checked_bytes(args.kc), pinned=True)
    except ValueError as exc:
        p.error(str(exc))
    print(as_c_catalogue(manifest) if args.format == "c" else
          json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
