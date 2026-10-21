#!/usr/bin/env python3
"""Auditable read-only macOS 27 XNU source selector and SWEET port inventory.

Only Apple's distribution-macOS release.json may choose a release's XNU tag.
Never infer an XNU tag from a marketing version, a Darwin version, or 26A/26B.
Even a release manifest is NOT an exact build-to-XNU or boot ABI attestation.

Authoritative references (verified 2026-10-21):
  macOS 27.0.1 (26A434), 2026-09-28:
    https://developer.apple.com/news/releases/?id=09282026c
  macOS 27.2 RC (26B118), 2026-10-19:
    https://developer.apple.com/news/releases/?id=10192026c
  Xcode SDK availability:
    https://developer.apple.com/xcode/system-requirements
  Apple OSS manifests:
    https://github.com/apple-oss-distributions/distribution-macOS
  Apple XNU tags:
    https://github.com/apple-oss-distributions/xnu
  blacktop builder:
    https://github.com/blacktop/darwin-xnu-build

Checks consume tiny public source metadata and local patch/workflow text ONLY.
No OS image, Xcode, SDK, KDK, firmware, git checkout, patch application,
build, device access or repository modification is performed.
"""
from __future__ import annotations

import argparse
import json
import plistlib
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

BUILD_TARGETS = {
    '27.0.1': {
        'build': '26A434', 'release_train': '27.0',
        'apple_release': '2026-09-28',
        'evidence': 'https://developer.apple.com/news/releases/?id=09282026c',
    },
    '27.2': {
        'build': '26B118', 'release_train': '27.2',
        'apple_release': '2026-10-19', 'prerelease': 'RC',
        'evidence': 'https://developer.apple.com/news/releases/?id=10192026c',
    },
}
APPLE_RELEASE = 'https://raw.githubusercontent.com/apple-oss-distributions/distribution-macOS/macos-{branch}/release.json'
APPLE_XNU = 'https://github.com/apple-oss-distributions/xnu.git'
BLACKTOP_SCRIPT = 'https://raw.githubusercontent.com/blacktop/darwin-xnu-build/main/build.sh'
APPLE_SDK_INFO = 'https://developer.apple.com/xcode/system-requirements'
XNU_TAG = re.compile(r'xnu-[0-9]+(?:\.[0-9]+){1,4}\Z')
GIT_REF = re.compile(r'([0-9a-f]{40})\s+refs/tags/(xnu-[^\s^]+)(\^\{\})?\Z')
PATCH_PATH = re.compile(r'^diff --git a/([^\s]+) b/([^\s]+)$', re.M)
UNIFIED_PATH = re.compile(
    r'^--- (?:a/([^\s]+)|(/dev/null))\s*\n'
    r'\+\+\+ (?:b/([^\s]+)|(/dev/null))\s*$', re.M)
MAX_MANIFEST_BYTES = 2_000_000


def release_url(target: str) -> str:
    version = BUILD_TARGETS[target]['release_train']
    return APPLE_RELEASE.format(branch=version.replace('.', ''))


def parse_release(raw: bytes, target: str) -> dict[str, Any]:
    """Require authentic *shape* of Apple metadata; cannot verify its origin.

    A caller-provided manifest is never network-authenticated by this code.
    Attestation requires a separately verified secure source/snapshot.
    """
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError('oversize Apple release manifest')
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError('invalid release JSON') from exc
    if not isinstance(document, dict):
        raise ValueError('release manifest must be an object')
    version = BUILD_TARGETS[target]['release_train']
    if document.get('release') != 'macOS ' + version or document.get('major_release') != 'macOS 27':
        raise ValueError('release train or major_release mismatch')
    projects = document.get('projects')
    if not isinstance(projects, list):
        raise ValueError('manifest projects array missing')
    xnu = [p.get('tag') for p in projects if isinstance(p, dict) and p.get('project') == 'xnu']
    if len(xnu) != 1 or not isinstance(xnu[0], str) or not XNU_TAG.fullmatch(xnu[0]):
        raise ValueError('exactly one canonical xnu tag required')
    # Upstream macOS26.5 maps to xnu-12377.121.6; never hardcode a guessed
    # macOS27 generation or confuse any 26.x tag with a 27.x release.
    if int(xnu[0].split('-')[1].split('.')[0]) <= 12377:
        raise ValueError('xnu tag no newer than verified macOS26.5 baseline')
    return {'tag': xnu[0], 'release': document['release'],
            'major_release': document['major_release'],
            'build_specific_proven': False}


def parse_xnu_refs(raw: str) -> dict[str, str]:
    """Accept git ls-remote --tags, preferring peeled commit of annotated tags."""
    direct: dict[str, str] = {}
    peeled: dict[str, str] = {}
    for line in raw.splitlines():
        match = GIT_REF.fullmatch(line.strip())
        if match:
            sha, tag, suffix = match.groups()
            if XNU_TAG.fullmatch(tag):
                (peeled if suffix else direct)[tag] = sha
    return {**direct, **peeled}


def script_supports_version(source: str, version: str) -> bool:
    """Check actual shell 'case' branch; a README support row is not enough."""
    case_block = re.search(r'case\s+\$\{?MACOS_VERSION\}?\s+in\s*(.*?)\n\s*esac',
                           source, re.S)
    if not case_block:
        return False
    explicit = re.escape(version)
    return bool(re.search(r"(?:['\"]" + explicit + r"['\"]|\b" + explicit +
                          r"\b)\s*\)", case_block.group(1)))


def check_sdk(sdk_path: Path | None, target: str) -> dict[str, Any]:
    """Check actual local SDKSettings.plist, NOT an unverified CLI label."""
    info: dict[str, Any] = {
        'required': BUILD_TARGETS[target]['release_train'],
        'official_available': True, 'installed_verified': False,
        'evidence': APPLE_SDK_INFO,
        'note': 'Xcode 27 has macOS 27 SDK; Xcode 27.2 RC has macOS 27.2 SDK',
    }
    if sdk_path is None:
        return info
    settings = sdk_path / 'SDKSettings.plist'
    if not settings.is_file():
        info['error'] = 'SDKSettings.plist not found'
        return info
    try:
        data = plistlib.loads(settings.read_bytes())
        version = data.get('Version')
        if not isinstance(version, str):
            raise ValueError('SDK Version absent')
        info['found'] = version
        info['path'] = str(sdk_path)
        required = tuple(int(v) for v in info['required'].split('.'))
        parsed = re.fullmatch(r'([0-9]+)\.([0-9]+)(?:\.([0-9]+))?', version)
        info['installed_verified'] = bool(parsed and
            (int(parsed[1]), int(parsed[2])) >= (required[0], required[1]) and
            int(parsed[1]) == 27)
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
        info['error'] = 'SDKSettings.plist is malformed'
    return info


def patch_inventory(patchdir: Path) -> dict[str, Any]:
    """Enumerate exact paths touched by existing SWEET patches for rebase."""
    all_patches = sorted(patchdir.glob('*.patch')) if patchdir.is_dir() else []
    categories: dict[str, set[str]] = {
        'arm64_boot_mmu_pmap': set(),
        'platform_expert_machine': set(),
        'kernel_configs_exports': set(),
        'bsd_vfs_drivers': set(),
        'iokit_libkern': set(),
        'other': set(),
    }
    paths: dict[str, set[str]] = {k: set() for k in categories}
    malformed: list[str] = []
    non_utf8: list[str] = []
    for patch in all_patches:
        try:
            content = patch.read_bytes()
        except OSError:
            malformed.append(patch.name)
            continue
        try:
            raw = content.decode('utf-8')
        except UnicodeDecodeError:
            non_utf8.append(patch.name)
            # Git patch header tokens are ASCII. Preserve those even if a
            # vendor-bundled file body includes non-UTF8 bytes.
            raw = content.decode('utf-8', errors='replace')
        touched = set(PATCH_PATH.findall(raw))
        for a, deleted, b, created in UNIFIED_PATH.findall(raw):
            if deleted and b:
                touched.add((b, b))
            elif created and a:
                touched.add((a, a))
            elif a and b:
                touched.add((a, b))
        if not touched or any(before != after for before, after in touched):
            malformed.append(patch.name)
        for a, b in touched:
            if a != b:
                continue  # moving paths need manual analysis
            if a.startswith(('osfmk/arm/', 'osfmk/arm64/')):
                key = 'arm64_boot_mmu_pmap'
            elif a.startswith(('pexpert/', 'osfmk/machine/')):
                key = 'platform_expert_machine'
            elif a.startswith(('config/', 'osfmk/conf/')):
                key = 'kernel_configs_exports'
            elif a.startswith(('bsd/', 'hfs/')):
                key = 'bsd_vfs_drivers'
            elif a.startswith(('iokit/', 'libkern/')):
                key = 'iokit_libkern'
            else:
                key = 'other'
            categories[key].add(patch.name)
            paths[key].add(a)
    return {
        'total_patch_files': len(all_patches), 'malformed_or_renames': malformed,
        'non_utf8_patch_files': non_utf8,
        'categories': {k: {'patch_count': len(v), 'patches': sorted(v),
                           'touched_paths': sorted(paths[k])}
                       for k, v in categories.items()},
        'rebase_required': bool(all_patches),
        'apply_to_new_xnu_verified': False,
    }


def workflow_inventory(repo: Path) -> dict[str, Any]:
    path = repo / '.github/workflows/xnu.yml'
    if not path.is_file():
        return {'found': False, 'ready_for_macos27': False}
    raw = path.read_text(encoding='utf-8')
    pinned = re.search(r'^\s*DXB_SHA:\s*([a-f0-9]{40})\s*$', raw, re.M)
    version = re.search(r"^\s*MACOS_VERSION:\s*.*?'([0-9.]+)'", raw, re.M)
    data: dict[str, Any] = {
        'found': True,
        'pinned_blacktop_commit': pinned.group(1) if pinned else None,
        'default_macos_version': version.group(1) if version else None,
        'macos14_runner': 'runs-on: macos-14' in raw,
        'xcode15_iig_assumption': 'Xcode 15' in raw or 'Xcode 16' in raw,
        'copies_all_patch_files': 'cp xnu/patches/*.patch' in raw,
        'uses_sweet_machine': 'SWEET' in raw,
        'ready_for_macos27': False,
    }
    data['changes_required'] = [
        'select verified Apple macOS27 release manifest and XNU tag',
        'update blacktop version case/release URL plus versioned patch directory',
        'supply Xcode27 toolchain + macOS27 SDK and matching kernel SDK/KDK headers/libraries',
        'revalidate iig/MIG/SDK, kernel symbol exports, XNU config targets',
        'rebase every applied SWEET patch on actual selected XNU; compile and link',
        'verify macOS27 userland/root, boot ABI and userspace/kernel feature compatibility',
    ]
    return data


def get_small_https(url: str) -> bytes:
    # Immutable allowlist; never fetch from user-controlled URLs.
    allowed = (APPLE_RELEASE.format(branch='270'),
               APPLE_RELEASE.format(branch='272'), BLACKTOP_SCRIPT)
    if url not in allowed:
        raise ValueError('URL outside tiny source-metadata allowlist')
    with urllib.request.urlopen(url, timeout=8) as response:
        body = response.read(MAX_MANIFEST_BYTES + 1)
    if len(body) > MAX_MANIFEST_BYTES:
        raise ValueError('source metadata too large')
    return body


def collect(repo: Path, target: str, release_bytes: bytes | None,
            xnu_refs_text: str | None, blacktop_source: str | None,
            sdk_path: Path | None, observations: dict[str, str] | None = None) -> dict[str, Any]:
    build = BUILD_TARGETS[target]
    report: dict[str, Any] = {
        'target': {'version': target, **build},
        'provenance': {'release_manifest': release_url(target),
                       'xnu_tags': APPLE_XNU,
                       'builder': BLACKTOP_SCRIPT,
                       'sdk': APPLE_SDK_INFO},
        'source': {'release_manifest_available': release_bytes is not None,
                   'verified_xnu_tag': None,
                   'build_specific_source_proven': False},
        'builder': {'target_case_supported': False, 'source_available': blacktop_source is not None},
        'sdk': check_sdk(sdk_path, target),
        'workflow': workflow_inventory(repo),
        'patches': patch_inventory(repo / 'xnu/patches'),
        'probe_notes': observations or {},
    }
    blockers = []
    tag = None
    if release_bytes is None:
        blockers.append('Apple macOS27 release.json unavailable; exact XNU tag unverified')
    else:
        try:
            manifest = parse_release(release_bytes, target)
            tag = manifest['tag']
            report['source']['release_manifest_tag'] = tag
        except ValueError as e:
            blockers.append(f'Apple release.json invalid: {e}')
    if tag is not None:
        refs = parse_xnu_refs(xnu_refs_text or '')
        if tag in refs:
            report['source']['verified_xnu_tag'] = tag
            report['source']['upstream_peeled_sha'] = refs[tag]
            report['source']['tag_in_upstream_snapshot'] = True
        else:
            blockers.append('release-selected XNU tag missing from upstream tag evidence')
        # The release manifest maps macOS minor releases, not 26A434 / 26B118.
        blockers.append('no authenticated build-ID to XNU-source equivalence for this exact build')
    if blacktop_source is None:
        blockers.append('blacktop build.sh version support not inspected')
    else:
        is_supported = script_supports_version(blacktop_source, build['release_train'])
        report['builder']['target_case_supported'] = is_supported
        if not is_supported:
            blockers.append('blacktop build.sh has no matching macOS27 version case')
    if not report['sdk']['installed_verified']:
        blockers.append('matching macOS27 SDK not verified on local build host')
    if not report['workflow']['ready_for_macos27']:
        blockers.append('existing macos-14 / Xcode15 / macOS13.5 SWEET workflow requires migration')
    if report['patches']['rebase_required']:
        blockers.append('SWEET XNU patch series must be rebased and linked against selected XNU')
    report['blockers'] = blockers
    report['ready_for_macos27_kernel_build'] = not blockers
    report['selected_xnu_tag'] = tag if report['source']['verified_xnu_tag'] else None
    report['device_runtime_verified'] = False
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=tuple(BUILD_TARGETS), default='27.2')
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--release-json', type=Path, help='saved Apple release manifest')
    parser.add_argument('--xnu-refs', type=Path, help='saved git ls-remote --tags output')
    parser.add_argument('--blacktop-script', type=Path, help='saved upstream build.sh')
    parser.add_argument('--sdk', type=Path, help='installed macOS SDK directory')
    parser.add_argument('--probe-public', action='store_true', help='read tiny public metadata only')
    parser.add_argument('--strict', action='store_true', help='exit 2 when migration is blocked')
    args = parser.parse_args(argv)

    notes: dict[str, str] = {}
    release = args.release_json.read_bytes() if args.release_json else None
    refs = args.xnu_refs.read_text() if args.xnu_refs else None
    script = args.blacktop_script.read_text() if args.blacktop_script else None
    if args.probe_public:
        if release is None:
            try:
                release = get_small_https(release_url(args.target))
                notes['apple_release'] = 'HTTP 200; validate content before use'
            except (OSError, ValueError, urllib.error.URLError) as e:
                notes['apple_release'] = f'unavailable ({type(e).__name__})'
        if script is None:
            try:
                script = get_small_https(BLACKTOP_SCRIPT).decode('utf-8')
                notes['blacktop'] = 'live build.sh inspected'
            except (OSError, ValueError, urllib.error.URLError, UnicodeDecodeError) as e:
                notes['blacktop'] = f'unavailable ({type(e).__name__})'
        if refs is None:
            try:
                proc = subprocess.run(['git', 'ls-remote', '--tags', APPLE_XNU],
                                      capture_output=True, text=True, timeout=15, check=True)
                refs = proc.stdout
                notes['xnu_refs'] = 'git ls-remote --tags (no checkout)'
            except (OSError, subprocess.SubprocessError) as e:
                notes['xnu_refs'] = f'unavailable ({type(e).__name__})'
    report = collect(args.repo, args.target, release, refs, script, args.sdk, notes)
    print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
    return 2 if args.strict and not report['ready_for_macos27_kernel_build'] else 0


if __name__ == '__main__':
    sys.exit(main())
