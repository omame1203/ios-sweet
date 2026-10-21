#!/usr/bin/env python3
"""Build a REVIEW-ONLY Android GKI boot v4 image for macOS 27 diagnostics.

CRITICAL: This does NOT boot macOS 27. The kernel field is the DIZI
DIZI_MACOS27_PREFLIGHT shim, whose audited shim_main returns without calling
the old XNU loader. The raw 26A434 ARM64e fileset is inert boot ramdisk DATA,
not a Linux Image, an initramfs/CPIO, or an XNU executable payload.

No fastboot, device/partition access, flash, Apple signature forgery, or jump
to XNU. This packager refuses to write unless --no-execute-review-gate is
explicitly supplied. It does NOT claim the image is safe to boot on hardware.

The generated .review.json is for static review and references the unchanged
Apple BuildManifest hash. Apple signatures/boot policy are NOT verified.
Only one >=80MB output file is created: mkbootimg reads the original KC file
directly; no full-size ramdisk/Apple artifact copy is staged separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ELF = ROOT / "shim/out/mac27-readonly-preflight-isRGNgJc/mac27-preflight-only.elf"
DEFAULT_KC = ROOT / "research/macos27-26A434/kernel.vma2.macho/kernelcache.release.vma2.decompressed"
DEFAULT_MANIFEST = ROOT / "research/macos27-26A434/26A434__MacOS/BuildManifest.plist"
KC_SIZE = 81444864
KC_SHA256 = "ca55ea8c4c86170e870380ae5501b8b43adb2d2d3db28be4531b3040653be203"
MANIFEST_SHA256 = "2585e3bd35a2491773bdf8c40803e0b10aa6ed222a27c790b34d25b5fa6842af"
MAX_IMAGE_BYTES = 100 * 1024 * 1024
MAX_ELF_BYTES = 2 * 1024 * 1024
BOOT_PAGE = 4096
ELF_MAGIC = b"\x7fELF"
MACHO_FILESET = 0xC


class Rejected(ValueError):
    pass


def require(test: bool, reason: str) -> None:
    if not test:
        raise Rejected(reason)


def command(*args: str) -> str:
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Rejected(f"offline tool failed {args[0]}: {exc}") from exc


def regular_file(path: Path, label: str) -> int:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise Rejected(f"cannot open {label} read-only: {exc}") from exc
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise Rejected(f"{label}: must be an offline regular file (never a device)")
    return fd


def file_hash(path: Path, max_bytes: int, label: str) -> tuple[str, int]:
    fd = regular_file(path, label)
    try:
        size = os.fstat(fd).st_size
        require(0 < size <= max_bytes, f"{label}: unsupported/budget-exceeding size")
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest(), size
    finally:
        os.close(fd)


def read_small(path: Path, max_bytes: int, label: str) -> bytes:
    fd = regular_file(path, label)
    try:
        n = os.fstat(fd).st_size
        require(0 < n <= max_bytes, f"{label}: bad file size")
        return os.pread(fd, n, 0)
    finally:
        os.close(fd)


def verify_kc(path: Path) -> dict:
    digest, size = file_hash(path, MAX_IMAGE_BYTES, "macOS 27 KC")
    require(size == KC_SIZE and digest == KC_SHA256,
            "KC is NOT the recorded 26A434 vma2 decompressed MH_FILESET (SHA256/size mismatch)")
    fd = regular_file(path, "macOS 27 KC")
    try:
        h = os.pread(fd, 32, 0)
        require(len(h) == 32, "truncated KC Mach-O header")
        magic, cpu, subtype, kind, count, sizecmds, _, _ = struct.unpack("<8I", h)
        require((magic, cpu, subtype, kind) ==
                (0xFEEDFACF, 0x0100000C, 0xC0000002, MACHO_FILESET),
                "KC is not the recorded ARM64e MH_FILESET")
        require(0 < count < 4096 and 0 < sizecmds <= 2 * 1024 * 1024,
                "KC load command bounds invalid")
    finally:
        os.close(fd)
    return {"sha256": digest, "bytes": size, "format": "MH_FILESET",
            "cpu": "arm64e", "subtype": "0xc0000002", "build": "26A434",
            "apple_signature_verified": False}


def verify_manifest(path: Path) -> dict:
    digest, length = file_hash(path, MAX_IMAGE_BYTES, "BuildManifest")
    require(digest == MANIFEST_SHA256, "BuildManifest differs from recorded 26A434 provenance")
    return {"sha256": digest, "bytes": length, "cryptographic_trust_verified": False}


def elf_symbol_table(elf: Path) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line in command("aarch64-linux-gnu-nm", "-n", str(elf)).splitlines():
        tokens = line.split()
        if len(tokens) == 3 and re.fullmatch(r"[0-9a-fA-F]+", tokens[0]):
            symbols[tokens[2]] = int(tokens[0], 16)
    return symbols


def check_no_jump(elf: Path, symbols: dict[str, int], *, pac_register_diagnostic: bool = False) -> None:
    assembly = command("aarch64-linux-gnu-objdump", "-d", "--disassemble=shim_main", str(elf))
    start = command("aarch64-linux-gnu-objdump", "-d", "--disassemble=_start", str(elf))
    required = {"bootlog_init", "bootlog_puts", "con_clear", "con_hex", "con_hex2",
                "con_str", "mac27_dizi_probe_dtb", "bootlog_sync"}
    if pac_register_diagnostic:
        require(all(name in symbols for name in (
            "mac27_pac_recovery_sample", "mac27_pac_recovery_exc_handler",
            "mac27_pac_recovery_read_isar1", "mac27_pac_recovery_read_isar2")),
            "PAC register diagnostic requires enabled reader and exception handler")
        required.add("mac27_pac_recovery_sample")
        handler = command("aarch64-linux-gnu-objdump", "-d", "--disassemble=exc_handler", str(elf))
        require(re.search(r"\bbl\s+[0-9a-f]+\s+<mac27_pac_recovery_exc_handler>", handler) is not None,
                "PAC reader exception hook is not wired")
    external_branches = []
    for line in assembly.splitlines():
        match = re.search(r"^\s*[0-9a-f]+:\s+[0-9a-f]+\s+(bl|b)\s+([0-9a-f]+)\s+<([^>]+)>", line)
        if match:
            dest = match.group(3).split("+", 1)[0]
            if dest != "shim_main":
                external_branches.append(dest)
    require("mac27_dizi_probe_dtb" in external_branches and
            "bootlog_sync" in external_branches,
            "shim_main does not contain both KC inspection and return-to-park path")
    require(set(external_branches).issubset(required),
            f"shim_main contains unknown branch/call targets: {set(external_branches) - required}")
    require(not re.search(r"^\s*[0-9a-f]+:\s+[0-9a-f]+\s+(br|blr)\b", assembly, re.M),
            "shim_main contains an unchecked indirect jump")
    require(re.search(r"\bbl\s+[0-9a-f]+\s+<shim_main>", start) is not None and
            re.search(r"\bwfe\b", start) is not None,
            "_start is not the expected shim_main then WFE parking loop")


def verify_elf(elf: Path, target_image: Path, *, pac_register_diagnostic: bool = False) -> dict:
    raw = read_small(elf, MAX_ELF_BYTES, "preflight-only ELF")
    require(raw[:5] == ELF_MAGIC + b"\x02" and raw[5] == 1,
            "preflight ELF must be ELF64 little endian")
    require(struct.unpack_from("<H", raw, 18)[0] == 183 and
            struct.unpack_from("<Q", raw, 24)[0] == 0,
            "preflight ELF must be AArch64 linked at address 0")
    symbols = elf_symbol_table(elf)
    require(symbols.get("_head") == 0 and 0 < symbols.get("_start", 0) < MAX_ELF_BYTES,
            "missing linked Linux header / entry")
    require("mac27_dizi_probe_dtb" in symbols and "mac27_kc_inspect_fixups" in symbols,
            "macOS27 diagnostics are not linked")
    end = symbols.get("_end", 0)
    require(0 < end <= MAX_ELF_BYTES and end % BOOT_PAGE == 0,
            "_end missing, misaligned or exceeds shim size budget")
    check_no_jump(elf, symbols, pac_register_diagnostic=pac_register_diagnostic)
    command("aarch64-linux-gnu-objcopy", "-O", "binary", str(elf), str(target_image))
    with target_image.open("r+b") as stream:
        header = stream.read(64)
        require(len(header) == 64, "Linux Image header is incomplete")
        branch, _code1, offset, imgsize, flags = struct.unpack_from("<IIQQQ", header)
        require(header[56:60] == b"ARM\x64", "invalid ARM64 Linux Image magic")
        require(branch & 0xFC000000 == 0x14000000 and (branch & 0x3FFFFFF) * 4 == symbols["_start"],
                "Linux Image code0 does not branch to _start")
        require(offset == 0 and imgsize == end and flags == 0xA,
                "unexpected AArch64 Image text_offset/image_size/page-size/placement flags")
        require(header[4:8] == b"\x00" * 4 and header[32:56] == b"\x00" * 24 and
                header[60:64] == b"\x00" * 4,
                "unexpected executable header fields")
        current = stream.seek(0, os.SEEK_END)
        require(current <= end, "objcopy produced a file bigger than linked memory image")
        stream.truncate(end)
    return {"elf_sha256": hashlib.sha256(raw).hexdigest(),
            "image_sha256": file_hash(target_image, MAX_ELF_BYTES, "shim Image")[0],
            "image_size": end, "entry_offset": symbols["_start"],
            "linux_image_flags": "0x000000000000000a",
            "header_verified": True, "no_xnu_jump_verified_static_disassembly": True,
            "el1_diagnostics_may_access_hardware": True,
            "pac_register_diagnostic": pac_register_diagnostic}


def align(value: int, page: int = BOOT_PAGE) -> int:
    return ((value + page - 1) // page) * page


def verify_v4(image: Path, image_bytes: int, image_sha: str,
              kc_bytes: int, kc_sha: str) -> dict:
    fd = regular_file(image, "packaged boot.img")
    try:
        total = os.fstat(fd).st_size
        require(0 < total <= MAX_IMAGE_BYTES, "GKI v4 image exceeds strict 100MiB budget")
        header = os.pread(fd, BOOT_PAGE, 0)
        require(len(header) == BOOT_PAGE and header[:8] == b"ANDROID!",
                "mkbootimg output lacks ANDROID! magic")
        ksize, rsize, _osversion, hsize = struct.unpack_from("<4I", header, 8)
        version = struct.unpack_from("<I", header, 40)[0]
        require(version == 4 and hsize == 1584 and ksize == image_bytes and rsize == kc_bytes,
                "GKI boot v4 sections do not match expected sizes")
        require(b"mac27_diag_nojump=1" in header[44:1580],
                "missing explicit diagnostic-only cmdline marker")
        require(struct.unpack_from("<I", header, 1580)[0] == 0,
                "GKI boot signature must remain absent; do not impersonate an OEM image")
        koff = BOOT_PAGE
        roff = koff + align(ksize)
        require(total == roff + align(rsize),
                "unsupported GKI v4 layout or nonempty appended signature")
        def section_digest(offset: int, length: int) -> str:
            d = hashlib.sha256()
            n = 0
            while n < length:
                chunk = os.pread(fd, min(1024 * 1024, length - n), offset + n)
                require(bool(chunk), "truncated boot image section")
                d.update(chunk)
                n += len(chunk)
            return d.hexdigest()
        require(section_digest(koff, ksize) == image_sha, "packaged Image changed unexpectedly")
        require(section_digest(roff, rsize) == kc_sha, "packaged inert KC bytes differ from source")
        return {"sha256": section_digest(0, total), "bytes": total,
                "header_version": 4, "kernel_offset": koff, "kernel_size": ksize,
                "ramdisk_offset": roff, "ramdisk_size": rsize,
                "ramdisk_kind": "RAW_KC_INERT_BYTES_NOT_CPIO",
                "ramdisk_executable": False, "gki_signature_bytes": 0}
    finally:
        os.close(fd)


def package(elf: Path, kc: Path, manifest: Path, output: Path,
            *, enabled: bool, pac_register_diagnostic: bool = False) -> dict:
    require(enabled, "refusing to build: supply --no-execute-review-gate explicitly")
    require(not output.is_symlink() and not output.exists(),
            "output already exists; no overwrites allowed")
    report = Path(str(output) + ".review.json")
    require(not report.is_symlink() and not report.exists(),
            "review manifest already exists; no overwrites allowed")
    require(output.parent.is_dir() and not output.parent.is_symlink(),
            "output parent must already exist (no directory creation)")
    require(not output.name.startswith("."), "hidden image output is prohibited")
    require(elf.resolve() != output.resolve() and kc.resolve() != output.resolve(),
            "must not overwrite any input")
    require(not output.parent.resolve().is_relative_to((ROOT / "research").resolve()),
            "do not place generated images among retained research/Apple artifacts")

    kc_meta = verify_kc(kc)
    manifest_meta = verify_manifest(manifest)
    require(KC_SIZE + 2 * BOOT_PAGE + MAX_ELF_BYTES < MAX_IMAGE_BYTES,
            "input exceeds 100MiB image budget before packaging")
    with tempfile.TemporaryDirectory(prefix="mac27-nojump-", dir=output.parent) as tmp:
        work = Path(tmp)
        shim_image = work / "Linux-Image"
        shim_meta = verify_elf(elf, shim_image, pac_register_diagnostic=pac_register_diagnostic)
        staged = work / "boot.img"
        command("mkbootimg", "--header_version", "4", "--kernel", str(shim_image),
                "--ramdisk", str(kc), "--os_version", "12.0.0",
                "--os_patch_level", "2025-09",
                "--cmdline", "console=null mac27_diag_nojump=1", "-o", str(staged))
        image_meta = verify_v4(staged, shim_meta["image_size"],
                               shim_meta["image_sha256"], kc_meta["bytes"], kc_meta["sha256"])
        result = {
            "schema": "macos27-noexecute-gki-v4-review/1",
            "purpose": "OFFLINE_REVIEW_ONLY_NOT_AN_AUTHORIZED_DEVICE_BOOT",
            "product": "POCO Pad dizi", "apple_build": "26A434",
            "arm64_linux_image": shim_meta,
            "kernel_collection_inert_data": kc_meta,
            "apple_build_manifest": manifest_meta,
            "android_gki_boot_v4": image_meta,
            "no_xnu_jump": True,
            "no_flash_or_device_operations": True,
            "native_macos27_boot_demonstrated": False,
            "apple_boot_trust_verified": False,
            "remaining_blockers": [
                "ARM64e PAC and fixups incompatible/unproven on dizi CPU",
                "Apple Image4/SSV/LocalPolicy/SEP trust not established",
                "APFS root and Preboot/Recovery VolumeGroup not mounted/verified",
                "No native XNU macOS27 entry or runtime driver chain",
                "EL1 diagnostics still have hardware side effects; do not boot without separate review",
            ],
        }
        review = work / "boot.img.review.json"
        review.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        # Hard links atomically create final paths without overwriting and
        # without making a second 81MB copy. If any step fails, erase only
        # our newly linked names, never preexisting files or source artifacts.
        linked_review = False
        linked_image = False
        try:
            os.link(review, report, follow_symlinks=False)
            linked_review = True
            os.link(staged, output, follow_symlinks=False)
            linked_image = True
        except OSError:
            if linked_image:
                output.unlink()
            if linked_review:
                report.unlink()
            raise
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-elf", type=Path, default=DEFAULT_ELF)
    parser.add_argument("--kc", type=Path, default=DEFAULT_KC)
    parser.add_argument("--build-manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--no-execute-review-gate", action="store_true",
                        help="acknowledge the output is inert, not a native macOS boot image")
    parser.add_argument("--pac-register-diagnostic", action="store_true",
                        help="allow the separately enabled EL1 CPU ID reader; XNU entry stays disabled")
    args = parser.parse_args(argv)
    try:
        result = package(args.preflight_elf, args.kc, args.build_manifest,
                         args.output, enabled=args.no_execute_review_gate,
                         pac_register_diagnostic=args.pac_register_diagnostic)
    except (Rejected, OSError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"output": str(args.output),
                      "review": str(args.output) + ".review.json",
                      "bytes": result["android_gki_boot_v4"]["bytes"],
                      "sha256": result["android_gki_boot_v4"]["sha256"],
                      "native_macos27_boot_demonstrated": False}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
