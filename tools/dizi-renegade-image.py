#!/usr/bin/env python3
"""Conditionally package an INDEPENDENTLY REVIEWED Renegade EDK2 FD/wrapper as dizi GKI-v4.

This does not convert an EDK2 .fd into executable AArch64 machine code.
The --wrapper-image must ALREADY be a separately implemented native AArch64
Linux Image whose _entry accepts x0=physical FDT (Android ABL's ARM64 ABI),
reads /chosen/linux,initrd-start/end, finds the exact FD (including any
Android vendor-ramdisk prefix), copies its FV to verified exclusive dizi
physical RAM, completes proper cache/MMU transitions and transfers to its
audited ARM64 EDK2 SEC/PrePi entry. A linked ELF, an FD, a gzipped BootShim+FD
from upstream edk2-msm, or an arbitrary Linux kernel is NOT such a wrapper.

No such wrapper or Silicon/Qualcomm/sm7435 EDK2 platform exists in the
2026-10-21 audited upstream checkout. Absent the full wrapper, independent
binary hash pins AND the exact machine-code review contract, fail closed.
The offline packager can validate layout, hashes and evidence consistency;
it cannot prove the external review, device RAM ownership or a boot result.
Never flashes, invokes fastboot, mounts partitions, or overwrites files.
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
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PAGE = 4096
BOOT_HEADER_SIZE = 1584
MAX_WRAPPER = 2 * 1024 * 1024
MAX_FD = 32 * 1024 * 1024
MAX_BOOT = 36 * 1024 * 1024
MIN_FD = 64 * 1024
RAM_BASE = 0x8C0000000
RAM_SIZE = 0xB0000000
CMDLINE = b"console=null dizi_renegade_fd=1"
SCHEMA = "dizi-sm7435-renegade-edk2-wrapper-audit/1"

# Source-reviewed machine code must be pinned HERE by an explicit future
# source review, separately from user-provided hashes/audit JSON. A self-signed
# JSON claim, a valid Image header and matching CLI --approved-* hashes are
# NOT evidence that a BootShim actually locates/copies/enters EDK2 firmware.
# No SM7435 wrapper or FD has been independently reviewed as of 2026-10-21.
# Review entry schema: {sha256_of_wrapper: {"fd_sha256": <sha256>,
#                                         "fd_base_pa": <hex address>,
#                                         "wrapper_entry_offset": <int>}}.
# Keep EMPTY until a genuine SM7435-compatible binary is audited.
VERIFIED_DIZI_WRAPPERS: dict[str, dict] = {}


class Rejected(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise Rejected(message)


def align(value: int) -> int:
    return (value + PAGE - 1) & -PAGE


def approved_hash(value: str, label: str) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None,
            f"{label}: independent SHA-256 pin required (64 lowercase hex characters)")
    return value


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError as e:
        raise Rejected(f"{label}: no readable regular artifact: {e}") from e
    try:
        size = os.fstat(fd)
        require(stat.S_ISREG(size.st_mode) and 0 < size.st_size <= maximum,
                f"{label}: file must be regular, nonempty and within size budget")
        chunks = []
        left = size.st_size
        while left:
            block = os.read(fd, min(left, 1024 * 1024))
            require(bool(block), f"{label}: truncated read")
            chunks.append(block)
            left -= len(block)
        return b"".join(chunks)
    finally:
        os.close(fd)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_uefi_fd(raw: bytes, *, expected_sha256: str, fd_base: int) -> dict:
    """One complete, checksummed UEFI Firmware Volume at FD offset zero.

    Many real EDK2 builds use other layouts. Reject them until an actual
    SM7435 build supplies a justified parser; do not guess FV offsets.
    """
    approved_hash(expected_sha256, "FD")
    require(sha(raw) == expected_sha256, "FD SHA-256 differs from independent pin")
    size = len(raw)
    require(MIN_FD <= size <= MAX_FD and size % 0x10000 == 0,
            "FD size must be nonempty, 64KiB aligned and within 32MiB")
    require(fd_base % 0x10000 == 0 and RAM_BASE <= fd_base and
            size <= RAM_BASE + RAM_SIZE - fd_base,
            "FD physical load base/size outside dizi candidate high RAM")
    require(raw[:16] == b"\0" * 16 and raw[16:32] != b"\0" * 16,
            "FD lacks expected UEFI firmware volume zero vector/GUID")
    fv_length = struct.unpack_from("<Q", raw, 32)[0]
    header_length = struct.unpack_from("<H", raw, 48)[0]
    require(raw[40:44] == b"_FVH" and raw[54] == 0 and raw[55] == 2,
            "FD missing UEFI _FVH signature or incompatible revision")
    require(fv_length == size and 72 <= header_length <= PAGE and
            header_length % 2 == 0,
            "FD FV length/header bounds mismatch")
    checksum = sum(struct.unpack_from(f"<{header_length // 2}H", raw, 0)) & 0xFFFF
    require(checksum == 0, "FD firmware-volume header checksum mismatch")
    blocks = []
    cursor = 56
    while cursor + 8 <= header_length:
        n, bsize = struct.unpack_from("<II", raw, cursor)
        cursor += 8
        if n == bsize == 0:
            break
        require(n > 0 and bsize >= 0x1000 and bsize % PAGE == 0 and
                n * bsize <= size,
                "FD firmware volume block map invalid")
        blocks.append((n, bsize))
        require(len(blocks) <= 16, "FD firmware block map too long")
    else:
        raise Rejected("FD block map lacks terminator")
    require(blocks and sum(n * block_size for n, block_size in blocks) == size,
            "FD FV block map does not describe exact firmware extent")
    return {"sha256": sha(raw), "bytes": size, "fv_length": fv_length,
            "fv_header_length": header_length, "fv_revision": 2,
            "fd_base_pa": hex(fd_base), "fv_offset": 0, "checksum_valid": True}


def check_arm64_wrapper(raw: bytes, *, expected_sha256: str) -> dict:
    approved_hash(expected_sha256, "wrapper")
    require(sha(raw) == expected_sha256, "wrapper SHA-256 differs from independent pin")
    require(PAGE <= len(raw) <= MAX_WRAPPER and len(raw) % PAGE == 0,
            "wrapper must be a bounded, page-aligned ARM64 Linux Image")
    code0, code1 = struct.unpack_from("<2I", raw, 0)
    offset, image_size, flags = struct.unpack_from("<3Q", raw, 8)
    require(raw[56:60] == b"ARM\x64" and code1 == 0 and
            raw[32:56] == b"\0" * 24 and raw[60:64] == b"\0" * 4,
            "wrapper lacks exact ARM64 Linux Image header")
    require(offset == 0 and image_size == len(raw) and flags == 0xA,
            "wrapper has incorrect Linux Image text_offset/size/flags")
    require(code0 >> 26 == 0b000101, "wrapper code0 must be unconditional ARM64 B")
    entry_offset = (code0 & 0x3FFFFFF) * 4
    require(64 <= entry_offset < len(raw) and entry_offset % 4 == 0,
            "ARM64 Linux Image branch entry offset outside wrapper")
    first = struct.unpack_from("<I", raw, entry_offset)[0]
    require(first not in (0, 0xD65F03C0, 0xD503207F, 0xD4200000, 0xD503201F),
            "wrapper entry is blank, WFE, BRK, NOP or immediate return")
    return {"sha256": sha(raw), "bytes": len(raw), "entry_offset": entry_offset,
            "linux_image_magic": "ARMd", "code0": hex(code0),
            "text_offset": offset, "image_size": image_size,
            "flags": hex(flags)}


def parse_contract(blob: bytes, wrapper_meta: dict, fd_meta: dict,
                   *, reviewed: bool) -> dict:
    require(reviewed, "independent machine-code review gate must be explicit")
    try:
        info = json.loads(blob)
    except (UnicodeDecodeError, ValueError) as exc:
        raise Rejected(f"invalid wrapper audit contract JSON: {exc}") from exc
    require(type(info) is dict, "audit contract must be JSON object")
    expected = {
        "schema": SCHEMA,
        "board": "dizi",
        "soc": "SM7435",
        "linux_entry_abi": "aarch64-linux-image-x0-physical-fdt",
        "fd_transport": "android-gki-v4-ramdisk-fv",
        "fd_image_layout": "one-uefi-firmware-volume-at-offset-0",
        "fd_sha256": fd_meta["sha256"],
        "fd_size": fd_meta["bytes"],
        "fd_base_pa": fd_meta["fd_base_pa"],
        "wrapper_sha256": wrapper_meta["sha256"],
        "wrapper_entry_offset": wrapper_meta["entry_offset"],
        "initrd_vendor_prefix_handling_verified": True,
        "fd_copier_and_uefi_entry_machine_code_reviewed": True,
        "aarch64_cache_and_mmu_transition_reviewed": True,
        "runtime_ram_ownership_verified_out_of_band": True,
    }
    require(set(info) == set(expected) and all(type(info[k]) is type(v) and
            info[k] == v for k, v in expected.items()),
            "contract mismatches pinned wrapper/FD, dizi ABI, or required independent review")
    return info


def verify_v4_bytes(image: bytes, wrapper: bytes, fd: bytes) -> dict:
    require(len(image) <= MAX_BOOT and len(image) >= PAGE and
            image[:8] == b"ANDROID!", "wrong GKI boot-v4 magic/extent")
    kernel_size, ramdisk_size, os_version, header_size = struct.unpack_from("<4I", image, 8)
    header_version = struct.unpack_from("<I", image, 40)[0]
    signature_bytes = struct.unpack_from("<I", image, 1580)[0]
    require((kernel_size, ramdisk_size, os_version, header_size,
             header_version, signature_bytes) ==
            (len(wrapper), len(fd), 0, BOOT_HEADER_SIZE, 4, 0),
            "wrong GKI-v4 sizes/version/header or nonempty signature")
    require(image[24:40] == b"\0" * 16 and
            image[44:1580] == CMDLINE + b"\0" * (1536 - len(CMDLINE)) and
            image[1584:PAGE] == b"\0" * (PAGE - BOOT_HEADER_SIZE),
            "GKI-v4 command line/reserved header corrupted")
    kernel_start, fd_start = PAGE, PAGE + align(len(wrapper))
    require(fd_start + align(len(fd)) == len(image),
            "GKI v4 kernel/ramdisk offsets, size or trailing bytes invalid")
    require(image[kernel_start:kernel_start + len(wrapper)] == wrapper and
            image[fd_start:fd_start + len(fd)] == fd,
            "GKI kernel Image or UEFI FD content differs from inputs")
    require(image[kernel_start + len(wrapper):fd_start] == b"\0" * (
            fd_start - kernel_start - len(wrapper)) and
            image[fd_start + len(fd):] == b"\0" * (align(len(fd)) - len(fd)),
            "nonzero GKI section padding")
    return {"sha256": sha(image), "bytes": len(image), "header_version": 4,
            "header_bytes": BOOT_HEADER_SIZE, "kernel_offset": kernel_start,
            "kernel_bytes": len(wrapper), "kernel_sha256": sha(wrapper),
            "fd_ramdisk_offset": fd_start, "fd_ramdisk_bytes": len(fd),
            "fd_ramdisk_sha256": sha(fd), "signature_bytes": 0}


def build_v4(wrapper: bytes, fd: bytes) -> tuple[bytes, dict]:
    require(PAGE + align(len(wrapper)) + align(len(fd)) <= MAX_BOOT,
            "GKI-v4 size exceeds dizi 36MiB budget")
    header = bytearray(PAGE)
    header[:8] = b"ANDROID!"
    struct.pack_into("<4I", header, 8, len(wrapper), len(fd), 0, BOOT_HEADER_SIZE)
    struct.pack_into("<I", header, 40, 4)
    header[44:44 + len(CMDLINE)] = CMDLINE
    image = (bytes(header) + wrapper + b"\0" * (align(len(wrapper)) - len(wrapper)) +
             fd + b"\0" * (align(len(fd)) - len(fd)))
    return image, verify_v4_bytes(image, wrapper, fd)


def check_destination(output: Path, inputs: tuple[Path, ...]) -> Path:
    sidecar = Path(str(output) + ".review.json")
    require(output.name and not output.name.startswith(".") and
            output.parent.is_dir() and not output.parent.is_symlink(),
            "output directory must already exist, no hidden filename or symlink")
    require(not output.exists() and not output.is_symlink() and
            not sidecar.exists() and not sidecar.is_symlink(),
            "output or review already exists; never overwrite")
    require(output.resolve() not in {p.resolve() for p in inputs} and
            sidecar.resolve() not in {p.resolve() for p in inputs},
            "output collides with an input")
    require(not output.resolve().is_relative_to((ROOT / "research").resolve()),
            "never stage an output among preserved firmware/research artifacts")
    return sidecar


def package(*, fd_path: Path, wrapper_path: Path, contract_path: Path,
            output: Path, approved_fd_sha256: str, approved_wrapper_sha256: str,
            fd_base: int, reviewed: bool) -> dict:
    # All cheap refusal conditions and no-write gates run first.
    inputs = (fd_path, wrapper_path, contract_path)
    sidecar = check_destination(output, inputs)
    require(reviewed, "independently reviewed Linux Image wrapper is required")
    approved_hash(approved_wrapper_sha256, "wrapper")
    approved_hash(approved_fd_sha256, "FD")
    require(approved_wrapper_sha256 in VERIFIED_DIZI_WRAPPERS,
            "no audited dizi EDK2 Linux Image wrapper is allowlisted; "
            "an FD or self-declared ABI contract cannot boot UEFI")
    pinned = VERIFIED_DIZI_WRAPPERS[approved_wrapper_sha256]
    require(pinned == {"fd_sha256": approved_fd_sha256,
                       "fd_base_pa": hex(fd_base),
                       "wrapper_entry_offset": pinned.get("wrapper_entry_offset")},
            "allowlisted wrapper is not approved for this exact FD/hash/PA")
    fd = read_regular(fd_path, MAX_FD, "UEFI FD")
    wrapper = read_regular(wrapper_path, MAX_WRAPPER, "Linux Image wrapper")
    contract = read_regular(contract_path, 16384, "machine-code audit contract")
    fv = check_uefi_fd(fd, expected_sha256=approved_fd_sha256, fd_base=fd_base)
    kern = check_arm64_wrapper(wrapper, expected_sha256=approved_wrapper_sha256)
    proof = parse_contract(contract, kern, fv, reviewed=reviewed)
    require(pinned["wrapper_entry_offset"] == kern["entry_offset"],
            "allowlisted executable entry is not this Linux Image branch target")
    image, image_meta = build_v4(wrapper, fd)
    report = {
        "schema": "dizi-renegade-gki-v4-offline-review/1",
        "device": "POCO Pad dizi", "soc": "SM7435",
        "firmware_volume": fv, "reviewed_linux_image": kern,
        "wrapper_review_contract": proof,
        "boot_v4": image_meta,
        "format_and_hashes_verified": True,
        "external_wrapper_review_claim_not_independently_proven_by_packager": True,
        "physical_fd_ram_exclusivity_verified_by_packager": False,
        "uefi_runtime_execution_verified": False,
        "safe_to_flash": False,
        "device_actions_performed": False,
    }
    with tempfile.TemporaryDirectory(prefix="dizi-edk2-v4-", dir=output.parent) as tmp:
        staged_image = Path(tmp) / "boot.img"
        staged_report = Path(tmp) / "boot.review.json"
        staged_image.write_bytes(image)
        staged_report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        require(verify_v4_bytes(staged_image.read_bytes(), wrapper, fd) == image_meta,
                "staged image failed exact roundtrip validation")
        linked_report = linked_image = False
        try:
            # O_EXCL equivalent via same-filesystem atomic create; don't follow
            # existing symlinks and never replace or delete a preexisting path.
            os.link(staged_report, sidecar, follow_symlinks=False)
            linked_report = True
            os.link(staged_image, output, follow_symlinks=False)
            linked_image = True
        except OSError:
            if linked_image:
                output.unlink()
            if linked_report:
                sidecar.unlink()
            raise
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fd", type=Path, required=True)
    parser.add_argument("--wrapper-image", type=Path, required=True)
    parser.add_argument("--wrapper-audit-contract", type=Path, required=True)
    parser.add_argument("--approved-fd-sha256", required=True)
    parser.add_argument("--approved-wrapper-sha256", required=True)
    parser.add_argument("--fd-base-pa", required=True,
                        help="independently attested dizi exclusive physical FD destination")
    parser.add_argument("--reviewed-wrapper-abi", action="store_true",
                        help="confirm separate human/agent review of actual wrapper FD transfer machine code")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        base = int(args.fd_base_pa, 0)
        require(base >= 0 and base < 1 << 64, "FD base must fit 64-bit PA")
        result = package(fd_path=args.fd, wrapper_path=args.wrapper_image,
                         contract_path=args.wrapper_audit_contract, output=args.output,
                         approved_fd_sha256=args.approved_fd_sha256,
                         approved_wrapper_sha256=args.approved_wrapper_sha256,
                         fd_base=base, reviewed=args.reviewed_wrapper_abi)
    except (Rejected, OSError, ValueError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"output": str(args.output),
                      "review": str(args.output) + ".review.json",
                      "sha256": result["boot_v4"]["sha256"],
                      "bytes": result["boot_v4"]["bytes"],
                      "real_uefi_boot_proven": False}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
