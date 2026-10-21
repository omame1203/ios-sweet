#!/usr/bin/env python3
"""Auditable AArch64 native/GKI-v4 + genuine dizi EDK2 FD OFFLINE staging.

IMPORTANT: this is NOT an UEFI boot image maker. We verify stock dizi's
authentic Linux ARM64 Image, and can independently compile worker-8's
genuine AArch64 DiziNativeEntry.S + linker into a new 4096-byte native Image.
That native entry performs real register checks, then parks with WFE even
when checks pass. DiziGkiHandoff.c is a read-only planner, NOT an x0/FDT-to-SEC
trampoline. An authentic EDK2 FD is firmware *data*, never executable Linux
Image entry code or a grant of secure RAM.

This tool deliberately produces a .NOT-BOOTABLE-STAGE blob (GKI v4 structure)
and a hard-negative audit manifest, NEVER boot.img or a claimed live wrapper.
The separate tools/dizi-renegade-image.py remains the only strict future
release packager and its code-review allowlist MUST remain empty. No fastboot,
partition action, proprietary EFI blobs, signing, device operation, or commit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile

PAGE = 4096
BOOT_V4_HEADER_BYTES = 1584
VENDOR_V4_HEADER_BYTES = 2128
MAX_BOOT_PARTITION = 128 * 1024 * 1024
MAX_VENDOR_PARTITION = 96 * 1024 * 1024
MAX_FD_BYTES = 32 * 1024 * 1024
FD_COLD_20261021_SHA = "8326f9cdfd3db67eb3a924d6ceff15df98256f6aef23e21112fd06b0935497d5"
FD_VERIFIED_20261021_SHA = "7bb217aebee2d79910ea9e9d2bb204cb6375a6d6bcb637fb9e7dd81cf2e78ec8"
PINNED_DIZI_EDK2_FD_SHAS = frozenset((FD_COLD_20261021_SHA,
                                       FD_VERIFIED_20261021_SHA))
STOCK_BOOT_A_SHA = "b599bfbdc0ee336dba7de26e6f3e970e6888a7d839097be954b4b31594846dae"
STOCK_VENDOR_A_SHA = "f053adc7d6f5aaead81f16be16d5275185ebddedb769adbb837bfef435422b08"
STOCK_KERNEL_SHA = "42c827b562da776539da12ef90e7755495b1ebd33fe16d6257e299a0530fb801"
SCHEMA = "dizi-renegade-native-gki4-nonbootable-stage/1"
STAGE_BLOB = "dizi.NONBOOTABLE-STAGE.gki-v4"
STAGE_MANIFEST = "dizi.NONBOOTABLE-STAGE.audit.json"
STAGE_NATIVE_IMAGE = "dizi.NONBOOTABLE-NATIVE.Image"
NATIVE_SOURCES = Path(__file__).resolve().parents[1] / (
    "ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435/DiziBootShim")
NATIVE_SOURCE_SHA_PINS = {
    "DiziNativeEntry.S": "122092cf16737e4030f9da7aced7bc899273b41152085d036df74377d00966aa",
    "DiziNativeEntry.ld": "251ac64c340c8516c2380e22f4f689166aacaf742e7772a54d6cd0ddb47b754a",
    "DiziNativeEntry.h": "f575f6ea43f154a8b3b63ea68d151ed62c3d086b5cf981cef29306684a7043e9",
}
NATIVE_STAGE_IMAGE_SHA = "6b6cdb7a3bead908b6600a0cf8e38bc5aaf19948bfd85e1c5e2c805a54bb34dd"


class Reject(ValueError):
    pass


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise Reject(reason)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def aligned(size: int) -> int:
    return (size + PAGE - 1) & ~(PAGE - 1)


def regular_file(path: Path, cap: int) -> bytes:
    """Don't follow source symlinks, FIFOs, devices or open-ended files."""
    try:
        handle = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise Reject(f"cannot read regular input {path}: {exc}") from exc
    try:
        st = os.fstat(handle)
        need(stat.S_ISREG(st.st_mode) and 0 < st.st_size <= cap,
             f"input is not a bounded regular file: {path}")
        blocks = []
        left = st.st_size
        while left:
            data = os.read(handle, min(left, 1024 * 1024))
            need(bool(data), "input unexpectedly truncated")
            blocks.append(data)
            left -= len(data)
        return b"".join(blocks)
    finally:
        os.close(handle)


def linux_image_header(kernel: bytes) -> dict:
    """Real Linux arm64 Image ABI, incl. optional PE/COFF EFI-stub MZ opcode.

    Image header offset 0x38 has 0x644d5241 (ASCII ARMd), NOT executable
    UEFI SEC. Real stock dizi begins with the AArch64 instruction word that
    embeds 'MZ', followed by unconditional B at offset 4. Do not demand a
    made-up 64-byte wrapper with code0 B / code1 zero.
    """
    need(len(kernel) >= 64 and kernel[56:60] == b"ARM\x64", "not a Linux ARM64 Image")
    code0, code1, text_offset, image_size, flags = struct.unpack_from("<IIQQQ", kernel)
    need(kernel[32:56] == b"\0" * 24, "ARM64 Image reserved fields nonzero")
    need(image_size and image_size <= len(kernel) and (flags & ~0xF) == 0,
         "ARM64 Image size/flags invalid")
    has_efi_stub = (code0 & 0xFFFF) == 0x5A4D
    instruction = code1 if has_efi_stub else code0
    need(instruction >> 26 == 0b000101,
         "ARM64 Image entry lacks architecture-defined unconditional B")
    offset = (instruction & 0x03FFFFFF) << 2
    need(0 < offset < len(kernel), "ARM64 Image startup branch target out of range")
    return {"sha256": sha(kernel), "size": len(kernel), "header_image_size": image_size,
            "text_offset": text_offset, "flags": hex(flags),
            "arm64_magic": "ARMd", "efi_stub_mz": has_efi_stub,
            "initial_branch_at_offset": 4 if has_efi_stub else 0,
            "initial_branch_word": hex(instruction), "branch_target_offset": offset,
            "efi_sec_handoff_implemented": False}


def build_native_entry_image() -> tuple[bytes, dict]:
    """Actually assemble/link worker8's AArch64 first-PC; no fake SEC jump.

    All build products stay in temporary /tmp, never written to the repo.
    Source SHA is just reproducible provenance, not permission to boot.
    """
    asm = NATIVE_SOURCES / "DiziNativeEntry.S"
    ldscript = NATIVE_SOURCES / "DiziNativeEntry.ld"
    header = NATIVE_SOURCES / "DiziNativeEntry.h"
    for path in (asm, ldscript, header):
        need(path.is_file() and not path.is_symlink(),
             f"missing upstream worker8 native source: {path}")
        need(sha(path.read_bytes()) == NATIVE_SOURCE_SHA_PINS[path.name],
             f"native worker8 source diverged from independent exact SHA pin: {path.name}")
    names = ("aarch64-linux-gnu-gcc", "aarch64-linux-gnu-ld",
             "aarch64-linux-gnu-objcopy", "aarch64-linux-gnu-objdump",
             "aarch64-linux-gnu-nm", "aarch64-linux-gnu-readelf")
    for name in names:
        need(shutil.which(name) is not None, f"AArch64 toolchain missing: {name}")

    def call(*args: str) -> str:
        try:
            return subprocess.run(args, capture_output=True, text=True,
                                  check=True, timeout=45).stdout
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise Reject(f"native Image build/audit failure: {exc}") from exc

    with tempfile.TemporaryDirectory(prefix="dizi-native-entry-build-") as d:
        obj = str(Path(d) / "DiziNativeEntry.o")
        elf = str(Path(d) / "DiziNativeEntry.elf")
        image = str(Path(d) / "Image")
        call("aarch64-linux-gnu-gcc", "-c", "-x", "assembler-with-cpp",
             "-nostdlib", "-ffreestanding", "-Wall", "-Wextra", "-Werror",
             "-I", str(NATIVE_SOURCES), str(asm), "-o", obj)
        call("aarch64-linux-gnu-ld", "-nostdlib", "-static",
             "-T", str(ldscript), "-o", elf, obj)
        call("aarch64-linux-gnu-objcopy", "-O", "binary", elf, image)
        raw = Path(image).read_bytes()
        disasm = call("aarch64-linux-gnu-objdump", "-d", "-j", ".text", elf)
        reloc = call("aarch64-linux-gnu-readelf", "-Wr", elf)
        symbols = call("aarch64-linux-gnu-nm", "-n", elf)
    image_head = linux_image_header(raw)
    need(sha(raw) == NATIVE_STAGE_IMAGE_SHA,
         "compiled native Image diverged from exact audited machine-code pin")
    need(len(raw) == PAGE and struct.unpack_from("<IIQQQ", raw) ==
         (0x14000010, 0, 0, PAGE, 0xA) and
         struct.unpack_from("<II", raw, 64) == (0xD53B422E, 0xD5034FDF),
         "unexpected worker8 native entry machine code or header ABI")
    need("dizi_native_first_pc" in disasm and "dizi_native_park" in disasm and
         re.search(r"\bwfe\b", disasm) is not None and
         len(re.findall(r"\bwfe\b", disasm)) == 1,
         "native stage has no verified first-PC terminal park")
    need("There are no relocations in this file" in reloc and
         "0000000000000040 T dizi_native_first_pc" in symbols and
         "0000000000001000 T __dizi_native_image_end" in symbols,
         "native stage has unexpected relocations/entry symbols")
    # WFE end must be the only sink; prohibit a direct/indirect SEC target.
    asm_text = asm.read_text(encoding="utf-8")
    need("b       dizi_native_park" in asm_text and
         "br x16" not in asm_text and "blr " not in asm_text and
         "str x0" not in asm_text and "DiziSecEnterPrePi" not in asm_text,
         "native first-PC source is no longer safely default-parked")
    return raw, {"kind": "worker8-genuine-native-aarch64-register-only",
                 "native_image": image_head,
                 "asm_sha256": sha(asm.read_bytes()),
                 "ldscript_sha256": sha(ldscript.read_bytes()),
                 "header_sha256": sha(header.read_bytes()),
                 "compiler": "aarch64-linux-gnu-gcc",
                 "linker": "aarch64-linux-gnu-ld",
                 "first_pc": 64, "first_pc_daif_read_opcode": "0xd53b422e",
                 "first_pc_daifset_opcode": "0xd5034fdf",
                 "parks_with_wfe_on_every_path": True,
                 "edk2_sec_transfer_permitted": False}


def parse_boot_v4(blob: bytes, *, expected_sha: str = STOCK_BOOT_A_SHA) -> tuple[dict, bytes, bytes]:
    need(sha(blob) == expected_sha, "captured boot_a SHA-256 differs from pinned source")
    need(BOOT_V4_HEADER_BYTES <= len(blob) <= MAX_BOOT_PARTITION and
         blob[:8] == b"ANDROID!", "captured boot magic invalid")
    kernel_bytes, ramdisk_bytes, os_version, header_bytes = struct.unpack_from("<4I", blob, 8)
    version = struct.unpack_from("<I", blob, 40)[0]
    signature_bytes = struct.unpack_from("<I", blob, 1580)[0]
    need(version == 4 and header_bytes == BOOT_V4_HEADER_BYTES and
         blob[24:40] == b"\0" * 16,
         "captured boot must be genuine Android header v4")
    need(1 <= kernel_bytes <= 96 * 1024 * 1024 and
         0 < ramdisk_bytes <= 32 * 1024 * 1024 and
         signature_bytes in (0, 4096), "captured kernel/ramdisk/signature sizes unsupported")
    kstart = PAGE
    rstart = kstart + aligned(kernel_bytes)
    sstart = rstart + aligned(ramdisk_bytes)
    need(sstart + aligned(signature_bytes) <= len(blob), "boot v4 payload exceeds partition")
    need(blob[kstart + kernel_bytes:rstart].count(0) == rstart - kstart - kernel_bytes,
         "nonzero kernel page padding")
    need(blob[rstart + ramdisk_bytes:sstart].count(0) == sstart - rstart - ramdisk_bytes,
         "nonzero ramdisk padding")
    kernel = blob[kstart:kstart + kernel_bytes]
    ramdisk = blob[rstart:rstart + ramdisk_bytes]
    header = linux_image_header(kernel)
    need(header["sha256"] == STOCK_KERNEL_SHA or expected_sha != STOCK_BOOT_A_SHA,
         "captured stock kernel mismatches independent SHA-256 pin")
    return ({"sha256": sha(blob), "size": len(blob), "header_version": version,
             "header_bytes": header_bytes, "page_bytes": PAGE,
             "kernel_bytes": kernel_bytes, "kernel_sha256": sha(kernel),
             "ramdisk_bytes": ramdisk_bytes, "ramdisk_sha256": sha(ramdisk),
             "os_version": os_version, "boot_signature_bytes": signature_bytes,
             "native_linux_image": header}, kernel, ramdisk)


def parse_vendor_v4(blob: bytes, *, expected_sha: str = STOCK_VENDOR_A_SHA) -> dict:
    need(sha(blob) == expected_sha, "captured vendor_boot_a SHA-256 differs from pin")
    need(VENDOR_V4_HEADER_BYTES <= len(blob) <= MAX_VENDOR_PARTITION and
         blob[:8] == b"VNDRBOOT", "not a captured vendor_boot")
    version, page, kernel_pa, ramdisk_pa, ramdisk_bytes = struct.unpack_from("<5I", blob, 8)
    header_size, dtb_bytes = struct.unpack_from("<2I", blob, 2096)
    dtb_pa = struct.unpack_from("<Q", blob, 2104)[0]
    table_bytes, table_entries, table_entry_bytes, bootconfig_bytes = struct.unpack_from("<4I", blob, 2112)
    need(version == 4 and page == PAGE and header_size == VENDOR_V4_HEADER_BYTES,
         "vendor_boot v4 header/page mismatch")
    need(0 < ramdisk_bytes <= 32 * 1024 * 1024 and
         0 < dtb_bytes <= 16 * 1024 * 1024 and
         table_bytes == table_entries * table_entry_bytes and
         table_entries > 0 and table_entry_bytes >= 108 and
         bootconfig_bytes <= PAGE, "vendor_boot v4 table/dtb/ramdisk invalid")
    ramdisk_off = PAGE
    dtb_off = ramdisk_off + aligned(ramdisk_bytes)
    table_off = dtb_off + aligned(dtb_bytes)
    bootconfig_off = table_off + aligned(table_bytes)
    need(bootconfig_off + aligned(bootconfig_bytes) <= len(blob),
         "vendor_boot total extent exceeds partition")
    need(blob[dtb_off:dtb_off + 4] == b"\xd0\x0d\xfe\xed", "vendor FDT magic mismatch")
    return {"sha256": sha(blob), "header_version": version, "page_bytes": page,
            "header_bytes": header_size, "vendor_ramdisk_bytes": ramdisk_bytes,
            "ramdisk_pa": hex(ramdisk_pa), "kernel_pa": hex(kernel_pa),
            "dtb_bytes": dtb_bytes, "dtb_pa": hex(dtb_pa),
            "dtb_sha256": sha(blob[dtb_off:dtb_off + dtb_bytes]),
            "vendor_ramdisk_entries": table_entries, "table_bytes": table_bytes,
            "vendor_bootconfig_bytes": bootconfig_bytes,
            "vendor_ramdisk_merging_or_fd_offset_runtime_verified": False}


def edk2_fd_header(fd: bytes, *, expected_sha: str | None = None) -> dict:
    if expected_sha is None:
        need(sha(fd) in PINNED_DIZI_EDK2_FD_SHAS,
             "EDK2 FD differs from BOTH exact source-backed pinned FV builds")
    else:
        # Caller-specified only for host-level structural fixtures; stage()
        # never passes this and can never add a new self-declared allowlist.
        need(sha(fd) == expected_sha, "EDK2 FD differs from supplied fixture hash")
    need(0x10000 <= len(fd) <= MAX_FD_BYTES and len(fd) % 0x10000 == 0,
         "EDK2 FD must be aligned to 64KiB")
    branch, = struct.unpack_from("<I", fd)
    target = (branch & 0x3FFFFFF) * 4
    need(branch & 0xFC000000 == 0x14000000 and 72 <= target < len(fd),
         "EDK2 GenFv AArch64 SEC branch invalid")
    need(fd[4:16] == bytes(12) and fd[16:32] != bytes(16),
         "EDK2 FV header zero vector/FS GUID invalid")
    fv_len = struct.unpack_from("<Q", fd, 32)[0]
    header_len, = struct.unpack_from("<H", fd, 48)
    need(fd[40:44] == b"_FVH" and fv_len == len(fd) and
         72 <= header_len <= PAGE and not header_len % 2 and fd[55] == 2,
         "genuine FD `_FVH` length/revision/checksum header invalid")
    need(sum(struct.unpack_from(f"<{header_len // 2}H", fd)) & 0xFFFF == 0,
         "EDK2 FV checksum invalid")
    pairs = []
    for offset in range(56, header_len, 8):
        need(offset + 8 <= header_len, "truncated FD block map")
        n, unit = struct.unpack_from("<II", fd, offset)
        if n == unit == 0:
            break
        need(n > 0 and unit >= PAGE and unit % PAGE == 0, "FD block map invalid")
        pairs.append((n, unit))
        need(len(pairs) <= 16, "FD block map too many entries")
    else:
        raise Reject("FD block map missing terminator")
    need(sum(n * unit for n, unit in pairs) == len(fd), "FD map total mismatches FV length")
    return {"sha256": sha(fd), "bytes": len(fd), "fv_length": fv_len,
            "fv_header_length": header_len, "fv_checksum_valid": True,
            "sec_branch_word": hex(branch), "sec_entry_offset": target,
            "sec_source_entry_is_android_linux_image": False,
            "uefi_executable_ownership_verified": False}


def create_stage(kernel: bytes, fd: bytes) -> tuple[bytes, dict]:
    """Real GKI-v4 *file format*, NOT an authenticated native EDK2 loader."""
    linux_image_header(kernel)
    need(fd[:4] != b"ANDROID!", "FD is not a kernel image")
    cmd = b"androidboot.dizi_renegade_stage_only=1"
    need(len(cmd) < 1536, "command line too long")
    header = bytearray(PAGE)
    header[:8] = b"ANDROID!"
    struct.pack_into("<4I", header, 8, len(kernel), len(fd), 0, BOOT_V4_HEADER_BYTES)
    struct.pack_into("<I", header, 40, 4)
    header[44:44 + len(cmd)] = cmd
    # All 16 reserved bytes zero; no boot signature is fabricated or reused.
    struct.pack_into("<I", header, 1580, 0)
    payload = (bytes(header) + kernel + bytes(aligned(len(kernel)) - len(kernel)) +
               fd + bytes(aligned(len(fd)) - len(fd)))
    need(len(payload) <= MAX_BOOT_PARTITION and payload[56:60] != b"ARM\x64",
         "invalid stage partition layout")
    return payload, {"sha256": sha(payload), "bytes": len(payload),
                     "boot_header_version": 4, "boot_header_bytes": BOOT_V4_HEADER_BYTES,
                     "page_bytes": PAGE, "kernel_bytes": len(kernel),
                     "kernel_sha256": sha(kernel), "ramdisk_bytes": len(fd),
                     "ramdisk_fd_sha256": sha(fd), "ramdisk_start": PAGE + aligned(len(kernel)),
                     "boot_signature_bytes": 0, "os_version": 0,
                     "actual_uefi_handoff": False}


def verify_stage(raw: bytes, kernel: bytes, fd: bytes) -> None:
    need(raw[:8] == b"ANDROID!" and len(raw) == PAGE + aligned(len(kernel)) + aligned(len(fd)),
         "stage v4 size/magic invalid")
    need(struct.unpack_from("<4I", raw, 8) ==
         (len(kernel), len(fd), 0, BOOT_V4_HEADER_BYTES) and
         struct.unpack_from("<I", raw, 40)[0] == 4 and
         struct.unpack_from("<I", raw, 1580)[0] == 0,
         "stage v4 fields incorrect")
    kernel_end = PAGE + len(kernel)
    fd_start = PAGE + aligned(len(kernel))
    need(raw[PAGE:kernel_end] == kernel and raw[kernel_end:fd_start] ==
         bytes(fd_start - kernel_end), "native Image payload/padding mismatch")
    fd_end = fd_start + len(fd)
    need(raw[fd_start:fd_end] == fd and raw[fd_end:] == bytes(len(raw) - fd_end),
         "EDK2 FD stage payload/padding mismatch")


def stage(*, boot_path: Path, vendor_path: Path, fd_path: Path,
          directory: Path | None, native_entry: bool = False) -> dict:
    boot_bytes = regular_file(boot_path, MAX_BOOT_PARTITION)
    vendor_bytes = regular_file(vendor_path, MAX_VENDOR_PARTITION)
    fd_bytes = regular_file(fd_path, MAX_FD_BYTES)
    boot, kernel, _ = parse_boot_v4(boot_bytes)
    vendor = parse_vendor_v4(vendor_bytes)
    fv = edk2_fd_header(fd_bytes)
    native = None
    if native_entry:
        kernel, native = build_native_entry_image()
    staged, staged_meta = create_stage(kernel, fd_bytes)
    verify_stage(staged, kernel, fd_bytes)
    manifest = {"schema": SCHEMA, "board": "dizi", "soc": "SM7435",
                "source_boot": boot, "source_vendor_boot": vendor,
                "genuine_uefi_fd": fv, "gki_v4_structural_stage": staged_meta,
                "native_aarch64_image_proven": True,
                "native_image_entry": ("worker8-DiziNativeEntry-first-PC-register-check-WFE"
                                       if native_entry else "original-stock-Linux/Android-not-UEFI"),
                "native_entry_build": native,
                "gki_fd_transport_copier_present": False,
                "runtime_fdt_vendor_ramdisk_fd_offsets_verified": False,
                "bootshim_native_uefi_entry_implemented": False,
                "fd_ram_and_executable_permissions_verified": False,
                "sec_prepi_early_write_ownership_verified": False,
                "android_verified_boot_signature_preserved": False,
                "safe_to_boot": False, "safe_to_flash": False,
                "device_actions_performed": False,
                "reason": "No native Image performs authorized EDK2 FD transfer. "
                          "Worker8's native first-PC parks in WFE by design. "
                          "DiziGkiHandoff.c only returns LAYOUT_UNAUTHORIZED. "
                          "Gunyah/XPU/EL1 PrePi ownership proof is missing."}
    if directory is not None:
        # Destination must be a pre-existing /tmp directory; never let the
        # current working tree, an input, or a symlink become an output root.
        need(directory.is_dir() and not directory.is_symlink(), "stage-dir must exist")
        real = directory.resolve(strict=True)
        need(real.is_relative_to(Path("/tmp")) and real != Path("/tmp"),
             "stage output allowed only in a dedicated /tmp directory")
        need(all(not p.resolve().is_relative_to(real) for p in
                 (boot_path, vendor_path, fd_path)), "stage-dir contains source inputs")
        blob_path = real / STAGE_BLOB
        report_path = real / STAGE_MANIFEST
        native_path = real / STAGE_NATIVE_IMAGE if native_entry else None
        need(not blob_path.exists() and not blob_path.is_symlink() and
             not report_path.exists() and not report_path.is_symlink() and
             (native_path is None or (not native_path.exists() and not native_path.is_symlink())),
             "stage files already exist: refusal rather than overwrite")
        with tempfile.TemporaryDirectory(prefix="dizi-native-v4-", dir=real) as name:
            temp = Path(name)
            image_tmp = temp / "v4.blob"
            report_tmp = temp / "manifest.json"
            image_tmp.write_bytes(staged)
            verify_stage(image_tmp.read_bytes(), kernel, fd_bytes)
            report_tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            native_tmp = temp / "native-aarch64-Image"
            if native_entry:
                native_tmp.write_bytes(kernel)
            linked = []
            try:
                pairs = [(report_tmp, report_path), (image_tmp, blob_path)]
                if native_path is not None:
                    pairs.append((native_tmp, native_path))
                for src, dest in pairs:
                    os.link(src, dest, follow_symlinks=False)
                    linked.append(dest)
            except OSError:
                for dest in linked:
                    dest.unlink(missing_ok=True)
                raise
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--boot-a", type=Path, required=True)
    parser.add_argument("--vendor-boot-a", type=Path, required=True)
    parser.add_argument("--fd", type=Path, required=True)
    parser.add_argument("--stage-only", action="store_true", help="acknowledge NONBOOTABLE stage")
    parser.add_argument("--build-native-entry", action="store_true",
                        help="compile actual worker8 register-only ARM64 Image (parks with WFE)")
    parser.add_argument("--stage-dir", type=Path, help="existing /tmp-only destination; omit for no-write audit")
    args = parser.parse_args(argv)
    try:
        need(args.stage_dir is None or args.stage_only,
             "--stage-dir requires explicit --stage-only; no deployable boot.img output")
        manifest = stage(boot_path=args.boot_a, vendor_path=args.vendor_boot_a,
                         fd_path=args.fd, directory=args.stage_dir,
                         native_entry=args.build_native_entry)
    except (Reject, ValueError, OSError, struct.error) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
