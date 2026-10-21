#!/usr/bin/env python3
"""OFFLINE GKI-v4 packager for a separately reviewed macOS 27 entry/BRK ELF.

Not an XNU bootloader and not a native macOS boot. A specially built AArch64
shim is required: DIZI_MACOS27_XNU_ENTRY_EXPERIMENT=1 and the precise, auditable
trampoline ABI below. The unchanged Apple 26A434 VMAPPLE MH_FILESET is DATA
in boot ramdisk, not a Linux kernel, a signed image or executable initramfs.

ABI (matches shim/macos27_entry_experiment.{c,S}, independently reviewed):
  shim_main -> mac27_entry_experiment_run -> trampoline.
  exc_handler -> mac27_entry_experiment_exc_handler before panic.
  run() checks source SHA-256 and ownership, stages an independent writable
  KC copy, writes BRK #0x4e27 to the genuine B target in that copy, performs
  D-cache/I-cache maintenance, and arms a one-shot EL1 synchronous handler.
  trampoline: stp x29,x30; mov x29,sp; br x1; resume: mov w0,#1;
              ldp x29,x30; ret.
  x1 is the verified original B entry in private staged executable memory.
  x0 is 0 or independently verified 1152-byte boot_args. The original Apple
  B reaches our BRK and exception recovery returns to resume (not to XNU).
  This script CANNOT prove external FDT/RAM ownership or EL1 trap routing;
  pin the independently reviewed ELF SHA-256 before ever packaging.

This script only verifies structural features and exact bytes, not a safe
runtime memory mapping, executable permissions, PAC or hardware feasibility.
No live device commands, no writes to KC, no data/boot image generation unless
--emit-reviewed-image AND --entry-experiment-opt-in AND ELF SHA pin are provided.
Do not use an ELF with a fake validator or self-provided unreviewed SHA pin.
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
DEFAULT_KC = ROOT / "research/macos27-26A434/kernel.vma2.macho/kernelcache.release.vma2.decompressed"
DEFAULT_MANIFEST = ROOT / "research/macos27-26A434/26A434__MacOS/BuildManifest.plist"
KC_SHA256 = "ca55ea8c4c86170e870380ae5501b8b43adb2d2d3db28be4531b3040653be203"
KC_BYTES = 81444864
MANIFEST_SHA256 = "2585e3bd35a2491773bdf8c40803e0b10aa6ed222a27c790b34d25b5fa6842af"
EXPECTED_ENTRY_VA = 0xFFFFFE0009EB4480
EXPECTED_TARGET_VA = 0xFFFFFE0009EB8070
EXPECTED_ENTRY_OFFSET = 0x02EB0480
EXPECTED_TARGET_OFFSET = 0x02EB4070
EXPECTED_ENTRY_BRANCH = 0x14000EFC
EXPECTED_TARGET_ORIGINAL = 0xD510109F  # msr oslar_el1,xzr, NOT BRK
BRK_IMM = 0x4E27
BRK_OPCODE = 0xD4200000 | BRK_IMM << 5
PAGE = 4096
MAX_ELF = 2 * 1024 * 1024
MAX_BOOT_IMAGE = 100 * 1024 * 1024
ENTRY_ARCH = 183
ELF_LOAD = 1
SYMS = ("_head", "_start", "_end", "shim_main", "exc_handler", "vectors",
        "mac27_entry_experiment_trampoline", "mac27_entry_experiment_resume",
        "mac27_entry_experiment_run", "mac27_entry_experiment_validate",
        "mac27_entry_experiment_match_brk", "mac27_entry_experiment_sha256",
        "mac27_entry_experiment_exc_handler")
TRAMPOLINE = (
    0xA9BF7BFD,  # stp x29,x30,[sp,#-16]!
    0x910003FD,  # mov x29,sp
    0xD61F0020,  # br x1 -> unchanged entry B in writable KC copy
    0x52800020,  # resume: mov w0,#1
    0xA8C17BFD,  # ldp x29,x30,[sp],#16
    0xD65F03C0,  # ret
)


class Rejected(ValueError):
    pass


def require(condition: bool, why: str) -> None:
    if not condition:
        raise Rejected(why)


def open_readonly(path: Path, description: str) -> int:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise Rejected(f"{description}: read-only open failed: {exc}") from exc
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise Rejected(f"{description}: only offline regular files accepted")
    return fd


def sha256_file(path: Path, limit: int, name: str) -> tuple[str, int]:
    fd = open_readonly(path, name)
    try:
        n = os.fstat(fd).st_size
        require(0 < n <= limit, f"{name}: wrong or excessive size")
        h = hashlib.sha256()
        while True:
            blob = os.read(fd, 1024 * 1024)
            if not blob:
                break
            h.update(blob)
        return h.hexdigest(), n
    finally:
        os.close(fd)


def checked_digest(value: str, description: str) -> str:
    require(bool(re.fullmatch(r"[0-9a-f]{64}", value)) and value != "0" * 64,
            f"{description}: expected independent SHA-256 pin (64 lowercase hex)")
    return value


def verify_apple(kc: Path, manifest: Path,
                 *, expected_kc_digest: str = KC_SHA256,
                 expected_kc_size: int = KC_BYTES,
                 expected_manifest_digest: str = MANIFEST_SHA256,
                 entry_offset: int = EXPECTED_ENTRY_OFFSET,
                 target_offset: int = EXPECTED_TARGET_OFFSET) -> dict:
    expected_kc_digest = checked_digest(expected_kc_digest, "KC digest")
    checked_digest(expected_manifest_digest, "manifest digest")
    kc_hash, kc_size = sha256_file(kc, MAX_BOOT_IMAGE, "26A434 VMAPPLE KC")
    require(kc_size == expected_kc_size and kc_hash == expected_kc_digest,
            "wrong KC: expected genuine 26A434 VMAPPLE SHA-256 and size")
    fd = open_readonly(kc, "26A434 VMAPPLE KC")
    try:
        head = os.pread(fd, 32, 0)
        require(len(head) == 32, "truncated MH_FILESET header")
        magic, cpu, subtype, kind = struct.unpack_from("<4I", head)
        require((magic, cpu, subtype, kind) ==
                (0xFEEDFACF, 0x0100000C, 0xC0000002, 12),
                "unsupported KC: expected ARM64e MH_FILESET")
        require(0 <= entry_offset <= kc_size - 4 and
                0 <= target_offset <= kc_size - 4 and
                entry_offset < target_offset,
                "KC entry B/target offsets outside fileset")
        entry_word = struct.unpack("<I", os.pread(fd, 4, entry_offset))[0]
        target_word = struct.unpack("<I", os.pread(fd, 4, target_offset))[0]
        require(entry_word == EXPECTED_ENTRY_BRANCH,
                "XNU entry B modified: must retain genuine instruction")
        relative = entry_word & 0x03FFFFFF
        if relative & 0x02000000:
            relative -= 0x04000000
        target = EXPECTED_ENTRY_VA + 4 * relative
        require(target == EXPECTED_TARGET_VA and
                target_offset - entry_offset == 4 * relative,
                "entry B does not branch to genuine bootstrap target")
        require(target_word == EXPECTED_TARGET_ORIGINAL and target_word != BRK_OPCODE,
                "KC raw bootstrap target must stay unchanged; BRK only in private staging")
    finally:
        os.close(fd)
    manifest_hash, manifest_size = sha256_file(manifest, MAX_BOOT_IMAGE, "BuildManifest")
    require(manifest_hash == expected_manifest_digest,
            "wrong 26A434 BuildManifest SHA-256")
    return {"kc_sha256": kc_hash, "kc_size": kc_size,
            "manifest_sha256": manifest_hash, "manifest_size": manifest_size,
            "cpu": "arm64e", "macos_build": "26A434",
            "entry_va": hex(EXPECTED_ENTRY_VA),
            "entry_fileoff": entry_offset,
            "entry_b_word": hex(entry_word),
            "bootstrap_target_va": hex(EXPECTED_TARGET_VA),
            "bootstrap_target_fileoff": target_offset,
            "bootstrap_target_original_word": hex(target_word),
            "raw_kc_modified": False, "apple_signature_verified": False}


def elf_symbols(path: Path) -> dict[str, int]:
    try:
        result = subprocess.run(["aarch64-linux-gnu-nm", "--defined-only", str(path)],
                                check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Rejected(f"ELF symbols unavailable: {exc}") from exc
    symbols: dict[str, int] = {}
    for line in result.stdout.splitlines():
        cols = line.split()
        if len(cols) != 3 or not re.fullmatch(r"[0-9A-Fa-f]+", cols[0]):
            continue
        if cols[2] in symbols:
            raise Rejected(f"duplicate ELF symbol {cols[2]}")
        symbols[cols[2]] = int(cols[0], 16)
    return symbols


def elf_image(raw: bytes, symbols: dict[str, int]) -> bytes:
    """Verify ELF LOAD has VMA0, then materialize ELF p_filesz into Image RAM.

    This is NOT a relocation engine; nontrivial ELF layouts are rejected.
    Synthetic and pre-verified shim must have a single contiguous PT_LOAD.
    """
    require(len(raw) >= 64 and raw[:6] == b"\x7fELF\x02\x01",
            "ELF64 little-endian required")
    require(struct.unpack_from("<HH", raw, 16) == (2, ENTRY_ARCH) and
            struct.unpack_from("<Q", raw, 24)[0] == 0,
            "expected ET_EXEC AArch64 ELF with entry at zero")
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    phsize, phcount = struct.unpack_from("<HH", raw, 54)
    require(phsize == 56 and 0 < phcount <= 16 and
            phoff <= len(raw) and phcount * phsize <= len(raw) - phoff,
            "invalid ELF program header table")
    loads = []
    for index in range(phcount):
        pos = phoff + 56 * index
        kind, flags, offset, vaddr, paddr, filesz, memsz, alignment = struct.unpack_from("<II6Q", raw, pos)
        if kind == ELF_LOAD:
            require(offset <= len(raw) and filesz <= len(raw) - offset and
                    memsz >= filesz and memsz <= MAX_ELF and alignment in (1, 4, 16, PAGE, 65536),
                    "invalid ELF load span")
            loads.append((flags, offset, vaddr, paddr, filesz, memsz))
    require(len(loads) == 1, "experimental ELF must have exactly one LOAD")
    flags, offset, vaddr, paddr, filesz, memsz = loads[0]
    require(vaddr == paddr == 0 and memsz <= MAX_ELF and memsz > 64 and
            (flags & 1) and (flags & 4), "ELF must map executable VMA0, bounded")
    require(shoff != 0, "stripped ELF without section/symbol audit unsupported")
    require(symbols.get("_head") == 0 and symbols.get("_start", 0) >= 64 and
            symbols.get("_end", 0) >= memsz and symbols["_end"] <= MAX_ELF and
            symbols["_end"] % PAGE == 0,
            "missing _head/_start/_end or invalid linked image size")
    image = raw[offset:offset + filesz].ljust(symbols["_end"], b"\0")
    require(len(image) == symbols["_end"] and len(image) <= MAX_ELF,
            "ELF Image padded size invalid")
    return image


def instruction(image: bytes, addr: int) -> int:
    require(0 <= addr <= len(image) - 4 and addr % 4 == 0,
            "unmapped/misaligned instruction symbol")
    return struct.unpack_from("<I", image, addr)[0]


def called_symbols(elf: Path, function: str) -> set[str]:
    """Exact direct BL symbol edges; no trust inferred from arbitrary strings."""
    try:
        output = subprocess.run(
            ["aarch64-linux-gnu-objdump", "-d", f"--disassemble={function}", str(elf)],
            capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Rejected(f"failed to verify callgraph of {function}: {exc}") from exc
    require(re.search(rf"<(?={re.escape(function)}>){re.escape(function)}>", output) is not None,
            f"no disassembly of required function {function}")
    found: set[str] = set()
    for line in output.splitlines():
        match = re.search(r"^\s*[0-9a-f]+:\s+[0-9a-f]+\s+bl\s+[0-9a-f]+\s+<([^>]+)>", line)
        if match:
            found.add(match.group(1).split("+", 1)[0])
    return found


def verify_brk_staging_machine_code(elf: Path) -> None:
    """Inspect actual run() instructions, not a self-declared manifest flag.

    This audits a MOVZ+MOVK constructing BRK #0x4e27 and a register-offset
    STR to the staged target, followed by architectural cache maintenance.
    It still cannot authenticate the actual runtime PA ownership/checks.
    """
    try:
        result = subprocess.run(
            ["aarch64-linux-gnu-objdump", "-d",
             "--disassemble=mac27_entry_experiment_run", str(elf)],
            check=True, capture_output=True, text=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Rejected(f"cannot disassemble BRK staging path: {exc}") from exc
    words: list[tuple[int, int]] = []
    for line in result.splitlines():
        m = re.search(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{8})\s+", line)
        if m:
            words.append((int(m.group(1), 16), int(m.group(2), 16)))
    require(len(words) >= 20, "entry run() too short for safe KC staging / BRK recovery")
    verified = False
    for i, (address, code) in enumerate(words):
        if ((code & 0xFF800000) != 0x52800000 or
                ((code >> 5) & 0xFFFF) != (BRK_OPCODE & 0xFFFF) or
                ((code >> 21) & 3) != 0):
            continue
        register = code & 0x1F
        # Require the same register's MOVK top half immediately or within
        # 3 instructions; no speculation from data bytes resembling BRK.
        for j in range(i + 1, min(i + 5, len(words))):
            high = words[j][1]
            if ((high & 0xFF800000) != 0x72800000 or
                    ((high >> 5) & 0xFFFF) != (BRK_OPCODE >> 16) or
                    ((high >> 21) & 3) != 1 or (high & 31) != register):
                continue
            for k in range(j + 1, min(j + 8, len(words))):
                store = words[k][1]
                if (store & 0xFFE0FC00) == 0xB8206800 and (store & 31) == register:
                    # Require the patch to be in the same compiled function,
                    # then cache flushes and a transfer to the trampoline.
                    rest = [v for _, v in words[k + 1:]]
                    require(0xD5033F9F in rest and 0xD5033B9F in rest and
                            any(v & 0xFFFFFFC0 == 0xD50B7B00 for v in rest) and
                            any(v & 0xFFFFFFC0 == 0xD50B7500 for v in rest),
                            "BRK staging is missing D-cache/I-cache synchronization")
                    verified = True
                    break
            if verified:
                break
        if verified:
            break
    require(verified,
            "C run() does not construct and store precise BRK #0x4e27 at staged bootstrap target")


def verify_callgraph(elf: Path, symbols: dict[str, int]) -> None:
    # No direct/indirect XNU call is inferred merely from a trampoline symbol:
    # it must be on the shim_main and EL1 synchronous exception-handler paths.
    startup = called_symbols(elf, "_start")
    require("shim_main" in startup,
            "_start must invoke shim_main to activate the gated experiment")
    main = called_symbols(elf, "shim_main")
    run = "mac27_entry_experiment_run"
    entry = "mac27_entry_experiment_execute"
    if run not in main:
        require(entry in main and entry in symbols and
                run in called_symbols(elf, entry),
                "shim_main has no direct reviewed entry-experiment call path")
    require("mac27_entry_experiment_trampoline" in called_symbols(elf, run),
            "C entry experiment does not reach the dedicated assembly trampoline")
    require("mac27_entry_experiment_sha256" in called_symbols(elf, run) and
            "mac27_entry_experiment_validate" in called_symbols(elf, run),
            "C entry experiment lacks full hash and validation calls")
    require("mac27_entry_experiment_exc_handler" in called_symbols(elf, "exc_handler"),
            "EL1 exception handler is not wired to the one-shot BRK recovery")
    require("mac27_entry_experiment_match_brk" in
            called_symbols(elf, "mac27_entry_experiment_exc_handler"),
            "BRK recovery is not guarded by exact ESR/ELR/slot matcher")
    verify_brk_staging_machine_code(elf)


def validate_trampoline(image: bytes, symbols: dict[str, int]) -> dict:
    require(set(SYMS).issubset(symbols),
            "DIZI_MACOS27_XNU_ENTRY_EXPERIMENT trampoline ABI symbols absent")
    start = symbols["_start"]
    trampoline = symbols["mac27_entry_experiment_trampoline"]
    resume = symbols["mac27_entry_experiment_resume"]
    # Direct branch in Linux Image header to _start, not an indirect jump.
    require(instruction(image, 0) == 0x14000000 | ((start // 4) & 0x3FFFFFF),
            "ARM64 Image code0 branch does not point at _start")
    require(image[4:8] == b"\0" * 4 and image[56:60] == b"ARMd" and
            struct.unpack_from("<QQQ", image, 8) == (0, len(image), 0xA) and
            image[32:56] == b"\0" * 24 and image[60:64] == b"\0" * 4,
            "invalid AArch64 Linux Image magic/offset/size/flags")
    require(0 < start < len(image), "_start outside linked executable ELF")
    require(trampoline % 4 == 0 and trampoline + 4 * len(TRAMPOLINE) <= len(image),
            "trampoline not within bounded executable image")
    for i, word in enumerate(TRAMPOLINE):
        require(instruction(image, trampoline + 4 * i) == word,
                f"BRK bootstrap target trampoline instruction {i} mismatch")
    require(resume == trampoline + 12,
            "EL1 BRK recovery resume label is not after trampoline BR X1")
    require(BRK_OPCODE == 0xD429C4E0, "expected BRK #0x4e27 encoding changed")
    # No source code or disassembly can establish validator semantics. Require
    # an out-of-band APPROVED HASH for the complete, reviewed linked binary.
    return {"macro": "DIZI_MACOS27_XNU_ENTRY_EXPERIMENT=1 and MAC27_ENTRY_EXPERIMENT_HANDLER_WIRED=1",
            "macro_opt_in": True,
            "trampoline_offset": trampoline,
            "brk_recovery_resume_offset": resume,
            "brk_opcode": hex(BRK_OPCODE),
            "brk_target_expected_va": hex(EXPECTED_TARGET_VA),
            "entry_b_expected_va": hex(EXPECTED_ENTRY_VA),
            "validator_runtime_semantics_verified_by_packager": False,
            "stage_target_ownership_verified_by_packager": False}


def verify_elf(path: Path, externally_approved_sha256: str) -> tuple[dict, bytes]:
    checked_digest(externally_approved_sha256, "independently approved ELF")
    fd = open_readonly(path, "entry-experiment ELF")
    try:
        n = os.fstat(fd).st_size
        require(0 < n <= MAX_ELF, "entry-experiment ELF too large")
        raw = os.pread(fd, n, 0)
        require(len(raw) == n, "short ELF read")
    finally:
        os.close(fd)
    digest = hashlib.sha256(raw).hexdigest()
    require(digest == externally_approved_sha256,
            "ELF SHA256 differs from independent reviewed pin")
    symbols = elf_symbols(path)
    image = elf_image(raw, symbols)
    trampoline_report = validate_trampoline(image, symbols)
    verify_callgraph(path, symbols)
    return {"elf_sha256": digest, "image_sha256": hashlib.sha256(image).hexdigest(),
            "image_size": len(image), "elf_bytes": len(raw), **trampoline_report}, image


def align(n: int) -> int:
    return (n + PAGE - 1) // PAGE * PAGE


def verify_output_boot_v4(path: Path, kernel_bytes: bytes, kc_hash: str,
                          kc_size: int) -> dict:
    fd = open_readonly(path, "experimental boot-v4 image")
    try:
        size = os.fstat(fd).st_size
        require(size <= MAX_BOOT_IMAGE, "output exceeds 100MiB budget")
        header = os.pread(fd, PAGE, 0)
        require(len(header) == PAGE and header[:8] == b"ANDROID!",
                "not an Android boot image")
        kernellen, ramdisklen, _osversion, headersize = struct.unpack_from("<4I", header, 8)
        version = struct.unpack_from("<I", header, 40)[0]
        require(version == 4 and headersize == 1584 and
                kernellen == len(kernel_bytes) and ramdisklen == kc_size,
                "bad GKI v4 header version/section bounds")
        cmdline = header[44:1580].split(b"\0", 1)[0]
        require(cmdline == b"console=null mac27_entry_experiment=1",
                "GKI kernel commandline must identify entry experiment")
        require(struct.unpack_from("<I", header, 1580)[0] == 0,
                "unexpected GKI boot signature; not OEM-authorized")
        coff = PAGE
        roff = coff + align(kernellen)
        require(size == roff + align(ramdisklen),
                "bad kernel/ramdisk offset, padding or signature")
        def readhash(offset: int, n: int) -> str:
            h = hashlib.sha256()
            pos = 0
            while pos < n:
                data = os.pread(fd, min(1024 * 1024, n - pos), offset + pos)
                require(bool(data), "truncated GKI segment")
                h.update(data)
                pos += len(data)
            return h.hexdigest()
        require(readhash(coff, kernellen) == hashlib.sha256(kernel_bytes).hexdigest(),
                "staged kernel Image altered")
        require(readhash(roff, ramdisklen) == kc_hash,
                "KC data altered by packaging")
        return {"sha256": readhash(0, size), "bytes": size,
                "header_version": version, "kernel_offset": coff,
                "kernel_bytes": kernellen, "ramdisk_offset": roff,
                "ramdisk_bytes": ramdisklen, "kc_is_raw_data": True,
                "native_xnu_boot": False, "gki_signature_bytes": 0}
    finally:
        os.close(fd)


def review(elf: Path, kc: Path, manifest: Path, approved_elf_sha256: str) -> tuple[dict, bytes]:
    apple = verify_apple(kc, manifest,
                         expected_kc_digest=KC_SHA256,
                         expected_kc_size=KC_BYTES,
                         expected_manifest_digest=MANIFEST_SHA256,
                         entry_offset=EXPECTED_ENTRY_OFFSET,
                         target_offset=EXPECTED_TARGET_OFFSET)
    elfmeta, kernel = verify_elf(elf, approved_elf_sha256)
    require(align(len(kernel)) + align(apple["kc_size"]) + PAGE <= MAX_BOOT_IMAGE,
            "GKI budget exceeded")
    info = {"schema": "macos27-xnu-brk-entry-review/1",
            "experimental_first_instruction_only": True,
            "native_xnu_boot": False,
            "requires_independent_elf_review": True,
            "true_runtime_staging_validation_performed": False,
            "real_apple_boot_trust_verified": False,
            "kernel_collection": apple, "entry_experiment_elf": elfmeta,
            "blockers": [
                "Runtime validator ABI and stage ownership are not verified by this packager",
                "BRK at real bootstrap target requires writable private KC staging and correct I-cache invalidation",
                "PAC/fixups/16K MMU/boot_args and platform requirements remain unresolved",
                "Apple Image4, SSV, APFS and SEP LocalPolicy trust remain unverified",
            ]}
    return info, kernel


def check_destination(target: Path, elf: Path, kc: Path, manifest: Path) -> Path:
    """No writes. This preliminary check is backed by O_EXCL-style link later."""
    require(target.name and target.parent.is_dir() and
            not target.parent.is_symlink(), "output directory must exist")
    require(not target.is_symlink() and not target.exists(),
            "output exists: never overwrite saved images")
    sidecar = Path(str(target) + ".review.json")
    require(not sidecar.is_symlink() and not sidecar.exists(),
            "review manifest exists: never overwrite")
    require(not target.parent.resolve().is_relative_to((ROOT / "research").resolve()) and
            not target.parent.resolve().is_relative_to((ROOT / "shim/out").resolve()),
            "do not place experimental boot image among preserved artifacts")
    require(target.resolve() not in (kc.resolve(), elf.resolve(), manifest.resolve()),
            "output path aliases an input")
    return sidecar


def package(elf: Path, kc: Path, manifest: Path, target: Path,
            approved_elf_sha256: str, *, opt_in: bool, emit: bool) -> dict:
    require(opt_in, "explicit --entry-experiment-opt-in required")
    sidecar = check_destination(target, elf, kc, manifest) if emit else None
    info, kernel = review(elf, kc, manifest, approved_elf_sha256)
    if not emit:
        return info  # read-only dry-run is default; no file creation
    assert sidecar is not None
    with tempfile.TemporaryDirectory(prefix="m27-entry-review-", dir=target.parent) as d:
        stage = Path(d)
        image = stage / "Image"
        image.write_bytes(kernel)  # <= 2MiB, not an Apple asset
        boot = stage / "review.img"
        command = ["mkbootimg", "--header_version", "4", "--kernel", str(image),
                   "--ramdisk", str(kc), "--cmdline",
                   "console=null mac27_entry_experiment=1",
                   "--os_version", "12.0.0", "--os_patch_level", "2025-09",
                   "-o", str(boot)]
        try:
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise Rejected(f"mkbootimg failed offline: {exc}") from exc
        info["android_gki_v4"] = verify_output_boot_v4(
            boot, kernel, info["kernel_collection"]["kc_sha256"],
            info["kernel_collection"]["kc_size"])
        report = stage / "review.json"
        report.write_text(json.dumps(info, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        # Atomic no-clobber file creation via hard links (no Apple KC copy).
        linked_report = False
        try:
            os.link(report, sidecar, follow_symlinks=False)
            linked_report = True
            os.link(boot, target, follow_symlinks=False)
        except OSError:
            if linked_report:
                sidecar.unlink()
            raise
    return info


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--experiment-elf", type=Path, required=True)
    p.add_argument("--approved-elf-sha256", required=True)
    p.add_argument("--kc", type=Path, default=DEFAULT_KC)
    p.add_argument("--build-manifest", type=Path, default=DEFAULT_MANIFEST)
    p.add_argument("--entry-experiment-opt-in", action="store_true")
    p.add_argument("--emit-reviewed-image", action="store_true",
                   help="explicitly emit an OFFLINE image only after external review")
    p.add_argument("--output", type=Path)
    args = p.parse_args(argv)
    try:
        require(not args.emit_reviewed_image or args.output is not None,
                "--emit-reviewed-image requires --output")
        require(not args.output or args.emit_reviewed_image,
                "--output requires explicit --emit-reviewed-image")
        result = package(args.experiment_elf, args.kc, args.build_manifest,
                         args.output if args.output else Path("unused"),
                         args.approved_elf_sha256,
                         opt_in=args.entry_experiment_opt_in,
                         emit=args.emit_reviewed_image)
    except (Rejected, OSError) as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"result": "EXPERIMENTAL_FIRST_INSTRUCTION_REVIEW_ONLY",
                      "image_written": args.emit_reviewed_image,
                      "output": str(args.output) if args.emit_reviewed_image else None,
                      "native_xnu_boot": False,
                      "entry_experiment": result["entry_experiment_elf"],
                      "kernel_collection": result["kernel_collection"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
