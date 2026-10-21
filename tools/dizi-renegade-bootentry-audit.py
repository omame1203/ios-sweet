#!/usr/bin/env python3
"""Read-only evidence audit: Android GKI-v4 ABL -> Linux Image -> Renegade BootShim -> EDK2.

This audits *actual* captured dizi boot/ABL/FDT and the upstream BootShim
transport. It cannot infer real loader execution merely from ELF/ARMd magic,
an apparent branch, an FDT memory bank, or self-declared runtime ownership.
The outcome is ALWAYS BLOCKED until independently observed FD/SEC entry,
verified RAM exclusion, EL1/EL2 mappings, cache control and the specific
BootShim-to-EDK2 PrePi ABI exist. Never emits a boot image or allowlist.

Renegade's generic pipeline (Silicon/platform.sh.inc) is:
    gzip(BootShim.bin + <SOC>_UEFI.fd) + <device>.dtb
in Android's boot kernel section. This is *not* the same as putting an FV in
the GKI v4 ramdisk behind a Linux Image wrapper. Android vendor_boot v4
contributes additional ramdisks; /chosen/linux,initrd-start/end is runtime
data and cannot be reconstructed conclusively from the boot partition.
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
import zlib

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = Path("/tmp/dizi-edk2-msm-audit-20261021")
PAGE = 4096
MAX_BOOT = 256 * 1024 * 1024
MAX_VENDOR = 128 * 1024 * 1024
MAX_ABL = 8 * 1024 * 1024
MAX_FDT = 2 * 1024 * 1024
MAX_VENDOR_DTB_COLLECTION = 8 * 1024 * 1024
MAX_KERNEL = 80 * 1024 * 1024
MAX_FD = 32 * 1024 * 1024
DIZI_HIGH_PA = 0x8C0000000
DIZI_HIGH_SIZE = 0xB0000000
# Source-derived candidate ONLY, not an independently owned physical range:
# edk2-overlay/Platform/Qualcomm/sm7435/sm7435.fdf and
# Silicon/Qualcomm/sm7435/Library/PlatformMemoryMapLib/PlatformMemoryMapLib.c.
PARENT_CANDIDATE_FD_PA = 0x90000000
PARENT_CANDIDATE_FD_SIZE = 0x00400000
BLOCKERS = (
    "NO_INDEPENDENT_SM7435_EDK2_FD_AND_SEC_PREPI_HANDOFF",
    "NO_AUDITED_DIZI_GZIP_DTBO_OR_RAMDISK_TRANSPORT_EXECUTION",
    "NO_RUNTIME_ABL_EL1_EL2_REGISTERS_OR_MMU_CACHE_TRANSITION_PROOF",
    "NO_EXCLUSIVE_FD_RAM_OWNERSHIP_OR_DYNAMIC_RESERVED_MEMORY_PROOF",
    "NO_VERIFIED_FDT_VA_PA_AND_X0_ABI_AT_UEFI_TRANSFER",
    "NO_UEFI_IMAGE_EXECUTION_OR_EDK2_DRIVER_RUNTIME_EVIDENCE",
)


class Rejected(ValueError):
    pass


def require(predicate: bool, message: str) -> None:
    if not predicate:
        raise Rejected(message)


def open_regular(path: Path, maximum: int, title: str) -> tuple[int, int]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError as err:
        raise Rejected(f"{title}: not a readable regular source: {err}") from err
    size = os.fstat(fd)
    if not stat.S_ISREG(size.st_mode) or not 0 < size.st_size <= maximum:
        os.close(fd)
        raise Rejected(f"{title}: non-regular, empty or over budget")
    return fd, size.st_size


def read_regular(path: Path, maximum: int, title: str) -> bytes:
    fd, size = open_regular(path, maximum, title)
    try:
        parts = []
        pos = 0
        while pos < size:
            part = os.pread(fd, min(1024 * 1024, size - pos), pos)
            require(bool(part), f"{title}: short source read")
            parts.append(part)
            pos += len(part)
        return b"".join(parts)
    finally:
        os.close(fd)


def hash_regular(path: Path, maximum: int, title: str) -> str:
    fd,size=open_regular(path,maximum,title)
    try:
        h=hashlib.sha256()
        offset=0
        while offset<size:
            block=os.pread(fd,min(1024*1024,size-offset),offset)
            require(bool(block),f"{title}: short source hash read")
            h.update(block)
            offset+=len(block)
        return h.hexdigest()
    finally:
        os.close(fd)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def round4k(n: int) -> int:
    return (n + PAGE - 1) & ~(PAGE - 1)


def arm64_header(raw: bytes) -> dict:
    require(len(raw) >= 64, "truncated ARM64 Image header")
    code0, code1, offset, size, flags = struct.unpack_from("<IIQQQ", raw)
    require(raw[56:60] == b"ARM\x64", "not an ARM64 Linux Image header")
    return {"code0": hex(code0), "code1": hex(code1),
            "text_offset": offset, "image_size": size, "flags": hex(flags),
            "magic": "ARMd", "is_b_code0": code0 >> 26 == 0b000101,
            "is_pe_coff_code0": raw[:2] == b"MZ",
            "entry_class": ("pe-coff" if raw[:2] == b"MZ" else
                            "b-imm" if code0 >> 26 == 0b000101 else "other")}


def audit_stock_boot(path: Path) -> dict:
    """Check GKI-v4 partition metadata with no writes or signature claims."""
    fd, file_size = open_regular(path, MAX_BOOT, "Android boot partition")
    try:
        head = os.pread(fd, PAGE, 0)
        require(len(head) == PAGE and head[:8] == b"ANDROID!",
                "not an Android boot image")
        kernel_bytes, ramdisk_bytes, os_version, header_size = struct.unpack_from("<4I", head, 8)
        version = struct.unpack_from("<I", head, 40)[0]
        signature_bytes = struct.unpack_from("<I", head, 1580)[0]
        require(version == 4 and header_size == 1584,
                "not a GKI boot header v4 (size 1584)")
        require(64 <= kernel_bytes <= MAX_KERNEL and ramdisk_bytes <= 128*1024*1024,
                "GKI kernel/ramdisk size outside audited bounds")
        kernel_pa = PAGE
        ramdisk_pa = kernel_pa + round4k(kernel_bytes)
        sig_pa = ramdisk_pa + round4k(ramdisk_bytes)
        payload_end = sig_pa + round4k(signature_bytes)
        require(payload_end <= file_size and payload_end <= MAX_BOOT,
                "GKI v4 kernel, ramdisk or signature outside partition")
        require(signature_bytes <= 4096 * 4, "oversize boot signature")
        require(head[1584:] == b"\0" * (PAGE-1584),
                "unexpected nonzero GKI-v4 reserved header padding")
        require(head[24:40] == b"\0"*16,
                "nonzero GKI-v4 reserved header words")
        image_head = os.pread(fd, 64, kernel_pa)
        kernel = arm64_header(image_head)
        require(kernel["image_size"] == 0 or kernel["image_size"] <= kernel_bytes,
                "GKI kernel embedded ARM64 size exceeds declared kernel section")
        require(os.pread(fd, ramdisk_pa-(kernel_pa+kernel_bytes),
                         kernel_pa+kernel_bytes) ==
                b"\0"*(ramdisk_pa-kernel_pa-kernel_bytes),
                "nonzero GKI kernel alignment padding")
        require(os.pread(fd,sig_pa-(ramdisk_pa+ramdisk_bytes),
                         ramdisk_pa+ramdisk_bytes) ==
                b"\0"*(sig_pa-ramdisk_pa-ramdisk_bytes),
                "nonzero GKI ramdisk alignment padding")
        return {
            "header_version": version, "header_size": header_size,
            "partition_sha256": hash_regular(path,MAX_BOOT,"Android boot partition"),
            "partition_bytes": file_size,
            "kernel_offset": kernel_pa, "kernel_bytes": kernel_bytes,
            "ramdisk_offset": ramdisk_pa, "ramdisk_bytes": ramdisk_bytes,
            "signature_offset": sig_pa, "signature_bytes": signature_bytes,
            "payload_end": payload_end, "partition_padding_bytes": file_size-payload_end,
            "os_version_word": hex(os_version),
            "kernel_linux_image": kernel,
            "boot_signature_cryptographically_verified": False,
            "partition_trailing_padding_verified": False,
            "abl_entry_state_proven": False,
        }
    finally:
        os.close(fd)


def audit_vendor_boot(path: Path) -> dict:
    fd, cap = open_regular(path, MAX_VENDOR, "vendor_boot partition")
    try:
        head = os.pread(fd, PAGE, 0)
        require(len(head) == PAGE and head[:8] == b"VNDRBOOT", "not vendor_boot v4")
        version, page, _kernel_addr, ramdisk_addr, ramdisk_size = struct.unpack_from("<5I", head, 8)
        header_size = struct.unpack_from("<I", head, 2096)[0]
        require(version == 4 and page == PAGE and header_size == 2128,
                "unsupported vendor_boot version/page/header size")
        dtb_size = struct.unpack_from("<I", head, 2100)[0]
        ramdisk_start = round4k(header_size)
        dtb_start = ramdisk_start + round4k(ramdisk_size)
        require(dtb_start + dtb_size <= cap and ramdisk_size <= MAX_KERNEL and
                dtb_size <= MAX_VENDOR_DTB_COLLECTION,
                "vendor ramdisk or DTB layout exceeds captured partition")
        return {"header_version": version, "header_size": header_size,
                "partition_sha256": hash_regular(path,MAX_VENDOR,"vendor_boot partition"),
                "vendor_ramdisk_offset": ramdisk_start,
                "vendor_ramdisk_bytes": ramdisk_size,
                "dtb_offset": dtb_start, "dtb_bytes": dtb_size,
                "vendor_ramdisk_addr": hex(ramdisk_addr),
                "vendor_ramdisk_runtime_prefix_bytes": None,
                "vendor_ramdisk_included_by_runtime_ABL": "UNVERIFIED",
                "partition_bytes": cap}
    finally:
        os.close(fd)


def audit_abl(path: Path) -> dict:
    fd, size = open_regular(path, MAX_ABL, "captured dizi ABL")
    try:
        head = os.pread(fd, 64, 0)
        require(head[:4] == b"\x7fELF" and head[5] == 1,
                "saved ABL not ELF/little endian")
        require(head[4] in (1, 2), "saved ABL ELF class invalid")
        machine = struct.unpack_from("<H", head, 18)[0]
        require(machine in (40, 183), "saved ABL not ARM/AArch64")
        return {"elf_class": 32 if head[4] == 1 else 64,
                "elf_machine": machine, "bytes": size,
                "abl_sha256":hash_regular(path,MAX_ABL,"captured dizi ABL"),
                "entry_x0_fdt_proven_by_this_static_elf": False,
                "el1_sctlr_mmu_status_proven_by_this_static_elf": False,
                "gki_gzip_dtb_loader_behavior_proven_by_this_static_elf": False}
    finally:
        os.close(fd)


def audit_bootshim_source(raw: bytes) -> dict:
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as err:
        raise Rejected("BootShim.S not UTF-8 source") from err
    expected = (
        r"_Head:\s*",
        r"adr\s+x1,\s*_Payload",
        r"b\s+_Start",
        r"_StackSize0:[\s\S]*?\.quad\s+0",
        r"_StackBase:[\s\S]*?\.quad\s+UEFI_BASE",
        r"_StackSize:[\s\S]*?\.quad\s+UEFI_SIZE",
        r"_Start:[\s\S]*?mov\s+x4,\s*x1",
        r"_CopyLoop:[\s\S]*?ldp\s+x2,\s*x3,\s*\[x4\],\s*#16",
        r"stp\s+x2,\s*x3,\s*\[x5\],\s*#16",
        r"subs\s+x6,\s*x6,\s*#16",
        r"_Entry:[\s\S]*?br\s+x5",
    )
    for item in expected:
        require(re.search(item, source) is not None,
                f"BootShim.S code does not match audited upstream pattern: {item}")
    zeros = re.search(r"_StackSize0:[\s\S]*?\.quad\s+0[\s\S]*?_StackBase:", source)
    require(bool(zeros), "upstream Linux Image Size=0 not found")
    # Static warnings, not positive ABI attestations.
    return {"sha256": digest(raw), "bootshim_contract": "upstream-adr+copy-fd+br",
            "uses_linux_image_size_zero": True,
            "uses_linux_image_flags_zero": True,
            "source_destination_literal": "UEFI_BASE",
            "source_copy_bytes_literal": "UEFI_SIZE",
            "copies_raw_fd_in_16_byte_steps": True,
            "entry_call": "br x5",
            "overlap_bounds_checks": False,
            "fdt_validation": False,
            "cache_maintenance": False,
            "edk2_sec_prepi_abi_verified": False}


def audit_bootshim_binary(raw: bytes) -> dict:
    require(len(raw) >= 0x90 and len(raw) < 0x1000 and len(raw)%16==0,
            "BootShim binary is not a small aligned ARM64 loader")
    image = arm64_header(raw)
    code0, code1 = struct.unpack_from("<II", raw)
    require((code0 & 0x9F000000) == 0x10000000 and
            code1 >> 26 == 0b000101,
            "BootShim _Head must be ADR x1 followed by B _Start")
    require(image["image_size"] == 0 and image["flags"] == "0x0",
            "upstream BootShim header size/flags unexpectedly changed")
    require(raw[64:72] == b"EDK2-MSM",
            "upstream BootShim payload signature not found")
    fd_pa, fd_size = struct.unpack_from("<QQ", raw, 0x48)
    require(fd_pa != 0 and fd_size > 0 and fd_size % 16 == 0,
            "BootShim has invalid compile-time FD destination/size")
    require(struct.unpack_from("<I",raw,0x80)[0] == 0xD61F00A0 and
            struct.unpack_from("<I",raw,0x6c)[0] == 0xA8C10C82 and
            struct.unpack_from("<I",raw,0x70)[0] == 0xA8810CA2,
            "BootShim lacks exact 16-byte copy/BR x5 machine code")
    require((code0 & 31)==1, "BootShim ADR does not target x1")
    return {"sha256": digest(raw), "bytes": len(raw),
            "linux_image": image, "fd_destination_pa": hex(fd_pa),
            "fd_copied_bytes": fd_size,
            "known_other_soc_fd_base": fd_pa==0xCE000000,
            "image_size_zero_unusable_as_strict_gki_image": True,
            "has_checked_fd_source_length": False,
            "has_checked_destination_ownership": False,
            "has_cache_maintenance_before_br": False}


def inspect_gzip_fd_dtb(raw: bytes, bootshim: bytes) -> dict:
    """Parse upstream gzip(BootShim+FD)+DTB; DOES NOT mark it executable."""
    require(len(raw) >= 24 and len(raw) <= MAX_KERNEL and raw[:2] == b"\x1f\x8b",
            "Renegade kernel transport is not gzip(BootShim+FD)+DTB")
    decomp = zlib.decompressobj(wbits=31)
    try:
        unpacked = decomp.decompress(raw, len(bootshim)+MAX_FD+1)
        unpacked += decomp.flush()
    except zlib.error as err:
        raise Rejected(f"invalid gzip Renegade payload: {err}") from err
    require(decomp.eof and not decomp.unconsumed_tail and
            len(unpacked) <= len(bootshim)+MAX_FD,
            "gzip does not terminate as one bounded BootShim+FD member")
    require(unpacked.startswith(bootshim) and len(unpacked)>len(bootshim),
            "decompressed payload does not begin with exact audited BootShim")
    dtb = decomp.unused_data
    require(len(dtb) >= 40 and len(dtb) <= MAX_FDT and
            struct.unpack_from(">I", dtb, 0)[0] == 0xD00DFEED and
            struct.unpack_from(">I", dtb, 4)[0] == len(dtb),
            "gzip is missing a bounded complete appended FDT")
    return {"format": "gzip(BootShim.bin+FD)+DTB",
            "gzip_uncompressed_bytes": len(unpacked),
            "bootshim_prefix_bytes": len(bootshim),
            "fd_bytes": len(unpacked)-len(bootshim),
            "fd_sha256": digest(unpacked[len(bootshim):]),
            "appended_dtb_bytes": len(dtb), "appended_dtb_sha256": digest(dtb),
            "gzip_crc_checked": True,
            "appended_dtb_structurally_validated": False,
            "abl_gki_v4_decompression_verified": False,
            "bootshim_entry_compatible_with_dizi": False}


def _be32(blob: bytes, off: int) -> int:
    return struct.unpack_from(">I", blob, off)[0]


def _reg_cells(blob: bytes, addr: int, size: int,
               *, skip_empty_banks: bool = False) -> list[tuple[int,int]]:
    require(len(blob) > 0 and addr == size == 2 and len(blob)%16==0,
            "FDT requires dizi 64-bit 2/2 reg pairs")
    result = []
    for p in range(0,len(blob),16):
        base, length=struct.unpack_from(">QQ",blob,p)
        require(base+length<=1<<64, "FDT reg overflow")
        if length == 0 and skip_empty_banks:
            continue  # Real dizi /memory/reg includes one empty placeholder.
        require(length>0,"FDT reserved reg has a zero-length extent")
        result.append((base,length))
    return result


def audit_fdt(raw: bytes) -> dict:
    require(40 <= len(raw) <= MAX_FDT and _be32(raw,0)==0xD00DFEED,
            "invalid dizi FDT size/magic")
    total, so, st, reserve = (_be32(raw,p) for p in (4,8,12,16))
    szs, szstruct = _be32(raw,32),_be32(raw,36)
    require(total==len(raw) and so>=40 and st>=40 and
            so+szstruct<=total and st+szs<=total and
            40<=reserve<so and _be32(raw,20)>=17,
            "truncated or unsupported FDT header")
    reserved = []
    cursor = reserve
    while cursor+16 <= so:
        pa,n=struct.unpack_from(">QQ",raw,cursor);cursor+=16
        if pa==0 and n==0:break
        require(n>0 and pa+n<=1<<64,"invalid FDT memreserve")
        reserved.append((pa,n))
    else:raise Rejected("FDT reserve map lacks terminator")
    path=[]
    props:dict[str,dict[str,bytes]]={}
    cursor=so
    reached_end=False
    while cursor < so+szstruct:
        require(cursor+4<=so+szstruct,"truncated FDT structure token")
        token=_be32(raw,cursor);cursor+=4
        if token==1:
            require(len(path)<32,"FDT excessive nesting")
            end=raw.find(b"\0",cursor,so+szstruct)
            require(end>=0,"FDT missing node name terminator")
            name=raw[cursor:end].decode("ascii",errors="replace")
            cursor=(end+4)&~3
            path.append(name)
            props["/"+"/".join(path[1:])]={}
        elif token==2:
            require(bool(path),"unbalanced FDT")
            path.pop()
        elif token==3:
            require(bool(path) and cursor+8<=so+szstruct,"truncated FDT property")
            length, nameoff=_be32(raw,cursor),_be32(raw,cursor+4)
            cursor+=8
            require(nameoff<szs and cursor+length<=so+szstruct,
                    "FDT property offsets outside structure")
            nameend=raw.find(b"\0",st+nameoff,st+szs)
            require(nameend>=0,"FDT property string unterminated")
            propname=raw[st+nameoff:nameend].decode("ascii",errors="replace")
            key="/"+"/".join(path[1:])
            require(propname not in props[key], "FDT duplicate property")
            props[key][propname]=raw[cursor:cursor+length]
            cursor=(cursor+length+3)&~3
        elif token==4:continue
        elif token==9:
            require(not path,"FDT END with unclosed nodes")
            reached_end=True;break
        else:raise Rejected("bad FDT structure token")
    require(reached_end and props.get("/") is not None,"incomplete FDT structure")
    root=props["/"]
    require(root.get("#address-cells")==b"\0\0\0\2" and
            root.get("#size-cells")==b"\0\0\0\2",
            "dizi FDT root address/size cells must be 2/2")
    require(b"qcom,parrot" in root.get("compatible",b""),
            "FDT is not observed Qualcomm Parrot dizi candidate")
    memory=[]
    for path,node in props.items():
        if path=="/memory" or path.startswith("/memory@"):
            memory.extend(_reg_cells(node.get("reg",b""),2,2,skip_empty_banks=True))
    require(memory,"FDT has no usable DDR banks")
    region="/reserved-memory"
    rnode=props.get(region)
    require(rnode is not None and rnode.get("#address-cells")==b"\0\0\0\2" and
            rnode.get("#size-cells")==b"\0\0\0\2",
            "FDT reserved-memory parent lacks dizi 2/2 cells")
    dynamic=[]
    fixed=list(reserved)
    for path,node in props.items():
        if path.startswith(region+"/") and path.count("/")==2:
            if "reg" in node:fixed.extend(_reg_cells(node["reg"],2,2))
            else:dynamic.append(path.rsplit("/",1)[1])
    bank_candidate=any(pa<=DIZI_HIGH_PA and
                       DIZI_HIGH_PA+DIZI_HIGH_SIZE<=pa+length
                       for pa,length in memory)
    overlaps=[(hex(pa),hex(length)) for pa,length in fixed if
              pa < DIZI_HIGH_PA+DIZI_HIGH_SIZE and DIZI_HIGH_PA < pa+length]
    low=PARENT_CANDIDATE_FD_PA
    low_end=low+PARENT_CANDIDATE_FD_SIZE
    parent_in_ddr=any(pa<=low and low_end<=pa+n for pa,n in memory)
    parent_overlaps=[(hex(pa),hex(n)) for pa,n in fixed
                     if pa<low_end and low<pa+n]
    chosen=props.get("/chosen",{})
    def chosen_reg(name:str)->int|None:
        value=chosen.get(name)
        if value is None:return None
        require(len(value) in (4,8),f"FDT /chosen/{name} malformed")
        return int.from_bytes(value,"big")
    return {"sha256":digest(raw),"bytes":len(raw),
            "ddr_banks":len(memory),"candidate_ram_pa":hex(DIZI_HIGH_PA),
            "candidate_ram_bytes":hex(DIZI_HIGH_SIZE),
            "candidate_inside_one_ddr_bank":bank_candidate,
            "fixed_memreserve_and_reserved_ranges":len(fixed),
            "fixed_candidate_overlaps":overlaps,
            "parent_fd_candidate_inside_one_ddr_bank":parent_in_ddr,
            "parent_fd_candidate_fixed_reserved_overlaps":parent_overlaps,
            "dynamic_reserved_nodes":len(dynamic),
            "dynamic_reserved_names":dynamic,
            "chosen_initrd_start":chosen_reg("linux,initrd-start"),
            "chosen_initrd_end":chosen_reg("linux,initrd-end"),
            "captured_fdt_is_runtime_fresh":False,
            "exclusive_dma_and_stage2_access_verified":False}


def analyze(*, boot: Path, vendor: Path, abl: Path, fdt: Path,
            bootshim_asm: Path, bootshim_bin: Path,
            kernel_payload: Path|None = None) -> dict:
    output={"schema":"dizi-renegade-bootentry-offline-audit/1",
            "device":"dizi/SM7435",
            "status":"BLOCKED",
            "native_uefi_boot_proven":False,
            "build_or_device_actions_performed":False,
            "packager_allowlist_authorized":False,
            "required_runtime_blockers":list(BLOCKERS)}
    output["saved_android_boot"]=audit_stock_boot(boot)
    output["saved_vendor_boot"]=audit_vendor_boot(vendor)
    output["saved_abl"]=audit_abl(abl)
    output["saved_fdt"]=audit_fdt(read_regular(fdt,MAX_FDT,"saved dizi FDT"))
    asm=read_regular(bootshim_asm,32*1024,"upstream BootShim.S")
    compiled=read_regular(bootshim_bin,4096,"upstream BootShim.bin")
    output["upstream_bootshim_source"]=audit_bootshim_source(asm)
    output["upstream_bootshim_binary"]=audit_bootshim_binary(compiled)
    low=PARENT_CANDIDATE_FD_PA
    high=PARENT_CANDIDATE_FD_SIZE
    memory=output["saved_fdt"]
    output["edk2_parent_fd_transport_mismatch"]={
        "candidate_from_dizi_sm7435_parent_fd_base":hex(low),
        "candidate_fd_size":hex(high),
        "candidate_low_memory_ownership_proven":False,
        "captured_fdt_parent_fd_base_in_ddr":memory[
            "parent_fd_candidate_inside_one_ddr_bank"],
        "captured_fdt_parent_fd_fixed_reservations":memory[
            "parent_fd_candidate_fixed_reserved_overlaps"],
        "existing_dizi_renegade_image_packager_ram_base":hex(DIZI_HIGH_PA),
        "existing_dizi_renegade_image_packager_ram_size":hex(DIZI_HIGH_SIZE),
        "candidate_inside_old_packager_ram_constraint":
            DIZI_HIGH_PA<=low and high<=DIZI_HIGH_PA+DIZI_HIGH_SIZE-low,
        "low_32bit_pre_pei_memory_constraint_reviewed_only_from_source":True,
        "production_resolution":(
            "Reconcile the parent DSC/FDF/PrePi physical FD base and the "
            "independently reviewed entry wrapper against a live exclusive "
            "dizi DDR grant. Then change the separate packager's PA contract "
            "through coordinated review and pin audited code/FD hashes; "
            "never repurpose high DDR or 0xce000000 by bypassing gates."
        ),
        "static_high_ddr_candidate_ownership_proven":memory[
            "exclusive_dma_and_stage2_access_verified"],
    }
    output["abi_evidence_limitations"]={
        "saved_abl_is_arm32_elf":output["saved_abl"]["elf_machine"]==40,
        "known_shim_uses_x0_for_abl_fdt":True,
        "known_shim_src_claims_mmu_off_at_entry":True,
        "later_dizi_shim_live_sctlr_mmu_on_reported":True,
        "contradiction_resolved_from_this_offline_audit":False,
        "bootshim_gzip_decompressed_by_saved_abl_verified":False,
        "entry_el_stage2_cache_and_read_execute_access_verified":False,
    }
    if kernel_payload is not None:
        output["optional_upstream_transport"]=inspect_gzip_fd_dtb(
            read_regular(kernel_payload,MAX_KERNEL,"optional Renegade gzip/DTB kernel"),
            compiled)
    output["exact_current_status"] = (
        "Structural boot and BootShim inspection only; generic other-SoC "
        "UEFI_BASE copy/BR plus size-zero Image is not a verified dizi "
        "GKI-v4 Linux Image/EDK2 PrePi handoff. No boot image produced.")
    return output


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--boot",type=Path,default=ROOT/"backup/dizi/boot_a.img")
    parser.add_argument("--vendor-boot",type=Path,default=ROOT/"backup/dizi/vendor_boot_a.img")
    parser.add_argument("--abl",type=Path,default=ROOT/"backup/dizi/abl_a.img")
    parser.add_argument("--fdt",type=Path,default=ROOT/"backup/dizi/fdt")
    parser.add_argument("--bootshim-source",type=Path,
                        default=UPSTREAM/"tools/BootShim/BootShim.S")
    parser.add_argument("--bootshim-bin",type=Path,
                        default=UPSTREAM/"tools/BootShim/BootShim.bin")
    parser.add_argument("--kernel-payload",type=Path,default=None,
                        help="optional existing gzip(BootShim+FD)+DTB for read-only layout check")
    args=parser.parse_args(argv)
    try:
        report=analyze(boot=args.boot,vendor=args.vendor_boot,abl=args.abl,
                       fdt=args.fdt,bootshim_asm=args.bootshim_source,
                       bootshim_bin=args.bootshim_bin,kernel_payload=args.kernel_payload)
    except (Rejected,OSError,ValueError,struct.error) as exc:
        print(json.dumps({"schema":"dizi-renegade-bootentry-offline-audit/1",
                          "device":"dizi/SM7435","status":"BLOCKED",
                          "packager_allowlist_authorized":False,
                          "rejection":str(exc)},indent=2))
        return 2
    print(json.dumps(report,indent=2))
    # Always return an actionable BLOCKED status even if metadata is valid.
    return 2


if __name__=="__main__":
    sys.exit(main())
