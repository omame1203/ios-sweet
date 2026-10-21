#!/usr/bin/env python3
"""Offline rejection tests for dizi's Renegade ABL/GKI/BootShim entry path."""
from __future__ import annotations

import gzip
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"tools/dizi-renegade-bootentry-audit.py"
spec=importlib.util.spec_from_file_location("dizi_bootentry",SCRIPT)
assert spec and spec.loader
a=importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)

def linux_image()->bytes:
    b=bytearray(4096)
    struct.pack_into("<IIQQQ",b,0,0x14000010,0,0,len(b),0xa)
    b[56:60]=b"ARM\x64"
    return bytes(b)

def boot_v4()->bytes:
    b=bytearray(4096)
    b[:8]=b"ANDROID!"
    struct.pack_into("<4I",b,8,4096,1024,0x18000199,1584)
    struct.pack_into("<I",b,40,4)
    struct.pack_into("<I",b,1580,4096)
    return bytes(b)+linux_image()+b"\0"*4096+b"\0"*4096

def vendor_v4()->bytes:
    b=bytearray(4096)
    b[:8]=b"VNDRBOOT"
    struct.pack_into("<5I",b,8,4,4096,0x8000,0x1000000,120)
    struct.pack_into("<I",b,2096,2128)
    struct.pack_into("<I",b,2100,40)
    return bytes(b)+b"\0"*8192

def bootshim()->bytes:
    b=bytearray(144)
    struct.pack_into("<IIQQQ",b,0,0x10000481,0x14000015,0,0,0)
    b[56:60]=b"ARM\x64"
    b[64:72]=b"EDK2-MSM"
    struct.pack_into("<QQ",b,72,0xce000000,0x2000000)
    struct.pack_into("<III",b,0x6c,0xa8c10c82,0xa8810ca2,0xf10040c6)
    struct.pack_into("<I",b,0x80,0xd61f00a0)
    return bytes(b)

def bootshim_asm()->bytes:
    return b"""_Head:
 adr x1, _Payload
 b _Start
_StackSize0:
 .quad 0
 .quad 0
 .quad 0
_StackBase:
 .quad UEFI_BASE
_StackSize:
 .quad UEFI_SIZE
_Start:
 mov x4, x1
_CopyLoop:
 ldp x2, x3, [x4], #16
 stp x2, x3, [x5], #16
 subs x6, x6, #16
_Entry:
 br x5
_Payload:
"""

def synthetic_fdt(*, reserved_pa:int=0x81000000, dynamic:bool=True)->bytes:
    words=[b"#address-cells",b"#size-cells",b"compatible",b"reg",
           b"linux,initrd-start",b"linux,initrd-end"]
    names=b""; offsets={}
    for name in words:
        offsets[name]=len(names)
        names+=name+b"\0"
    parts=[]
    def token(n:int)->None:parts.append(struct.pack(">I",n))
    def node(name:bytes)->None:
        token(1)
        name+=b"\0"
        parts.append(name+b"\0"*((-len(name))%4))
    def prop(name:bytes,value:bytes)->None:
        token(3)
        parts.append(struct.pack(">II",len(value),offsets[name]))
        parts.append(value+b"\0"*((-len(value))%4))
    def end()->None:token(2)
    node(b"")
    prop(b"#address-cells",struct.pack(">I",2))
    prop(b"#size-cells",struct.pack(">I",2))
    prop(b"compatible",b"qcom,parrot-qrd\0qcom,parrot\0")
    node(b"memory")
    prop(b"reg",struct.pack(">QQQQQQ",0xe9500000,0,
                             0x80000000,0x20000000,a.DIZI_HIGH_PA,0xc0000000))
    end()
    node(b"reserved-memory")
    prop(b"#address-cells",struct.pack(">I",2))
    prop(b"#size-cells",struct.pack(">I",2))
    node(b"fixed")
    prop(b"reg",struct.pack(">QQ",reserved_pa,0x10000))
    end()
    if dynamic:
        node(b"dynamic-cma")
        end()
    end()
    node(b"chosen")
    prop(b"linux,initrd-start",struct.pack(">Q",0xb719f000))
    prop(b"linux,initrd-end",struct.pack(">Q",0xb7ffe6c4))
    end()
    end()
    token(9)
    structure=b"".join(parts)
    strings_start=80+len(structure)
    total=strings_start+len(names)
    header=bytearray(80)
    struct.pack_into(">7I",header,0,0xd00dfeed,total,80,strings_start,64,17,16)
    struct.pack_into(">2I",header,32,len(names),len(structure))
    return bytes(header)+structure+names

class BootEntryAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="dizi-bootentry-offline-")
        self.addCleanup(self.temp.cleanup)
        self.directory=Path(self.temp.name)
        self.boot=self.save("boot_a.img",boot_v4())
        self.vendor=self.save("vendor_boot_a.img",vendor_v4())
        abl=bytearray(256)
        abl[:8]=b"\x7fELF\x01\x01\x01\0"
        struct.pack_into("<H",abl,18,40)
        self.abl=self.save("abl_a.img",bytes(abl))
        self.fdt=self.save("dizi.dtb",synthetic_fdt())
        self.source=self.save("BootShim.S",bootshim_asm())
        self.shim=self.save("BootShim.bin",bootshim())

    def save(self,name:str,data:bytes)->Path:
        path=self.directory/name
        path.write_bytes(data)
        return path

    def inspect(self,**kwargs)->dict:
        return a.analyze(boot=self.boot,vendor=self.vendor,abl=self.abl,
                         fdt=self.fdt,bootshim_asm=self.source,
                         bootshim_bin=self.shim,**kwargs)

    def test_all_valid_headers_still_block_uefi(self):
        result=self.inspect()
        self.assertEqual(result["status"],"BLOCKED")
        self.assertFalse(result["native_uefi_boot_proven"])
        self.assertFalse(result["packager_allowlist_authorized"])
        self.assertEqual(len(result["required_runtime_blockers"]),6)
        self.assertEqual(result["saved_android_boot"]["signature_bytes"],4096)
        self.assertEqual(result["saved_vendor_boot"]["header_version"],4)
        self.assertEqual(result["saved_fdt"]["dynamic_reserved_nodes"],1)
        self.assertEqual(result["upstream_bootshim_binary"]["fd_destination_pa"],"0xce000000")
        mismatch=result["edk2_parent_fd_transport_mismatch"]
        self.assertEqual(mismatch["candidate_from_dizi_sm7435_parent_fd_base"],"0x90000000")
        self.assertFalse(mismatch["candidate_inside_old_packager_ram_constraint"])
        self.assertFalse(mismatch["candidate_low_memory_ownership_proven"])
        self.assertTrue(mismatch["captured_fdt_parent_fd_base_in_ddr"])
        self.assertFalse(result["abi_evidence_limitations"][
            "contradiction_resolved_from_this_offline_audit"])
        self.assertEqual(result["saved_android_boot"]["partition_sha256"],
                         a.digest(self.boot.read_bytes()))

    def test_gki_bad_magic_version_header_sections(self):
        original=self.boot.read_bytes()
        cases=[(0,b"WRONG!!!","not an Android"),
               (8,struct.pack("<I",0x7fffffff),"size outside"),
               (20,struct.pack("<I",1600),"header v4"),
               (40,struct.pack("<I",3),"header v4"),
               (1580,struct.pack("<I",0x7fffffff),"outside partition"),
               (1600,b"BAD","padding"),
               (4096+56,b"NOPE","ARM64")]
        for offset,data,msg in cases:
            with self.subTest(offset=offset):
                b=bytearray(original)
                b[offset:offset+len(data)]=data
                self.boot.write_bytes(b)
                with self.assertRaisesRegex(a.Rejected,msg):
                    a.audit_stock_boot(self.boot)
        self.boot.write_bytes(original[:5000])
        with self.assertRaises(a.Rejected):
            a.audit_stock_boot(self.boot)

    def test_vendor_bad_header_version_and_offsets(self):
        original=self.vendor.read_bytes()
        cases=[(0,b"NOTVBOOT","not vendor_boot"),
               (8,struct.pack("<I",3),"unsupported"),
               (2096,struct.pack("<I",100),"unsupported"),
               (2100,struct.pack("<I",0x20000000),"layout"),
               (24,struct.pack("<I",0x7fffffff),"layout")]
        for offset,data,msg in cases:
            with self.subTest(offset=offset):
                b=bytearray(original)
                b[offset:offset+len(data)]=data
                self.vendor.write_bytes(b)
                with self.assertRaisesRegex(a.Rejected,msg):
                    a.audit_vendor_boot(self.vendor)

    def test_linux_header_does_not_prove_branch_or_fdt_handoff(self):
        linux=a.arm64_header(linux_image())
        self.assertEqual(linux["entry_class"],"b-imm")
        self.assertEqual(linux["image_size"],4096)
        raw=bytearray(linux_image())
        raw[:2]=b"MZ"
        self.assertEqual(a.arm64_header(raw)["entry_class"],"pe-coff")
        raw[56:60]=b"FAIL"
        with self.assertRaisesRegex(a.Rejected,"ARM64"):
            a.arm64_header(raw)

    def test_bootshim_donor_binary_and_source_altered(self):
        source=bootshim_asm()
        self.assertEqual(a.audit_bootshim_source(source)["entry_call"],"br x5")
        for wrong in (source.replace(b"br x5",b"ret"),
                      source.replace(b"stp x2",b"nop x2")):
            with self.assertRaisesRegex(a.Rejected,"pattern"):
                a.audit_bootshim_source(wrong)
        original=bootshim()
        for offset,data,msg in (
            (56,b"FAIL","ARM64"),
            (16,struct.pack("<Q",0x10000),"size/flags"),
            (72,struct.pack("<Q",0),"invalid compile"),
            (0x80,struct.pack("<I",0xD503201F),"copy/BR"),
            (0x70,struct.pack("<I",0xD503201F),"copy/BR")):
            with self.subTest(offset=offset):
                raw=bytearray(original)
                raw[offset:offset+len(data)]=data
                with self.assertRaisesRegex(a.Rejected,msg):
                    a.audit_bootshim_binary(raw)

    def test_upstream_gzip_bootshim_fd_dtb_transport(self):
        shim=bootshim()
        fd=b"FV-TEST-ONLY"+b"\0"*(65536-len(b"FV-TEST-ONLY"))
        dtb=synthetic_fdt(dynamic=False)
        packed=gzip.compress(shim+fd,mtime=0)+dtb
        path=self.save("upstream-kernel.gz-dtb",packed)
        report=self.inspect(kernel_payload=path)
        transport=report["optional_upstream_transport"]
        self.assertEqual(transport["format"],"gzip(BootShim.bin+FD)+DTB")
        self.assertEqual(transport["fd_sha256"],a.digest(fd))
        self.assertTrue(transport["gzip_crc_checked"])
        self.assertFalse(transport["bootshim_entry_compatible_with_dizi"])
        self.assertFalse(report["packager_allowlist_authorized"])
        for raw,expected in (
            (gzip.compress(shim+fd)+b"NOTDTB","FDT"),
            (gzip.compress(b"NOTBOOTSHIM"+fd)+dtb,"BootShim"),
            (b"NO-GZIP"+packed,"not gzip")):
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(a.Rejected,expected):
                    a.inspect_gzip_fd_dtb(raw,shim)
        bad=bytearray(packed)
        bad[12]^=1
        with self.assertRaises(a.Rejected):
            a.inspect_gzip_fd_dtb(bad,shim)
        with self.assertRaisesRegex(a.Rejected,"bounded"):
            a.inspect_gzip_fd_dtb(
                gzip.compress(shim+b"X"*(a.MAX_FD+64))+dtb,shim)

    def test_fdt_dynamic_reserved_memory_and_overlap(self):
        fdt=a.audit_fdt(synthetic_fdt())
        self.assertTrue(fdt["candidate_inside_one_ddr_bank"])
        self.assertEqual(fdt["dynamic_reserved_names"],["dynamic-cma"])
        self.assertFalse(fdt["exclusive_dma_and_stage2_access_verified"])
        bad=a.audit_fdt(synthetic_fdt(reserved_pa=a.DIZI_HIGH_PA+4096))
        self.assertEqual(bad["fixed_candidate_overlaps"],
                         [(hex(a.DIZI_HIGH_PA+4096),hex(0x10000))])
        for b in (b"",b"UNKNOWN",synthetic_fdt()[:100],synthetic_fdt()[:-1]):
            with self.assertRaises(a.Rejected):
                a.audit_fdt(b)
        with self.assertRaisesRegex(a.Rejected,"Parrot"):
            a.audit_fdt(synthetic_fdt().replace(b"qcom,parrot",b"fake,boardz"))

    def test_invalid_abl_and_nonregular_source(self):
        original=bytearray(self.abl.read_bytes())
        struct.pack_into("<H",original,18,62)
        self.abl.write_bytes(original)
        with self.assertRaisesRegex(a.Rejected,"ARM"):
            a.audit_abl(self.abl)
        with self.assertRaises(a.Rejected):
            a.read_regular(Path("/dev/null"),4096,"device")
        symlink=self.directory/"link-to-kernel"
        symlink.symlink_to(self.boot)
        with self.assertRaises(a.Rejected):
            a.read_regular(symlink,8192,"symlink")

    def test_cli_never_authorizes_or_writes_any_artifacts(self):
        before={p.name:a.digest(p.read_bytes()) for p in self.directory.iterdir()}
        result=subprocess.run([sys.executable,str(SCRIPT),
            "--boot",str(self.boot),"--vendor-boot",str(self.vendor),
            "--abl",str(self.abl),"--fdt",str(self.fdt),
            "--bootshim-source",str(self.source),"--bootshim-bin",str(self.shim)],
            cwd=self.directory,capture_output=True,text=True)
        self.assertEqual(result.returncode,2,result.stderr)
        report=json.loads(result.stdout)
        self.assertEqual(report["status"],"BLOCKED")
        self.assertFalse(report["native_uefi_boot_proven"])
        self.assertFalse(report["packager_allowlist_authorized"])
        self.assertEqual(before,{p.name:a.digest(p.read_bytes()) for p in self.directory.iterdir()})
        self.assertFalse(list(self.directory.glob("boot-dizi*")))

    def test_real_saved_dizi_files_when_available_always_blocked(self):
        paths=dict(
            boot=ROOT/"backup/dizi/boot_a.img",
            vendor=ROOT/"backup/dizi/vendor_boot_a.img",
            abl=ROOT/"backup/dizi/abl_a.img",
            fdt=ROOT/"backup/dizi/fdt",
            bootshim_asm=Path("/tmp/dizi-edk2-msm-audit-20261021/tools/BootShim/BootShim.S"),
            bootshim_bin=Path("/tmp/dizi-edk2-msm-audit-20261021/tools/BootShim/BootShim.bin"),
        )
        if not all(p.is_file() for p in paths.values()):
            self.skipTest("local ignored dizi/BootShim snapshots unavailable")
        report=a.analyze(**paths)
        self.assertEqual(report["status"],"BLOCKED")
        self.assertEqual(report["saved_android_boot"]["signature_bytes"],4096)
        self.assertEqual(report["saved_android_boot"]["header_version"],4)
        self.assertEqual(report["saved_vendor_boot"]["header_version"],4)
        self.assertEqual(report["saved_abl"]["elf_machine"],40)
        self.assertEqual(report["saved_fdt"]["dynamic_reserved_nodes"],10)
        self.assertEqual(report["upstream_bootshim_binary"]["fd_destination_pa"],"0xce000000")
        self.assertFalse(report["packager_allowlist_authorized"])


if __name__=="__main__":
    unittest.main(verbosity=2)
