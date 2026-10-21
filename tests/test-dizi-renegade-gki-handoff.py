#!/usr/bin/env python3
"""End-to-end HOST sandbox and AArch64 object check for dizi raw FD staging.

All FD/FDT are synthetic. Neither an eligible EDK2 build nor runtime
ownership is attested. There is intentionally NO Linux Image/SEC trampoline
until that evidence exists. No fastboot/device/flash/code allowlist.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/"ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435/DiziBootShim/DiziGkiHandoff.c"
HARNESS=ROOT/"tests/test-dizi-renegade-gki-handoff.c"
FD_LEN=0x400000
FD_PA=0x90000000
INITRD_PA=0xb7100000

def synth_fdt(*, initrd_size:int=0, reserved_pa:int=0xb8000000,
              compatible:bytes=b"qcom,parrot\0", dynamic:bool=False,
              initrd_pa:int=INITRD_PA)->bytes:
    keys=[b"#address-cells",b"#size-cells",b"compatible",b"reg",
          b"linux,initrd-start",b"linux,initrd-end"]
    table=b"";indexes={}
    for k in keys:
        indexes[k]=len(table)
        table+=k+b"\0"
    parts=[]
    def tag(v:int)->None:parts.append(struct.pack(">I",v))
    def node(n:bytes)->None:
        tag(1)
        n+=b"\0"
        parts.append(n+b"\0"*((-len(n))%4))
    def prop(k:bytes,v:bytes)->None:
        tag(3)
        parts.append(struct.pack(">II",len(v),indexes[k]))
        parts.append(v+b"\0"*((-len(v))%4))
    def end()->None:tag(2)
    node(b"")
    prop(b"#address-cells",struct.pack(">I",2))
    prop(b"#size-cells",struct.pack(">I",2))
    prop(b"compatible",compatible)
    node(b"memory")
    prop(b"reg",struct.pack(">QQ",0x80000000,0x100000000))
    end()
    node(b"reserved-memory")
    prop(b"#address-cells",struct.pack(">I",2))
    prop(b"#size-cells",struct.pack(">I",2))
    node(b"framebuffer")
    prop(b"reg",struct.pack(">QQ",reserved_pa,0x10000))
    end()
    if dynamic:
        node(b"linux,cma")
        end()
    end()
    node(b"chosen")
    prop(b"linux,initrd-start",struct.pack(">Q",initrd_pa))
    prop(b"linux,initrd-end",struct.pack(">Q",initrd_pa+initrd_size))
    end()
    end()
    tag(9)
    struct_blob=b"".join(parts)
    off_strings=80+len(struct_blob)
    total=off_strings+len(table)
    head=bytearray(80)
    struct.pack_into(">7I",head,0,0xd00dfeed,total,80,off_strings,64,17,16)
    struct.pack_into(">2I",head,32,len(table),len(struct_blob))
    return bytes(head)+struct_blob+table

def synth_fd()->bytes:
    """GenFv-style reset vector branch + checksum and FV block map.

    This is NOT a runnable SEC binary: the branch target contains fixture
    bytes, so staging still cannot be authorized by a static header check.
    """
    b=bytearray(b"\xff"*FD_LEN)
    b[:16]=b"\0"*16
    struct.pack_into("<I",b,0,0x14000040) # B +0x100, SEC candidate
    b[16:32]=bytes(range(1,17))
    struct.pack_into("<Q",b,32,FD_LEN)
    b[40:44]=b"_FVH"
    struct.pack_into("<HH",b,48,72,0)
    b[54]=0;b[55]=2
    struct.pack_into("<IIII",b,56,1024,4096,0,0)
    struct.pack_into("<H",b,50,(-sum(struct.unpack_from("<36H",b)))&0xffff)
    struct.pack_into("<I",b,0x100,0xAA0003E0) # mov x0,x0, NOT an SEC entry proof
    return bytes(b)

class HandoffTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder=tempfile.TemporaryDirectory(prefix="dizi-gki-handoff-")
        root=Path(cls.folder.name)
        cls.host=root/"dizi-gki-hosttest"
        cls.arm=root/"dizi-gki-aarch64.o"
        common=["-O2","-Wall","-Wextra","-Werror","-std=c11",
                "-fno-tree-loop-distribute-patterns"]
        subprocess.run(["gcc",*common,"-fsanitize=address,undefined",
                        "-fno-sanitize-recover=all",str(SOURCE),str(HARNESS),
                        "-o",str(cls.host)],check=True)
        subprocess.run(["aarch64-linux-gnu-gcc",*common,"-ffreestanding",
                        "-fno-builtin","-fno-stack-protector","-mgeneral-regs-only",
                        "-mstrict-align","-c",str(SOURCE),"-o",str(cls.arm)],
                       check=True)
        nm=subprocess.run(["aarch64-linux-gnu-nm","-u",str(cls.arm)],
                          capture_output=True,text=True,check=True)
        if nm.stdout.strip():
            raise AssertionError("undefined runtime libc dependency:\n"+nm.stdout)
        cls.fd=synth_fd()
        cls.fd_sha=hashlib.sha256(cls.fd).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def run_case(self,*,fdt:bytes|None=None,ramdisk:bytes|None=None,
                 digest:str|None=None,physical:int=INITRD_PA,
                 expected:int=1)->None:
        source=(b"VENDOR-GKI-PREFIX"+self.fd if ramdisk is None else ramdisk)
        if fdt is None:
            fdt=synth_fdt(initrd_size=len(source),initrd_pa=physical)
        root=Path(self.folder.name)
        dtb=root/"current.dtb";rd=root/"current.initrd"
        dtb.write_bytes(fdt);rd.write_bytes(source)
        env={**os.environ,"ASAN_OPTIONS":"detect_leaks=1:abort_on_error=1"}
        run=subprocess.run([str(self.host),str(dtb),str(rd),digest or self.fd_sha,
                            hex(physical),str(expected)],capture_output=True,
                           text=True,env=env)
        self.assertEqual(run.returncode,0,run.stdout+"\n"+run.stderr)
        self.assertIn("no live FD write or EDK2 transfer",run.stdout)

    def test_gki_v4_merged_vendor_ramdisk_detects_exact_fd_and_no_execution(self):
        self.run_case()

    def test_dynamic_reserved_memory_is_reported_but_never_authorizes(self):
        ramdisk=b"VENDOR"+self.fd
        self.run_case(ramdisk=ramdisk,
                      fdt=synth_fdt(initrd_size=len(ramdisk),dynamic=True))

    def test_wrong_pinned_sha_refused(self):
        self.run_case(digest="0"*64,expected=-7)

    def test_corrupted_fd_branch_checksum_fv_revision_and_length(self):
        for offset,contents in ((0,b"\x00\x00\x00\x00"),(40,b"FVB!"),
                                (50,b"\x00\x00"),(55,b"\x01"),
                                (32,b"\0"*8),(56,b"\0"*4),
                                (0x100,b"\0"*4)):
            with self.subTest(offset=offset):
                bad=bytearray(self.fd)
                bad[offset:offset+len(contents)]=contents
                self.run_case(ramdisk=b"VENDOR"+bad,expected=-5)

    def test_initrd_bounds_mismatch_rejected(self):
        source=b"VENDOR"+self.fd
        self.run_case(ramdisk=source,
                      fdt=synth_fdt(initrd_size=len(source)+1),expected=-4)

    def test_explicit_candidate_memory_overlap_rejected(self):
        self.run_case(physical=FD_PA,expected=-9)
        source=b"VENDOR"+self.fd
        self.run_case(ramdisk=source,
                      fdt=synth_fdt(initrd_size=len(source),reserved_pa=FD_PA),
                      expected=-2)

    def test_wrong_board_fdt_truncated_and_fdt_root(self):
        src=b"VENDOR"+self.fd
        self.run_case(ramdisk=src,
                      fdt=synth_fdt(initrd_size=len(src),compatible=b"qcom,other\0"),
                      expected=-2)
        self.run_case(ramdisk=src,
                      fdt=synth_fdt(initrd_size=len(src))[:-8],expected=-2)

    def test_absent_fd_in_gki_ramdisk(self):
        source=b"X"*FD_LEN
        self.run_case(ramdisk=source,expected=-5)

    def test_real_saved_stock_headers_do_not_grant_sec_entry(self):
        boot=ROOT/"backup/dizi/boot_a.img"
        if not boot.is_file():
            self.skipTest("captured dizi boot_a missing")
        with boot.open("rb") as stream:
            header=stream.read(64)
        self.assertEqual(header[:8],b"ANDROID!")
        self.assertEqual(struct.unpack_from("<I",header,40)[0],4)
        self.assertEqual(struct.unpack_from("<I",header,20)[0],1584)
        # No _start, fd jump or ARM64 Linux Image is emitted by the C planner.

if __name__=="__main__":
    unittest.main(verbosity=2)
