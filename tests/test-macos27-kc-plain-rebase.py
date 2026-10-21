#!/usr/bin/env python3
"""Independent dyld format-8 oracle against the genuine 26A434 collections.

No KC/image files are modified. Original Apple dyld header:
  dyld/include/mach-o/fixup-chains.h
  dyld_chained_ptr_64_kernel_cache_rebase (target:30, cacheLevel:2,
  diversity:16, addrDiv:1, key:2, next:12, isAuth:1).
"""
from __future__ import annotations

import mmap
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PORT = ROOT / "ports/macos27"
TEST = ROOT / "tests/test-macos27-kc-plain-rebase.c"
REAL = ROOT / "research/macos27-26A434"
R64 = struct.Struct("<Q").unpack_from
R32 = struct.Struct("<I").unpack_from
R16 = struct.Struct("<H").unpack_from
COUNTS = {"vma2": (89086, 599964), "mac13g": (111542, 901819)}


def oracle_samples(data: mmap.mmap, target: Path, name: str) -> tuple[int, int]:
    """Parse ALL chains independently; sample both auth and plain sites."""
    assert R32(data, 0)[0] == 0xFEEDFACF
    cmds = R32(data, 16)[0]
    pos, segments, filesets, fixup = 32, [], [], None
    for _ in range(cmds):
        command, cmdsize = struct.unpack_from("<II", data, pos)
        if command == 0x19:
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", data, pos + 24)
            segments.append((vmaddr, vmsize, fileoff, filesize))
        elif command == 0x80000034:
            fixup = struct.unpack_from("<II", data, pos + 8)
        elif command == 0x80000035:
            filesets.append(R64(data, pos + 16)[0])
        pos += cmdsize
    assert fixup is not None and segments and filesets
    fixoff, fixsize = fixup
    first_base = segments[0][0]
    vm_base = first_base & ~0x1FFFFFF
    starts = R32(data, fixoff + 4)[0]
    count = R32(data, fixoff + starts)[0]
    assert count == len(segments)
    observed = [0, 0]
    sampled = 0
    straddled = 0
    with target.open("w", encoding="ascii") as stream:
        for si, seg in enumerate(segments):
            relative = R32(data, fixoff + starts + 4 + si * 4)[0]
            if not relative:
                continue
            base = fixoff + starts + relative
            pagesize, fmt = struct.unpack_from("<HH", data, base + 4)
            seg_delta = R64(data, base + 8)[0]
            pages = R16(data, base + 20)[0]
            assert fmt == 8 and pagesize == 16384
            assert seg_delta == seg[0] - first_base
            aux = base + 22 + pages * 2
            for page in range(pages):
                first = R16(data, base + 22 + page * 2)[0]
                if first == 0xFFFF:
                    continue
                if first & 0x8000:
                    index, starts_for_page = first & 0x7FFF, []
                    while True:
                        item = R16(data, aux + index * 2)[0]
                        starts_for_page.append(item & 0x7FFF)
                        index += 1
                        if item & 0x8000:
                            break
                else:
                    starts_for_page = [first]
                for chain_start in starts_for_page:
                    offset = chain_start
                    while True:
                        file_off = seg[2] + page * pagesize + offset
                        raw = R64(data, file_off)[0]
                        auth = (raw >> 63) & 1
                        level = (raw >> 30) & 3
                        next_link = (raw >> 51) & 0xFFF
                        assert level == 0
                        result = first_base + (raw & ((1 << 30) - 1))
                        assert any(v <= result < v + sz for v, sz, _, _ in segments)
                        if offset + 8 > pagesize:
                            straddled += 1
                        assert not any(file_off < edge < file_off + 8 for edge in filesets)
                        observed[auth] += 1
                        # A deterministic spacing independent of C's walker.
                        include = (observed[auth] <= 8 or
                                   observed[auth] % (503 if auth == 0 else 5003) == 0 or
                                   offset + 8 > pagesize)
                        if include:
                            window_off = seg[0] - vm_base + page * pagesize + offset
                            expected = raw if auth else result
                            stream.write(f"{file_off:x} {window_off:x} {raw:x} {expected:x}\n")
                            sampled += 1
                        if not next_link:
                            break
                        offset += next_link * 4
                        assert offset < pagesize
    expected = COUNTS[name]
    assert tuple(observed) == expected, (name, observed, expected)
    assert straddled >= 1, (name, straddled)
    assert sampled > 100
    print(f"PASS Python oracle {name}: {observed[0]:,} plain / {observed[1]:,} PAC, "
          f"{sampled} samples, {straddled} page-crossing entries")
    return tuple(observed)


def main() -> None:
    host = shutil.which("clang")
    cross = shutil.which("aarch64-linux-gnu-gcc")
    linker = shutil.which("aarch64-linux-gnu-ld")
    nm = shutil.which("aarch64-linux-gnu-nm")
    assert host and cross and linker and nm, "clang and GCC AArch64 cross tools are required"
    srcs = [PORT / "kc_plain_rebase.c", PORT / "kc_fixups.c", PORT / "kc_loader.c"]
    with tempfile.TemporaryDirectory(prefix="mac27-plain-worker8-") as td:
        temp = Path(td)
        exe = temp / "plain"
        subprocess.run([
            host, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
            *(str(s) for s in srcs), str(PORT / "boot_args.c"), str(TEST),
            "-o", str(exe),
        ], check=True)
        subprocess.run([str(exe)], check=True)
        objs = []
        for idx, source in enumerate(srcs):
            obj = temp / f"mac27-{idx}.o"
            subprocess.run([
                cross, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
                "-mgeneral-regs-only", "-mstrict-align", "-c", str(source),
                "-o", str(obj),
            ], check=True)
            objs.append(obj)
        rel = temp / "freestanding-rebase.o"
        subprocess.run([linker, "-r", *(str(o) for o in objs), "-o", str(rel)], check=True)
        unknown = subprocess.check_output([nm, "-u", str(rel)], text=True)
        assert not unknown.strip(), unknown
        print("PASS AArch64 freestanding: linked rebase + inspector + loader; zero undefined symbols")
        for name in ("vma2", "mac13g"):
            path = REAL / f"kernel.{name}.macho/kernelcache.release.{name}.decompressed"
            if not path.is_file():
                print(f"SKIP {name}: genuine decompressed KC not present")
                continue
            samples = temp / f"samples-{name}.txt"
            with path.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
                oracle_samples(data, samples, name)
            subprocess.run([str(exe), str(path), str(samples)], check=True)
    print("PASS format8 plain rebase offline; PAC encodings still require runtime signing")


if __name__ == "__main__":
    main()
