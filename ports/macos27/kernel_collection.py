"""Bounded Mach-O/KC reader for actual macOS port inputs.

Offsets in embedded fileset Mach-O segments are collection-relative, not
relative to LC_FILESET_ENTRY.fileoff. No fixups, PAC stripping or writes.
Reference: Apple mach-o/loader.h and dyld/include/mach-o/fixup-chains.h.
This reads structure and version metadata; it does not authenticate Apple
signatures, establish CPU compatibility or make a collection bootable.
"""
from __future__ import annotations

import re
import os
import stat
import struct
from pathlib import Path

MAX_BYTES = 256 * 1024 * 1024
ARM64 = 0x0100000C
MH_EXECUTE, MH_FILESET = 2, 12
LC_SEGMENT_64, LC_UNIXTHREAD = 0x19, 5
LC_FILESET_ENTRY, LC_CHAINED_FIXUPS = 0x80000035, 0x80000034
VERSION = re.compile(rb'Darwin Kernel Version (\d+)\.(\d+)\.(\d+):[^\x00\r\n]{1,300}')
XNU = re.compile(r'root:(xnu-[0-9]+(?:\.[0-9]+)+)~[0-9]+/([A-Z0-9_]+)')


def read_regular(path: Path, limit: int = MAX_BYTES) -> bytes:
    with path.open('rb') as stream:
        # fstat checks the opened file, including when path is a symlink.
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError('Expected a bounded regular artifact file')
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Artifact exceeds size limit')
    return data


def _range(data: bytes, offset: int, size: int) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError('Mach-O range outside artifact')


def _header(data: bytes, offset: int = 0) -> dict:
    _range(data, offset, 32)
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from('<8I', data, offset)
    if magic != 0xFEEDFACF or cpu != ARM64:
        raise ValueError('Expected a little-endian ARM64 Mach-O')
    if count > 4096 or size > 2 * 1024 * 1024 or count * 8 > size:
        raise ValueError('Invalid Mach-O load-command count/size')
    _range(data, offset + 32, size)
    end, cursor = offset + 32 + size, offset + 32
    segments, entries, fixups, threads = [], [], [], []
    for _ in range(count):
        if cursor + 8 > end:
            raise ValueError('Truncated Mach-O command')
        cmd, length = struct.unpack_from('<II', data, cursor)
        if length < 8 or length % 8 or length > end - cursor:
            raise ValueError('Invalid Mach-O command length')
        if cmd == LC_SEGMENT_64:
            if length < 72:
                raise ValueError('Truncated segment command')
            name = data[cursor + 8:cursor + 24].split(b'\0')[0].decode('ascii')
            va, vs, fo, fs, maxprot, prot, nsects, segflags = struct.unpack_from('<4Q4I', data, cursor + 24)
            # Unstripped standalone XNU uses a nonresident __CTF debug segment.
            nonresident_ctf = name == '__CTF' and vs == 0 and segflags & 4
            if 72 + nsects * 80 != length or (fs > vs and not nonresident_ctf) or va + vs > 1 << 64:
                raise ValueError('Invalid segment extent/sections')
            _range(data, fo, fs)
            segments.append(dict(name=name, vmaddr=va, vmsize=vs,
                                 fileoff=fo, filesize=fs, initprot=prot))
        elif cmd == LC_FILESET_ENTRY:
            if length < 40:
                raise ValueError('Truncated fileset entry')
            va, fo, stringoff, pad = struct.unpack_from('<QQII', data, cursor + 8)
            if not 32 <= stringoff < length or pad:
                raise ValueError('Invalid fileset entry identifier')
            namebytes = data[cursor + stringoff:cursor + length]
            if b'\0' not in namebytes:
                raise ValueError('Unterminated fileset entry identifier')
            name = namebytes.split(b'\0')[0].decode('ascii')
            if not name or len(name) > 1024:
                raise ValueError('Invalid fileset entry name')
            _range(data, fo, 32)
            entries.append(dict(name=name, vmaddr=va, fileoff=fo))
        elif cmd == LC_CHAINED_FIXUPS:
            if length != 16:
                raise ValueError('Invalid chained-fixups command')
            fo, fs = struct.unpack_from('<II', data, cursor + 8)
            _range(data, fo, fs)
            fixups.append((fo, fs))
        elif cmd == LC_UNIXTHREAD:
            # Only the ARM_THREAD_STATE64 layout is meaningful for this reader.
            if length < 288:
                raise ValueError('Truncated ARM64 thread state')
            flavor, words = struct.unpack_from('<II', data, cursor + 8)
            if flavor != 6 or words != 68 or length != 16 + words * 4:
                raise ValueError('Unsupported ARM64 thread state')
            threads.append(struct.unpack_from('<Q', data, cursor + 16 + 32 * 8)[0])
        cursor += length
    if cursor != end or len(fixups) > 1 or len(threads) > 1:
        raise ValueError('Ambiguous Mach-O load commands')
    return dict(filetype=kind, cpu_subtype=subtype, segments=segments,
                entries=entries, fixups=fixups, entry=threads[0] if threads else None)


def _chain_layout(data: bytes, image: dict) -> list[dict]:
    """Read starts metadata only. Never interpret an authenticated pointer as raw."""
    if not image['fixups']:
        return []
    base, length = image['fixups'][0]
    if length < 28:
        raise ValueError('Truncated chained-fixups header')
    version, starts, imports, symbols, count, imports_fmt, symbols_fmt = struct.unpack_from('<7I', data, base)
    if version != 0 or not 28 <= starts <= length - 4:
        raise ValueError('Unsupported chained-fixups header')
    if count or imports > length or symbols > length:
        raise ValueError('Imports or invalid fixup offsets require a separate resolver')
    segcount = struct.unpack_from('<I', data, base + starts)[0]
    if segcount != len(image['segments']) or starts + 4 + 4 * segcount > length:
        raise ValueError('Invalid fixup segment table')
    layouts = []
    for index in range(segcount):
        relative = struct.unpack_from('<I', data, base + starts + 4 + 4 * index)[0]
        if relative == 0:
            continue
        pos = starts + relative
        if relative < 4 + 4 * segcount or pos > length - 22:
            raise ValueError('Invalid fixup segment offset')
        size, page_size, fmt, seg_offset, max_valid, pages = struct.unpack_from('<IHHQIH', data, base + pos)
        segment = image['segments'][index]
        if (size < 22 + 2 * pages or size > length - pos or
                page_size not in (4096, 16384) or pages * page_size > segment['vmsize'] or
                seg_offset != segment['vmaddr'] - image['segments'][0]['vmaddr']):
            raise ValueError('Invalid fixup page table')
        layouts.append(dict(segment=segment['name'], pointer_format=fmt,
                            page_size=page_size, page_count=pages, segment_offset=seg_offset))
    return layouts


def inspect(data: bytes) -> dict:
    """Read a standalone kernel or a KC, retaining all fileset providers."""
    if not 64 <= len(data) <= MAX_BYTES:
        raise ValueError('Unsupported or oversized kernel artifact')
    outer = _header(data)
    if outer['filetype'] not in (MH_EXECUTE, MH_FILESET):
        raise ValueError('Expected a kernel executable or kernel collection')
    kernel = outer
    if outer['filetype'] == MH_FILESET:
        names = [e['name'] for e in outer['entries']]
        if len(names) != len(set(names)) or names.count('com.apple.kernel') != 1:
            raise ValueError('Collection must contain one unambiguous com.apple.kernel')
        for entry in outer['entries']:
            mapped = [s for s in outer['segments'] if
                      s['fileoff'] <= entry['fileoff'] and
                      entry['fileoff'] + 32 <= s['fileoff'] + s['filesize'] and
                      s['vmaddr'] + entry['fileoff'] - s['fileoff'] == entry['vmaddr']]
            if len(mapped) != 1:
                raise ValueError('Fileset header is outside its mapped segment')
            embedded = _header(data, entry['fileoff'])
            if embedded['filetype'] not in (MH_EXECUTE, 11):  # MH_KEXT_BUNDLE
                raise ValueError('Invalid embedded fileset Mach-O')
            if entry['name'] == 'com.apple.kernel':
                if embedded['filetype'] != MH_EXECUTE:
                    raise ValueError('com.apple.kernel is not MH_EXECUTE')
                kernel = embedded
    elif outer['entries']:
        raise ValueError('Fileset entries in a standalone executable')
    text = [s for s in kernel['segments'] if s['name'] == '__TEXT' and s['filesize']]
    if len(text) != 1:
        raise ValueError('Kernel __TEXT segment missing or ambiguous')
    seg = text[0]
    versions = {m.group(0).decode('ascii') for m in VERSION.finditer(
        data[seg['fileoff']:seg['fileoff'] + seg['filesize']])}
    if len(versions) != 1:
        raise ValueError('Native kernel Darwin version missing or ambiguous')
    version = versions.pop()
    match, source = VERSION.fullmatch(version.encode('ascii')), XNU.search(version)
    entry = outer['entry']
    if entry is None or not any(s['initprot'] & 4 and s['vmaddr'] <= entry < s['vmaddr'] + s['filesize']
                                for s in outer['segments']):
        raise ValueError('Kernel entry is outside file-backed executable segments')
    return dict(format='MH_FILESET' if outer['filetype'] == MH_FILESET else 'MH_EXECUTE',
                darwin='.'.join(m.decode() for m in match.groups()),
                darwin_major=int(match[1]), version_string=version,
                observed_xnu_tag=source[1] if source else None,
                configuration=source[2] if source else None,
                cpu_subtype=kernel['cpu_subtype'], arm64e=(kernel['cpu_subtype'] & 0xFF) == 2,
                entry_va=entry, segments=outer['segments'],
                fileset_entries=outer['entries'], chained_fixups=_chain_layout(data, outer))
