#!/usr/bin/env python3
"""Symbolicate SWEET console crash reports (patch 0043) typed in from a photo.

  sweet-crash.py CACHE ROOT [REPORT.txt]       (report on stdin if omitted)

Use --symbols-only if ipsw's all-cache ObjC analysis fails. This resolves
the containing image and loads only that image's existing symbols; the
printed offset is relative to the nearest known symbol, not a function-size
check. This mode also works with a read-only shared cache.

CACHE is the dyld_shared_cache_arm64 (in a writable directory: ipsw keeps a
symbol cache next to it), ROOT the mounted iOS root image. Lines look like

  CRASH name[pid] sig 6 code 0x... sub 0x... slide 0x... mh 0x...
  CRASH name pc 0x... lr 0x... sp 0x... fp 0x... far 0x...
  CRASH name bt 0x... 0x... ...

Addresses inside the shared cache are unslid (addr - slide) and resolved
with `ipsw dyld a2s`; addresses in the main binary are shown as offsets
from its Mach-O header (address - mh + 0x100000000, the binary's own
vmaddr) for llvm-objdump of ROOT's executable.
"""
import argparse, bisect, json, re, subprocess, sys

CACHE_LO, CACHE_HI = 0x180000000, 0x300000000


def a2s(cache, addr):
    r = subprocess.run(['ipsw', 'dyld', 'a2s', cache, hex(addr)], capture_output=True, text=True)
    lines = [l for l in r.stdout.splitlines() if l.startswith('0x')]
    return lines[-1].split(': ', 1)[1] if lines else '?'


class ImageSymbols:
    def __init__(self, cache):
        self.cache = cache
        result = subprocess.run(['ipsw', 'dyld', 'info', cache, '--dylibs', '--json'],
                                capture_output=True, text=True, check=True)
        self.images = sorted(json.loads(result.stdout)['dylibs'],
                             key=lambda image: image['load_address'])
        self.bases = [image['load_address'] for image in self.images]
        self.symbols = {}

    def lookup(self, addr):
        index = bisect.bisect_right(self.bases, addr) - 1
        if index < 0:
            return '?'
        image = self.images[index]
        name = image['name']
        if name not in self.symbols:
            result = subprocess.run(['ipsw', 'dyld', 'symaddr', self.cache,
                                     '--image', name], capture_output=True,
                                    text=True, check=True)
            symbols = []
            for line in result.stdout.splitlines():
                match = re.match(r'0x([0-9a-fA-F]+):\s*(.*)', line)
                if match and 'undefined' not in match[2]:
                    symbols.append((int(match[1], 16), match[2]))
            symbols.sort()
            self.symbols[name] = ([address for address, _ in symbols], symbols)
        addresses, symbols = self.symbols[name]
        index = bisect.bisect_right(addresses, addr) - 1
        if index < 0:
            return f'{name} +0x{addr - image["load_address"]:x} (image offset)'
        address, symbol = symbols[index]
        return f'{symbol} +0x{addr - address:x} (nearest symbol in {name})'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cache')
    parser.add_argument('root')
    parser.add_argument('report', nargs='?')
    parser.add_argument('--symbols-only', action='store_true')
    args = parser.parse_args()
    cache = args.cache
    text = open(args.report).read() if args.report else sys.stdin.read()
    resolver = ImageSymbols(cache) if args.symbols_only else None
    resolved = {}
    slide = mh = 0
    # The console can truncate long lines without preserving their newline.
    for line in re.split(r'\n|(?<=[^\n])(?=(?:SMP|CRASH) )', text):
        m = re.search(r'slide (0x[0-9a-f]+) mh (0x[0-9a-f]+)', line)
        if m:
            slide, mh = int(m.group(1), 16), int(m.group(2), 16)
            print(line)
            continue
        print(line)
        for a in re.findall(r'(?:pc|lr|bt|\s)(?: )?(0x[0-9a-f]{6,})', line):
            v = int(a, 16)
            if CACHE_LO <= v - slide < CACHE_HI:
                unslid = v - slide
                if unslid not in resolved:
                    resolved[unslid] = resolver.lookup(unslid) if resolver else a2s(cache, unslid)
                print(f'    {a} = cache {hex(unslid)} {resolved[unslid]}')
            elif mh and mh <= v < mh + 0x10000000:
                print(f'    {a} = main binary {hex(v - mh + 0x100000000)}')


if __name__ == '__main__':
    main()
