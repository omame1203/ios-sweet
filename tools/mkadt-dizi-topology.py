#!/usr/bin/env python3
"""Generate dizi ADT with source-verified, *opt-in* two-cluster metadata.

No changes to tools/mkadt.py or boot args. Default output is byte-equivalent
for a fixed seed to mkadt.build(board='dizi'); the experimental topology
requires BOTH this --experimental-two-cluster option and XNU boot arg
`dizismpclusters=1` with `cpus>1`. No PSCI/GICR operation is performed.
"""
import argparse
import json
import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adt
import mkadt

ROOT = Path(__file__).resolve().parents[1]
# Prefer the original ignored live FDT when available. The small tracked
# excerpt contains only its CPU/cache/cpu-map nodes (no device identifiers),
# so experimental ADT generation remains reproducible in a fresh checkout.
LIVE_FDT = ROOT / 'research/ipad5/dizi-live.dts'
FDT_EXCERPT = ROOT / 'tests/fixtures/dizi-cpu-only.dts'
FDT = LIVE_FDT if LIVE_FDT.is_file() else FDT_EXCERPT
BOARD = ROOT / 'boards/dizi.json'


def live_core_evidence(fdt=FDT):
    text = Path(fdt).read_text()
    found = []
    for match in re.finditer(r'\bCPU([0-7]):\s+cpu@([0-9a-f]+)\s*\{(.*?)^\t\t\};', text,
                             re.MULTILINE | re.DOTALL):
        idx, unit, body = int(match.group(1)), int(match.group(2), 16), match.group(3)
        reg = re.search(r'\breg\s*=\s*<0x([0-9a-f]+)\s+0x([0-9a-f]+)>;', body)
        capacity = re.search(r'\bcapacity-dmips-mhz\s*=\s*<0x([0-9a-f]+)>;', body)
        if not reg or not capacity or int(reg.group(1), 16) != 0:
            raise ValueError(f'FDT CPU{idx}: unsupported MPIDR or capacity schema')
        mpidr = int(reg.group(2), 16)
        if unit != mpidr or mpidr != idx << 8:
            raise ValueError(f'FDT CPU{idx}: MPIDR unexpected {mpidr:#x}')
        found.append((idx, mpidr, int(capacity.group(1), 16)))
    if found != [(i, i << 8, 0x400 if i < 4 else 0x799) for i in range(8)]:
        raise ValueError(f'FDT CPU0..7 core/capacity mismatch: {found}')
    segment = text.split('\n\t\tcpu-map {', 1)[1].split('\n\t\t};', 1)[0]
    for cluster, first in [(0, 0), (1, 4)]:
        group = re.search(rf'cluster{cluster}\s*\{{(.*?)\n\t\t\t\}};', segment, re.S)
        if group is None:
            raise ValueError(f'FDT missing CPU cluster{cluster}')
        expected = [f'cpu = <0x{0x19 + first + k:x}>;' for k in range(4)]
        if any(item not in group.group(1) for item in expected):
            raise ValueError(f'FDT unexpected cluster{cluster} core map')
    return found


def apply_dizi_topology(tree, evidence, board=BOARD):
    """Mutates an in-memory dizi ADT. Do not call for sweet/QEMU."""
    profile = json.loads(Path(board).read_text())
    if profile['board'] != 'dizi' or profile['cpu_mpidrs'] != [p for _, p, _ in evidence] or profile['little_cores'] != 4:
        raise ValueError('dizi board CPU profile disagrees with live FDT')
    cpus = next(c for c in tree.children if c.name == 'cpus')
    if len(cpus.children) != 8:
        raise ValueError('dizi ADT CPU count is not eight')
    for i, core in enumerate(cpus.children):
        idx, mpidr, capacity = evidence[i]
        assert idx == i
        if core.name != f'cpu{i}' or core.prop('reg') != mkadt.u32(mpidr):
            raise ValueError(f'ADT cpu{i}: unexpected MPIDR')
        props = {k: v for k, _flags, v in core.props}
        if props['cluster-type'] != mkadt.u32(0):
            raise ValueError('ADT already describes non-legacy cluster type')
        cluster = i // 4
        updates = {
            'cluster-id': mkadt.u32(cluster),        # informative; XNU derives ID from E/P
            'cluster-type': mkadt.u32(ord('E') if cluster == 0 else ord('P')),
            'die-cluster-id': mkadt.u32(cluster),
            'cluster-core-id': mkadt.u32(i % 4),
            'capacity-dmips-mhz': mkadt.u32(capacity),  # source FDT: 1024 / 1945
            'dizi,topology-v1': mkadt.u32(1),         # only in explicitly opted-in ADT
        }
        core.props = [(key, flags, updates.pop(key, value)) for key, flags, value in core.props]
        core.props.extend((key, 0, value) for key, value in updates.items())
    return tree


def build(*, experimental=False, seed=None, product_adt=None, identity=None, wlan_mac=None):
    tree = mkadt.build(board='dizi', seed=seed, product_adt=product_adt,
                       identity=identity, wlan_mac=wlan_mac)
    if experimental:
        apply_dizi_topology(tree, live_core_evidence())
    return tree


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--experimental-two-cluster', action='store_true',
                        help='Opt in to 4x A55 (E) + 4x A78 (P) ADT; kernel also needs dizismpclusters=1, cpus>1')
    parser.add_argument('--identity', choices=('iphone-x', 'ipad5'))
    parser.add_argument('--product-adt')
    parser.add_argument('--wlan-mac-file', type=Path,
                        help='Private raw six-byte unicast MAC, same validation as mkadt.py')
    parser.add_argument('--dump', action='store_true')
    args = parser.parse_args()
    tree = build(experimental=args.experimental_two_cluster,
                 product_adt=args.product_adt, identity=args.identity,
                 wlan_mac=args.wlan_mac_file.read_bytes() if args.wlan_mac_file else None)
    blob = adt.serialize(tree)
    args.output.write_bytes(blob)
    if args.dump:
        adt.dump(adt.parse(blob)[0])
    print(f'{args.output}: {len(blob)} bytes, clusters={"E/P EXPERIMENTAL" if args.experimental_two_cluster else "legacy single SMP"}', file=sys.stderr)
