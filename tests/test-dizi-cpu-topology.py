#!/usr/bin/env python3
"""Independent offline ADT/XNU topology verification for 0107; NO hardware."""
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import adt
import mkadt

spec = importlib.util.spec_from_file_location('dizi_topology', ROOT / 'tools/mkadt-dizi-topology.py')
topo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(topo)


def number(n, key):
    value = n.prop(key)
    assert value is not None and len(value) == 4, (n.name, key, value)
    return struct.unpack('<I', value)[0]


def verify(tree, experimental):
    cpus = next(n for n in tree.children if n.name == 'cpus')
    profile = json.loads((ROOT / 'boards/dizi.json').read_text())
    assert profile['ipados_cmdline'].find('cpus=1') != -1
    assert profile['bringup_cmdline'].find('cpus=1') != -1
    assert 'dizismpclusters=1' not in profile['ipados_cmdline']
    assert 'dizismpclusters=1' not in profile['bringup_cmdline']
    assert len(cpus.children) == 8
    for i, core in enumerate(cpus.children):
        p = i // 4
        assert core.name == f'cpu{i}'
        assert number(core, 'reg') == profile['cpu_mpidrs'][i] == 0x100 * i
        assert number(core, 'cpu-id') == i
        assert number(core, 'l2-cache-id') == i
        assert number(core, 'l3-cache-id') == 0
        assert number(core, 'clock-frequency') == profile['cpu_max_hz'][p]
        assert core.prop('state') == (b'running\0' if i == 0 else b'stopped\0')
        assert core.prop('compatible').find(b'arm,cortex-a55' if p == 0 else b'arm,cortex-a78') >= 0
        if experimental:
            assert number(core, 'cluster-id') == p
            assert number(core, 'die-cluster-id') == p
            assert number(core, 'cluster-core-id') == i % 4
            assert number(core, 'cluster-type') == ord('E' if p == 0 else 'P')
            assert number(core, 'capacity-dmips-mhz') == (0x400 if p == 0 else 0x799)
            assert number(core, 'dizi,topology-v1') == 1
        else:
            assert number(core, 'cluster-id') == 0
            assert number(core, 'cluster-type') == 0
            assert number(core, 'cluster-core-id') == i
            assert core.prop('dizi,topology-v1') is None
    return cpus


evidence = topo.live_core_evidence()
assert evidence == [(i, i * 0x100, 0x400 if i < 4 else 0x799) for i in range(8)]
# The version-controlled, identity-free FDT CPU excerpt must agree with the
# actual saved live FDT when the latter is locally available.
assert topo.live_core_evidence(topo.FDT_EXCERPT) == evidence
if topo.LIVE_FDT.is_file():
    assert topo.live_core_evidence(topo.LIVE_FDT) == evidence
seed = b'\xa5' * 64
plain = mkadt.build(board='dizi', seed=seed)
overlay_default = topo.build(experimental=False, seed=seed)
# Strongest check: no regression to the standard dizi ADT for identical seed.
assert adt.serialize(plain) == adt.serialize(overlay_default)
verify(overlay_default, False)
experimental = topo.build(experimental=True, seed=seed)
verify(experimental, True)
legacy_blob = adt.serialize(plain)
experimental_blob = adt.serialize(experimental)
assert legacy_blob != experimental_blob
parsed, offset = adt.parse(experimental_blob)
assert offset == len(experimental_blob)
verify(parsed, True)
assert adt.serialize(parsed) == experimental_blob
# No non-CPU ADT nodes may change: board identity, GIC, display, UFS, boot flags.
for legacy, modern in zip(plain.children, experimental.children):
    assert legacy.name == modern.name
    if legacy.name != 'cpus':
        assert adt.serialize(legacy) == adt.serialize(modern)

patch = (ROOT / 'xnu/patches/0107-dizi-cpu-topology.patch').read_text()
assert 'dizismpclusters' in patch
assert 'cpu_boot_arg > 1' in patch
assert 'dizi_platform == 1' in patch
assert 'cluster_type = 0;' in patch
assert 'MAX_CPU_CLUSTERS               2' in patch
assert 'MAX_CPU_CLUSTERS               1' in patch
assert 'CLUSTER_TYPE_E' in patch and 'CLUSTER_TYPE_P' in patch
assert '__ARM_AMP__' in patch and 'does NOT enable' in patch
assert 'SWEET_SMP_MAX_CPUS' in patch or 'SWEET_SMP_MAX_CPUS' in (ROOT/'research/bt0099/xnu/pexpert/pexpert/arm64/SWEET.h').read_text()

with tempfile.TemporaryDirectory(prefix='dizi-topology-test-') as dirname:
    path = Path(dirname) / 'dizi.adt'
    cmd = [sys.executable, str(ROOT/'tools/mkadt-dizi-topology.py'), str(path), '--experimental-two-cluster']
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    parsed_cmd, used = adt.parse(path.read_bytes())
    assert used == len(path.read_bytes())
    verify(parsed_cmd, True)
    # Unsupported core mapping must be rejected rather than silently guessing.
    bad = Path(dirname) / 'bad.dts'
    bad.write_text(topo.FDT.read_text().replace('capacity-dmips-mhz = <0x799>;',
                                                'capacity-dmips-mhz = <0x111>;', 1))
    try:
        topo.live_core_evidence(bad)
        raise AssertionError('bad hardware map was accepted')
    except ValueError:
        pass
    cmd = [sys.executable, str(ROOT/'tools/mkadt-dizi-topology.py'), str(path)]
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    parsed_cmd, used = adt.parse(path.read_bytes())
    assert used == len(path.read_bytes())
    verify(parsed_cmd, False)

# Host model of the platform's condition: default and cpus=1 never enable E/P.
def xnu_cluster_type(dizi, bootarg, cpus, fdt_type):
    enabled = dizi == 1 and bootarg == 1 and cpus > 1
    return fdt_type if enabled else 0
for cpus in (0, 1):
    for enabled in (0, 1):
        assert xnu_cluster_type(1, enabled, cpus, ord('E')) == 0
        assert xnu_cluster_type(1, enabled, cpus, ord('P')) == 0
for cpu in range(8):
    expected = ord('E') if cpu < 4 else ord('P')
    assert xnu_cluster_type(1, 1, 8, expected) == expected
    assert xnu_cluster_type(1, 0, 8, expected) == 0
    assert xnu_cluster_type(0, 1, 8, expected) == 0

print('PASS 0107 FDT MPIDR/cpu-map capacities; baseline ADT byte-equivalence; opt-in 4E/4P roundtrip; preserved non-CPU ADT; cpus=1 safeguards')
