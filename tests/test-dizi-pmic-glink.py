#!/usr/bin/env python3
"""Check dizi FDT/MiCode source binding and test exact 0105 header under ASan/UBSan."""
from pathlib import Path
import re
import subprocess
import tempfile
root=Path(__file__).resolve().parents[1]
patch=(root/'xnu/patches/0105-dizi-pmic-glink-telemetry.patch').read_text()
start=patch.index('+++ b/iokit/Kernel/arm/DiziPmicTelemetry.h')
header=patch[start:].split('\n',1)[1]
header='\n'.join(row[1:] for row in header.splitlines() if row.startswith('+'))+'\n'
assert '#define DIZI_BC_OWNER       32778u' in header
assert '#define DIZI_BC_BATT_GET    0x30u' in header
assert '#define DIZI_BC_USB_GET     0x32u' in header
assert '#define DIZI_BC_NOTIFY_IND  0x07u' in header
assert 'DIZI_BC_FULL_MASK' in header
fdt_path=root/'research/ipad5/dizi-live.dts'
if fdt_path.is_file():
    fdt=fdt_path.read_text()
    assert 'qcom,pmic-glink-channel = "PMIC_RTR_ADSP_APPS"' in fdt
    assert '"msm/adsp/charger_pd"' in fdt
    assert 'compatible = "qcom,battery-charger"' in fdt
else:
    print('SKIP vendor PMIC FDT cross-check (ignored live FDT absent)',flush=True)
linux_path=root/'research/xiaomi-ruan/drivers/power/supply/qti_battery_charger.c'
if linux_path.is_file():
    linux=linux_path.read_text()
    for label,constant in [('MSG_OWNER_BC','32778'),('BC_BATTERY_STATUS_GET','0x30'),('BC_USB_STATUS_GET','0x32'),('BC_NOTIFY_IND','0x07')]:
        assert re.search(r'#define\s+'+label+r'\s+'+constant+r'\b', linux)
    for label,property_id in [('BATT_STATUS',0),('BATT_PRESENT',2),('BATT_CAPACITY',4),('BATT_VOLT_NOW',7),('BATT_CURR_NOW',9),('BATT_TEMP',12),('BATT_CHG_FULL',17)]:
        src=linux.split('enum battery_property_id {',1)[1].split('};',1)[0]
        names=[s.split(',')[0].strip().split('=')[0].strip() for s in src.splitlines() if s.strip() and not s.lstrip().startswith('/*')]
        assert names[property_id]==label, (property_id,label,names[property_id])
else:
    print('SKIP vendor PMIC driver cross-check (ignored MiCode absent)',flush=True)
assert 'dizi_pmic_glink_receive' in patch
assert 'if (fDizi)' in patch
assert 'dizi_bc_link(&dizi_bc_telemetry, false, false)' in patch
with tempfile.TemporaryDirectory(prefix='dizi-pmic-test-') as tmp:
    td=Path(tmp)
    (td/'DiziPmicTelemetry.h').write_text(header)
    exe=td/'battery-test'
    cmd=['gcc','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(td),str(root/'tests/test_dizi_pmic_glink.c'),'-o',str(exe)]
    subprocess.run(cmd,check=True)
    subprocess.run([str(exe)],check=True)
print('PASS source-grounded Linux/FDT protocol and 0105 host test')
