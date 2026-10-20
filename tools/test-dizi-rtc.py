#!/usr/bin/env python3
"""Host test directly extracts the new 0101 RTC C code with fake v7 observer.

No actual hardware access. Extracts implementation from patched TU (rather than
rewriting a reference algorithm in Python), including the two snapshot reads.
"""
from pathlib import Path
import re
import subprocess
import tempfile
root = Path(__file__).resolve().parents[1]
patch = (root/'xnu/patches/0101-dizi-rtc-read.patch').read_text()
# All RTC logic in this patch is new; extract its added lines exactly.
src = ''.join(line[1:] for line in patch.splitlines(keepends=True) if line.startswith('+') and not line.startswith('+++'))
fdt=(root/'research/ipad5/dizi-live.dts').read_text()
linux=(root/'research/xiaomi-ruan/drivers/rtc/rtc-pm8xxx.c').read_text()
rtc_node=re.search(r'rtc@6100\s*\{(.*?)\};',fdt,re.S)
assert rtc_node and 'qcom,pmk8350-rtc' in rtc_node.group(1)
assert 'reg = <0x6100 0x6200>;' in rtc_node.group(1)
linux_regs=re.search(r'pmk8350_regs = \{(.*?)\};',linux,re.S)
assert linux_regs
for name,value in [('ctrl','0x6146'),('read','0x6148'),('write','0x6140'),('alarm_rw','0x6240')]:
    assert re.search(fr'\.{name}\s*=\s*{value}\s*,',linux_regs.group(1))
assert 'rtc@6100' in src and '#define DIZI_RTC_PPID          0x061u' in src
assert '#define DIZI_RTC_CTRL          0x6146u' in src
assert '#define DIZI_RTC_READ          0x6148u' in src
start = src.index('/* DIZI_RTC_TEST_BEGIN')
end = src.index('/* Explicitly opt in:', start)
rtc_code = src[start:end]
defines='\n'.join(line for line in src.splitlines() if line.startswith('#define DIZI_RTC_'))
assert "str %w" not in src  # RTC patch adds no PMIC register writes
assert 'clock_set_calendar_microtime(' not in rtc_code
assert 'sysctl_handle_quad(oidp, &observed, 0, req)' in src
assert 'if (!enabled && !rtc)' in src
assert 'keys_find_apid(DIZI_RTC_PPID, count)' in src
assert 'dizi_rtc_ready = true' in src
assert 'rtc_requested == 1' in src
prelude = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>
'''+defines+r'''
#define KEYS_NO_APID 0xffffu
static uint16_t dizi_rtc_apid = 63u;
struct op { uint16_t reg; uint8_t val; bool ok; };
static struct op ops[400];
static unsigned head, tail;
static void push(uint16_t reg, uint8_t val, bool ok) {
    assert(tail < sizeof(ops)/sizeof(ops[0]));
    ops[tail++] = (struct op){reg,val,ok};
}
static bool keys_read(uint16_t apid, uint16_t addr, uint8_t *out) {
    assert(apid == 63u);
    assert(head < tail);
    struct op op = ops[head++];
    assert(op.reg == addr);
    if (op.ok) *out = op.val;
    return op.ok;
}
static void reset(void) { head = tail = 0; }
static void ctrl(uint8_t val) { push(DIZI_RTC_CTRL,val,true); }
static void raw(uint32_t value, bool low_ok, bool first_ok) {
    uint8_t low = (uint8_t)value;
    for (unsigned i=0;i<4;i++) push(DIZI_RTC_READ+i,(uint8_t)(value>>(8*i)),first_ok || i!=0);
    push(DIZI_RTC_READ,low,low_ok);
}
static void raw_torn(uint32_t value) {
    for (unsigned i=0;i<4;i++) push(DIZI_RTC_READ+i,(uint8_t)(value>>(8*i)),true);
    push(DIZI_RTC_READ,(uint8_t)(value+1),true);
}
static void pair(uint32_t first, uint32_t second) { raw(first,true,true);raw(second,true,true); }
static bool dizi_rtc_sample(uint32_t *out);
static void check(bool expected, uint32_t value) {
    uint32_t got = 0xdecafbad;
    bool ok = dizi_rtc_sample(&got);
    assert(ok == expected);
    if(ok) assert(got==value);
    else assert(got==0xdecafbad); /* invalid data cannot alter output */
    assert(head == tail);
}
'''
# Strict C function declarations for static functions: prelude fake keys_read must precede code.
post = r'''
int main(void) {
    uint8_t b[4]={0x78,0x56,0x34,0x12};
    assert(dizi_rtc_decode(b)==0x12345678u);
    assert(dizi_rtc_valid_pair(1700000000u,1700000000u));
    assert(dizi_rtc_valid_pair(1700000000u,1700000001u));
    assert(!dizi_rtc_valid_pair(1700000001u,1700000000u));
    assert(!dizi_rtc_valid_pair(1700000000u,1700000002u));
    assert(!dizi_rtc_valid_pair(0u,0u));
    assert(!dizi_rtc_valid_pair(DIZI_RTC_MIN_SECONDS-1,DIZI_RTC_MIN_SECONDS-1));
    assert(dizi_rtc_valid_pair(DIZI_RTC_MIN_SECONDS,DIZI_RTC_MIN_SECONDS));
    assert(dizi_rtc_valid_pair(DIZI_RTC_MAX_SECONDS-2,DIZI_RTC_MAX_SECONDS-1));
    assert(!dizi_rtc_valid_pair(DIZI_RTC_MAX_SECONDS-1,DIZI_RTC_MAX_SECONDS));
    reset();ctrl(0x80);pair(1700000000u,1700000000u);check(true,1700000000u);
    reset();ctrl(0x81);pair(1700000000u,1700000001u);check(true,1700000001u);
    reset();ctrl(0x80);pair(0x654321ffu,0x65432200u);check(true,0x65432200u); /* LSB rollover */
    reset();ctrl(0);check(false,0); /* disabled RTC stops before reading seconds */
    reset();push(DIZI_RTC_CTRL,0,false);check(false,0); /* observer/status failure */
    reset();ctrl(0x80);raw_torn(1700000000u);pair(1700000000u,1700000000u);check(true,1700000000u);
    reset();ctrl(0x80);push(DIZI_RTC_READ,0,false);pair(1700000000u,1700000000u);check(true,1700000000u);
    reset();ctrl(0x80);raw(1700000000u,false,true);pair(1700000000u,1700000000u);check(true,1700000000u);
    reset();ctrl(0x80);for(unsigned i=0;i<DIZI_RTC_ATTEMPTS;i++)pair(1700000003u,1700000001u);check(false,0);
    reset();ctrl(0x80);for(unsigned i=0;i<DIZI_RTC_ATTEMPTS;i++)pair(1700000000u,1700000002u);check(false,0);
    reset();ctrl(0x80);for(unsigned i=0;i<DIZI_RTC_ATTEMPTS;i++)pair(0,0);check(false,0);
    reset();ctrl(0x80);for(unsigned i=0;i<DIZI_RTC_ATTEMPTS;i++)pair(DIZI_RTC_MAX_SECONDS,DIZI_RTC_MAX_SECONDS);check(false,0);
    puts("PASS genuine 0101 C RTC parser and observer sampling: decode, pair, rollover, torn/error retry, disable, backward, jump, range and output integrity");
    return 0;
}
'''
# Program includes the actual source code segment after mock definitions.
with tempfile.TemporaryDirectory(prefix='dizi-rtc-host-') as temp:
    out=Path(temp)/'test.c'
    exe=Path(temp)/'test'
    out.write_text(prelude+'\n'+rtc_code+'\n'+post)
    cmd=['gcc','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(out),'-o',str(exe)]
    subprocess.run(cmd,check=True)
    subprocess.run([str(exe)],check=True)
