#include "nvt_session_0120.h"
#include "nvt_session_xnu_0120.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

struct mock {
    unsigned page, write, verify, downs, ups;
    int fail_write, fail_boot;
    uint16_t x, y;
};
static int page(void *c, uint32_t addr) { struct mock *m=c; ++m->page; return addr > 0xffffffu; }
static int write_sram(void *c, uint8_t off, const uint8_t *b, size_t n)
{ struct mock *m=c; ++m->write; return m->fail_write || off > 127 || !b || n == 0 || n > 128; }
static int verify(void *c, uint8_t fwv)
{ struct mock *m=c; ++m->verify; return m->fail_boot || fwv != 0x12; }
static void contact(void *c, unsigned id, bool down, unsigned x, unsigned y)
{ struct mock *m=c; assert(id < 10); if (down) ++m->downs; else ++m->ups; m->x=x; m->y=y; }
static void le32(uint8_t *p, uint32_t value)
{ for (int i=0;i<4;++i) p[i]=(uint8_t)(value>>(8*i)); }
static void fake_fw(uint8_t *buf)
{
    memset(buf,0,8192); le32(buf,0x30); /* 2 normal parts, no info headers */
    le32(buf+0x00,0x40); le32(buf+0x04,0x2000); le32(buf+0x08,1);
    le32(buf+0x0c,0x50); le32(buf+0x10,0x3000); le32(buf+0x14,1);
    buf[4096]=0x12; buf[4097]=0xed;
    memcpy(buf+8189,"NVT",3);
}
static struct dizi_nvt0120_lease all_proofs(void)
{
    return (struct dizi_nvt0120_lease){true,true,true,true,true,true,true,true};
}
static void valid_frame(uint8_t *p)
{
    memset(p,0,108);
    p[1] = (1u << 3)|1u; /* finger ID 1 down */
    p[2]=0x13;p[3]=0x88; /* x=5000 => 500 */
    p[4]=0x27;p[5]=0x10; /* y=10000 => 1000 */
    unsigned checksum=0;
    for(unsigned i=1;i<65;i++) checksum+=p[i];
    p[65]=(uint8_t)(0u-checksum);
}
int main(void)
{
    uint8_t firmware[8192],packet[108]; fake_fw(firmware);
    struct mock m={0};
    struct dizi_nvt0120_ops ops={&m,page,write_sram,verify,contact};
    struct dizi_nvt0120_lease proof=all_proofs();
    struct dizi_nvt0120_session s={0};
    assert(DIZI_NVT0120_NATIVE_TRANSPORT_READY == 0);
    assert(dizi_nvt0120_kernel_state() == DIZI_NVT0120_STOPPED);
    assert(dizi_nvt0120_kernel_start(&proof, &ops, firmware, sizeof(firmware)) < 0);
    assert(dizi_nvt0120_kernel_frame(packet, sizeof(packet)) < 0);
    assert(dizi_nvt0120_kernel_state() == DIZI_NVT0120_STOPPED);
    for(unsigned missing=0;missing<8;++missing) {
        struct dizi_nvt0120_lease deny=proof;
        bool *flags[] = {&deny.smmu_gpi_sid416_owned,
            &deny.smmu_qup_sid403_owned, &deny.gpi_event_ring_owned,
            &deny.qup_data_iova_mapped, &deny.se9_gcc_tlmm_owned,
            &deny.irq54_owned, &deny.spi_chip_identity_read,
            &deny.no_other_touch_reader};
        *flags[missing] = false;
        assert(dizi_nvt0120_start(&s,&deny,&ops,firmware,sizeof(firmware))<0);
        assert(s.state==DIZI_NVT0120_STOPPED && m.write==0);
    }
    assert(dizi_nvt0120_start(&s,&proof,&ops,firmware,4096)<0);
    assert(dizi_nvt0120_start(&s,&proof,&ops,firmware,sizeof(firmware))==0);
    assert(s.state==DIZI_NVT0120_ACTIVE && m.page==2 && m.write==2 && m.verify==1);
    assert(dizi_nvt0120_start(&s,&proof,&ops,firmware,sizeof(firmware))<0);
    valid_frame(packet);
    assert(dizi_nvt0120_frame(&s,packet,sizeof(packet))==0);
    assert(m.downs==1 && m.x==500 && m.y==1000);
    assert(dizi_nvt0120_frame(&s,packet,sizeof(packet))==0 && m.downs==1);
    uint8_t bad[108];memcpy(bad,packet,sizeof(bad));bad[2]^=0x80;
    for(unsigned n=0;n<9;++n)assert(dizi_nvt0120_frame(&s,bad,sizeof(bad))<0);
    assert(m.ups==0 && s.active_mask==1);
    assert(dizi_nvt0120_frame(&s,bad,sizeof(bad))<0);
    assert(m.ups==1 && s.active_mask==0);
    assert(dizi_nvt0120_frame(&s,packet,sizeof(packet))==0 && m.downs==2);
    dizi_nvt0120_stop(&s);assert(m.ups==2 && s.state==DIZI_NVT0120_STOPPED);
    m.fail_write=1;
    assert(dizi_nvt0120_start(&s,&proof,&ops,firmware,sizeof(firmware))<0);
    assert(s.state==DIZI_NVT0120_FAILED);
    assert(dizi_nvt0120_start(&s,&proof,&ops,firmware,sizeof(firmware))<0);
    dizi_nvt0120_stop(&s);
    m.fail_write=0;m.fail_boot=1;
    assert(dizi_nvt0120_start(&s,&proof,&ops,firmware,sizeof(firmware))<0);
    assert(s.state==DIZI_NVT0120_FAILED);
    dizi_nvt0120_stop(&s);
    puts("PASS: 0120 firmware upload/boot handshake, contact parsing, 8 ownership negatives, poison/release");
    return 0;
}
