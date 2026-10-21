#include "../shim/macos27_entry_stage.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOW_INITRD UINT64_C(0xb7200000)
#define LOW_FDT UINT64_C(0xa8000000)

static void be32(unsigned char *p, uint32_t x)
{
    for (unsigned j=0;j<4;++j) p[j]=(unsigned char)(x>>(24-8*j));
}
static void be64(unsigned char *p, uint64_t x)
{
    be32(p,(uint32_t)(x>>32)); be32(p+4,(uint32_t)x);
}
static void property(unsigned char *b, size_t *pos, uint32_t nameoff,
                     const unsigned char *bytes, uint32_t len)
{
    be32(b+*pos,3);be32(b+*pos+4,len);be32(b+*pos+8,nameoff);*pos+=12;
    memcpy(b+*pos,bytes,len);*pos+=len;
    *pos=(*pos+3)&~(size_t)3;
}
static void node(unsigned char *b,size_t *pos,const char *name)
{
    be32(b+*pos,1);*pos+=4;
    size_t len=strlen(name)+1;
    memcpy(b+*pos,name,len);*pos+=len;
    *pos=(*pos+3)&~(size_t)3;
}
static void end_node(unsigned char *b,size_t *pos)
{ be32(b+*pos,2);*pos+=4; }
static size_t fdt_make(unsigned char *buf,size_t capacity,uint64_t initrd_size,
                       uint64_t reserved_pa)
{
    assert(capacity>=512);
    memset(buf,0,capacity);
    static const char strings[] =
        "#address-cells\0#size-cells\0linux,initrd-start\0linux,initrd-end\0reg\0";
    const uint32_t offs_addr=0, offs_size=15, offs_start=27,
                   offs_end=46, offs_reg=63;
    unsigned char cells[16];
    size_t p=128;
    node(buf,&p,"");
    be32(cells,2);property(buf,&p,offs_addr,cells,4);
    property(buf,&p,offs_size,cells,4);
    node(buf,&p,"chosen");
    be64(cells,LOW_INITRD);property(buf,&p,offs_start,cells,8);
    be64(cells,LOW_INITRD+initrd_size);property(buf,&p,offs_end,cells,8);
    end_node(buf,&p);
    node(buf,&p,"memory");
    be64(cells,M27_STAGE_BASE);be64(cells+8,UINT64_C(0xc0000000));
    property(buf,&p,offs_reg,cells,16);
    end_node(buf,&p);
    node(buf,&p,"reserved-memory");
    be32(cells,2);property(buf,&p,offs_addr,cells,4);
    property(buf,&p,offs_size,cells,4);
    node(buf,&p,"firmware@0");
    if (reserved_pa!=UINT64_MAX) {
        be64(cells,reserved_pa);be64(cells+8,0x10000);
        property(buf,&p,offs_reg,cells,16);
    }
    end_node(buf,&p);
    end_node(buf,&p);
    end_node(buf,&p);
    be32(buf+p,9);p+=4;
    size_t str=p;
    memcpy(buf+str,strings,sizeof(strings));
    size_t total=str+sizeof(strings);
    be32(buf,0xd00dfeed);be32(buf+4,(uint32_t)total);
    be32(buf+8,128);be32(buf+12,(uint32_t)str);be32(buf+16,64);
    be32(buf+20,17);be32(buf+24,16);
    be32(buf+32,sizeof(strings));be32(buf+36,(uint32_t)(str-128));
    return total;
}

static unsigned char *load_file(const char *path,size_t *sz)
{
    FILE *f=fopen(path,"rb"); assert(f);
    assert(!fseek(f,0,SEEK_END));
    long len=ftell(f);assert(len==M27_STAGE_VMAPPLE_BYTES);
    rewind(f);
    unsigned char *b=malloc((size_t)len);assert(b);
    assert(fread(b,(size_t)len,1,f)==1);
    assert(!fclose(f));
    *sz=(size_t)len;
    return b;
}
static uint32_t le32(const unsigned char *b)
{ return (uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24; }

static int stage_bad(struct m27_entry_stage_request *req)
{
    struct m27_entry_stage_plan r;
    memset(&r,0xa6,sizeof(r));
    int err=m27_entry_stage_plan(req,&r);
    assert(err);
    for (size_t i=0;i<sizeof(r);++i)
        assert(((unsigned char *)&r)[i]==0xa6);
    return err;
}

static void real(const char *path)
{
    size_t len=0;
    unsigned char *kc=load_file(path,&len);
    enum {PREFIX=79,SUFFIX=37};
    unsigned char *initrd=malloc(PREFIX+M27_STAGE_VMAPPLE_BYTES+SUFFIX);
    assert(initrd);
    memset(initrd,0x34,PREFIX+len+SUFFIX);
    /* Plausible but truncated magic before genuine fileset. */
    memcpy(initrd+3,"\xcf\xfa\xed\xfe",4);
    memcpy(initrd+PREFIX,kc,len);
    unsigned char fdt[768];
    size_t fdt_bytes=fdt_make(fdt,sizeof(fdt),PREFIX+len+SUFFIX,0x81000000);
    struct m27_stage_span exclusions[2]={{LOW_INITRD,PREFIX+len+SUFFIX},
                                          {LOW_FDT,fdt_bytes}};
    struct m27_entry_stage_request req={0};
    req.initrd=initrd;req.initrd_size=PREFIX+len+SUFFIX;
    req.initrd_pa=LOW_INITRD;
    req.fdt=fdt;req.fdt_capacity=fdt_bytes;req.fdt_pa=LOW_FDT;
    req.excluded=exclusions;req.excluded_count=2;
    req.exclusive_writable_ram=1;
    struct m27_entry_stage_plan plan;
    int err=m27_entry_stage_plan(&req,&plan);
    if (err) fprintf(stderr,"genuine entry stage plan failed: %d\n",err);
    assert(!err);
    assert(plan.initrd_kc_offset==PREFIX);
    assert(plan.kc.fileset_count==216 && plan.fixups.pointers==689050);
    assert(plan.first_b_pa==plan.kc.entry_pa);
    assert(plan.first_b_target_pa==M27_STAGE_BASE+
           M27_STAGE_VMA2_FIRST_TARGET-plan.kc.virt_base);
    assert(plan.stage_end_pa==plan.kc.kernel_end_pa);
    assert(plan.native_entry_permitted==0);
    assert(plan.authenticated_pointers_unresolved==1);
    /* Every original file-backed byte, including PAC encodings, must survive
     * unchanged in physical-layout RAM. This proves no fixup was applied. */
    size_t cap=(size_t)(plan.stage_end_pa-M27_STAGE_BASE);
    unsigned char *ram=malloc(cap+1);assert(ram);
    memset(ram,0x63,cap+1);
    assert(!m27_entry_stage_copy(&req,&plan,ram,cap));
    assert(ram[cap]==0x63);
    uint64_t entry_off=plan.first_b_pa-M27_STAGE_BASE;
    assert(le32(ram+entry_off)==UINT32_C(0x14000efc));
    for (uint32_t i=0;i<plan.kc.segment_count;++i) {
        const struct mac27_kc_segment *s=&plan.kc.segments[i];
        assert(!memcmp(ram+(s->vmaddr-plan.kc.virt_base),
                       kc+s->fileoff,(size_t)s->filesize));
    }
    unsigned char *snapshot=malloc(cap);assert(snapshot);
    memcpy(snapshot,ram,cap);
    assert(m27_entry_stage_copy(&req,&plan,ram,cap-1)==M27_STAGE_CAPACITY);
    assert(!memcmp(ram,snapshot,cap));
    struct m27_entry_stage_plan tampered=plan;
    tampered.first_b_pa^=4;
    assert(m27_entry_stage_copy(&req,&tampered,ram,cap)==M27_STAGE_STALE);
    assert(!memcmp(ram,snapshot,cap));
    free(snapshot);
    req.exclusive_writable_ram=0;
    assert(stage_bad(&req)==M27_STAGE_RAM);
    req.exclusive_writable_ram=1;
    req.adt=(const void *)"fake";req.adt_size=4;
    req.stage_boot_args=1;req.adt_verified=0;
    assert(stage_bad(&req)==M27_STAGE_BOOT_ARGS);
    req.adt=NULL;req.adt_size=0;req.stage_boot_args=0;
    exclusions[0].pa=M27_STAGE_BASE+0x40000;
    assert(stage_bad(&req)==M27_STAGE_OVERLAP);
    exclusions[0].pa=LOW_INITRD;
    /* Even if all other layout facts are accepted, a live reserved carveout
     * in the dizi destination must prohibit all KC writes. */
    be64(fdt+64,M27_STAGE_BASE+0x20000);be64(fdt+72,0x8000);
    assert(stage_bad(&req)==M27_STAGE_FDT);
    memset(fdt+64,0,16);
    fdt_bytes=fdt_make(fdt,sizeof(fdt),PREFIX+len+SUFFIX,M27_STAGE_BASE+0x40000);
    req.fdt_capacity=fdt_bytes;exclusions[1].size=fdt_bytes;
    assert(stage_bad(&req)==M27_STAGE_FDT);
    fdt_bytes=fdt_make(fdt,sizeof(fdt),PREFIX+len+SUFFIX,0x81000000);
    req.fdt_capacity=fdt_bytes;exclusions[1].size=fdt_bytes;
    fdt_bytes=fdt_make(fdt,sizeof(fdt),PREFIX+len+SUFFIX,UINT64_MAX);
    req.fdt_capacity=fdt_bytes;exclusions[1].size=fdt_bytes;
    assert(stage_bad(&req)==M27_STAGE_FDT);
    req.dynamic_reservations_attested=1;
    assert(!m27_entry_stage_plan(&req,&plan));
    req.dynamic_reservations_attested=0;
    fdt_bytes=fdt_make(fdt,sizeof(fdt),PREFIX+len+SUFFIX,0x81000000);
    req.fdt_capacity=fdt_bytes;exclusions[1].size=fdt_bytes;
    req.initrd_pa+=4;
    assert(stage_bad(&req)==M27_STAGE_FDT);
    req.initrd_pa-=4;
    initrd[PREFIX+0x10000]^=0x01;
    assert(stage_bad(&req)==M27_STAGE_KC_TRUST);
    initrd[PREFIX+0x10000]^=0x01;
    /* Synthetic opaque ADT exercises only the externally attested optional
     * boot-argument serializer; it is NOT a verified genuine Apple ADT. */
    static const unsigned char stub_adt[] = {0x41,0x44,0x54,0x00,0,0,0,0};
    static const char line[] = "cpus=1 -v";
    req.stage_boot_args=1;req.adt=stub_adt;req.adt_size=sizeof(stub_adt);
    req.adt_verified=1;req.command_line=line;
    req.command_line_size=sizeof(line)-1;
    struct m27_entry_stage_plan with_boot;
    assert(!m27_entry_stage_plan(&req,&with_boot));
    assert(with_boot.stage_boot_args==1 &&
           with_boot.boot_args_pa>with_boot.adt_pa &&
           with_boot.stage_end_pa>with_boot.boot_args_pa);
    size_t expanded=(size_t)(with_boot.stage_end_pa-M27_STAGE_BASE);
    unsigned char *grown=realloc(ram,expanded+1);assert(grown);ram=grown;
    memset(ram,0x66,expanded+1);
    assert(!m27_entry_stage_copy(&req,&with_boot,ram,expanded));
    assert(ram[expanded]==0x66);
    assert(!memcmp(ram+(with_boot.adt_pa-M27_STAGE_BASE),
                   stub_adt,sizeof(stub_adt)));
    struct mac27_boot_args encoded;
    memcpy(&encoded,ram+(with_boot.boot_args_pa-M27_STAGE_BASE),sizeof(encoded));
    assert(encoded.virt_base==with_boot.kc.virt_base);
    assert(encoded.phys_base==M27_STAGE_BASE);
    assert(encoded.device_tree_va==with_boot.kc.virt_base+
           with_boot.adt_pa-M27_STAGE_BASE);
    assert(encoded.device_tree_length==sizeof(stub_adt));
    assert(!strcmp(encoded.command_line,line));
    assert(with_boot.native_entry_permitted==0);
    puts("PASS genuine 26A434 VMAPPLE: SHA256 attested, GKI prefix discovered, B instruction unchanged, PAC opaque");
    free(ram);free(initrd);free(kc);
}
int main(int argc,char **argv)
{
    if (argc==2) real(argv[1]);
    else puts("SKIP real KC missing; AArch64 compilation still available");
    return 0;
}
