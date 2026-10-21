#include "macos27_entry_stage.h"

/* The SHA256 of Apple's actual 26A434 decompressed VMAPPLE Mach-O, established
 * in the existing BuildManifest/provenance audit; not the IMG4 wrapper hash. */
static const uint8_t known_sha256[32] = {
    0xca,0x55,0xea,0x8c,0x4c,0x86,0x17,0x0e,
    0x87,0x03,0x80,0xae,0x55,0x01,0xb8,0xb4,
    0x3a,0xdb,0x2d,0x2d,0x3d,0xb2,0x8b,0xe4,
    0x53,0x1b,0x30,0x40,0x65,0x3b,0xe2,0x03
};
static const uint32_t sha_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static uint32_t u32le(const uint8_t *p)
{ return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24; }
static uint32_t u32be(const uint8_t *p)
{ return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | (uint32_t)p[3]; }
static uint64_t u64be(const uint8_t *p)
{ return ((uint64_t)u32be(p)<<32) | u32be(p+4); }
static uint32_t rotr(uint32_t x, unsigned b) { return (x>>b) | (x<<(32-b)); }
static void clear_bytes(void *dst,size_t size)
{
    volatile uint8_t *p=dst;
    for (size_t i=0;i<size;++i) p[i]=0;
}
static void copy_bytes(void *dst,const void *src,size_t size)
{
    volatile uint8_t *d=dst;
    const uint8_t *s=src;
    for (size_t i=0;i<size;++i) d[i]=s[i];
}
static int fits(uint64_t off, uint64_t n, uint64_t cap)
{ return off<=cap && n<=cap-off; }
static int intersect(uint64_t a, uint64_t n, uint64_t b, uint64_t m)
{
    return n>UINT64_MAX-a || m>UINT64_MAX-b ||
           (n && m && a<b+m && b<a+n);
}
static int contains(uint64_t base, uint64_t n, uint64_t a, uint64_t m)
{ return a>=base && fits(a-base,m,n); }
static int disjoint(const void *a, size_t an, const void *b, size_t bn)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x<=UINTPTR_MAX-an && y<=UINTPTR_MAX-bn &&
           !(an && bn && x<y+bn && y<x+an);
}
static int equals(const uint8_t *p, size_t n, const char *s)
{
    size_t i=0;
    while (i<n && s[i] && p[i]==(uint8_t)s[i]) ++i;
    return i<n && p[i]==0 && s[i]==0;
}
static uint64_t roundup(uint64_t value)
{ return value<=UINT64_MAX-0x3fff ? (value+0x3fff)&~UINT64_C(0x3fff) : 0; }

static void hash_block(uint32_t state[8], const uint8_t *block)
{
    uint32_t w[64],a,b,c,d,e,f,g,h;
    for (unsigned j=0;j<16;++j) w[j]=u32be(block+4*j);
    for (unsigned j=16;j<64;++j) {
        uint32_t s0=rotr(w[j-15],7)^rotr(w[j-15],18)^(w[j-15]>>3);
        uint32_t s1=rotr(w[j-2],17)^rotr(w[j-2],19)^(w[j-2]>>10);
        w[j]=w[j-16]+s0+w[j-7]+s1;
    }
    a=state[0];b=state[1];c=state[2];d=state[3];
    e=state[4];f=state[5];g=state[6];h=state[7];
    for (unsigned j=0;j<64;++j) {
        uint32_t x=rotr(e,6)^rotr(e,11)^rotr(e,25);
        uint32_t y=(e&f)^(~e&g);
        uint32_t t1=h+x+y+sha_k[j]+w[j];
        uint32_t z=rotr(a,2)^rotr(a,13)^rotr(a,22);
        uint32_t t2=z+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    state[0]+=a;state[1]+=b;state[2]+=c;state[3]+=d;
    state[4]+=e;state[5]+=f;state[6]+=g;state[7]+=h;
}
static int authentic_bytes(const uint8_t *input)
{
    uint32_t state[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                       0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    const uint32_t length=M27_STAGE_VMAPPLE_BYTES;
    for (uint32_t offset=0;offset+64<=length;offset+=64)
        hash_block(state,input+offset);
    uint8_t last[128];
    clear_bytes(last,sizeof(last));
    uint32_t remainder=length&63u;
    for (uint32_t j=0;j<remainder;++j) last[j]=input[(length&~63u)+j];
    last[remainder]=0x80;
    uint32_t padded=remainder>=56 ? 128 : 64;
    uint64_t nbits=(uint64_t)length*8;
    for (unsigned i=0;i<8;++i) last[padded-1-i]=(uint8_t)(nbits>>(8*i));
    hash_block(state,last);
    if (padded==128) hash_block(state,last+64);
    uint8_t mismatch=0;
    for (unsigned i=0;i<32;++i)
        mismatch|=(uint8_t)(state[i/4]>>(24-8*(i%4)))^known_sha256[i];
    return mismatch==0;
}

/* Reject malformed/truncated FDT, missing chosen initrd, missing containing
 * /memory/reg, and ANY overlap with DT reserve map and /reserved-memory reg.
 * Support only observed dizi root and reserved 2-address/2-size cells. */
static int check_fdt(const struct m27_entry_stage_request *r,
                     uint64_t dest_end)
{
    const uint8_t *b=r->fdt;
    size_t size=r->fdt_capacity;
    if (!b || size<40 || size>M27_STAGE_MAX_DTB ||
        u32be(b)!=0xd00dfeed) return 0;
    uint32_t total=u32be(b+4), offstruct=u32be(b+8),
             offstrings=u32be(b+12), offreserve=u32be(b+16),
             version=u32be(b+20), lenstrings=u32be(b+32),
             lenstruct=u32be(b+36);
    if (version<17 || total<40 || total>size ||
        !fits(offstruct,lenstruct,total) || !fits(offstrings,lenstrings,total) ||
        offreserve<40 || !fits(offreserve,16,total) ||
        offstruct<offreserve) return 0;
    int ended=0;
    for (uint32_t cur=offreserve;fits(cur,16,offstruct);cur+=16) {
        uint64_t address=u64be(b+cur),bytes=u64be(b+cur+8);
        if (!address && !bytes) { ended=1;break; }
        if (!bytes || bytes>UINT64_MAX-address ||
            intersect(M27_STAGE_BASE,dest_end-M27_STAGE_BASE,address,bytes))
            return 0;
    }
    if (!ended) return 0;
    uint32_t depth=0,cur=offstruct,end=offstruct+lenstruct;
    uint32_t root_addr=0,root_size=0,res_addr=0,res_size=0;
    int chosen=0,memory=0,reserved=0,found_memory=0,found_reserved=0;
    int child_has_reg=0;
    int have_start=0,have_end=0,finished=0;
    uint64_t initrd_start=0,initrd_end=0;
    while (cur+4<=end) {
        uint32_t token=u32be(b+cur);cur+=4;
        if (token==1) {
            uint32_t start=cur;
            while (cur<end && b[cur]) ++cur;
            if (cur==end || depth>=16) return 0;
            uint32_t namebytes=cur-start;
            ++cur;
            if (cur>UINT32_MAX-3) return 0;
            cur=(cur+3)&~3u;
            if (cur>end) return 0;
            ++depth;
            if (depth==2) {
                chosen=equals(b+start,namebytes+1,"chosen");
                memory=equals(b+start,namebytes+1,"memory") ||
                       (namebytes>=7 && b[start]=='m' && b[start+1]=='e' &&
                        b[start+2]=='m' && b[start+3]=='o' && b[start+4]=='r' &&
                        b[start+5]=='y' && b[start+6]=='@');
                reserved=equals(b+start,namebytes+1,"reserved-memory");
                if (reserved) found_reserved=1;
            }
            if (depth==3 && reserved) child_has_reg=0;
            if (depth>3 && reserved) return 0;
        } else if (token==2) {
            if (!depth) return 0;
            if (depth==3 && reserved && !child_has_reg &&
                r->dynamic_reservations_attested!=1) return 0;
            if (depth==2) chosen=memory=reserved=0;
            --depth;
        } else if (token==3) {
            if (!fits(cur,8,end)) return 0;
            uint32_t len=u32be(b+cur),nameoff=u32be(b+cur+4);
            cur+=8;
            if (!fits(cur,len,end) || nameoff>=lenstrings) return 0;
            uint32_t nameidx=offstrings+nameoff,stop=nameidx;
            while (stop<offstrings+lenstrings && b[stop]) ++stop;
            if (stop==offstrings+lenstrings) return 0;
            const uint8_t *value=b+cur;
            int reg=equals(b+nameidx,stop-nameidx+1,"reg");
            if (depth==1 && len==4) {
                if (equals(b+nameidx,stop-nameidx+1,"#address-cells"))
                    root_addr=u32be(value);
                if (equals(b+nameidx,stop-nameidx+1,"#size-cells"))
                    root_size=u32be(value);
            }
            if (depth==2 && reserved && len==4) {
                if (equals(b+nameidx,stop-nameidx+1,"#address-cells"))
                    res_addr=u32be(value);
                if (equals(b+nameidx,stop-nameidx+1,"#size-cells"))
                    res_size=u32be(value);
            }
            if (depth==2 && chosen && (len==4 || len==8)) {
                uint64_t v=len==4 ? u32be(value):u64be(value);
                if (equals(b+nameidx,stop-nameidx+1,"linux,initrd-start"))
                    {initrd_start=v;have_start=1;}
                if (equals(b+nameidx,stop-nameidx+1,"linux,initrd-end"))
                    {initrd_end=v;have_end=1;}
            }
            if (reg && ((depth==2 && memory) || (depth==3 && reserved))) {
                if (depth==3) child_has_reg=1;
                if ((depth==2 && (root_addr!=2 || root_size!=2)) ||
                    (depth==3 && (res_addr!=2 || res_size!=2)) ||
                    !len || (len&15)) return 0;
                for (uint32_t i=0;i<len;i+=16) {
                    uint64_t address=u64be(value+i),bytes=u64be(value+i+8);
                    if (!bytes || bytes>UINT64_MAX-address) return 0;
                    if (depth==2) {
                        if (contains(address,bytes,M27_STAGE_BASE,
                                     dest_end-M27_STAGE_BASE)) found_memory=1;
                    } else if (intersect(M27_STAGE_BASE,dest_end-M27_STAGE_BASE,
                                         address,bytes)) return 0;
                }
            }
            if (len>UINT32_MAX-cur-3) return 0;
            cur=(cur+len+3)&~3u;
            if (cur>end) return 0;
        } else if (token==4) {
            continue;
        } else if (token==9) {
            if (depth) return 0;
            finished=1;break;
        } else return 0;
    }
    return finished && found_memory && found_reserved &&
           res_addr==2 && res_size==2 &&
           root_addr==2 && root_size==2 &&
           have_start && have_end && initrd_start==r->initrd_pa &&
           initrd_end>=initrd_start &&
           initrd_end-initrd_start==r->initrd_size;
}

static int eligible(const struct m27_entry_stage_request *r,
                    const struct mac27_kc_plan *p,
                    struct m27_entry_stage_plan *stage)
{
    uint64_t top=p->kernel_end_pa;
    if (top<=M27_STAGE_BASE || top> M27_STAGE_BASE+M27_STAGE_BYTES)
        return M27_STAGE_RAM;
    stage->loaded_pa_end=top;
    if (r->stage_boot_args) {
        if (!r->adt || !r->adt_size || r->adt_size>UINT32_MAX ||
            r->adt_verified!=1 || (r->command_line_size && !r->command_line))
            return M27_STAGE_BOOT_ARGS;
        stage->adt_pa=roundup(top);
        if (!stage->adt_pa || r->adt_size>UINT64_MAX-stage->adt_pa)
            return M27_STAGE_RAM;
        stage->boot_args_pa=roundup(stage->adt_pa+r->adt_size);
        if (!stage->boot_args_pa ||
            stage->boot_args_pa>UINT64_MAX-MAC27_KC_PAGE)
            return M27_STAGE_RAM;
        top=stage->boot_args_pa+MAC27_KC_PAGE;
        struct mac27_boot_params params;
        clear_bytes(&params,sizeof(params));
        uint8_t output[MAC27_BOOT_ARGS_SIZE];
        params.virt_base=p->virt_base;
        params.phys_base=M27_STAGE_BASE;
        params.mem_size=params.mem_size_actual=M27_STAGE_BYTES;
        params.device_tree_pa=stage->adt_pa;
        params.device_tree_length=(uint32_t)r->adt_size;
        params.boot_args_pa=stage->boot_args_pa;
        params.top_of_kernel_data=top;
        params.command_line=r->command_line;
        params.command_line_length=r->command_line_size;
        if (mac27_encode_boot_args(output,sizeof(output),&params))
            return M27_STAGE_BOOT_ARGS;
    } else if (r->adt || r->adt_size || r->adt_verified ||
               r->command_line || r->command_line_size) return M27_STAGE_BOOT_ARGS;
    if (top>M27_STAGE_BASE+M27_STAGE_BYTES) return M27_STAGE_RAM;
    stage->stage_end_pa=top;
    stage->stage_boot_args=r->stage_boot_args;
    if (!check_fdt(r,top)) return M27_STAGE_FDT;
    if (intersect(M27_STAGE_BASE,top-M27_STAGE_BASE,
                  r->initrd_pa,r->initrd_size) ||
        intersect(M27_STAGE_BASE,top-M27_STAGE_BASE,
                  r->fdt_pa,r->fdt_capacity)) return M27_STAGE_OVERLAP;
    for (uint32_t i=0;i<r->excluded_count;++i) {
        const struct m27_stage_span *s=&r->excluded[i];
        if (!s->size || s->size>UINT64_MAX-s->pa ||
            intersect(M27_STAGE_BASE,top-M27_STAGE_BASE,s->pa,s->size))
            return M27_STAGE_OVERLAP;
    }
    return M27_STAGE_OK;
}

int m27_entry_stage_plan(const struct m27_entry_stage_request *r,
                         struct m27_entry_stage_plan *out)
{
    struct m27_entry_stage_plan candidate;
    clear_bytes(&candidate,sizeof(candidate));
    if (!r || !out || !r->initrd || !r->fdt ||
        !disjoint(out,sizeof(*out),r,sizeof(*r)) ||
        !disjoint(out,sizeof(*out),r->initrd,r->initrd_size) ||
        !disjoint(out,sizeof(*out),r->fdt,r->fdt_capacity) ||
        (r->excluded_count && !r->excluded) ||
        r->excluded_count>M27_STAGE_MAX_EXCLUSIONS ||
        (r->excluded_count && !disjoint(out,sizeof(*out),r->excluded,
                                        r->excluded_count*sizeof(*r->excluded))) ||
        (r->adt && !disjoint(out,sizeof(*out),r->adt,r->adt_size)) ||
        (r->command_line && !disjoint(out,sizeof(*out),r->command_line,
                                      r->command_line_size)))
        return M27_STAGE_ARGUMENT;
    if (r->exclusive_writable_ram!=1 ||
        r->dynamic_reservations_attested>1) return M27_STAGE_RAM;
    if (r->initrd_size<M27_STAGE_VMAPPLE_BYTES ||
        r->initrd_size>MAC27_KC_MAX_BYTES ||
        !fits(r->initrd_pa,r->initrd_size,UINT64_MAX) ||
        r->fdt_capacity<40 || r->fdt_capacity>M27_STAGE_MAX_DTB ||
        !fits(r->fdt_pa,r->fdt_capacity,UINT64_MAX))
        return M27_STAGE_ARGUMENT;
    /* We must parse FDT before touching a large potentially stale initrd. */
    if (!check_fdt(r,M27_STAGE_BASE+MAC27_KC_PAGE))
        return M27_STAGE_FDT;
    const uint8_t *input=r->initrd;
    int plausible=0, trusted=0;
    for (size_t pos=0;pos<=r->initrd_size-M27_STAGE_VMAPPLE_BYTES;++pos) {
        if (input[pos]!=0xcf || input[pos+1]!=0xfa ||
            input[pos+2]!=0xed || input[pos+3]!=0xfe) continue;
        const uint8_t *kc=input+pos;
        struct mac27_kc_plan p;
        if (mac27_kc_plan(kc,M27_STAGE_VMAPPLE_BYTES,M27_STAGE_BASE,
                          M27_STAGE_BYTES,&p) ||
            p.cpu_subtype!=UINT32_C(0xc0000002) ||
            p.fileset_count!=216 || p.segment_count!=7 ||
            p.entry_va!=M27_STAGE_VMA2_ENTRY) continue;
        plausible=1;
        if (!authentic_bytes(kc)) continue;
        if (trusted++) return M27_STAGE_KC_TRUST; /* ambiguous duplicate */
        copy_bytes(&candidate.kc,&p,sizeof(p));
        candidate.initrd_kc_offset=pos;
    }
    if (!trusted) return plausible ? M27_STAGE_KC_TRUST:M27_STAGE_NO_KC;
    const uint8_t *kc=input+candidate.initrd_kc_offset;
    if (mac27_kc_inspect_fixups(kc,M27_STAGE_VMAPPLE_BYTES,
            M27_STAGE_BASE,M27_STAGE_BYTES,&candidate.fixups) ||
        candidate.fixups.unauthenticated!=89086 ||
        candidate.fixups.authenticated!=599964 ||
        candidate.fixups.nonzero_cache_level)
        return M27_STAGE_KC_TRUST;
    /* Actual first instruction at 26A434 XNU entry: B +0x3bf0.
     * Keep it byte-identical; a separately guarded module can instrument
     * the B target with BRK, after this module finishes. */
    uint64_t entry_file=UINT64_MAX,target_file=UINT64_MAX;
    uint64_t target_va=M27_STAGE_VMA2_FIRST_TARGET;
    for (uint32_t i=0;i<candidate.kc.segment_count;++i) {
        const struct mac27_kc_segment *s=&candidate.kc.segments[i];
        if (!(s->protection&4)) continue;
        if (contains(s->vmaddr,s->filesize,candidate.kc.entry_va,4))
            entry_file=s->fileoff+candidate.kc.entry_va-s->vmaddr;
        if (contains(s->vmaddr,s->filesize,target_va,4))
            target_file=s->fileoff+target_va-s->vmaddr;
    }
    if (entry_file==UINT64_MAX || target_file==UINT64_MAX ||
        u32le(kc+entry_file)!=UINT32_C(0x14000efc) ||
        !fits(target_file,4,M27_STAGE_VMAPPLE_BYTES) ||
        target_va-candidate.kc.entry_va!=UINT64_C(0x3bf0))
        return M27_STAGE_KC_ENTRY;
    candidate.first_b_pa=candidate.kc.entry_pa;
    candidate.first_b_target_pa=M27_STAGE_BASE+
        target_va-candidate.kc.virt_base;
    int err=eligible(r,&candidate.kc,&candidate);
    if (err) return err;
    candidate.native_entry_permitted=0;
    candidate.authenticated_pointers_unresolved=1;
    const uint8_t *bytes=(const uint8_t *)&candidate;
    uint8_t *dest=(uint8_t *)out;
    for (size_t i=0;i<sizeof(candidate);++i) dest[i]=bytes[i];
    return M27_STAGE_OK;
}

int m27_entry_stage_copy(const struct m27_entry_stage_request *r,
                         const struct m27_entry_stage_plan *approved,
                         void *window, size_t capacity)
{
    struct m27_entry_stage_plan verified;
    struct mac27_kc_plan loaded;
    uint8_t encoded[MAC27_BOOT_ARGS_SIZE];
    if (!r || !approved || !window || !capacity ||
        !disjoint(window,capacity,r,sizeof(*r)) ||
        !disjoint(window,capacity,approved,sizeof(*approved)) ||
        !disjoint(window,capacity,r->initrd,r->initrd_size) ||
        !disjoint(window,capacity,r->fdt,r->fdt_capacity) ||
        (r->excluded_count && r->excluded &&
         !disjoint(window,capacity,r->excluded,
                   r->excluded_count*sizeof(*r->excluded))) ||
        (r->adt && !disjoint(window,capacity,r->adt,r->adt_size)) ||
        (r->command_line && !disjoint(window,capacity,
                                      r->command_line,r->command_line_size)))
        return M27_STAGE_ARGUMENT;
    int err=m27_entry_stage_plan(r,&verified);
    if (err) return err;
    const uint8_t *a=(const uint8_t *)approved,*b=(const uint8_t *)&verified;
    for (size_t i=0;i<sizeof(verified);++i)
        if (a[i]!=b[i]) return M27_STAGE_STALE;
    if (verified.stage_end_pa-M27_STAGE_BASE>capacity)
        return M27_STAGE_CAPACITY;
    if (verified.stage_boot_args) {
        struct mac27_boot_params params;
        clear_bytes(&params,sizeof(params));
        params.virt_base=verified.kc.virt_base;
        params.phys_base=M27_STAGE_BASE;
        params.mem_size=params.mem_size_actual=M27_STAGE_BYTES;
        params.device_tree_pa=verified.adt_pa;
        params.device_tree_length=(uint32_t)r->adt_size;
        params.boot_args_pa=verified.boot_args_pa;
        params.top_of_kernel_data=verified.stage_end_pa;
        params.command_line=r->command_line;
        params.command_line_length=r->command_line_size;
        if (mac27_encode_boot_args(encoded,sizeof(encoded),&params))
            return M27_STAGE_BOOT_ARGS;
    }
    const uint8_t *kc=(const uint8_t *)r->initrd+verified.initrd_kc_offset;
    if (mac27_kc_load(kc,M27_STAGE_VMAPPLE_BYTES,
                       M27_STAGE_BASE,M27_STAGE_BYTES,
                       window,capacity,&loaded)) return M27_STAGE_CAPACITY;
    if (verified.stage_boot_args) {
        uint8_t *dst=(uint8_t *)window;
        uint64_t adtoff=verified.adt_pa-M27_STAGE_BASE;
        uint64_t boot=verified.boot_args_pa-M27_STAGE_BASE;
        for (size_t i=0;i<r->adt_size;++i) dst[adtoff+i]=((const uint8_t *)r->adt)[i];
        for (size_t i=0;i<MAC27_KC_PAGE;++i) dst[boot+i]=0;
        for (size_t i=0;i<sizeof(encoded);++i) dst[boot+i]=encoded[i];
    }
    return M27_STAGE_OK;
}
