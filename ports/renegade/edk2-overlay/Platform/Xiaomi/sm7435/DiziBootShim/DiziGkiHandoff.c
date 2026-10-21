/** @file
  dizi strict FD source and pre-SEC read-only planner, NOT a boot enabler.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include "DiziGkiHandoff.h"

/* The compiler may lower large aggregate zeroing/copying to libc calls,
   including in -ffreestanding mode. Keep this source standalone. Weak
   linkage permits an EDK2 build to supply its independently reviewed
   stronger freestanding memory primitives. No allocation or MMIO. */
__attribute__((weak)) void *memset(void *to, int value, size_t count) {
  volatile uint8_t *out=(volatile uint8_t *)to;
  size_t i;
  for (i=0;i<count;i++) out[i]=(uint8_t)value;
  return to;
}
__attribute__((weak)) void *memcpy(void *to, const void *from, size_t count) {
  volatile uint8_t *out=(volatile uint8_t *)to;
  const volatile uint8_t *in=(const volatile uint8_t *)from;
  size_t i;
  for (i=0;i<count;i++)out[i]=in[i];
  return to;
}

#define FDT_MAGIC UINT32_C(0xd00dfeed)
#define FDT_BEGIN_NODE 1
#define FDT_END_NODE 2
#define FDT_PROP 3
#define FDT_NOP 4
#define FDT_END 9
#define MAX_NESTING 32

static uint32_t be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static uint64_t be64(const uint8_t *p) {
  return ((uint64_t)be32(p) << 32) | be32(p + 4);
}
static uint32_t le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t le64(const uint8_t *p) {
  return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32);
}
static int same(const char *a, const char *b) {
  while (*a && *b && *a == *b) { a++; b++; }
  return *a == *b;
}
static int begins(const char *a, const char *b) {
  while (*b && *a == *b) { a++; b++; }
  return !*b;
}
static int bytes_are(const uint8_t *p, uint8_t value, size_t n) {
  while (n--) if (*p++ != value) return 0;
  return 1;
}
static int overlaps(uint64_t a, uint64_t n, uint64_t b, uint64_t m) {
  return n && m && a < b + m && b < a + n;
}

/* Small stack-only SHA-256; no libc, globals, heap, or hardware writes. */
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
static uint32_t rr(uint32_t n, unsigned k) {
  return (n >> k) | (n << (32 - k));
}
static void sha_block(uint32_t h[8], const uint8_t *p) {
  uint32_t w[64], a,b,c,d,e,f,g,z;
  unsigned i;
  for (i=0;i<16;i++) w[i]=be32(p+4*i);
  for (i=16;i<64;i++) {
    uint32_t x=w[i-15], y=w[i-2];
    w[i]=(rr(y,17)^rr(y,19)^(y>>10))+w[i-7]+
         (rr(x,7)^rr(x,18)^(x>>3))+w[i-16];
  }
  a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];z=h[7];
  for (i=0;i<64;i++) {
    uint32_t t1=z+(rr(e,6)^rr(e,11)^rr(e,25))+
                ((e&f)^(~e&g))+sha_k[i]+w[i];
    uint32_t t2=(rr(a,2)^rr(a,13)^rr(a,22))+
                ((a&b)^(a&c)^(b&c));
    z=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
  }
  h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;
  h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=z;
}
static void sha256(const uint8_t *p, size_t n, uint8_t output[32]) {
  uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                 0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  uint8_t tail[128]={0};
  size_t left=n, i;
  while (left>=64) {sha_block(h,p);p+=64;left-=64;}
  for (i=0;i<left;i++) tail[i]=p[i];
  tail[left]=0x80;
  if (left>=56) sha_block(h,tail);
  if (left>=56) for (i=0;i<56;i++) tail[i]=0;
  {uint64_t bits=((uint64_t)n)*8;
   for (i=0;i<8;i++) tail[56+i]=(uint8_t)(bits>>(56-8*i));}
  sha_block(h,tail);
  for (i=0;i<8;i++) {
    output[i*4]=(uint8_t)(h[i]>>24);
    output[i*4+1]=(uint8_t)(h[i]>>16);
    output[i*4+2]=(uint8_t)(h[i]>>8);
    output[i*4+3]=(uint8_t)h[i];
  }
}

typedef struct {
  uint64_t chosen_start,chosen_end;
  uint8_t chosen_start_seen,chosen_end_seen;
  uint8_t compatible_ok,root_addr2,root_size2;
  uint8_t reserve_addr2,reserve_size2;
  uint8_t memory_covers_fd;
  uint32_t dynamic_reserved_count;
} FDT_EVIDENCE;

static int apply_reg(const uint8_t *p, size_t n, int memory,
                     FDT_EVIDENCE *ev) {
  size_t pos;
  if (n==0 || n%16!=0) return 0;
  for (pos=0;pos<n;pos+=16) {
    uint64_t pa=be64(p+pos), size=be64(p+pos+8);
    if (size > UINT64_MAX-pa) return 0;
    if (memory) {
      if (pa<=DIZI_FD_BASE && DIZI_EARLY_REGION_END<=pa+size)
        ev->memory_covers_fd=1;
    } else {
      if (!size || overlaps(pa,size,DIZI_FD_BASE,
                            DIZI_EARLY_REGION_END-DIZI_FD_BASE))
        return 0;
    }
  }
  return 1;
}

static int fdt_evidence(const uint8_t *dtb, size_t capacity,
                        FDT_EVIDENCE *ev) {
  uint32_t totalsize,offstr,offstruct,offreserve,size_str,size_struct;
  uint32_t pos,end;
  uint8_t in_reserved_child[MAX_NESTING]={0};
  uint8_t child_has_reg[MAX_NESTING]={0};
  unsigned depth=0;
  const uint8_t *strings;
  char names[MAX_NESTING][64]={{0}};
  int ended=0;
  if (!dtb || capacity<40 || capacity>DIZI_GKI_MAX_DTB ||
      be32(dtb)!=FDT_MAGIC || be32(dtb+20)<17) return 0;
  totalsize=be32(dtb+4);offstruct=be32(dtb+8);
  offstr=be32(dtb+12);offreserve=be32(dtb+16);
  size_str=be32(dtb+32);size_struct=be32(dtb+36);
  if (totalsize<40 || totalsize>capacity || offstruct<40 ||
      offstr<40 || offstruct>totalsize ||
      size_struct>totalsize-offstruct || offstr>totalsize ||
      size_str>totalsize-offstr || offreserve<40 ||
      offreserve>=offstruct || offreserve%8) return 0;
  {
    size_t r=offreserve;
    int terminated=0;
    while (r+16<=offstruct) {
      uint64_t pa=be64(dtb+r),sz=be64(dtb+r+8);
      r+=16;
      if (!pa && !sz) {terminated=1;break;}
      if (!sz || sz>UINT64_MAX-pa ||
          overlaps(pa,sz,DIZI_FD_BASE,
                   DIZI_EARLY_REGION_END-DIZI_FD_BASE)) return 0;
    }
    if (!terminated) return 0;
  }
  strings=dtb+offstr;
  pos=offstruct;end=offstruct+size_struct;
  while (pos+4<=end) {
    uint32_t tag=be32(dtb+pos);pos+=4;
    if (tag==1) {
      unsigned i=0;
      if (depth>=MAX_NESTING || pos>=end) return 0;
      while (pos+i<end && i<63 && dtb[pos+i]) {
        names[depth][i]=(char)dtb[pos+i];i++;
      }
      if (pos+i>=end || dtb[pos+i]!=0) return 0;
      names[depth][i]=0;
      pos=(pos+i+4)&~3u;
      if (pos>end) return 0;
      in_reserved_child[depth]=(depth==2 && same(names[1],"reserved-memory"));
      child_has_reg[depth]=0;
      depth++;
    } else if (tag==2) {
      if (!depth) return 0;
      depth--;
      if (in_reserved_child[depth] && !child_has_reg[depth]) {
        if (ev->dynamic_reserved_count==UINT32_MAX) return 0;
        ev->dynamic_reserved_count++;
      }
    } else if (tag==3) {
      uint32_t len,nameoff;
      size_t strend=0;
      const char *name;
      const uint8_t *value;
      if (!depth || pos+8>end) return 0;
      len=be32(dtb+pos);nameoff=be32(dtb+pos+4);pos+=8;
      if (len>end-pos || nameoff>=size_str) return 0;
      while (nameoff+strend<size_str && strings[nameoff+strend])
        strend++;
      if (nameoff+strend==size_str) return 0;
      name=(const char *)(strings+nameoff);value=dtb+pos;
      if (depth==1 && same(name,"#address-cells"))
        ev->root_addr2=(len==4 && be32(value)==2);
      if (depth==1 && same(name,"#size-cells"))
        ev->root_size2=(len==4 && be32(value)==2);
      if (depth==1 && same(name,"compatible")) {
        size_t i=0;
        while (i<len) {
          size_t n=i;
          while (n<len && value[n])n++;
          if (n==len) return 0;
          if (n-i==11) {
            const char *want="qcom,parrot";
            size_t k=0;
            while (k<n-i && value[i+k]==(uint8_t)want[k])k++;
            if (k==n-i)ev->compatible_ok=1;
          }
          i=n+1;
        }
      }
      if (depth==2 && same(names[1],"reserved-memory") &&
          same(name,"#address-cells"))
        ev->reserve_addr2=(len==4 && be32(value)==2);
      if (depth==2 && same(names[1],"reserved-memory") &&
          same(name,"#size-cells"))
        ev->reserve_size2=(len==4 && be32(value)==2);
      if (depth==2 && same(name,"reg") &&
          (same(names[1],"memory") || begins(names[1],"memory@"))) {
        if (!apply_reg(value,len,1,ev))return 0;
      }
      if (depth==3 && same(names[1],"reserved-memory") &&
          same(name,"reg")) {
        if (child_has_reg[2] || !apply_reg(value,len,0,ev))return 0;
        child_has_reg[2]=1;
      }
      if (depth==2 && same(names[1],"chosen")) {
        if (same(name,"linux,initrd-start") ||
            same(name,"linux,initrd-end")) {
          uint64_t v;
          if (len!=4 && len!=8) return 0;
          v=len==4 ? be32(value) : be64(value);
          if (same(name,"linux,initrd-start")) {
            if (ev->chosen_start_seen++)return 0;
            ev->chosen_start=v;
          } else {
            if (ev->chosen_end_seen++)return 0;
            ev->chosen_end=v;
          }
        }
      }
      pos=(pos+len+3)&~3u;
    } else if (tag==4) {
      continue;
    } else if (tag==9) {
      if (depth) return 0;
      ended=1;break;
    } else return 0;
  }
  return ended && ev->compatible_ok && ev->root_addr2 && ev->root_size2 &&
         ev->reserve_addr2 && ev->reserve_size2 && ev->memory_covers_fd &&
         ev->chosen_start_seen==1 && ev->chosen_end_seen==1 &&
         ev->chosen_start<ev->chosen_end;
}

static int valid_fd(const uint8_t *fv) {
  uint16_t sum=0;
  uint32_t header;
  size_t j;
  uint32_t vector=le32(fv);
  uint32_t branch_to;
  if ((vector>>26)!=5 || (le32(fv+40)!=UINT32_C(0x4856465f)))
    return 0;
  /* Real AArch64 SEC FV: GenFv patches the first 8-byte zero vector with
     B SEC_ENTRY. It is NOT all zero; see GenFvInternalLib.c. */
  branch_to=(vector&0x03ffffffu)*4;
  if (branch_to<72 || branch_to>=DIZI_FD_SIZE || (branch_to&3))
    return 0;
  if (le64(fv+32)!=DIZI_FD_SIZE || fv[54]!=0 || fv[55]!=2) return 0;
  header=(uint32_t)(fv[48]|((uint32_t)fv[49]<<8));
  if (header<72 || header>4096 || (header&1) || branch_to<header)
    return 0;
  if (bytes_are(fv+16,0,16) || bytes_are(fv+branch_to,0xff,4) ||
      bytes_are(fv+branch_to,0,4))return 0;
  for (j=0;j<header;j+=2)
    sum+=(uint16_t)(fv[j]|((uint16_t)fv[j+1]<<8));
  if (sum!=0 || le32(fv+56)!=1024 || le32(fv+60)!=4096 ||
      le32(fv+64)!=0 || le32(fv+68)!=0) return 0;
  return 1;
}

int dizi_gki_fd_plan(const DIZI_GKI_REQUEST *r, DIZI_GKI_PLAN *plan) {
  FDT_EVIDENCE ev={0};
  DIZI_GKI_PLAN result={0};
  size_t i,found=0, untrusted_fv=0;
  if (!r || !plan || !r->fdt || !r->initrd ||
      r->fdt_capacity<40 || r->fdt_capacity>DIZI_GKI_MAX_DTB ||
      r->initrd_bytes<DIZI_FD_SIZE ||
      r->initrd_bytes>DIZI_GKI_MAX_INITRD ||
      r->initrd_physical>UINT64_MAX-r->initrd_bytes)
    return DIZI_GKI_BAD_REQUEST;
  if (!fdt_evidence(r->fdt,r->fdt_capacity,&ev))
    return DIZI_GKI_BAD_FDT;
  if (ev.chosen_start!=r->initrd_physical ||
      ev.chosen_end!=r->initrd_physical+r->initrd_bytes)
    return DIZI_GKI_INITRD_MISMATCH;
  if (overlaps(r->initrd_physical,r->initrd_bytes,DIZI_FD_BASE,
               DIZI_EARLY_REGION_END-DIZI_FD_BASE))
    return DIZI_GKI_MEMORY_CONFLICT;
  for (i=0;i<=r->initrd_bytes-DIZI_FD_SIZE;i++) {
    const uint8_t *p=r->initrd+i;
    if (p[40]=='_' && p[41]=='F' && p[42]=='V' && p[43]=='H' &&
        valid_fd(p)) {
      uint8_t hash[32];
      unsigned j;
      untrusted_fv++;
      sha256(p,DIZI_FD_SIZE,hash);
      for (j=0;j<32 && hash[j]==r->exact_fd_sha256[j];j++) {}
      if (j==32) {
        if (++found>1)return DIZI_GKI_FD_AMBIGUOUS;
        result.source_offset=i;
        result.fd_bytes=DIZI_FD_SIZE;
        result.fd_destination_pa=DIZI_FD_BASE;
        result.sec_branch_word=le32(p);
        result.sec_branch_target_offset=(le32(p)&0x03ffffffu)*4;
        result.dynamic_reservation_count=ev.dynamic_reserved_count;
        for (j=0;j<32;j++)result.actual_sha256[j]=hash[j];
      }
    }
  }
  if (!found)return untrusted_fv ? DIZI_GKI_FD_HASH : DIZI_GKI_FD_MISSING;
  /* No live executable permission/physical ownership attestation is in FDT.
     A copied private buffer is not proof either. NEVER authorize BR. */
  result.authorized_to_copy_or_execute=0;
  *plan=result;
  return DIZI_GKI_LAYOUT_UNAUTHORIZED;
}

int dizi_gki_copy_to_private(const DIZI_GKI_REQUEST *r,
                             const DIZI_GKI_PLAN *p,
                             uint8_t *dst, size_t cap) {
  DIZI_GKI_PLAN checked={0};
  size_t i;
  uintptr_t a,b;
  if (!r || !p || !dst || cap<DIZI_FD_SIZE)
    return DIZI_GKI_BAD_REQUEST;
  if (dizi_gki_fd_plan(r,&checked)!=DIZI_GKI_LAYOUT_UNAUTHORIZED)
    return DIZI_GKI_FD_INVALID;
  if (checked.source_offset!=p->source_offset ||
      checked.fd_bytes!=p->fd_bytes ||
      checked.fd_destination_pa!=p->fd_destination_pa ||
      checked.sec_branch_word!=p->sec_branch_word ||
      checked.sec_branch_target_offset!=p->sec_branch_target_offset ||
      checked.dynamic_reservation_count!=p->dynamic_reservation_count ||
      p->authorized_to_copy_or_execute)
    return DIZI_GKI_FD_INVALID;
  for (i=0;i<32;i++)
    if (checked.actual_sha256[i]!=p->actual_sha256[i])
      return DIZI_GKI_FD_HASH;
  a=(uintptr_t)dst;b=(uintptr_t)r->initrd;
  if (a>UINTPTR_MAX-DIZI_FD_SIZE ||
      b>UINTPTR_MAX-r->initrd_bytes ||
      (a<b+r->initrd_bytes && b<a+DIZI_FD_SIZE))
    return DIZI_GKI_MEMORY_CONFLICT;
  b=(uintptr_t)r->fdt;
  if (b>UINTPTR_MAX-r->fdt_capacity ||
      (a<b+r->fdt_capacity && b<a+DIZI_FD_SIZE))
    return DIZI_GKI_MEMORY_CONFLICT;
  for (i=0;i<DIZI_FD_SIZE;i++)dst[i]=r->initrd[p->source_offset+i];
  return DIZI_GKI_LAYOUT_UNAUTHORIZED;
}
