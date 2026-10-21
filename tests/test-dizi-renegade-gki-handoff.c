/* Portable native unit harness for genuine dizi FDT -> initrd -> FV planner.
   NEVER maps physical memory or transfers to firmware. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435/DiziBootShim/DiziGkiHandoff.h"

static uint8_t *read_file(const char *path, size_t *n) {
  FILE *fp=fopen(path,"rb");
  uint8_t *buf;
  long length;
  assert(fp);
  assert(fseek(fp,0,SEEK_END)==0);
  length=ftell(fp);
  assert(length>0);
  assert(fseek(fp,0,SEEK_SET)==0);
  buf=malloc((size_t)length);
  assert(buf);
  assert(fread(buf,1,(size_t)length,fp)==(size_t)length);
  assert(fclose(fp)==0);
  *n=(size_t)length;
  return buf;
}
static uint64_t number(const char *s) {
  char *end;
  unsigned long long u=strtoull(s,&end,0);
  assert(end && *end==0);
  return (uint64_t)u;
}
static void fromhex(uint8_t h[32],const char *s) {
  unsigned i;
  assert(strlen(s)==64);
  for (i=0;i<32;i++) {
    unsigned c;
    assert(sscanf(s+2*i,"%2x",&c)==1);
    h[i]=(uint8_t)c;
  }
}

int main(int argc,char **argv) {
  DIZI_GKI_REQUEST r={0};
  DIZI_GKI_PLAN p={0},bad;
  uint8_t *owned;
  int expected,actual;
  size_t i;
  if (argc!=6) {
    fputs("usage: test <fdt> <initrd> <hex-sha> <ramdisk-pa> <expected-status>\n",stderr);
    return 2;
  }
  r.fdt=read_file(argv[1],&r.fdt_capacity);
  r.initrd=read_file(argv[2],&r.initrd_bytes);
  fromhex(r.exact_fd_sha256,argv[3]);
  r.initrd_physical=number(argv[4]);
  expected=(int)strtol(argv[5],NULL,0);
  actual=dizi_gki_fd_plan(&r,&p);
  if (actual!=expected) {
    fprintf(stderr,"expected %d, got %d\n",expected,actual);
    abort();
  }
  if (actual==DIZI_GKI_LAYOUT_UNAUTHORIZED) {
    assert(p.authorized_to_copy_or_execute==0);
    assert(p.fd_bytes==DIZI_FD_SIZE);
    assert(p.fd_destination_pa==DIZI_FD_BASE);
    assert(p.sec_branch_target_offset>=72);
    assert(p.sec_branch_target_offset<DIZI_FD_SIZE);
    assert(p.source_offset+DIZI_FD_SIZE<=r.initrd_bytes);
    owned=malloc(DIZI_FD_SIZE);
    assert(owned);
    memset(owned,0xa5,DIZI_FD_SIZE);
    assert(dizi_gki_copy_to_private(&r,&p,owned,DIZI_FD_SIZE)==
           DIZI_GKI_LAYOUT_UNAUTHORIZED);
    assert(memcmp(owned,r.initrd+p.source_offset,DIZI_FD_SIZE)==0);
    assert(dizi_gki_copy_to_private(&r,&p,owned,DIZI_FD_SIZE-1)==
           DIZI_GKI_BAD_REQUEST);
    assert(dizi_gki_copy_to_private(&r,&p,(uint8_t*)r.initrd+p.source_offset,
                                    DIZI_FD_SIZE)==DIZI_GKI_MEMORY_CONFLICT);
    assert(dizi_gki_copy_to_private(&r,&p,(uint8_t*)r.initrd,
                                    DIZI_FD_SIZE)==DIZI_GKI_MEMORY_CONFLICT);
    assert(dizi_gki_copy_to_private(&r,&p,(uint8_t*)r.fdt,
                                    DIZI_FD_SIZE)==DIZI_GKI_MEMORY_CONFLICT);
    bad=p; bad.authorized_to_copy_or_execute=1;
    assert(dizi_gki_copy_to_private(&r,&bad,owned,DIZI_FD_SIZE)==DIZI_GKI_FD_INVALID);
    bad=p; bad.source_offset++;
    assert(dizi_gki_copy_to_private(&r,&bad,owned,DIZI_FD_SIZE)==DIZI_GKI_FD_INVALID);
    bad=p;bad.dynamic_reservation_count++;
    assert(dizi_gki_copy_to_private(&r,&bad,owned,DIZI_FD_SIZE)==DIZI_GKI_FD_INVALID);
    bad=p;bad.actual_sha256[0]^=1;
    assert(dizi_gki_copy_to_private(&r,&bad,owned,DIZI_FD_SIZE)==DIZI_GKI_FD_HASH);
    for (i=0;i<32;i++)assert(p.actual_sha256[i]==r.exact_fd_sha256[i]);
    free(owned);
  } else {
    assert(p.fd_destination_pa==0 && p.authorized_to_copy_or_execute==0);
  }
  free((void *)r.fdt);
  free((void *)r.initrd);
  printf("PASS source layout=%d, no live FD write or EDK2 transfer\n",actual);
  return 0;
}
