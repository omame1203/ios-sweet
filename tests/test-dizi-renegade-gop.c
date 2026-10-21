/* Host-only real TianoCore UEFI GOP primitive tests; no device or MMIO.
 * Never map 0xb8000000 or execute DXE on actual POCO Pad. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#undef NULL
#include "../ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435/DiziSafeGopDxe/DiziSafeGopBlt.h"
#define UINTN_MAX (~(UINTN)0)

#define FB_BYTES DIZI_GOP_VISIBLE_BYTES
#define SENTINEL 128
#define CHECK(c) do { checks++; if (!(c)) { fprintf(stderr,"CHECK FAIL at %d: %s\n", __LINE__,#c); abort(); } } while (0)
static unsigned checks;
static UINT8 *alloc_fb(void) {
  UINT8 *mem = malloc(FB_BYTES+SENTINEL);
  CHECK(mem!=NULL);
  memset(mem, 0x9e, FB_BYTES+SENTINEL);
  return mem;
}
static void untouched(const UINT8 *fb) {
  for (size_t i=FB_BYTES;i<FB_BYTES+SENTINEL;i++) CHECK(fb[i]==0x9e);
}
static UINT8 *pixel(UINT8 *fb,size_t x,size_t y) {
  return fb+(y*DIZI_GOP_STRIDE_PIXELS+x)*4;
}
static void set_pixel(UINT8 *fb,size_t x,size_t y,const UINT8 *p) {
  memcpy(pixel(fb,x,y),p,4);
}
static void get_pixel(UINT8 *fb,size_t x,size_t y,UINT8 *out) {
  memcpy(out,pixel(fb,x,y),4);
}
static void check_pixel(UINT8 *fb,size_t x,size_t y,
                        UINT8 b,UINT8 g,UINT8 r,UINT8 a) {
  UINT8 exp[4]={b,g,r,a};
  CHECK(memcmp(pixel(fb,x,y),exp,4)==0);
}
static void negative_cases(UINT8 *fb) {
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL px = {0x11,0x22,0x33,0x44};
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL scratch[64]={0};
  size_t cases=0;
  for (size_t op=0;op<4;op++) {
    CHECK(DiziSafeBlt(NULL,FB_BYTES,&px,(EFI_GRAPHICS_OUTPUT_BLT_OPERATION)op,
                      0,0,0,0,1,1,0)==EFI_INVALID_PARAMETER);
    CHECK(DiziSafeBlt(fb,FB_BYTES-1,&px,(EFI_GRAPHICS_OUTPUT_BLT_OPERATION)op,
                      0,0,0,0,1,1,0)==EFI_INVALID_PARAMETER);
    CHECK(DiziSafeBlt(fb,DIZI_GOP_RESERVED_BYTES+1,&px,
                      (EFI_GRAPHICS_OUTPUT_BLT_OPERATION)op,
                      0,0,0,0,1,1,0)==EFI_INVALID_PARAMETER);
    CHECK(DiziSafeBlt(fb,FB_BYTES,NULL,(EFI_GRAPHICS_OUTPUT_BLT_OPERATION)op,
                      0,0,0,0,1,1,0)==(op==EfiBltVideoToVideo?EFI_SUCCESS:EFI_INVALID_PARAMETER));
    for (UINTN n=0;n<2;n++) {
      UINTN invalid=n?UINTN_MAX:1600;
      CHECK(DiziSafeBlt(fb,FB_BYTES,&px,(EFI_GRAPHICS_OUTPUT_BLT_OPERATION)op,
                        invalid,0,invalid,0,1,1,0)==EFI_INVALID_PARAMETER);
      cases++;
    }
  }
  CHECK(DiziSafeBlt(fb,FB_BYTES,&px,EfiGraphicsOutputBltOperationMax,
                    0,0,0,0,1,1,0)==EFI_INVALID_PARAMETER);
  CHECK(DiziSafeBlt(fb,FB_BYTES,&px,EfiBltVideoFill,
                    0,0,0,0,0,1,0)==EFI_INVALID_PARAMETER);
  CHECK(DiziSafeBlt(fb,FB_BYTES,&px,EfiBltVideoToBltBuffer,
                    0,0,0,0,1,0,0)==EFI_INVALID_PARAMETER);
  CHECK(DiziSafeBlt(fb,FB_BYTES,&px,EfiBltBufferToVideo,
                    0,0,1599,0,2,1,0)==EFI_INVALID_PARAMETER);
  CHECK(DiziSafeBlt(fb,FB_BYTES,&px,EfiBltVideoToVideo,
                    0,0,0,2559,1,2,0)==EFI_INVALID_PARAMETER);
  CHECK(DiziSafeBlt(fb,FB_BYTES,scratch,EfiBltVideoToBltBuffer,
                    0,0,1,0,1,1,0)==EFI_INVALID_PARAMETER);
  CHECK(DiziSafeBlt(fb,FB_BYTES,scratch,EfiBltBufferToVideo,
                    1,0,0,0,1,1,0)==EFI_INVALID_PARAMETER);
  CHECK(DiziSafeBlt(fb,FB_BYTES,scratch,EfiBltVideoToBltBuffer,
                    0,0,1,0,1,1,4)==EFI_INVALID_PARAMETER);
  CHECK(DiziSafeBlt(fb,FB_BYTES,scratch,EfiBltBufferToVideo,
                    1,0,0,0,1,1,4)==EFI_INVALID_PARAMETER);
  CHECK(DiziSafeBlt(fb,FB_BYTES,scratch,EfiBltBufferToVideo,
                    UINTN_MAX,0,0,0,1,1,8)==EFI_INVALID_PARAMETER);
  CHECK(DiziSafeBlt(fb,FB_BYTES,scratch,EfiBltBufferToVideo,
                    0,UINTN_MAX,0,0,1,1,8)==EFI_INVALID_PARAMETER);
  CHECK(DiziSafeBlt(fb,FB_BYTES,scratch,EfiBltBufferToVideo,
                    0,0,0,0,4,2,15)==EFI_INVALID_PARAMETER);
  CHECK(DiziSafeBlt(fb,FB_BYTES,scratch,EfiBltVideoToBltBuffer,
                    0,0,0,0,4,2,15)==EFI_INVALID_PARAMETER);
  (void)cases;
  untouched(fb);
}

static void fill_and_buf(UINT8 *fb) {
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL px={0x12,0x34,0x56,0x78};
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL scratch[32];
  memset(scratch,0xcc,sizeof scratch);
  CHECK(DiziSafeBlt(fb,FB_BYTES,&px,EfiBltVideoFill,9999,9999,
                    1598,2558,2,2,UINTN_MAX)==EFI_SUCCESS);
  check_pixel(fb,1598,2558,0x12,0x34,0x56,0x78);
  check_pixel(fb,1599,2559,0x12,0x34,0x56,0x78);
  check_pixel(fb,1597,2559,0x9e,0x9e,0x9e,0x9e);
  CHECK(DiziSafeBlt(fb,FB_BYTES,scratch,EfiBltVideoToBltBuffer,
                    1598,2558,0,0,2,2,0)==EFI_SUCCESS);
  CHECK(memcmp(scratch,&px,4)==0);
  CHECK(memcmp(scratch+3,&px,4)==0);
  scratch[0]=(EFI_GRAPHICS_OUTPUT_BLT_PIXEL){0xff,0xee,0xdd,0xcc};
  CHECK(DiziSafeBlt(fb,FB_BYTES,scratch,EfiBltBufferToVideo,
                    0,0,0,0,1,1,0)==EFI_SUCCESS);
  check_pixel(fb,0,0,0xff,0xee,0xdd,0xcc);

  /* Explicit Delta is row bytes of *whole client buffer*. Source and
   * destination offsets are then interpreted in that buffer correctly. */
  for (size_t i=0;i<32;i++) scratch[i]=(EFI_GRAPHICS_OUTPUT_BLT_PIXEL)
       {(UINT8)i,(UINT8)(i+1),(UINT8)(i+2),(UINT8)(i+3)};
  CHECK(DiziSafeBlt(fb,FB_BYTES,scratch,EfiBltBufferToVideo,
                    2,1,90,100,3,2,8*4)==EFI_SUCCESS);
  CHECK(memcmp(pixel(fb,90,100),&scratch[1*8+2],4)==0);
  CHECK(memcmp(pixel(fb,92,101),&scratch[2*8+4],4)==0);
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL out[32];
  memset(out,0xb4,sizeof out);
  CHECK(DiziSafeBlt(fb,FB_BYTES,out,EfiBltVideoToBltBuffer,
                    90,100,3,1,3,2,8*4)==EFI_SUCCESS);
  CHECK(memcmp(&out[1*8+3],&scratch[1*8+2],4)==0);
  CHECK(memcmp(&out[2*8+5],&scratch[2*8+4],4)==0);
  CHECK(memcmp(&out[0],(UINT8[]){0xb4,0xb4,0xb4,0xb4},4)==0);
  untouched(fb);
}

static void overlapping(UINT8 *fb) {
  UINT8 *ref = malloc(FB_BYTES);
  CHECK(ref != NULL);
  const size_t startX=40,startY=57,width=10,height=7;
  for (size_t y=0;y<25;y++) {
    for (size_t x=0;x<25;x++) {
      UINT8 pixelv[4]={(UINT8)(x+y),(UINT8)(x*5),(UINT8)(y*2),0x7f};
      set_pixel(fb,startX+x,startY+y,pixelv);
    }
  }
  for (size_t dir=0;dir<6;dir++) {
    memcpy(ref,fb,FB_BYTES);
    size_t sx=startX+2,sy=startY+2,dx=sx,dy=sy;
    if (dir==0) {dx=sx+1;dy=sy;}
    if (dir==1) {dx=sx-1;dy=sy;}
    if (dir==2) {dx=sx;dy=sy+1;}
    if (dir==3) {dx=sx;dy=sy-1;}
    if (dir==4) {dx=sx+1;dy=sy+1;}
    if (dir==5) {dx=sx-1;dy=sy-1;}
    UINT8 expected[7][10][4];
    for(size_t y=0;y<height;y++)
      for(size_t x=0;x<width;x++)
        get_pixel(ref,sx+x,sy+y,expected[y][x]);
    for(size_t y=0;y<height;y++)
      for(size_t x=0;x<width;x++)
        set_pixel(ref,dx+x,dy+y,expected[y][x]);
    CHECK(DiziSafeBlt(fb,FB_BYTES,NULL,EfiBltVideoToVideo,
                      sx,sy,dx,dy,width,height,0)==EFI_SUCCESS);
    CHECK(memcmp(ref,fb,FB_BYTES)==0);
  }
  free(ref);
  untouched(fb);
}

static void boundary_end(UINT8 *fb) {
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL px={1,2,3,4};
  CHECK(DiziSafeBlt(fb,FB_BYTES,&px,EfiBltVideoFill,
                    0,0,1599,2559,1,1,0)==EFI_SUCCESS);
  check_pixel(fb,1599,2559,1,2,3,4);
  untouched(fb);
}

int main(void) {
  UINT8 *fb=alloc_fb();
  negative_cases(fb);
  fill_and_buf(fb);
  overlapping(fb);
  boundary_end(fb);
  printf("PASS %u genuine GOP BGRA BLT host assertions; no panel/MMIO/scanout init\n",checks);
  free(fb);
  return 0;
}
