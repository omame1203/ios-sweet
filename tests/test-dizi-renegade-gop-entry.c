/* Host-mocked UEFI services; never actually dereference 0xb8000000.
 * Even the synthetic provider demonstrates only logic, NOT EL2 ownership. */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#undef NULL
#include <Uefi.h>
#include <Protocol/GraphicsOutput.h>
#include <Library/UefiBootServicesTableLib.h>
#include "../ports/renegade/edk2-overlay/Platform/Xiaomi/sm7435/DiziSafeGopDxe/DiziSafeGopDxe.h"

#define CHECK(v) do { checked++; if (!(v)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#v); abort(); } } while(0)
static unsigned checked;
EFI_BOOT_SERVICES *gBS;
EFI_GUID gEfiGraphicsOutputProtocolGuid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
static EFI_GRAPHICS_OUTPUT_PROTOCOL *published;
static DIZI_SAFE_GOP_GRANT grant;
static int allow_grant, already_gop, allow_read;
static unsigned read_checks, writes, clears, installs;

static EFI_STATUS EFIAPI
validate(DIZI_SAFE_GOP_GRANT *g, UINT32 action, DIZI_SAFE_GOP_MAPPING *m)
{
  CHECK(g==&grant);
  CHECK(m!=NULL);
  if (action == DIZI_SAFE_GOP_GRANT_READ) {
    read_checks++;
    if (!allow_read) return EFI_ACCESS_DENIED;
  } else if (action == DIZI_SAFE_GOP_GRANT_WRITE) {
    writes++;
    return EFI_ACCESS_DENIED;
  } else {
    clears++;
    return EFI_ACCESS_DENIED;
  }
  m->FrameBufferPa=DIZI_GOP_FB_PA;
  m->CpuIdentityAddress=(volatile UINT8 *)(UINTN)DIZI_GOP_FB_PA;
  m->MappedBytes=DIZI_GOP_VISIBLE_BYTES;
  m->Width=DIZI_GOP_WIDTH;
  m->Height=DIZI_GOP_HEIGHT;
  m->PixelsPerScanLine=DIZI_GOP_STRIDE_PIXELS;
  m->BitsPerPixel=32;
  m->OwnershipAccess=DIZI_SAFE_GOP_REQUIRED_ACCESS;
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
locate(EFI_GUID *guid, VOID *registration, VOID **out)
{
  EFI_GUID owner_guid=DIZI_SAFE_GOP_GRANT_GUID;
  CHECK(registration==NULL);
  CHECK(out!=NULL);
  *out=NULL;
  if (memcmp(guid,&gEfiGraphicsOutputProtocolGuid,sizeof(*guid))==0) {
    if (already_gop) { *out=(VOID *)1; return EFI_SUCCESS; }
    return EFI_NOT_FOUND;
  }
  if (memcmp(guid,&owner_guid,sizeof(*guid))==0 && allow_grant) {
    *out=&grant;
    return EFI_SUCCESS;
  }
  return EFI_NOT_FOUND;
}

static EFI_STATUS EFIAPI
publish(EFI_HANDLE *handle, ...)
{
  EFI_GUID *guid;
  EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;
  va_list args;
  va_start(args,handle);
  guid=va_arg(args, EFI_GUID *);
  gop=va_arg(args, EFI_GRAPHICS_OUTPUT_PROTOCOL *);
  CHECK(memcmp(guid,&gEfiGraphicsOutputProtocolGuid,sizeof(*guid))==0);
  CHECK(va_arg(args, VOID *)==NULL);
  va_end(args);
  CHECK(handle!=NULL && gop!=NULL);
  *handle=(EFI_HANDLE)gop;
  published=gop;
  installs++;
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
alloc(EFI_MEMORY_TYPE type, UINTN bytes, VOID **ptr)
{
  CHECK(type==EfiBootServicesData);
  *ptr=malloc(bytes);
  return *ptr?EFI_SUCCESS:EFI_OUT_OF_RESOURCES;
}

int main(void)
{
  EFI_BOOT_SERVICES bs;
  EFI_SYSTEM_TABLE system;
  EFI_STATUS status;
  memset(&bs,0,sizeof bs);
  memset(&system,0,sizeof system);
  system.BootServices=&bs;
  bs.LocateProtocol=locate;
  bs.InstallMultipleProtocolInterfaces=publish;
  bs.AllocatePool=alloc;
  gBS=&bs;
  grant.Version=DIZI_SAFE_GOP_GRANT_VERSION;
  grant.Size=sizeof(grant);
  grant.Validate=validate;
  CHECK(DiziSafeGopEntry(NULL,NULL)==EFI_INVALID_PARAMETER);
  CHECK(DiziSafeGopEntry(NULL,&system)==EFI_ACCESS_DENIED);
  CHECK(installs==0);
  allow_grant=1;
  already_gop=1;
  CHECK(DiziSafeGopEntry(NULL,&system)==EFI_ACCESS_DENIED);
  already_gop=0;
  CHECK(installs==0);
  allow_read=0;
  CHECK(DiziSafeGopEntry(NULL,&system)==EFI_ACCESS_DENIED);
  CHECK(installs==0);
  allow_read=1;
  status=DiziSafeGopEntry(NULL,&system);
  CHECK(status==EFI_SUCCESS);
  CHECK(installs==1 && published!=NULL);
  CHECK(read_checks==2);
  CHECK(published->Mode->Info->HorizontalResolution==1600);
  CHECK(published->Mode->Info->VerticalResolution==2560);
  CHECK(published->Mode->Info->PixelsPerScanLine==1600);
  CHECK(published->Mode->FrameBufferBase==DIZI_GOP_FB_PA);
  CHECK(published->Mode->FrameBufferSize==DIZI_GOP_VISIBLE_BYTES);
  CHECK(writes==0 && clears==0); /* NO entry-time destructive writes */
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info=NULL;
  UINTN bytes=0;
  CHECK(published->QueryMode(published,0,&bytes,&info)==EFI_SUCCESS);
  CHECK(info && bytes==sizeof *info && info!=published->Mode->Info);
  CHECK(info->PixelFormat==PixelBlueGreenRedReserved8BitPerColor);
  free(info);
  CHECK(published->QueryMode(published,1,&bytes,&info)==EFI_INVALID_PARAMETER);
  CHECK(published->SetMode(published,1)==EFI_UNSUPPORTED);
  CHECK(published->SetMode(published,0)==EFI_ACCESS_DENIED);
  CHECK(clears==1);
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL pix={1,2,3,4};
  CHECK(published->Blt(published,&pix,EfiBltVideoFill,0,0,0,0,1,1,0)==EFI_ACCESS_DENIED);
  CHECK(writes==1);
  allow_read=0;
  CHECK(published->Blt(published,&pix,EfiBltVideoToBltBuffer,0,0,0,0,1,1,0)==EFI_ACCESS_DENIED);
  CHECK(installs==1);
  printf("PASS %u synthetic GOP entry assertions; default requires trusted producer; zero framebuffer accesses\n",checked);
  return 0;
}
