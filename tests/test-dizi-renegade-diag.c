/* EDK2 GOP and UEFI system-table mocks. Actual production entry is the
 * unmodified DiziDiagDxe.c compiled with real TianoCore Uefi.h headers. */
#include <string.h>
#include <stdio.h>
/* Host libc and EDK2 both define NULL; avoid the test-only redefinition. */
#undef NULL
#include <Uefi.h>
#include <Protocol/GraphicsOutput.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "check failed: %s at %d\n", #x, __LINE__); \
    return 3; } } while (0)

EFI_GUID gEfiGraphicsOutputProtocolGuid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
extern EFI_STATUS EFIAPI DiziDiagEntry(EFI_HANDLE, EFI_SYSTEM_TABLE *);

static EFI_GRAPHICS_OUTPUT_PROTOCOL *current_gop;
static EFI_STATUS locate_status;
static unsigned messages;

static EFI_STATUS EFIAPI locate(EFI_GUID *id, VOID *registration, VOID **out)
{
    (void)registration;
    if (id != &gEfiGraphicsOutputProtocolGuid) return EFI_INVALID_PARAMETER;
    *out = current_gop;
    return locate_status;
}

static EFI_STATUS EFIAPI output(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *con,
                               CHAR16 *string)
{
    (void)con;
    if (string == NULL || string[0] != 'R' || string[1] != 'e') return EFI_INVALID_PARAMETER;
    ++messages;
    return EFI_SUCCESS;
}

int main(void)
{
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION info;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE mode;
    EFI_GRAPHICS_OUTPUT_PROTOCOL gop;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL console;
    EFI_BOOT_SERVICES boot;
    EFI_SYSTEM_TABLE system;

    memset(&info, 0, sizeof(info));
    memset(&mode, 0, sizeof(mode));
    memset(&gop, 0, sizeof(gop));
    memset(&console, 0, sizeof(console));
    memset(&boot, 0, sizeof(boot));
    memset(&system, 0, sizeof(system));
    info.HorizontalResolution = 1600;
    info.VerticalResolution = 2560;
    info.PixelsPerScanLine = 1600;
    info.PixelFormat = PixelBlueGreenRedReserved8BitPerColor;
    mode.Info = &info;
    mode.FrameBufferBase = 0xb8000000;
    mode.FrameBufferSize = 0xfa0000;
    gop.Mode = &mode;
    current_gop = &gop;
    boot.LocateProtocol = locate;
    console.OutputString = output;
    system.BootServices = &boot;
    system.ConOut = &console;

    CHECK(DiziDiagEntry(NULL, NULL) == EFI_INVALID_PARAMETER);
    CHECK(DiziDiagEntry(NULL, &system) == EFI_SUCCESS);
    CHECK(messages == 1);

    locate_status = EFI_NOT_FOUND;
    CHECK(DiziDiagEntry(NULL, &system) == EFI_NOT_FOUND);
    locate_status = EFI_SUCCESS;
    current_gop = NULL;
    CHECK(DiziDiagEntry(NULL, &system) == EFI_NOT_READY);
    current_gop = &gop;
    mode.FrameBufferBase = 0xce000000;
    CHECK(DiziDiagEntry(NULL, &system) == EFI_UNSUPPORTED);
    mode.FrameBufferBase = 0xb8000000;
    mode.FrameBufferSize = 0x02b00001;
    CHECK(DiziDiagEntry(NULL, &system) == EFI_UNSUPPORTED);
    mode.FrameBufferSize = 0x00f9ffff;
    CHECK(DiziDiagEntry(NULL, &system) == EFI_UNSUPPORTED);
    mode.FrameBufferSize = 0xfa0000;
    info.HorizontalResolution = 1080;
    CHECK(DiziDiagEntry(NULL, &system) == EFI_UNSUPPORTED);
    info.HorizontalResolution = 1600;
    info.PixelFormat = PixelRedGreenBlueReserved8BitPerColor;
    CHECK(DiziDiagEntry(NULL, &system) == EFI_UNSUPPORTED);
    info.PixelFormat = PixelBlueGreenRedReserved8BitPerColor;
    system.ConOut = NULL;
    CHECK(DiziDiagEntry(NULL, &system) == EFI_SUCCESS);
    CHECK(messages == 1);
    puts("PASS genuine EDK2 GOP-only dizi DXE: success, no-ConOut, wrong FB, hostile dimensions and formats");
    return 0;
}
