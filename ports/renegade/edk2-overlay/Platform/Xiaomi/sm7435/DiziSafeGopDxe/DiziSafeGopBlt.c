/** @file
  Reviewed visible-only GOP BLT implementation for an inherited 1600x2560
  BGRA8888 scanout. All offsets/row strides checked before first pixel touch.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include "DiziSafeGopBlt.h"

static BOOLEAN
RectValid (UINTN X, UINTN Y, UINTN W, UINTN H)
{
  return W != 0 && H != 0 &&
         X < DIZI_GOP_WIDTH && Y < DIZI_GOP_HEIGHT &&
         W <= DIZI_GOP_WIDTH - X && H <= DIZI_GOP_HEIGHT - Y;
}

static BOOLEAN
Mul (UINTN A, UINTN B, UINTN *Out)
{
  if (A != 0 && B > (~(UINTN)0) / A) {
    return FALSE;
  }
  *Out = A * B;
  return TRUE;
}

static BOOLEAN
Add (UINTN A, UINTN B, UINTN *Out)
{
  if (B > (~(UINTN)0) - A) {
    return FALSE;
  }
  *Out = A + B;
  return TRUE;
}

static BOOLEAN
BufferSpan (
  UINTN X, UINTN Y, UINTN W, UINTN H,
  UINTN Delta, UINTN *Stride
  )
{
  UINTN EndX, EndY, LastRow, LastPixel, LastByte, Span;
  /* Delta=0 is a tightly-packed W-wide buffer; no source/destination
   * subrectangle origin may be used without an explicit row delta. */
  if (Delta == 0) {
    if (X != 0 || Y != 0 || !Mul(W, 4, &Delta)) {
      return FALSE;
    }
  }
  if ((Delta & 3U) != 0 ||
      !Add(X, W, &EndX) || !Add(Y, H, &EndY) ||
      !Mul(EndX, 4, &LastByte) || LastByte > Delta ||
      !Mul(EndY - 1, Delta, &LastRow) ||
      !Mul(EndX - 1, 4, &LastPixel) ||
      !Add(LastRow, LastPixel, &Span) || !Add(Span, 4, &Span)) {
    return FALSE;
  }
  /* GOP supplies no buffer length. We can reject overflow/invalid Delta,
   * but the caller must provide an actually allocated span. */
  *Stride = Delta;
  return TRUE;
}

static VOID
ReadPixel (volatile const UINT8 *Source, UINT8 Pixel[4])
{
  UINTN Byte;
  for (Byte = 0; Byte < 4; ++Byte) {
    Pixel[Byte] = Source[Byte];
  }
}

static VOID
WritePixel (volatile UINT8 *Destination, const UINT8 Pixel[4])
{
  UINTN Byte;
  for (Byte = 0; Byte < 4; ++Byte) {
    Destination[Byte] = Pixel[Byte];
  }
}

EFI_STATUS
DiziSafeBlt (
  volatile UINT8                         *CpuVisible,
  UINTN                                  MappedBytes,
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL          *BltBuffer,
  EFI_GRAPHICS_OUTPUT_BLT_OPERATION      Operation,
  UINTN                                  SourceX,
  UINTN                                  SourceY,
  UINTN                                  DestinationX,
  UINTN                                  DestinationY,
  UINTN                                  Width,
  UINTN                                  Height,
  UINTN                                  Delta
  )
{
  UINTN BufferStride = 0, FrameStride = DIZI_GOP_STRIDE_PIXELS * 4U;
  UINTN X, Y;
  UINT8 Pixel[4];
  UINT8 *Buffer = (UINT8 *)(VOID *)BltBuffer;

  if (CpuVisible == NULL || MappedBytes < DIZI_GOP_VISIBLE_BYTES ||
      MappedBytes > DIZI_GOP_RESERVED_BYTES ||
      Operation >= EfiGraphicsOutputBltOperationMax) {
    return EFI_INVALID_PARAMETER;
  }
  if (Operation == EfiBltVideoFill ||
      Operation == EfiBltBufferToVideo ||
      Operation == EfiBltVideoToVideo) {
    if (!RectValid(DestinationX, DestinationY, Width, Height)) {
      return EFI_INVALID_PARAMETER;
    }
  }
  if (Operation == EfiBltVideoToBltBuffer ||
      Operation == EfiBltVideoToVideo) {
    if (!RectValid(SourceX, SourceY, Width, Height)) {
      return EFI_INVALID_PARAMETER;
    }
  }
  if (Operation != EfiBltVideoToVideo) {
    if (BltBuffer == NULL) {
      return EFI_INVALID_PARAMETER;
    }
    if (Operation == EfiBltVideoToBltBuffer) {
      if (!BufferSpan(DestinationX, DestinationY, Width, Height,
                      Delta, &BufferStride)) {
        return EFI_INVALID_PARAMETER;
      }
    } else if (Operation == EfiBltBufferToVideo) {
      if (!BufferSpan(SourceX, SourceY, Width, Height,
                      Delta, &BufferStride)) {
        return EFI_INVALID_PARAMETER;
      }
    }
  }
  /* The visible framebuffer geometry is fixed: 1600 * 2560 * 4. Every
   * coordinate rectangle is already validated before any framebuffer load
   * or store. No allocation and no clear of reserved scanout tail. */
  switch (Operation) {
    case EfiBltVideoFill:
      for (X = 0; X < 4; ++X) {
        Pixel[X] = Buffer[X];
      }
      for (Y = 0; Y < Height; ++Y) {
        volatile UINT8 *Line =
          CpuVisible + (DestinationY + Y) * FrameStride + DestinationX * 4;
        for (X = 0; X < Width; ++X) {
          WritePixel(Line + X * 4, Pixel);
        }
      }
      return EFI_SUCCESS;

    case EfiBltVideoToBltBuffer:
      for (Y = 0; Y < Height; ++Y) {
        volatile UINT8 *Line =
          CpuVisible + (SourceY + Y) * FrameStride + SourceX * 4;
        UINT8 *BufferLine =
          Buffer + (DestinationY + Y) * BufferStride + DestinationX * 4;
        for (X = 0; X < Width; ++X) {
          ReadPixel(Line + X * 4, Pixel);
          for (UINTN I = 0; I < 4; ++I) {
            BufferLine[X * 4 + I] = Pixel[I];
          }
        }
      }
      return EFI_SUCCESS;

    case EfiBltBufferToVideo:
      for (Y = 0; Y < Height; ++Y) {
        UINT8 *BufferLine =
          Buffer + (SourceY + Y) * BufferStride + SourceX * 4;
        volatile UINT8 *Line =
          CpuVisible + (DestinationY + Y) * FrameStride + DestinationX * 4;
        for (X = 0; X < Width; ++X) {
          for (UINTN I = 0; I < 4; ++I) {
            Pixel[I] = BufferLine[X * 4 + I];
          }
          WritePixel(Line + X * 4, Pixel);
        }
      }
      return EFI_SUCCESS;

    case EfiBltVideoToVideo:
      /* Equivalent to memmove on rows and pixels, but uses volatile pixel
       * I/O and never speculatively reads outside the visible framebuffer.
       * Choose reverse order when a destination overlaps below/right. */
      for (Y = 0; Y < Height; ++Y) {
        UINTN Row = DestinationY > SourceY ? Height - 1 - Y : Y;
        volatile UINT8 *From =
          CpuVisible + (SourceY + Row) * FrameStride + SourceX * 4;
        volatile UINT8 *To =
          CpuVisible + (DestinationY + Row) * FrameStride + DestinationX * 4;
        for (X = 0; X < Width; ++X) {
          UINTN Column =
            DestinationY == SourceY && DestinationX > SourceX
            ? Width - 1 - X : X;
          ReadPixel(From + Column * 4, Pixel);
          WritePixel(To + Column * 4, Pixel);
        }
      }
      return EFI_SUCCESS;

    default:
      return EFI_INVALID_PARAMETER;
  }
}
