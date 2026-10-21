/*
 * Raw Linux ARM64 Image layout. VMA is ZERO, instructions are PC relative;
 * no guessed ABL load PA, FD, FDT, stack or heap addresses.
 *
 * Link using:
 *   aarch64-linux-gnu-ld -nostdlib -static -T DiziNativeEntry.ld ...
 *   aarch64-linux-gnu-objcopy -O binary ...elf ...Image
 * Header image_size is the actual 4KiB-rounded output extent. This
 * intentionally emits a diagnostic/park Image, not a bootable EDK2 loader.
 */
OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(dizi_native_image_header)

SECTIONS
{
  . = 0;
  .text : ALIGN(4096) {
    KEEP(*(.text.head))
    KEEP(*(.text.native))
    *(.text .text.*)
    /* ALIGN must be INSIDE the output section: outside changes the ELF
       address cursor but fails to pad objcopy -O binary to image_size. */
    . = ALIGN(4096);
  }
  __dizi_native_image_end = .;

  /DISCARD/ : {
    *(.bss .bss.* .data .data.* .rodata .rodata.*)
    *(.eh_frame .eh_frame.* .note.* .comment .interp .plt .got .got.*)
  }
  ASSERT(dizi_native_image_header == 0,
         "Image must start with ARM64 entry at file offset 0")
  ASSERT(dizi_native_first_pc >= 64 && dizi_native_first_pc < 4096,
         "The first-PC implementation must be inside the first page")
  ASSERT(__dizi_native_image_end == 4096,
         "Unexpected native Image growth requires independent review")
}
