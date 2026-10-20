#!/bin/bash
# Build the shim and wrap it in a boot.img v2 that mirrors the stock PixelOS header.
set -euo pipefail
cd "$(dirname "$0")"
CC=aarch64-linux-gnu-gcc
OBJCOPY=aarch64-linux-gnu-objcopy
CFLAGS="-O2 -ffreestanding -nostdlib -fno-pic -mgeneral-regs-only -mstrict-align -fno-stack-protector -Wall -Wextra"
BOARD=${BOARD:-sweet}
case "$BOARD" in
	sweet) OUT=out; BOARD_FLAGS= ;;
	dizi) OUT=out/dizi; BOARD_FLAGS=-DBOARD_DIZI ;;
	*) echo "Unsupported BOARD: $BOARD" >&2; exit 1 ;;
esac
if [ "$BOARD" = dizi ] && [ "${DIZI_USB_DIAG:-1}" = 1 ]; then
	# Live EP0 boot log over USB. DIZI_USB_DIAG=0 builds without the DMA path.
	BOARD_FLAGS="$BOARD_FLAGS -DDIZI_USB_DIAG"
fi
if [ "$BOARD" = dizi ] && [ "${DIZI_UFS_DIAG:-0}" = 1 ]; then
	BOARD_FLAGS="$BOARD_FLAGS -DDIZI_UFS_DIAG"
fi
if [ "$BOARD" = dizi ] && [ "${DIZI_UFS_WAKE:-0}" = 1 ]; then
	BOARD_FLAGS="$BOARD_FLAGS -DDIZI_UFS_WAKE"
fi
if [ "$BOARD" = dizi ] && [ "${DIZI_UFS_LOG:-0}" = 1 ]; then
	BOARD_FLAGS="$BOARD_FLAGS -DDIZI_UFS_LOG"
fi
if [ "$BOARD" = dizi ] && [ "${DIZI_INPUT_DIAG:-0}" = 1 ]; then
	BOARD_FLAGS="$BOARD_FLAGS -DDIZI_INPUT_DIAG"
fi
if [ "$BOARD" = dizi ] && [ "${DIZI_INPUT_SPI_CLOCK:-0}" = 1 ]; then
	BOARD_FLAGS="$BOARD_FLAGS -DDIZI_INPUT_SPI_CLOCK"
fi
mkdir -p "$OUT"
objects=()
for f in start.S shim.c console.c mmu.c fdt.c loader.c ufs.c input_diag.c bootlog.c usb_control.c usb_diag.c; do
	$CC $CFLAGS $BOARD_FLAGS -c "$f" -o "$OUT/${f%.*}.o"
	objects+=("$OUT/${f%.*}.o")
done
# The image runs wherever ABL puts it with no relocation pass: only the
# header's image_size (start.o, linked at 0) may be an absolute address.
abs=$(aarch64-linux-gnu-readelf -r "${objects[@]:1}" | grep -c ABS64 || true)
[ "$abs" = 0 ] || { echo "error: $abs absolute relocations in C objects" >&2; exit 1; }
$CC $CFLAGS -static -T shim.ld -Wl,--build-id=none -Wl,--no-warn-rwx-segments -Wl,-N \
	"${objects[@]}" -o "$OUT/shim.elf"
$OBJCOPY -O binary "$OUT/shim.elf" "$OUT/Image"
# ABL copies the file; pad to image_size so .bss/stacks exist as zeroed bytes.
size=$(aarch64-linux-gnu-nm "$OUT/shim.elf" | awk '$3=="_end"{print strtonum("0x"$1)}')
truncate -s "$size" "$OUT/Image"
# Ramdisk: an xnu payload (tools/mkpayload.py) if given as $1, else an empty
# newc cpio (ABL dislikes a zero-size ramdisk on some builds) -> diagnostics.
if [ -n "${1:-}" ]; then
	cp "$1" "$OUT/ramdisk.bin"
else
	# Reproducible empty initramfs, no staging directory removal needed.
	printf '' | cpio -o -H newc --quiet --reproducible | gzip -n -9 > "$OUT/ramdisk.bin"
fi
if [ "$BOARD" = dizi ]; then
	# Match the actual GKI boot-v4 device. Its existing vendor_boot supplies
	# the DTB and vendor ramdisk; neither partition is flashed by this script.
	mkbootimg --header_version 4 --kernel "$OUT/Image" --ramdisk "$OUT/ramdisk.bin" \
		--os_version 12.0.0 --os_patch_level 2025-09 --cmdline "console=null" -o "$OUT/shim-boot.img"
else
mkbootimg --header_version 2 --kernel out/Image --ramdisk out/ramdisk.bin \
	--dtb ../dtb/boot_unpacked/dtb --base 0 --kernel_offset 0x8000 --ramdisk_offset 0x1000000 \
	--tags_offset 0x100 --dtb_offset 0x1f00000 --pagesize 4096 \
	--os_version 17.0.0 --os_patch_level 2035-06 \
	--cmdline "console=null" -o out/shim-boot.img
fi
# Host checks: console layout and the EP0 protocol decoder.
gcc -O1 -Wall $BOARD_FLAGS -o "$OUT/host_test" console.c bootlog.c host_test.c
"$OUT/host_test"
gcc -O1 -Wall -Wextra -o "$OUT/usb_control_test" usb_control_test.c usb_control.c
"$OUT/usb_control_test"
ls -l "$OUT/Image" "$OUT/shim-boot.img"
