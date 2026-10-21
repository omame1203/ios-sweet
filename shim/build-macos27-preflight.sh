#!/usr/bin/env bash
# Produce a standalone, OFFLINE AArch64 ELF for code-review and host analysis.
# It is NOT a macOS27-bootable image: no ramdisk/KC gets bundled, no Android
# boot.img is created, and no fastboot/device commands are run. The separate
# DIZI_MACOS27_PREFLIGHT shim returns before GIC/MMU/USB/UFS/auto-reset and
# parks in WFE instead of entering Apple's unported arm64e XNU27 KC.
set -euo pipefail
cd "$(dirname "$0")"
CC=aarch64-linux-gnu-gcc
NM=aarch64-linux-gnu-nm
READELF=aarch64-linux-gnu-readelf
OBJDUMP=aarch64-linux-gnu-objdump
for tool in "$CC" "$NM" "$READELF" "$OBJDUMP"; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done
CFLAGS=(-std=c11 -O2 -ffreestanding -nostdlib -fno-pic -fno-builtin
        -mgeneral-regs-only -mstrict-align -fno-stack-protector
        -Wall -Wextra -Werror -DBOARD_DIZI -DDIZI_MACOS27_PREFLIGHT)
case "${1:-}" in
    "") ;;
    --pac-register-diagnostic)
        CFLAGS+=(-DDIZI_MACOS27_PAC_TRAP_DIAGNOSTIC=1
                 -DMAC27_PAC_RECOVERY_ENABLE=1
                 -DMAC27_PAC_RECOVERY_HANDLER_WIRED=1)
        ;;
    *) echo "Usage: $0 [--pac-register-diagnostic]" >&2; exit 2 ;;
esac
# Never overwrite existing/working iPadOS diagnostic artifacts or saved images.
mkdir -p out
OUT=$(mktemp -d out/mac27-readonly-preflight-XXXXXXXX)
objects=()
for src in start.S shim.c console.c mmu.c fdt.c loader.c ufs.c input_diag.c \
           bootlog.c usb_control.c usb_diag.c macos27_kc.c macos27_kc_probe.c \
           macos27_pac_recovery.c macos27_pac_recovery.S \
           ../ports/macos27/kc_loader.c ../ports/macos27/kc_fixups.c \
           ../ports/macos27/kc_plain_rebase.c \
           ../ports/macos27/boot_args.c; do
    obj="$OUT/$(printf '%02d' "${#objects[@]}").o"
    "$CC" "${CFLAGS[@]}" -c "$src" -o "$obj"
    objects+=("$obj")
done
# This shim is entered as a relocatable Android Linux Image. The startup
# header legitimately references _end, but absolute relocations in C objects
# would point at link address zero rather than their ABL-assigned address.
abs=$(aarch64-linux-gnu-readelf -r "${objects[@]:1}" | grep -c ABS64 || true)
if [ "$abs" != 0 ]; then
    echo "Refusing $abs absolute relocations in non-startup objects" >&2
    exit 1
fi
"$CC" "${CFLAGS[@]}" -static -T shim.ld -Wl,--build-id=none \
       -Wl,--no-warn-rwx-segments -Wl,-N "${objects[@]}" \
       -o "$OUT/mac27-preflight-only.elf"
if [ -n "$("$NM" -u "$OUT/mac27-preflight-only.elf")" ]; then
    echo "Unexpected unresolved AArch64 symbols" >&2
    exit 1
fi
"$READELF" -h "$OUT/mac27-preflight-only.elf" > "$OUT/elf-header.txt"
"$NM" -n "$OUT/mac27-preflight-only.elf" > "$OUT/symbols.txt"
"$OBJDUMP" -d "$OUT/mac27-preflight-only.elf" > "$OUT/disassembly.txt"
grep -q 'Machine: *AArch64' "$OUT/elf-header.txt"
grep -q ' mac27_dizi_probe_dtb$' "$OUT/symbols.txt"
grep -q ' mac27_kc_inspect_fixups$' "$OUT/symbols.txt"
echo "OFFLINE preflight ELF: $OUT/mac27-preflight-only.elf"
echo "NO Apple XNU jump, NO boot.img, NO device/fastboot, NO auto reset"
