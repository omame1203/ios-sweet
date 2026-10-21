# Renegade Project / EDK2 port to POCO Pad (`dizi`, SM7435)

**Status, 2026-10-21: hardware source audit only; NOT an EDK2 build or boot.**

## Scope and source provenance

The original Renegade Project porting guide is written for the older
`edk2-sdm845` tree and walks through Android OTA `xbl.img` extraction,
UEFI firmware parser/UEFITool, donor DXE replacement, a donor DSC/FDF,
display resolution, target registration and `fastboot boot`. The guide's
donor-platform binaries are not verified on a newer Qualcomm SoC.

Sources:

- https://renegade-project.tech/en/porting (current linked guide)
- https://renegade-doc.readthedocs.io/en/latest/edk2/port.html (legacy steps)
- https://forum.renegade-project.tech/t/edk2-sdm845-new-device-porting-guide/417
- https://github.com/edk2-porting/edk2-msm (current multi-SoC EDK2 tree)
- https://github.com/edk2-porting/edk2-msm/issues/418 (POCO Pad request; not implementation)

An offline sparse checkout of upstream `edk2-msm` `e1952621f419f8db60ed28271264e1b5184c571d`
was inspected under `/tmp/dizi-edk2-msm-audit-20261021` (outside this repo).
At that revision, `configs/sm7435.conf`,
`Silicon/Qualcomm/sm7435/` and `Platform/Xiaomi/sm7435/dizi.dsc` are
**missing**. A device config alone will NOT build usable Renegade UEFI.
Actual available older donors (e.g. SM7325 `lisa`) use
`configs/devices/*.conf`, `Platform/Xiaomi/<soc>/*.dsc` and `.fdf.inc`
plus platform-specific Silicon drivers. Their ACPI/firmware binary/FD_BASE
values are NOT interchangeable with SM7435.

## Reused local dizi data (no hardware actions required)

The previously captured `backup/dizi/fdt`, `boards/dizi.json` and
`shim/board.h` provide a foundation without partition writes.

| Device fact | Grounded value | Scope |
|---|---|---|
| Board/SoC | `dizi` / SM7435 (Qualcomm parrot) | Live FDT snapshot |
| Framebuffer | PA `0xb8000000`, 1600×2560, 6400-byte stride | Existing framebuffer diagnostic screen ran on-device |
| FB reservation | `0x2b00000` bytes | FDT `/reserved-memory/splash_region` |
| GICD/GICR | `0x17200000` / `0x17260000` | Captured board/DTB, not a UEFI driver |
| UFS register candidate | `0x1d84000`, size `0x3000` | Hardware inventory; no Renegade UFS DXE |
| Boot transport | Android GKI boot header v4 | Known working `fastboot boot` diagnostics |
| Proposed high RAM workspace | `0x8c0000000` + `0xb0000000` | In captured DDR; NOT present-day exclusive ownership |
| FDT DDR and reservations | 7 nonempty DDR banks, 35 fixed entries, 10 dynamic/unlocated children | Read-only captured FDT only |

Run `python3 tools/dizi-renegade-preflight.py` to get a JSON report of
the hardware facts and unresolved responsibilities; no files are written.
Tests: `python3 tests/test-dizi-renegade-preflight.py` include malformed
FDT, non-dizi, DDR out-of-range, framebuffer mismatch and reserved-memory
overlap rejections. Only `ports/renegade/dizi.conf` is proposed as a **candidate**
for `edk2-msm/configs/devices/dizi.conf` when a real SM7435 Silicon port exists.

## What must be implemented before an EDK2 UEFI shell can boot

1. Independently map and verify XBL/ABL handoff memory, all runtime reservations,
   EL1 MMU/cache, EL2/SMMU/XPU permissions; never take the saved FDT's RAM
   membership as proof of safe executable/writable ownership.
2. Add `Silicon/Qualcomm/sm7435/` UEFI platform initialization, clocks,
   timers, GIC, resource and memory protocols derived from the parrot board.
3. Implement `Platform/Xiaomi/sm7435/dizi.dsc` and `.fdf.inc` with real PCDs,
   actual vendor firmware compatibility and a usable Debug framebuffer path.
4. Audit every candidate XBL EFI DXE binary for the exact firmware ABI before
   inclusion. No unverified XBL DXE transplantation and no fake ACPI tables.
5. Add minimal output-only GOP/framebuffer and CPU/PSCI diagnostics first.
   UFS, USB, buttons, PMIC and storage write paths remain disabled until their
   exact hardware ownership/contracts are independently verified.
6. Build an isolated image via the current `edk2-msm` build system; inspect the
   AArch64 Linux Image header, GKI-v4 packaging, reservations, relocations and
   image size before considering a **temporary** Fastboot boot. Never flash
   Android, EFI, boot/recovery or userdata while developing this port.
7. Prove an on-device UEFI Shell or a Renegade framebuffer screen rather than
   relying only on Fastboot `Booting OKAY` as proof.

## Relationship to the macOS 27 port

EDK2 would be an **optional boot/diagnostic environment** on the POCO Pad.
It does not provide Apple's board-specific ADT, the macOS 27 arm64e PAC
feature/keys, correct authenticated Kernel Collection fixups, the VMAPPLE
HVC contract, macOS Qualcomm IOKit drivers, or APFS/SSV/Preboot trust.
The existing macOS27 GKI shim proves a display/boot handoff without needing
EDK2. A future Renegade port is useful for diagnostics/standard boot services,
but must not be reported as native XNU27 startup.

**Do not use the SDM845 Renegade installation guide to resize/delete storage
partitions on dizi.** Known iPadOS and Android boot artifacts are preserved.
