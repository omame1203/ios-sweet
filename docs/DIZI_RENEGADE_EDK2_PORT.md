# Renegade Project / EDK2 port to POCO Pad (`dizi`, SM7435)

## 2026-10-21: native Android boot-entry code after black-screen report

The first temporary command previously executed against a **raw EDK2 FD**
returned Fastboot `Sending 'boot.img' OKAY / Booting OKAY`, but the user
observed a black display with no UEFI Shell/console, and Fastboot still
recognized the device afterward. This is **NOT a proven SEC/PrePi execution**:
the raw FV had `_FVH` at +0x28, not the required Linux `ARM\x64` magic
at +0x38. No persistent partition write occurred. This source-only follow-up
**did not execute fastboot boot or flash again**.

The new `DiziBootShim/DiziNativeEntry.{S,h,c,ld}` provides a **genuine**
4,096-byte AArch64 Linux Image with an executable first-PC branch,
`ARM\x64` at offset 56, image size 4,096, `flags=0xa` and
position-independent register-only entry at +0x40. Its very first code
reads DAIF and masks exceptions, validates physical DTB `x0` alignment,
`x1..x3=0`, EL1, incoming DAIF IRQ/FIQ masking and disabled EL1 MMU and
D-cache; it preserves original DTB `x0`. On any result it **parks with WFE**,
with a reason in `x16`. The no-owner result is reason 12. This is a real
machine-code *entry* but it is **not yet a UEFI-executing wrapper**.
No stack or unowned memory is accessed in this path.

The complementary new **real post-grant transfer** source
`DiziBootShim/DiziSecTransfer.{c,h,S}` implements what must happen once
the first-PC loader has **independently verified** the current-boot grant:

1. Take a hardware-backed owner/EL2/XPU proof for the complete low-memory
   16 MiB window, source initrd+DTB, current kernel-image allocation,
   cache/execute permissions and quiesced DMA. This is **not** inferred
   from the captured DTB, guest code, unlocked Fastboot or a self-declared flag.
2. Locate the exact 4 MiB FV in a possibly prefixed GKI-v4 initrd; verify
   FDT structure, live chosen initrd addresses, all source/destination
   disjoint intervals, FV header/block map, SEC vector and exact SHA-256.
3. Copy verified FV to `0x90000000`, check copied bytes, clean
   D-cache to the PoC, invalidate I-cache to the PoU, execute barriers,
   mask asynchronous interrupts and branch to the FV reset vector with
   `x0=physical FDT`, `x1=x2=x3=0`.

The whole memory-writing transfer is gated by **both**
`DIZI_SEC_ENABLE=1` and `DIZI_SEC_TRUSTED_OWNER_IMPLEMENTED=1`,
plus an actual independently authored `DiziSecGetTrustedRuntimeGrant`.
No such owner provider is in this repository, so the default build
always returns `DIZI_SEC_NO_OWNER` and **no read, copy or BR executes**.
Deliberately enabling both macros without the real provider fails the
actual AArch64 ELF link with
`undefined reference to DiziSecGetTrustedRuntimeGrant`. This is
intentional: simply turning on a macro cannot authorize physical writes.
Even after a provider exists, a trusted pre-stack first-PC call/stack
placement and the existing PrePi's first unguarded FDT/vector/stack writes
must be proven safe before this path may be connected to the native Image.

The new `tools/dizi-renegade-native-image.py` builds the actual
`DiziNativeEntry.S` using AArch64 GNU assembler/linker/objcopy and
independently checks its opcode/header layout, then stages an Android
**GKI-v4 structured, explicitly NONBOOTABLE** image with the SHA-pinned
genuine 4 MiB FD as a ramdisk payload. Unlike the previous raw-FD Fastboot
attempt, it truly includes an Android-compatible native Image entry,
but **its native entry deliberately parks** and does not invoke the
post-grant transfer. It must NOT be passed to `fastboot boot` as UEFI.

Most recent in-place/offline build of the strictly nonbootable native stage:
`/tmp/dizi-renegade-gki-native-20261021-prime/dizi.NONBOOTABLE-STAGE.gki-v4`;
4,202,496 bytes, SHA-256
`b80d98f6913f1f13211533e30309b5aa4756f473ddbc5bcf16c13542e9ace9af`.
Actual 4,096-byte native Image SHA-256
`6b6cdb7a3bead908b6600a0cf8e38bc5aaf19948bfd85e1c5e2c805a54bb34dd`.
Payload FD SHA-256
`7bb217aebee2d79910ea9e9d2bb204cb6375a6d6bcb637fb9e7dd81cf2e78ec8`.
The stage manifest explicitly sets `safe_to_boot=false` and
`safe_to_flash=false`. Existing `VERIFIED_DIZI_WRAPPERS` remains empty.

Host verification:

```sh
python3 tests/test-dizi-renegade-native-entry.py
python3 tests/test-dizi-renegade-native-abi.py
python3 tests/test-dizi-renegade-native-image.py
python3 tests/test-dizi-renegade-sec-transfer.py
```

Source-backed detailed ABL/Android/Gunyah evidence and outstanding runtime
owner requirements are in `docs/DIZI_RENEGADE_NATIVE_ENTRY_AUDIT.md`.

## 2026-10-21 follow-up: native boot prerequisites and source implementation

Following the genuinely compiled 4-MiB SM7435 FD, additional dizi-specific
source and host validation were developed rather than changing the target
back to the macOS27 shim. **An EDK2 UEFI boot has still NOT been observed on
POCO Pad.** No flash or temporary EDK2 `fastboot boot` was performed.

### Entry ABI and memory ownership

`Silicon/Qualcomm/sm7435/Library/DiziEarlyHandoffGuard` now contains a
freestanding AArch64 no-stack/no-memory-write **deny-only** entry symbol and
bounded read-only source FDT checker. Actual upstream
`QcomPkg/PrePi/ModuleEntryPoint.S` stores incoming `x0` to
`PcdDeviceTreeStore`, writes its 2-KiB exception vectors and clears the SEC
stack **before** entering C or the platform's trusted-memory admission
function. The new guard deliberately parks instead of executing PrePi; it
is not wired into the present FD as a functional UEFI loader. There is no
independently observed ABL/Gunyah/XPU ownership grant allowing those writes
to provisional physical addresses `0x90000000` through `0x91000000`.

`Platform/Xiaomi/sm7435/DiziBootShim` contains a constrained GKI-v4/FDT/
vendor-initrd/UEFI-FV planning and isolated-buffer-copy implementation,
where its actual completion remains **layout-only, not execution authority**.
The saved ABL and boot images do not establish how an independently relocated
FD can safely be copied and jumped into from the running primary CPU under
the real MMU/cache/stage-2 configuration. Reusing another device's BootShim
or setting the packager allowlist without this evidence remains forbidden.

### Display and interrupts

`Platform/Xiaomi/sm7435/DiziSafeGopDxe` provides a source-level inherited
1600x2560, stride-6400, BGRA8888 GOP implementation with bounded BLT
operations. Unlike the generic upstream display module, it does **not**
clear the framebuffer at driver entry. Board inclusion is controlled by
`DIZI_ENABLE_SAFE_GOP` and defaults to `FALSE`; independent display mapping,
EL2/XPU ownership and cache-lifetime grant integration are additionally
required before it can install or write the GOP protocol. Current firmware
has no trusted grant-protocol producer.

`Silicon/Qualcomm/sm7435/Drivers/DiziGicTimer` contains a separately
guarded GICv3/virtual-timer PPI27 configuration path and host state planner.
It does not silently enable the generic ArmGicV3 driver, whose whole-controller
initialization would interfere with unverified IRQ/Gunyah ownership. FDT
observations of GICD, GICR and 19.2 MHz timing are not permission to write
those registers. This driver remains excluded from the default firmware
unless ownership is independently attested.

### Reproducible build tooling

`tools/dizi-renegade-cold-build.py` validates pinned upstream and **eight
public submodule revisions**, byte-checks the complete staged board overlay,
and performs an explicitly requested AArch64 DEBUG build in a new private
workspace. It bypasses Renegade's upstream `build.sh` because that script
may initialize proprietary submodules and construct a donor-style boot image.
Output reports explicitly set `bootable=false`, and host-only negative tests
cover refusing modified sources, missing public dependencies, occupied
workspaces and incomplete firmware volumes. The first integration run of this
new runner produced another genuine 4,194,304-byte SM7435 UEFI FD, SHA-256
`16792d5cef480561f5832eb33e6f4f6c57fc9f7cc3c113e568c0fb38e505897e`,
using the then-current source overlay and the separately pinned public stage.
This is a **build artifact only**, not a firmware image approved for execution.

**Final after all follow-up sources were stable:** a new cold build in
`/tmp/dizi-edk2-msm-genuine-dizi-debug-20261021-w9/verify-final-20261021`
used exactly **35 matching board-overlay files** and eight pinned public
submodule revisions, produced a 4,194,304-byte `SM7435_UEFI.fd` with SHA-256
`b17435878dda89ca1306e4ede6a8cd49523e943f6f5d543c008308081b63412b`.
The build report explicitly records `bootable=false`,
`runtime_ram_ownership_proven=false`, `prepi_entry_abi_proven=false`,
`fastboot_performed=false`. The earlier diagnostic hashes above are not
identical to this final source snapshot and must not be substituted.

After a whitespace-only cleanup of the unlinked, guarded GKI planning source,
another full cold build from all 35 current files produced
`verify-commit-20261021/Build/dizi/DEBUG_GCC5/FV/SM7435_UEFI.fd`, size
4,194,304 bytes, SHA-256
`7bb217aebee2d79910ea9e9d2bb204cb6375a6d6bcb637fb9e7dd81cf2e78ec8`.
Use this **last observed build** to identify the verification-stage artifact;
repeated EDK2 builds can have different byte hashes due to build metadata,
so a SHA identifies exactly one FD, not a universal immutable firmware ID.

The strict GKI-v4 packager's FD parser now accepts a *real* TianoCore
AArch64 GenFv reset-vector forward-branch (`B SEC`) with bounded target,
while checking FV header checksum and block map. Its previous demand that
all first 16 bytes be zero was wrong for actual AArch64 UEFI firmware. This
fix **does not** grant the still-unverified high-RAM vs low-RAM address
contract or allowlist any executable wrapper.

Separately, an explicitly optional full public EDK2 firmware build with
`DIZI_ENABLE_SAFE_GOP=TRUE` linked a real AArch64 PE32+ GOP DXE module;
however, its runtime ownership-grant integration remains absent, and
the default board DSC keeps the module excluded. A likewise separately
compiled GIC/Timer DXE demonstrates a deliberately nonfunctional,
default-denied driver. An attempt to activate the GIC timer without the
external `DiziGicTimerGetTrustedGrant` owner implementation fails at link
time, as intended.

**Status, 2026-10-21: SM7435 EDK2 source port and isolated AArch64 DEBUG
firmware build now exist; NO Renegade UEFI boot on the POCO Pad.**

## 2026-10-21 implementation and firmware build checkpoint

The initial hardware preflight was followed by new **source** in
`ports/renegade/edk2-overlay/` targeting the pinned current Renegade
`edk2-msm` revision `e1952621f419f8db60ed28271264e1b5184c571d`:

- `Silicon/Qualcomm/sm7435`: own SoC package, firmware memory map, PrePi
  and PEI library sources, externally attested RAM admission. Before any
  independent owner verifier is connected, the memory-map implementation
  publishes **no usable RAM** and PrePi cannot normally proceed.
- `Platform/Qualcomm/sm7435`: distinct parent DSC/FDF using public EDK2
  components rather than copying older proprietary Qualcomm/EFI binaries.
- `Platform/Xiaomi/sm7435`: dizi board DSC, FV inclusion, board evidence,
  and actual `DiziDiagDxe` DXE source. The DXE consumes and checks a real
  GOP protocol but there is **no active dizi GOP provider**. Compilation
  and EFI linking do not imply DXE dispatch, video output or Boot Services.
- `configs`: guarded dizi configuration. `FD_BASE` and `FD_SIZE` remain
  intentionally unspecified until the boot-time physical/virtual memory
  contract and exclusive ownership are independently validated.
- `tools/dizi-renegade-overlay.py`: pin-checked audit and new-workspace
  preparation; `tools/dizi-renegade-basetools.sh`: host GCC GNU17 workaround;
  `tools/dizi-renegade-image.py`: strict *nonbooting by default* GKI boot v4
  packager. It has no approved entry-wrapper hash and rejects unreviewed input.
- `tools/dizi-renegade-bootentry-audit.py`: read-only original dizi
  `boot_a.img`/`vendor_boot_a.img`/`abl_a.img`/FDT and upstream BootShim
  transport review. The CLI returns status `BLOCKED` and exit code 2 by
  design, even for structurally consistent headers; no output firmware,
  allowlist, boot image or device access is created.

An independent **temporary** public-source build staging area under
`/tmp/dizi-edk2-msm-genuine-dizi-debug-20261021-w9` successfully ran a
genuine AArch64 `DEBUG_GCC5` EDK2 compilation and GenFds step. The clean
`WORKSPACE=.../verify-cold` build log records `- Done -` at 17:59:58 JST
and produced a 4,194,304-byte `SM7435_UEFI.fd`, with `_FVH` at byte 40
and an advertised FV length of `0x400000`. Its authoritative **cold build**
SHA-256 is `8326f9cdfd3db67eb3a924d6ceff15df98256f6aef23e21112fd06b0935497d5`.
The earlier incremental 4-MiB FD had a different hash; do not identify
incremental and cold build artifacts as identical.
The staging area initially contained temporary open-source library
resolutions and GCC16/C23 compatibility workarounds. Final public library
mappings and RAM layout were merged into this source overlay before the cold
rebuild. All 18 staged overlay files were checked byte-for-byte against
the repository's then-current overlay. This is
**reproducible host firmware output**, not execution or exclusive memory
ownership; hardware verification must precede any boot claim.

The exact commands, dependency gitlink revisions and host toolchain wrappers
are recorded in the isolated stage's `DIZI_DEBUG_BUILD_REPORT.md`.
`-D FD_BASE=0x90000000 -D FD_SIZE=0x00400000` were used as compile-time
diagnostic values ONLY, not an assertion that ABL owns that physical RAM.
Furthermore, the standalone strict v4 image packager currently requires
a high-RAM FD address, whereas the genuine FDF candidate is low-RAM;
it must remain blocked until one coherent independently reviewed physical
load/entry/FD region contract has been proved.

The captured dizi boot partition uses v4 header size 1584, a 46,854,828-byte
kernel, 1,380,093-byte boot ramdisk and 4096-byte signature. `vendor_boot_a`
is v4, and the saved ABL is an **ARM32 ELF** (not an AArch64
Linux Image entry stub). Actual upstream BootShim (`BootShim.S`, 144-byte
binary) uses `ADR`, 16-byte copy operations and an unverified jump into
an inherited `0xce000000` FD destination intended for another SoC. It lacks
an independently reviewed dizi entry proof, FDT/FD range verification and
cache/MMU ownership transition. Its upstream packaging
`gzip(BootShim + FD) + DTB` is also different from the guarded GKI-v4
Image+FV-in-ramdisk design. Merely changing the FD address cannot repair
those differences.

**Crucially, an FD is a firmware container, not an Android `fastboot boot`
image.** The current upstream BootShim/DTB/gzip combination is not proven
to satisfy the dizi ABL/GKI-v4 entry ABI; do not disguise it as an executable
Linux Image. Required attestation of the current dynamic FDT reservations,
16-MiB candidate at `0x90000000`, executable/writable mapping, entry EL/MMU,
Gunyah/EL2/XPU permissions and ABL ownership is not available. No Renegade
boot image has been approved, no `fastboot boot` of this FD has been attempted,
and **no flash operation was performed**. Earlier iPadOS graphics and CPU
diagnostics are independent results, not evidence that EDK2 reached DXE.

For repeatable, non-device host review from this repository, run:

```sh
python3 tools/dizi-renegade-overlay.py
python3 tests/test-dizi-renegade-preflight.py
python3 tests/test-dizi-renegade-overlay.py
python3 tests/test-dizi-renegade-basetools.py
python3 tests/test-dizi-renegade-config.py
python3 tests/test-dizi-renegade-silicon.py
python3 tests/test-dizi-renegade-soc-parent.py
python3 tests/test-dizi-renegade-platform.py
python3 tests/test-dizi-renegade-diag.py
python3 tests/test-dizi-renegade-image.py
python3 tests/test-dizi-renegade-bootentry-audit.py
```

All `tests/test-dizi-renegade-*` are **host tests**; passing them cannot
verify GIC/GOP/SEC runtime ownership or guarantee a device will boot.

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
