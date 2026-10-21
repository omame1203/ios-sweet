# POCO Pad (dizi) → genuine macOS 27 Golden Gate migration

### 2026-10-21: original XNU entry one-instruction experiment under source review

The requested unrestricted jump into genuine 26A434 XNU remains unqualified:
VMAPPLE's first branch enters an `OSLAR_EL1` system-register write, early
`HVC #0` with x0=0xc1000000 prior to SCTLR, and authenticated ARM64e PAC
fixups whose dizi hardware keys/ISA are unverified. The source-only experimental
trampoline `shim/macos27_entry_experiment.{c,h,S}` would execute **only** the
unchanged authentic first PC-relative `B +0x3bf0`, then trap on a private
`BRK #0x4e27` inserted at the copied target (not in preserved Apple source).
Host checks and AArch64 compilation confirm intended matching ESR/ELR logic,
but they do not prove real-world RAM ownership, stage-2 execute rights or
exception return behavior. Complementary FDT stage/guard and explicit-review
packaging tools remain offline and default-disabled. **No actual XNU27
instruction was executed on hardware during this development.** The user's
verified prior red screen was shim/real-KC read-only metadata execution only.

### 2026-10-21: real-device diagnostic display confirmed by user photo

The second `fastboot boot` transfer of the original 81,661,952-byte
`mac27-26A434-KC-nojump-review.img` returned `OKAY` for sending and booting.
The user then provided an actual photo of **dizi running the dedicated red
diagnostic shim screen** with `SHIM dizi (POCO Pad SM7435)`, `EL ...0004`,
`CNTFRQ ...0124F800`, `PSCI ver=00010001 smccc=00010001`,
`LOADER macOS27: real KC parsed; PAC/APFS/driver gate BLOCKED` and
`XNU27 PAC/fixups/platform not ready: NO JUMP`. This independently upgrades
the prior bootloader-only evidence: shim, framebuffer output and the read-only
decompressed KC structural/fixup-chain parser demonstrably **ran on hardware**.
The structural parser verifies neither KC signature nor authenticated fixup
contents, and the output is explicitly designed NOT to enter Apple XNU.
There is still **no native XNU27 execution**, PAC ISAR hardware attestation,
VMAPPLE HVC implementation, APFS root mount or macOS desktop. The original
photo is not committed as a binary research asset.

### 2026-10-21 KC unsigned rebase and CPU PAC prototype (not a boot)

- `kc_plain_rebase.{c,h}` and shim `mac27_shim_stage_plain()` perform strict
  source-validated, two-pass pointer rewriting **ONLY for `isAuth=0`** with
  format8/cacheLevel0 and first __TEXT header VA+target30, on independently
  owned staged RAM. Real VMA2: 89,086 plain rebased, 599,964 PAC encodings
  left intact. Real mac13g: 111,542 plain, 901,819 PAC unchanged. 314/418
  Python-independent oracle samples incl cross-page pointers, Clang sanitizer,
  and AArch64 linking all passed. No PAC auth pointer was signed or executed.
- New `macos27_pac_probe` and `macos27_pac_recovery` modules are opt-in,
  with exact MRS PC/ESR, staged EL1 exception resume path integrated in shim
  behind multiple disabled-by-default macros. Gunyah EL2-directed traps are
  still not recoverable here. The actual Fastboot-accepted diagnostic image
  was built with PAC reads DISABLED; no per-core PAC ability is established.

## 2026-10-21: temporary GKI diagnostic bootloader acceptance (NOT macOS27 kernel startup)

- Fastboot reported connected unlocked `dizi`, current slot `b`, max download
  354418688 bytes. Built fresh ignored diagnostic image
  `shim/out/dizi/mac27-26A434-KC-nojump-review.img` **81,661,952 bytes**,
  SHA256 `4c809464e32f7760a785f597204f693e9ab506d0fb9039a6ad7af6e077a7b5ee`.
  Its original 26A434 VMAPPLE `MH_FILESET` is exactly preserved **as inert
  ramdisk data**; kernel field is a dedicated no-branch AArch64 preflight shim.
  Sidecar `.review.json` documents SHA-256, header fields, and all NO-JUMP
  limitations. `tools/macos27-temporary-image.py` built the GKI boot v4
  image only after checking real KC, BuildManifest hash, complete AArch64
  Linux Image structure, disassembled shim function targets, GKI offsets,
  no signature payload and section hashes. 12 negative/host tests passed.
- With explicit user request to attempt a temporary boot, issued ONLY:
  `fastboot boot shim/out/dizi/mac27-26A434-KC-nojump-review.img`.
  Result: `Sending boot.img (79748 KB) OKAY [1.824s]` and
  `Booting OKAY [0.346s]` (total 2.212s). Subsequent fastboot/adb device
  queries returned empty. **This confirms loader transport and boot request
  acceptance, NOT that the shim painted a screen, passed real KC inspection,
  executed native Apple XNU, mounted APFS, or reached macOS.** No user photo,
  USB diagnostic, or new runtime trace was obtained. Boot image partitions,
  original Android/iPadOS partition data and user backups were not written.
- Read-only machine-word decode of genuine VMAPPLE entry gives
  `0xfffffe0009eb4480 → 0xfffffe0009eb8070`: physical x0 boot args,
  reads x20+8/16/24/0x470, initializes TCR_EL1/TTBR1_EL1 tables, then
  **executes HVC #0 (x0=0xc1000000) BEFORE SCTLR_EL1** and later `AUTDA`.
  No compatible Qualcomm Gunyah implementation of that guest hypercall has
  been observed. `entry_handoff_guard.{c,h}` fail-closed checks 14 exact
  machine instructions and immutable layout against the real 26A434 KC;
  120k hostile assertions, 14 mutations and AArch64 host build pass. This
  is an additional earliest-XNU startup blocker beyond PAC/SSV/IOKit.
- Real macOS27 XNU native entry transfer remains intentionally **prohibited**:
  millions of format8 KC pointers (599964 auth in vma2 alone), unknown dizi
  PAC registers/keys and Apple VMAPPLE HVC, absent Qualcomm platform expert,
  APFS/SSV Preboot trust, IOKit/GPU drivers. This milestone must never be
  described as a native macOS27 temporary boot.

## 2026-10-21: iPadOS boot-path reuse and genuine XNU27 no-jump preparation

The established iPadOS16/XNU22 0116 dizi GUI boot is hardware-bringup
evidence **only**, not proof that macOS27/XNU13432.1.9 runs. Its legacy shim
searches a custom SWEETXNU flat payload, copies pre-relocated arm64 segments,
populates 736-byte boot args, then branches to its entry. The genuine macOS27
26A434 Apple ARM64e MH_FILESET instead requires pointer authentication,
proper kernel-collection chained-fixup resolution, native provider linkage
and new 1152-byte boot args. `shim/loader.c` must not be pointed directly at
the decompressed KC or an IMG4-wrapped file.

Concrete code now in the repo working tree:

- `ports/macos27/kc_loader.{c,h}` copies genuine segment bytes and zero-fills
  BSS into an explicitly caller-owned host window; no native boot authority.
  `kc_fixups.{c,h}` traverses real format-8 16KiB-page chains with strictly
  bounded pointer reads, including valid 64-bit accesses straddling a 16KiB
  page boundary. Real offline vma2: 689050 chain entries (599964 auth), real
  mac13g: 1013361 (901819 auth). Neither authenticates/resigns/rebases PAC.
- `shim/macos27_kc.{c,h}` connects real KC structural staging, dizi RAM and
  reservation constraints, ADT placement and `boot_args.c` 1152-byte layout.
  It **always** marks the native jump disallowed. Unit test fixtures may use
  a placeholder ADT to check offsets, not an Apple-valid dizi device tree.
- `shim/macos27_kc_probe.{c,h}` and compile-time
  `DIZI_MACOS27_PREFLIGHT` select an intentionally non-booting diagnostic
  path; malformed/unmapped/unaligned inputs reject. This path returns to
  `_start` WFE **without running the legacy kernel jump, GIC/MMU/USB/UFS
  diagnostics or auto-reset**. It displays on the existing framebuffer and
  updates ramoops, so is NOT literally zero-side-effect on hardware.
  It was compiled and host tested only, **never deployed or executed on dizi**.
- `shim/build-macos27-preflight.sh` builds a separate review-only ELF under
  `shim/out/mac27-readonly-preflight-*`; it does not create an Android
  boot.img, issue fastboot calls, touch device storage or require an Apple
  kernel asset. `python3 tests/test-macos27-shim.py` runs Clang ASan/UBSan,
  malformed GKI-vendor-prefix tests, real Apple KC parsing, and the full
  AArch64 freestanding shim ELF linker. All passed offline.
- `ports/macos27/cpu_compat_gate.*` denies a false PAC attestation (dizi
  Android cpu.txt lacks paca/pacg; this is not a per-core ISAR observation),
  `storage_boot_gate.*` separates real APFS structure from SSV/SEP trust,
  and `iokit_resolver.*` rejects unsupported real 26A434 provider ABI.
  Their source-only/sanitizer/cross-compile tests passed; **no APFS boot
  provider, KC signature validation or IOKit driver attach** exists yet.

**No actual macOS27 XNU entry transfer has occurred.** Safely attempting an
actual jump still requires direct trusted PAC/arm64e capability and key/trap
semantics, correctly authenticated KC fixups, platform initialization/ADT,
memory-map ownership, and a compatible APFS root/SSV/Preboot/LocalPolicy
chain. Neither Apple VMAPPLE nor T8103 bundled platform drivers provide
native SM7435 UFS/GIC/Adreno/PMIC compatibility. The long-term target remains
all hardware features, not a subset.

## Scope / observed evidence (2026-10-21)

The target has changed from native **iPadOS 16.7.16** to native **macOS 27
Golden Gate**. It is **not** an Android launcher, Linux desktop, a renamed
iPadOS SpringBoard, or a macOS-looking XNU 22 binary. This document tracks
unfinished technical work, not a successful macOS boot.

Apple's published macOS 27.0.1 release/build is `26A434` (2026-09-28), and
the 27.2 RC is `26B118` (2026-10-19). Actual stock **26A434** KCs report
Darwin **27.0.0**, xnu-13432.1.9. The original Darwin26 assumption was wrong;
the `26A` build train is not the Darwin kernel major version.
Official reference pages:

- https://support.apple.com/en-us/127255 (supported Apple Silicon Macs)
- https://developer.apple.com/news/releases/?id=09282026c (27.0.1 build)
- https://developer.apple.com/news/releases/?id=10192026c (27.2 RC build)
- https://github.com/apple-oss-distributions/xnu (Apple OSS XNU releases)

The POCO Pad uses Qualcomm SM7435 rather than Apple Silicon; it is **not an
Apple-supported Mac target**. Using the words “Mac”, “MacBook”, “M1”, or
editing `SystemVersion.plist` does not provide platform firmware, SEP,
security signatures, graphics drivers or a valid macOS installation.

## Reusable, independently verified hardware bring-up

The known-good device checkpoint is the **iPadOS 16 / XNU 22.6.0** port:

| Subsystem | Reusable evidence | macOS 27 limitations |
|---|---|---|
| Fastboot v4 shim | Successfully chainloaded our 0116 XNU to iPadOS GUI | Not Apple iBoot or a macOS kernel-collection loader; firmware trust chain unverified |
| CPU/interrupts | Single CPU + GICv3 SGI/timer and 16 KiB MMU | New XNU ARM64 ABI, PAC, exception handling and SMP must be ported afresh |
| UFS | HFS-root read and HFSX boot to iPadOS GUI | APFS + Preboot + macOS signed and sealed volumes absent |
| Display | 1600×2560 panel / centered iPad framebuffer | WindowServer, IOAccelerator, Metal/AGX and GPU/display scheduling absent |
| Power/Home | Physical power and volume-up→Home works | Native macOS keyboard/mouse/trackpad HID integration incomplete |
| Touch | Novatek/GPI/SE9 software models through 0120 | GPI/QUP SIDs 0x416/0x403 are not authorized to DMA; physical touch off |
| macOS userspace | **No runtime evidence**; genuine files now available offline | Native launchd/WindowServer execution, installed APFS root and boot policy still needed |

The last 0120 kernel output (`xnu/out-0120/kernel.development.sweet`) has
`Darwin Kernel Version 22.6.0` embedded in the binary. It was compiled
from Apple OSS **xnu-8796.141.3 (macOS 13.5)** with SWEET patches; it is
**not macOS 27 XNU**, even though the target currently loads an Apple GUI.

## Non-destructive migration path

1. Keep the existing booted 0120/0116 images and the iPadOS root untouched.
   Use a distinct `dizi-macos27` project profile and separate scratch output;
   never `fastboot flash` macOS into the existing iPadOS `userdata` image.
2. Obtain legitimately sourced matching macOS **27** installer/update data,
   authenticated `SystemVersion.plist`, the correct ARM64 kernel collection,
   dyld shared caches and framework set; record vendor URLs, build IDs and
   SHA-256 hashes locally without committing any Apple binary or device IDs.
3. Identify Apple OSS XNU source **actually matching the observed kernel**, paired
   libraries and appropriate macOS SDK/KDK. Rebase low-level SM7435 CPU,
   GIC, pmap, platform expert, device tree, UFS, framebuffer, HID and key
   code from the known-good 0120 port using the new sources. The existing
   118 patches are written against xnu-8796; they are *not* a ready-made
   patch series for xnu-13432 / Darwin27. Old `macos_version=13.5` Actions
   build success cannot be reused to claim a Darwin27 build.
4. Build and validate a macOS 27-compatible boot/kernel-collection loader
   without bypassing Apple-signature provenance. The old shim payload layout
   assumes a standalone unslid Mach-O and does not support stock IMG4/KC
   securely by default; verify arm64/arm64e PAC and chained fixups first.
5. Implement a genuine APFS boot root: authenticated Preboot entries,
   System/Data volume group, authenticated sealed system snapshot (SSV),
   metadata, userland and appropriate mount/boot policy. An HFSX iPadOS
   `iOSRoot` partition cannot stand in for this.
6. Implement a working macOS WindowServer graphics path on Qualcomm,
   including display services, GPU allocation/synchronization and desktop
   input. Do not assume Apple DCP/AGX and Qualcomm Adreno are ABI-compatible.
7. First prove source compilation + host emulator checks + safe diagnostics.
   Only then consider non-destructive board-specific temporary boots,
   logging each outcome without changing Android/Apple recovery partitions.

## Actual 26A434 inputs now obtained (2026-10-21)

Apple CDN restore URL:
https://updates.cdn-apple.com/2026FallFCS/59241290-5d51-4ca8-9df4-31624b9a4eac/UniversalMac_27.0.1_26A434_Restore.ipsw

Only original manifests and two kernel components were range-extracted.
Ignored local directory: `research/macos27-26A434/`. The 30-MiB top-level
BuildManifest has SHA-256
`2585e3bd35a2491773bdf8c40803e0b10aa6ed222a27c790b34d25b5fa6842af`.
Both wrapped components match the manifest's SHA-384 digest. This links
downloaded bytes to the supplied manifest; it is **not** independent IMG4
signature or personalized boot-policy verification.

| Component | Wrapped bytes / SHA-256 | Decompressed bytes / SHA-256 |
|---|---|---|
| `kernelcache.release.vma2` | 23,159,655 / `a18374a448e74e2582e643385170fe238c55d5db50502479164d099f42625b7d` | 81,444,864 / `ca55ea8c4c86170e870380ae5501b8b43adb2d2d3db28be4531b3040653be203` |
| `kernelcache.release.mac13g` | 32,728,420 / `7c011c6a881c0e0494dd482e2549a14c7ff498a02b4d12c5f2f94cc268ead4a1` | 122,945,536 / `d196456a0809aca37bbf5918eb633cf8ada9000c48f4c0082ca8f61c86b2866b` |

Both are arm64e **MH_FILESET** collections and contain the native kernel
`Darwin Kernel Version 27.0.0`, `root:xnu-13432.1.9~1` (VMAPPLE / T8103).
The VMAPPLE collection has 216 fileset entries, including AppleARMGIC,
APFS, IOGraphicsFamily, IOSurface and AppleParavirtGPU providers. Those are
Apple VM drivers, not a native Qualcomm Adreno/display/storage backend.
T8103 has 342 entries and an additional `__DATA_SPTM` fixup segment.
Both use format-8 chained starts and 16-KiB pages. Embedded Mach-O segment
file offsets are collection-relative. No code or fixups were changed.

Repeatable extraction (Linux `ipsw` v3.1.739; `kernel dec --output` is a
DIRECTORY):

```sh
IPSW_URL=https://updates.cdn-apple.com/2026FallFCS/59241290-5d51-4ca8-9df4-31624b9a4eac/UniversalMac_27.0.1_26A434_Restore.ipsw
../host-tools/ipsw/ipsw extract --remote --pattern '(^|/)(BuildManifest|Restore)\.plist$' \
  --output research/macos27-26A434 "$IPSW_URL"
../host-tools/ipsw/ipsw extract --remote --pattern '^kernelcache\.release\.(vma2|mac13g)$' \
  --output research/macos27-26A434 "$IPSW_URL"
../host-tools/ipsw/ipsw kernel dec \
  research/macos27-26A434/26A434__MacOS/kernelcache.release.vma2 \
  --output research/macos27-26A434/kernel.vma2.macho
python3 tools/macos27-preflight.py --json \
  --kernel research/macos27-26A434/kernel.vma2.macho/kernelcache.release.vma2.decompressed \
  --build-manifest research/macos27-26A434/26A434__MacOS/BuildManifest.plist \
  --wrapped-kernel research/macos27-26A434/26A434__MacOS/kernelcache.release.vma2 \
  --component kernelcache.release.vma2
# Expected: kernel identity_only, manifest digest_matched, exit 2 / BLOCKED.
python3 tests/test-macos27-kernel-collection.py
```

`ports/macos27/kernel_collection.py` reads actual collection headers,
bounded segments, embedded kernel __TEXT/version, executable entry and
fixup starts. It never flattens filesets, strips authenticated pointers or
generates a SWEET payload. Decompressed-to-original linking is explicitly
separate from manifest digest verification; retain the extraction receipt.

Public source probes for the **observed** xnu-13432.1.9 tag were also made:
GitHub ref API, raw `config/MasterVersion` and Apple's tarball each returned
404; the full upstream tag/branch listings contain no 13432 generation.
This is a missing published source input, not an unknown binary version.
The old macOS13.5 workflow cannot build this kernel. No stock collection
was booted or repackaged, and no device/storage operation was performed.

The same IPSW's **RestoreRamDisk** (`043-70833-687.dmg`, 373,293,083 bytes,
SHA256 `7fd982e07bae3c3a587688ee96808d171f10fda90f9f720a3c45dae6514a17e8`)
and VMAPPLE device tree were subsequently extracted and their original
SHA-384 manifest entries matched. `ipsw img4 im4p extract` unwraps the
ramdisk to a real APFS container. Host `apfs-fuse -o ro` mounted it with
`ro,nosuid,nodev`; the files are under `/root/` inside the image. It has now
been unmounted. Saved `restore-artifacts/SystemVersion.plist` says macOS
27.0.1 / 26A434, **ReleaseType Restore**; actual launchd and dyld were also
copied for offline ABI inspection. Their fat binaries contain subtypes
`0x80000002` and `0x8000000c`, not a plain ARM64_ALL slice. No compatibility
of subtype12 has been established. This restore environment is not a
desktop System/Data volume group, and no Apple process was executed.
`ipsw extract --sys-ver --remote` is unsupported; use the plist extracted
from the readonly image. Private `provenance.json` records tool/source and
component hashes; `preflight-vma2.json` records the combined checks.

## Actual System/Cryptex/BaseSystem and boot ABI follow-up

All three decoded APFS images now match their **own** original 26A434
BuildManifest SHA-384. For these components the digest applies to the decoded
image, not encrypted `.aea` bytes. The original encrypted OS file passed ZIP
CRC-32 but its flat SHA-384 differed; the decoded OS exactly matches the
manifest. AEA decoding also completed its integrity checks. This does not
independently validate Apple boot-policy signatures or an installed SSV seal.

| Component | Retained decoded file under ignored `research/macos27-26A434/` | Bytes / SHA-256 |
|---|---|---|
| OS / System | `decrypted-os/043-70867-640.dmg` | 14,189,330,432 / `fbfb1a38af09d65dc86bb9814a13b870d1895e4c435c38fde42e00b52cff21b3` |
| Cryptex1,SystemOS | `decrypted-system-cryptex/043-70701-651.dmg` | 2,879,389,696 / `5fea3f16f856f3aa1b3f88aa3cedfe75977a36f70a17041d6cf6349ba9a0e4d2` |
| BaseSystem | `decrypted-base-system/022-20292-678.dmg` | 1,827,862,528 / `a4c987540a2f1feb3ee9cb7a9fdc6e8570544200c0bc8e20ad7924c2b586b2cc` |

Encoded intermediates created in this follow-up were removed only after the
decoded image matched the manifest; receipts retain their hashes and the
Apple URL. Original device/iPadOS backups remain intact. The raw OS image's
zero ranges were made sparse before computing its matching logical hash.

Readonly inspection found genuine macOS27.0.1/26A434 SystemVersion metadata,
launchd, dyld, Finder, Dock and WindowServer. The selected cryptex includes
`dyld_shared_cache_arm64e` and subcaches. The System image contains a
System-role volume without a Data/Preboot group or snapshots: these installer
inputs are not an installed bootable disk. No Apple process was executed.

The full System executables have ARM64 subtype2 and subtype12 slices.
[LLVM's architecture definitions](https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/MachO.h)
identify subtype12 as `ARM64E_X1` / `arm64e.x1`; [Apple's Xcode27 notes](https://developer.apple.com/documentation/xcode-release-notes/xcode-27-release-notes)
describe its additional hardware-checked pointer arithmetic. It is also a
PAC architecture. The reader now uses the entire 24-bit subtype and preserves
unknown variants. Saved dizi Android features lack paca/pacg; the actual
launchd disassembly contains authenticated return/branch instructions. This
does not demonstrate a native PAC execution path, nor a fresh per-core ISAR
measurement. Selecting subtype12 is not a plain-arm64 fallback.

Actual VMAPPLE KC entry `0xfffffe0009eb4480` branches to
`0xfffffe0009eb8070`. The first boot-argument loads through x20 read offsets
8/16/24 and **0x470**, while the legacy shim struct ends at 736 bytes. Its
16-KiB allocation is zeroed, so the layout mismatch is **not** proof of an
unmapped access or an observed macOS crash: the new tail fields are simply
not populated by the old struct.

`ports/macos27/boot_args.{c,h}` now implements the separate modern layout:
1152 bytes, 1024-byte command line, flags at 0x470, actual memory size at
0x478, virtual ADT pointer and checked placement/overflow/video/cmdline
encoding. The public [xnu-12377 ARM64 boot.h](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/pexpert/pexpert/arm64/boot.h)
is a layout reference, **not** corresponding macOS27 kernel source. A test
decodes the real 26A434 entry instructions and uses their offsets to read
the C encoder's output, confirming all four values. It also compiles the
encoder as a freestanding AArch64 object with no unresolved runtime calls.

```sh
python3 tests/test-macos27-boot-args.py
```

This is reusable loader code, not a KC loader or complete boot-ABI validation.
The legacy shim remains unchanged; no macOS payload/image was generated.
KC mapping/self-fixup, PAC, ADT/platform support and physical boot remain
unresolved. The public xnu-13432.1.9 tag and macos-270 manifest were rechecked
and still missing. Actual entry analysis remains a possible source of
further native bring-up work; do not replace it with relabeling the old XNU.

## Available migration tools

Source-based compatibility audits have also been added for the three major
platform subsystems. None implements real macOS 27 boot support:

```sh
# Apple public-release metadata, XNU-tag selection, 118 SWEET patch rebase,
# existing CI build-script and local SDK capability; result is JSON.
python3 tools/macos27-kernel-audit.py --target 27.0.1 --probe-public --strict

# An offline COPY of a real APFS container plus extracted Preboot artifacts,
# supplied manifest and physical APSB offsets; never opens a block device.
python3 ports/macos27/storage_probe.py \
  --manifest /path/to/evidence.json --root /path/to/offline-artifacts

# Current iPadOS baseline symbol audit vs macOS desktop IOFramebuffer,
# IOFBServer, IOSurface, Qualcomm Adreno/Metal and WindowServer requirements.
python3 ports/macos27/graphics_audit.py --kernel 0120

python3 tests/test-macos27-kernel-audit.py
python3 tests/test-macos27-storage.py
python3 tests/test-macos27-graphics.py
```

The kernel audit's real, public, read-only probe on 2026-10-21 showed
`distribution-macOS/macos-270/release.json` unavailable (HTTP 404), no
verified published Darwin27 XNU source tag, and `blacktop/darwin-xnu-build` lacking
a macOS 27 case. The highest XNU tag it independently related to an Apple
macOS manifest was `xnu-12377.121.6` from **macOS 26.5**, not macOS 27.
It reports exactly which existing CPU/IOKit/VFS patches need rebasing;
this is an inventory, not a new kernel build.

The storage probe checks APFS NXSB/APSB field positions and checksums,
System/Data volume-group roles and UUIDs, structural SSV/snapshot metadata,
Preboot/Recovery material and local file hashes. It neither verifies a real
cryptographic seal nor reports a bootable volume, even for a consistent
synthetic fixture. The present UFS HFSX `iOSRoot` remains unchanged.

The graphics gate uses actual 0120 Mach-O symbols and tracked XNU source:
mobile framebuffer and IOCoreSurfaceRoot exist, but the genuine desktop
IOFramebuffer/IOAccelerator providers and WindowServer/Metal-compatible
GPU/device interfaces are absent. The current SM7435 Adreno 710 has no
verified Apple AGX-compatible backend. Host-only 16-KiB frame mapping and
strided crop calculations are checked against malformed rectangles; no
panel/clock/GPU registers are written.

The tracked `boards/dizi-macos27.json` declares the new target; it does not
modify the legacy `boards/dizi.json` or claim compatibility. Use the
read-only strict identity check:

```sh
python3 tools/macos27-preflight.py --json \
  --system-version /path/to/real-macos-27/System/Library/CoreServices/SystemVersion.plist \
  --kernel /path/to/decompressed-macos27-kernel-collection
python3 tests/test-macos27-preflight.py
```

The preflight intentionally exits with status **2 (BLOCKED)** even if a
version plist and Mach-O declare the expected 27/Darwin27
versions. Strings are not a hardware trust chain, and modern Apple Silicon
kernel collections require a separate loader. This tool never boots or
mutates storage and rejects the current XNU 22/iPadOS kernel.

## Status / unresolved hard blockers

**NO genuine macOS 27 binary has been booted, loaded, built for this board,
or installed.** The existing iPadOS 16 and 0120 experimental files remain
available separately. Proceeding to a physical macOS desktop requires the
new kernel, APFS+SSV, OS userspace, Apple Silicon platform expectations,
Qualcomm graphics, device services and security attestation above.
