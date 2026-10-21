# POCO Pad (dizi) → genuine macOS 27 Golden Gate migration

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
| macOS userspace | **None** | `launchd`, `dyld`, `WindowServer`, APFS root and Apple-signed macOS27 resources needed |

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
