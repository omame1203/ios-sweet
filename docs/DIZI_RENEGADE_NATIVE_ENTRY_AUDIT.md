# POCO Pad dizi: ABL → Android AArch64 Image → Renegade EDK2 native-entry audit

**Audit date:** 2026-10-21. **Scope:** read-only saved artifacts, pinned
public source and the in-tree SM7435 overlay. **Disposition: BLOCKED** for
native FD relocation, PrePi stack use and any executable jump. This is **not**
a successful ABL handoff, a RAM-ownership grant, or a device boot report.
No fastboot/device/memory access, image modifications or commits occurred.

## Independent evidence / interpretation boundaries

| Saved input | SHA-256 | What it actually proves |
| --- | --- | --- |
| `backup/dizi/abl_a.img` | `1b7e88d890d7a836a393a075628c9546b6f70e6501943261445283a643d1c1eb` | An **ELF32 ARM packaging container** with an embedded UEFI FV (`_FVH` signature at file offset 0x1028), with ELF entry and load segment at **0x9fa00000** (LOAD file offset 0x1000, file size 0x30000, RWE); **not** the eventual AArch64 kernel PC, current EL, physical kernel load base or Qualcomm stage-2 mapping. |
| `backup/dizi/boot_a.img` | `b599bfbdc0ee336dba7de26e6f3e970e6888a7d839097be954b4b31594846dae` | Android boot **v4**, complete partition image of 134,217,728 B, with **kernel_size 46,854,828 B**, **ramdisk_size 1,380,093 B**, **boot_signature_size 4,096 B**, header_size 1,584 B. Kernel payload begins at **file** offset 0x1000. No physical load address is encoded by the boot v4 header. |
| `backup/dizi/vendor_boot_a.img` | `f053adc7d6f5aaead81f16be16d5275185ebddedb769adbb837bfef435422b08` | `VNDRBOOT` **v4**, page_size 4096, header_size 0x850, vendor_ramdisk_size **13,848,188 B**, dtb_size **4,886,872 B**, table_size 0x6c / one entry, bootconfig_size 0x55. Header fields `kernel_addr=0x8000`, `ramdisk_addr=0x1000000`, `dtb_addr=0x1f00000` must **not** be interpreted as measured loaded *physical* addresses on this boot. |
| `backup/dizi/fdt` | `13107fc680b51539989ecd86127edd9d50b77af22afe384ffc7956c3c2f8a944` | 851,726-byte **captured, already-assembled running DTB** (v17). Snapshot topology/reservations, not the PA at which ABL handed the DTB to the kernel, not current RAM permissions. |

### Actual Android kernel's first 64 bytes

Reading 64 bytes at `boot_a.img` **file** offset 4096 yields the **uncompressed
AArch64 Linux Image header**, not a compressed kernel, raw EDK2 FV or a
bootloader-supplied UEFI entry:

- `code0` begins with `MZ` (also valid AArch64 instruction encoding);
  `code1` is part of the executable entry stub.
- `text_offset = 0`, `image_size = 0x02a90000` (**44,630,016 B**),
  `flags = 0xA`, `magic = ARM\x64` at +56; `res5 = 0x40` at +60.
- At Image +0x40 there is a `PE\0\0` header, machine `0xaa64`
  (AArch64). **An EFI-stub-compatible Linux Image is not an EDK2 FD**.
  The presence of PE metadata also does **not** establish whether this
  device's ABL actually called the Linux Image entry or the PE EFI stub.
- Flags `0xA` mean little-endian, **4 KiB Linux page size** and
  2 MiB-aligned load base may be anywhere in otherwise usable RAM.
  The `image_size` region is required by Linux and differs from the
  boot header's whole `kernel_size`. Neither field gives a physical PA,
  a reserved range, nor a post-handoff *free* allocation.

**ABI source:** saved vendor Linux
`research/xiaomi-ruan/Documentation/arm64/booting.rst`,
“Call the kernel image” and “Before jumping into the kernel.” The required
normal AArch64 Linux Image entry is:

1. `x0 = physical address of an aligned DTB`; `x1 = x2 = x3 = 0`.
   DTB 8-byte aligned and ≤2 MiB. This **captured** FDT is under 2 MiB
   but its **runtime pointer x0 is unknown**.
2. Nonsecure **EL1 or EL2**, with PSTATE.DAIF masked and **MMU off**;
   cache state must satisfy the architecture's image PoC-clean / I-cache
   coherency rules. A successful Android boot does not independently
   attest these states for a *new* UEFI transfer.
3. Correct 2 MiB-aligned physical Image placement plus `text_offset`,
   image-size memory clearance, DTB/initrd constraints, architected timer,
   GICv3/PSCI/coherency prerequisites and quiesced DMA.
4. Any EFI-stub entry route is a **different path** that needs verified
   EFI boot services/PE entry ABI; do not conflate the two merely because
   a PE header exists.

These are **requirements**, not observations of ABL execution registers.
The ELF32 envelope around the embedded UEFI FV in `abl_a.img` also does
**not** prove that its final kernel handoff was an AArch32-to-AArch64
transition, nor reveal x0/EL/SCTLR at that moment. Static ABL image bytes
do not supply a fresh attestation.

### Observed live FDT memory, and where its evidence ends

- Seven nonempty `/memory/reg` DDR banks. The captured DT includes
  **35** fixed `/reserved-memory` regions and **10** dynamically placed
  reserved children without `reg`: `mem_dump_region`, `linux,cma`,
  `adsp_heap_region`, `audio_cma_region`, `sdsp_region`,
  `secure_cdsp_region`, `va_md_mem_region`,
  `non_secure_display_region`, `qseecom_region`,
  `qseecom_ta_region`. An FDT `size` or `alloc-ranges` constraint
  cannot replace the current physical placement of those allocations.
- `/chosen/linux,initrd-start` **0xb719f000**,
  `/chosen/linux,initrd-end` **0xb7ffe6c4**; this is a
  **captured Linux-running** initrd interval, not necessarily the initial
  ABL placement for a replacement kernel, and it differs from the raw
  vendor boot header's address fields.
- Splash/scanout reserved: **0xb8000000+0x02b00000**;
  ramoops **0x80d00000+0x00200000**. These and all other fixed
  reservations remain unavailable without a verified live ownership transfer.
- The saved FDT explicitly contains
  `qcom,gunyah-hypervisor-1.0`, `qcom,gunyah-vm-id` and a
  `hyp_region@80000000`. This establishes **hypervisor configuration
  in the saved tree**, **not** the current EL2 stage-2 translation, Gunyah
  VM memory assignment, XPU permission or executable attribute for EDK2.
- Checking the candidate `0x90000000..0x91000000` against nonempty DDR
  and fixed reservations is useful for rejecting contradictions, but a
  non-overlap test does **not** prove the candidate does not conflict with
  the **unknown runtime Linux Image allocation**, live dynamic reservations,
  EFI/ABL allocations, other active VM assignments or DMA.

**Do not infer a physical Image allocation from**: `abl_a.img` ELF
entry `0x9fa00000`; vendor header `kernel_addr=0x8000`; boot partition
offset `0x1000`; `/chosen` initrd positions; a later Linux
`/proc/iomem` (if ever supplied); an FDT DDR interval; a successfully
generated 4 MiB EDK2 `.fd`; or a fastboot `getvar` response.

## Qualcomm edk2-msm entry is not the Android Linux Image entry

Audited pinned upstream:
`/tmp/dizi-edk2-msm-audit-20261021/tools/BootShim/BootShim.S`,
`Silicon/Qualcomm/QcomPkg/PrePi/ModuleEntryPoint.S`, and
`Silicon/Qualcomm/QcomPkg/PrePi/Pi.c`.

**BootShim.S:** its own legacy-looking ARM64 Image header has zero
`text_offset/image_size/flags`; it moves `_Payload` to x1 and copies
`UEFI_SIZE` bytes, **16 bytes at a time**, to compile-time `UEFI_BASE`
before `br x5`. On the normal path it does not clobber x0, but this is
**not proof** of copied FD ownership, alignment, source/destination
non-overlap, cache maintenance, MMU/EL2 validity, relocatability or successful
SEC handoff. Its hardcoded UEFI target is not a measured dizi allocation.
An FD/FV header is not directly an AArch64 Linux Image wrapper.

**Qcom PrePi `_ModuleEntryPoint`: first nontrivial memory action is**
`mov x10, FixedPcdGet64(PcdDeviceTreeStore)`; `str x0,[x10]`.
This occurs **before** `ArmDisableCachesAndMmu`, exception-vector setup,
stack setup or `PlatformInitialize`. It then:

1. masks interrupts, disables MMU/caches, invalidates I-cache/TLB,
   touches `SCTLR_EL1` SPAN, loads/writes `VBAR_EL1`;
2. fills **0x800 bytes** at `PcdCpuVectorBaseAddress` on the primary
   branch, then sets `CPACR_EL1`;
3. clears the primary SEC stack with SIMD stores up to
   `PcdPrePiStackBase+PcdPrePiStackSize` **before the C gate**,
   and later enables caches and calls `CEntryPoint(stack, size)`.

The saved dizi SoC DSC currently proposes **not proven**:

| Candidate | Interval | Actual action / required proof |
| --- | --- | --- |
| FD/FV | `[0x90000000, 0x90400000)` | 4 MiB executable copy; validate freshness, non-overlap, stage-1/stage-2/XPU R/X/W and cache maintenance |
| FDT store + vectors | `[0x90400000, 0x90410000)` | unconditionally writes x0 to `0x90400000`, overwrites vectors near `0x90401000` |
| UEFI/HOB pool | `[0x90410000, 0x90fc0000)` | unpatched `Pi.c` uses **FixedPcdGet32** base/size |
| Primary stack | `[0x90fc0000, 0x91000000)` | SIMD clearing occurs before any C-based ownership guard |

`PrePi/Pi.c` also reads `PcdSystemMemoryBase`,
`PcdSystemMemorySize`, `PcdUefiMemPoolBase`,
`PcdUefiMemPoolSize` as **32-bit PCDs**. The separately observed high
DDR bank beginning at `0x8c0000000` cannot be dropped into these
unmodified PEI allocator fields. The 16 MiB low candidate is
**source configuration only**; the host-built FV at `0x90000000` does not
prove its live ownership or that the loader copied it.

`CEntryPoint` calls `PlatformInitialize`, then `PrePiMain`, where
`HobConstructor`, `MemoryPeim`, PlatformPeim and FV decompression
**use/modify the selected memory**. `PlatformInitialize` currently parks
unless a separate trusted memory-verifier has set its gate, but this occurs
**after** the first FDT/vector/stack memory writes. The separate
`DiziEarlyHandoffGuardEntry.S` currently parks on all paths;
it has no pre-SEC proof that can safely enable the upstream entry.

The in-tree `DiziGkiHandoff` is a **source-only FD/FDT planner**, not
a relocator/trampoline certified for ABL execution. The packaging gate
`tools/dizi-renegade-image.py:VERIFIED_DIZI_WRAPPERS` remains empty.

**Concurrent source-only progress (separately owned):**
`Platform/Xiaomi/sm7435/DiziBootShim/DiziNativeEntry.S` now contains a
genuine standalone ARM64 `Image` entry whose first branch reaches
register-only diagnostic checks of `x0..x3`, `DAIF`, `CurrentEL` and
`SCTLR_EL1`. It intentionally terminates in a `WFE` park on **every**
path and cannot establish the live FD/stack ownership it lacks.
`DiziSecTransfer.{S,c}` contains a separate **compile-time-disabled**
post-grant transfer candidate gated by `DIZI_SEC_ENABLE` **and**
`DIZI_SEC_TRUSTED_OWNER_IMPLEMENTED`; its required external
`DiziSecGetTrustedRuntimeGrant` provider is absent from the reviewed
handoff. These are useful implementation milestones, **not** fresh
evidence of ABL loading those new binaries or executing PrePi.
The old upstream `BootShim.S` should not silently substitute for them.

## Can the loader's already-allocated Linux Image RAM become FD + stack?

**Not on presently available evidence.** Its correct physical
`Image` load base, protected/reserved **extent**, copy/source lifetime,
whether it stays accessible on transfer, and ABL reclaim semantics are
not encoded in the four saved images. Reinterpreting that live memory as
free because Linux would no longer execute the Image is **unsafe**:

- It could overlap the executing native wrapper/trampoline, the *source*
  of an FD being copied, FDT, vendor/boot ramdisks, ABL data, Gunyah
  allocations or reserved firmware. Stack initialization is destructive.
- A live EL2 stage-2 mapping, security/XPU ownership and
  *instruction-fetch* permission are distinct from FDT DDR membership,
  bootloader image placement and EL1 page tables.
- With MMU enabled, `UEFI_BASE` as a physical PA cannot be used as a
  pointer/branch target without a proved VA translation and cache
  attributes. With MMU disabled, the PA is still subject to Gunyah/XPU
  and proper instruction-cache synchronization.
- Overlap-safe relocation requires measured **source, destination and
  copier/trampoline intervals**, headroom, stack, vectors, initial x0 DTB,
  initrd and both firmware volumes, before any memory write. The
  original Image header size is **not** a full allocation map.
- The existing `BootShim.S` uses non-overlap-assuming 16-byte `ldp/stp`
  copying; it must not be treated as an overlap-safe or permission-aware
  memcpy implementation. `FD_SIZE` and `BOOTIMG_HEADER_VERSION=4` alone
  do not implement a Linux Image ABI or secure transition.

Only after an independently verified **current-boot grant** to a
**disjoint, executable and writable** set of intervals could the actual
Image allocation *potentially* be partitioned for FD/stack. The grant
must give explicit ownership/revocation semantics and separate
permissions for each segment; no candidate address is approved here.

## Ordered entry gate: exact missing runtime proofs

1. **Kernel Image / wrapper entry trace:** independently captured actual
   boot handoff PC, physical loaded Image start and end, loaded Image
   size/headroom, and the entry **path** (normal `code0` vs EFI PE stub).
   Verify `x0..x3`, original DTB physical address, core MPIDR and
   expected exception level. Saved ABL ELF and partition headers cannot
   attest this. A code comment about earlier EL1/MMU observations is not
   a retained raw register capture and must not be treated as one.
2. **Pre-write RAM ownership:** live ABL/Gunyah/EL2 memory grants for
   each FD/FV, handoff slot, exception vector, PEI/HOB pool and stack.
   Complete all 10 dynamically allocated reserved ranges; reject
   overlap with live Image, boot/vendor initrd, FDT, framebuffer,
   ramoops, ABL runtime, DMA, peer-VM pages or the executing trampoline.
   This grant must be established **before the first** `str x0,[x10]`.
3. **Current CPU state / execution permission:** authenticated/current
   `CurrentEL`, `SCTLR_EL1`, `TCR_EL1`, `TTBR0/1_EL1`,
   `VBAR_EL1`, DAIF, cache coherency and exact AArch64 entry convention,
   plus actual stage-2/XPU PA read/write/execute and trap settings.
   Raw FDT values or self-declared software flags are insufficient.
4. **Relocator correctness:** reviewed, position-independent first
   instruction and actual native AArch64 Linux Image wrapper; checked
   aligned source/destination/stack intervals, source/destination
   non-overlap or explicit memmove, exact FD digest/size, I/D-cache
   maintenance and executable SEC entry. The loader must pass the
   DTB in x0 intact to Qualcomm PrePi.
5. **Early EDK2 correctness:** amend or externally guard all unconditional
   PrePi pre-C writes, verify 32-bit PCD allocation bounds, FDT store,
   vector/stack zeroing, cache/MMU disabling permissions and
   `PlatformInitialize` authorization **before** firmware publication.
   No donation of unrelated donor-SOC memory/GIC/UFS/ACPI/GOP drivers.
6. **Later device/platform work:** PSCI/GIC/clock/console/graphics/storage
   permissions and UEFI runtime devices are additional blockers **after**
   safe entry. A host-built `.efi`/`.fd` is not a live driver or boot.

### Safest next milestone

Create a **read-only, external boot-handoff attestation** containing real
load PA/extent, physical FDT x0, current EL/MMU/cache state and trusted
EL2/XPU RAM grants for all early write ranges. Validate its provenance and
non-overlap **before SEC**, rather than trying to write debug pixels or
reuse guessed Image memory. Until such evidence exists, keep the
Renegade wrapper/hash allowlist empty, the early guard parked, memory
publication disabled, and **do not jump to the SEC entry**.

No additional fastboot `getvar` was performed: bootloader variables cannot
establish current memory ownership, EL2 stage-2 page permissions, FDT x0
or runtime SCTLR/TTBRs. This audit makes no device-runtime assertions.
