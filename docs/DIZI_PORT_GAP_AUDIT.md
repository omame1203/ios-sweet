# dizi native iPadOS port: hardware gap audit

## 2026-10-21 touch transport integration (0117–0120)

* **XNU source connected, not device-verified:** 0117 implements source-based GPII0 TX/RX/event ring and completion mechanics; 0118 implements GENI SE9 SPI request/completion/timeout control; 0119 connects validated Novatek contacts to native coherent IOHIDEvent digitizer reports; 0120 connects firmware SRAM upload and verified post-upload boot to a native per-finger HID session. Host boundary tests and ARM64 object compilation cover these modules.
* **No physical touch enabled:** actual XNU ownership/doorbell/GPI IRQ/SMMU write backend remains absent. 0118 native backend is off and 0120's native transport gate is explicitly `0`. Existing board bootargs use `sweettouch=0` to protect known-good GUI.
* **Must be resolved before real touch:** independent hypervisor authority for both SIDs `0x403` (QUP SPI payloads) and `0x416` (GPI rings); actual ID2/SMR/S2CR/CB evidence and non-overlapping S1 page-table activation; separate coherent IOVA pages/pinning, physical ring and event completion handling, SE9 root clock and GPIO10–13 exclusive mux, GPIO54 routed IRQ, and actual NT36532 firmware transfer/readback/boot handshake. Static FDT entries and successful synthetic rings never imply hardware authority.


Audit date: 2026-10-21. Target: POCO Pad (SM7435, `dizi`), branch `pocopad-dizi`.
Sources: `boards/dizi.json`, `POCOPAD.md`, `NOTES.md`, patched XNU
sources (`xnu/patches/`) and preserved real-device console logs. This is a
read-only source audit; no device state or boot image has been changed by it.
The upstream `sweet` milestones near the bottom of `NOTES.md` apply to
**Redmi Note 10 Pro**, not to dizi unless independently verified.

## Already proven on the tablet

* Native XNU + iPadOS 16.7.16 reach the graphical lock/home screen, with UFS
  root mounting and `launchd`/SpringBoard running. This does not establish
  full Apple platform compatibility or driver coverage.
* XNU boot CPU/SGI and shim GICv3, timer and 16 KiB MMU work in the documented
  one-core configurations. The device reports four A55 + four A78 cores.
* Power-key HID and physical volume-up mapped to Home are user-confirmed with
  0099 key-test image (`sweetkeys=1 dizihomekey=1`). The default `dizi.json`
  still disables keys; volume-down and input latency remain unmeasured.
* Shim USB EP0 diagnostics work. This is separate from the native XNU DWC3
  device/ECM driver.
* GPII0 registers are readable and zero-valued, consistent with an
  unallocated channel (probe06–08), while apps SMMU
  ID/SMR/sCR0 can be read (probe09–13). There are zero live SMR matches for
  GPI1 SID 0x416 and QUP1 SID 0x403; the global register configures
  unmatched streams to fault. No such DMA transaction was executed.

## Dependencies directly preceding working physical touch

Touch support depends on independently validated ownership/control of the
QUP SE9 root clock, TLMM SPI pinmux and panel power/reset; correct SMMU
stream-to-context mappings for GPI1/0x416 and QUP1/0x403; coherent GPII0
TX/RX/event rings and SPI payload buffers using those *different* IOVA
domains; IRQ/completion/fault recovery; and Novatek NT36532 firmware download
when its SRAM state is absent. The published BOE firmware blob was verified
locally, but XNU has no transport to load it yet. Only after that can the
existing `0100` frame parser and HID event reporting be physically tested.
These dependencies need work; they are not all solved by increasing the
number of touchscreen-specific source files.

## Outstanding platform work, ordered by dependency

| Priority | Area | Evidence / actual limitation | Required next acceptance criterion |
| --- | --- | --- | --- |
| P1 | SMP topology / GIC / PSCI | `boards/dizi.json` boots with `cpus=1`; the existing `sweet` PSCI/SMP code supports up to 8 CPUs on its own 6-A55/2-A76 topology, whereas dizi has 4-A55/4-A78. No dizi secondaries tested; secondary suspend/resume is unsupported. | Validate dizi MPIDR/cluster/ISA and per-CPU GICR/SGI, bring up one extra core then all eligible cores, prove timer and scheduler stability. Do not simply raise `cpus` in the main GUI image. |
| P0 | SoC clocks, pinmux, regulators / PMIC ownership | Dizi clock framework is not generally ported. Probe02 SE9 root clock is stopped, FIFO disabled and DMA mode active; touch pins do not have verified active SPI mux. Native Linux FDT locates RPMh at 0x17a00000, unlike the sweet hardcoded RSC at 0x18220000 (`0062`). `0100` intentionally fails closed. | Read-only inventories followed by bounded, ownership-aware clock/rail/pinmux control with rollback; needed before touch or other device drivers. |
| P0 | IOMMU and coherent DMA domains | Probe12/13 find no active SMR matches for dizi touch's SIDs and unmatched streams fault. GPI rings and QUP SPI payloads need *distinct* valid IOVA mappings. | Implement a bounded translation/domain manager for these two streams after verifying hypervisor ownership; test fault handling and memory protection, then GPII0 descriptor/events. |
| P1 | RTC/absolute time | Saved native logs start near the Unix epoch. Dizi FDT has PMK8350 RTC at 0x6100 and alarm at 0x6200. The status-bar date/time is not proof of a real RTC clock. | Attach dizi PMIC/RTC (or a justified trusted alternative) to XNU wall-clock initialization; prove correct clock over reboot. |
| P0 | PMIC power/battery/charger/thermals | `0062` models Sweet's PM6150 SPMI layout and defaults to 100%/AC placeholders. The *real dizi log* records `SWEET BATTERY: static fallback, 100% 4200mV external=1 charging=0`—not a measurement. Dizi's FDT uses `qcom,pmic-glink` / ADSP battery-charger plus ADC7, PM6450 temperature alarm and thermal zones; 0099 ports only dizi key reads with SPMI v7. | Trace AOP/ADSP battery/chg protocol, add read-only real fuel gauge/charger/thermal status first; implement thermal safety and charge controls before sustained multithreaded load. |
| P1 | Watchdog, power states and restart | Sweet's watchdog service is a bring-up stub; a valid platform-controlled reboot, clean shutdown, CPU idle and system suspend/resume are not established on dizi. | Implement correct PSCI/Gunyah-compatible system power and wake operations and test in isolated stages, while preserving a fastboot recovery path. |
| P0 | Display, sleep/wake and LCD backlight control | iPadOS GUI is copied via CPU into the bootloader-initialized framebuffer. Dizi is a **DSI video LCD**, using TLMM57 external backlight-enable and GPIO98 reset, plus DSI panel rails. Sweet patch `0079` just fades framebuffer contents, with a comment assuming AMOLED; on this LCD it does **not** turn off backlight or panel power. No verified dizi suspend/resume. | Implement measured LCD brightness/backlight and panel sequencing, verify safe blank/unblank and full power-down/wake without screen corruption; native GPU acceleration is a distinct milestone. |
| P1 | Kernel USB / reliable diagnostics | Default `sweetusb=0 sweetearlyusb=0`. The bare-metal shim logger working does not establish XNU CDC-ECM; previous dizi XNU USB DMA trials panicked. | Safe XNU DWC3 init with proven DMA mapping, host enumeration, log/ECM RX/TX and panic recovery. |
| P1 | Hardware-backed peripheral interrupts | GICv3 virtual timer and SGI paths are proven, but dizi's PDC wake sources and peripheral IRQ paths have not been verified across controller drivers. Current physical keys are polled every 20 ms. | Route and verify interrupt-based keys and peripheral event delivery without blocking the scheduler; then wake-from-idle/suspend. |
| P1 | Storage robustness and UFS hardware lifecycle | HFS root mounts read-write via borrowed polled UFS path. Patch `0097` wakes an inherited ABL controller using SCSI START STOP UNIT; dizi FDT also has UFS PHY, clock, reset, vcc/vccq and interconnect requirements. Interrupt/queue support, cold reinit, native crash-safe iOS storage/data protection are unproven. | Multi-read/write integrity and flush tests, UFS PHY/clock and interrupted-power recovery, fault-contained failure and suspend/resume validation. |
| P2 | Wi-Fi/Bluetooth/networking | An ADT `wlan/local-mac-address` identity satisfied MobileGestalt, but no actual radio I/O. Dizi has WCN6750 WLAN over ICNSS2/WPSS and WCN6750 BT in the FDT; Android reports WLAN firmware ready, **not iPadOS**. | Real WCN6750 radio bring-up, firmware/remoteproc, interrupts and network stack integration; eventually Internet access and BT pairing. |
| P2 | Audio/sensors/cameras/pen | No dizi-specific functional drivers verified. FDT includes ADSP/LPASS + SoundWire audio, CCI/CSI camera nodes and sensor services, but these are Android-only evidence. NT36532 reports may include pen data while 0100 HID scaffold handles finger contacts only. | Port and individually test DSP/audio, sensors, ISP/cameras and pen protocols after platform controllers. |
| P2 | Apple platform trust/SEP/power services | Reference XNU uses a reduced KeyStore/entitlements model and `launchd_unsecure_cache=1`, and bypasses parts of genuine Apple security services for bring-up. | Inventory functional platform-service dependencies, implement principled compatibility and data protection before calling this a secure general-purpose iPadOS device. |

## Engineering order

### Confirmed 0107–0111 complete macOS kernel link (2026-10-21)

GitHub Actions `39470099403` passed against `e1ab9a4` after adding all five
new XNU patches. Downloaded kernel artifact `xnu/out-0111/kernel.development.sweet`
has SHA-256 `e2f5111ed22b2441be0b8d9fc2009567abd8371047bbbf65dcefa17669384dd4`
(17,283,736 bytes, ARM64 Mach-O), validated against the workflow's own
`SHA256SUMS`. This is full source compile/link only; real SMMU DMA,
GLINK/battery, LCD rails/backlight, touch, 8-core SMP, Wi-Fi/BT, or UFS
cold-start operation remain unverified. No hardware actions occurred.

An Ubuntu `.github/workflows/dizi-host.yml` was prepared locally for
patch-extracted code, ASan/UBSan and AArch64 cross-compilation from a clean
source checkout. GitHub rejected its push because the active OAuth token
lacks the `workflow` scope; this extra CI workflow is NOT installed remotely.
The host tests themselves passed locally with no ignored device assets.

### Additional non-device XNU integration (0107–0111)

* `0107`: optional dizi 4-A55/4-A78 ADT/XNU topology metadata. The
  tracked, identity-free `tests/fixtures/dizi-cpu-only.dts` permits offline
  reproduction of the source-observed FDT CPU mapping. No secondary PSCI,
  GICR or heterogeneous energy policy is enabled by default.
* `0108`: XNU compiles an offline SE9 clock/GCC/TLMM/IRQ54 planner plus a
  hard-disabled bridge. Host fake register model passes 143 assertions;
  no verified exclusive clock or hypervisor ownership, live GENI SPI,
  clock writes, or GPI DMA have been implemented.
* `0109`: framebuffer OFF/ON generation checks now protect the *pixel loop*
  as well as the later LCD bookkeeping. A per-row `fLock` prevents a stale
  OFF tick from painting over an accepted ON. Real backlight and panel
  sequencing are still missing.
* `0110`: PMIC-GLINK software scheduler requires verified ADSP and charger
  service handoff, local endpoint epoch and positive ownership evidence;
  pre-existing legacy untagged hooks cannot claim a valid battery link.
  Transport details (SMEM, IPCC, remoteproc, GLINK native/rpmsg, SSR/PDR)
  have not been implemented on XNU, so battery/thermal readings remain
  unverified.
* `0111`: polled UFS root's GPT table, 32-bit SCSI LBA and signed BSD block
  arithmetic are bounds-checked by portable helpers; test covers malformed
  lengths/ranges. This does **not** add a cold UFS PHY startup, asynchronous
  request queue, or suspend/reset recovery.

The above changes were applied to the archived full-XNU 0106 buildtree;
their C translation units produced ARM64 Mach-O objects with recorded
Apple compiler flags, while affected C++ sources passed syntax-only
compatibility checks. The subsequent macOS Actions full kernel link
for this expanded patchset is now confirmed above (`39470099403`).
No device actions occurred during this integration.

### Full XNU build verification (2026-10-21, no tablet access)

The macOS GitHub Actions full XNU build for patches 0101–0106 succeeded:
run `39465604101`, commit `71a2b4e`, macOS-14,
`MACHINE_CONFIG=SWEET`, `DEVELOPMENT`. Its `xnu-kernel` artifact was
downloaded to ignored `xnu/out-0106/`, SHA256SUMS-verified, and confirmed
as 17,266,272-byte ARM64 Mach-O (`34537ec17ff2457f0bae9e9cdc9c1011b2fd991fc3f63b4ccb63534a5635075b`).
This is a kernel compile/link milestone **only**, not evidence that any
unverified physical peripheral is working. Existing restrictions on all
device actions, including temporary boot, remain in force.

Source-only `0107` adds *optional* dizi 4x A55 / 4x A78 topology metadata
and verified ADT generation, while preserving the default one-core boot.
`dizismpclusters=1` and a separately generated experimental ADT are both
required in addition to `cpus>1`; neither change is selected for the known
GUI build. PSCI secondary bring-up/GIC redistributors and XNU scheduler
heterogeneity are still unverified; its full macOS link is pending.

The Apple `IONetworkingFamily-166` source study (ignored
`research/ionet-0109/REPORT.md`) establishes why adding a superficial
IOEthernetController is unsafe: legacy `sweet_usb.c` already owns the BSD
`ue0` ifnet, while Apple's IONetworkInterface owns and attaches its own
private ifnet, and patch 0098's fake IONetworkController class would collide
with the genuine ABI. Correct integration requires a single-interface
migration and an actual compatible family, not a cosmetic class rename.

### Offline source implementation checkpoint (2026-10-21)

After this audit, XNU patches `0101`–`0106` added testable pieces for
PMK8350 RTC readout, SMMUv2 Stage1 IOVA allocation and GPI TRE building,
BOE LCD power-state bookkeeping, Novatek SRAM firmware packet planning,
PMIC-GLINK battery reply validation and opt-in USB CDC-ECM link metadata.
They apply after the existing patch `0100`. Standalone mock and ARM64
compilation checks passed; see `tests/test-dizi-port.py` and separate
PMIC/USB tests. No new tablet runtime measurements or boots were performed.

The **hardware completeness table above remains accurate**: the SMMU
component is not yet attached to Gunyah-protected stream/context registers;
the GPI rings are not being driven; LCD has no verified TLMM/DSI/brightness
backend; the battery parser has no owned ADSP GLINK transport; and the USB
bridge does not establish working ECM or Internet on dizi. RTC values are
exposed raw, not applied as an authoritative system clock. GPU, WLAN/BT,
camera, audio, sensors, suspend/resume, security and several other platform
systems require additional native implementations. Full device functional
completion cannot be demonstrated without hardware validation.

First verify basic power/thermal status, then validate dizi CPU
topology/interrupts and build low-level clock, PMIC-GLINK/SPMI/regulator, RTC
and reliable diagnostics as reusable platform services.
Then establish DMA/SMMU ownership and fault handling, followed by GPI/SPI
transport, Novatek BOE SRAM firmware and actual touch. In parallel port safe
display power, battery and USB; later pursue accelerated graphics, radios,
multimedia and security compatibility.

No table row marked unfinished is a statement of runtime failure unless a
device log is cited. `0100` built successfully in GitHub Actions run
`39457087335`; the touch transport remains gated and has **not** been
shown to work physically. Preserve the confirmed 0099 GUI/key-test image.

Performance caveat: the saved native GUI log explicitly reports
`SWEET CPU: requested=1 selected=1` and UFS polling; framebuffer updates are
performed by CPU copies rather than a native GPU/MDSS driver. Thus slow
response has several plausible causes and must not be attributed solely
to the CPU count without latency measurements.

## 2026-10-21 source-only 0112–0113 audit

- UFS: gated primary GPT header/table CRC32, bounds, and populated-entry consistency added in 0112; offline synthetic validation only. No UFS PHY cold reset, queue interrupts, flush/error recovery or verified physical GPT.
- RTC: 0113 guarded one-time wall-clock seeding from read-only PMK8350 ticks; no live counter confidence and boot arg disabled by default.
- Touch: SE9/GPI/SMMU activation still blocked by unknown exclusive ownership and SIDs 0x403/0x416 with unmatched fault active; do not start DMA.
- Power/thermal: only software state machine and scheduler, no ADSP/PDR/SMEM/GLINK transport, no actual battery or thermal sample.
- Display: framebuffer generation race addressed, no verified physical backlight/DSI rails ownership.
- SMP: topology metadata available opt-in, `cpus=1` baseline maintained, no proven secondary-core PSCI/GICR bringup.
- USB: Apple IONetworkingFamily collides with existing fake IONetworkController and duplicates ifnet; no integration permitted without ownership redesign.
- Wi-Fi/Bluetooth, GPU, ADSP audio, cameras, sensors, pen, suspend/resume and secure-world compatibility remain outstanding; source/runtime implementation and provenance needed.

- **0112/0113 macOS link verified:** Actions `39472174737` succeeded, 17,283,968-byte ARM64 Mach-O kernel hash `be1e5f73200fd6136e0503ffb4a92673561b45adbdbb1206372649d1f8c8b422`; no real hardware behavior proven.

- **0114 source implementation:** guarded, read-only partial SMMUv2 GR0 audit in XNU (ID0/ID1/sCR0/SMR0 only), proven register addresses from past probes. No ID2/S2CR mapping, hypervisor stream ownership, CB allocation, GPI DMA enable or bus write; 54 simulated assertions + native ARM64 objects only.
- **0115 native IONetworkingFamily blocker:** true IONetworkInterface unconditionally allocates a second BSD ifnet, while fake IONetworkController class collides at link; only a standalone fail-closed future migration planner passes host tests, not native functional integration.

- **0116 LCD XNU integration:** default-disabled physical backlight ownership witness contract, wired into SweetFramebuffer black-frame request/completion; no trusted live witness/GPIO ownership/rail or DSI backend, thus no physical power toggle. Synthetic host tests + native ARM64 translation-unit check only. 0115 patch number reserved for rejected native networking migration (actual USB portable policy is not an XNU kext).

- **0116 complete macOS link:** Actions `39474995905` success, SHA-256 `2f867e8b658ba76166d21deb0d8803ba843a16cb6ba84400973b77baa9090328`, 17,300,528-byte ARM64 Mach-O; still no live GPIO57/DSI power ownership, physical panel toggle or device validation.
