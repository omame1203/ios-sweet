# dizi native iPadOS port: hardware gap audit

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
