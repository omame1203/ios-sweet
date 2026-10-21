## @file
# POCO Pad (dizi / 2405CPCFBG), Qualcomm SM7435, AArch64 EDK2-MSM platform.
# Source for a new board; NOT evidence of a bootable FD or Windows support.
#
# Upstream convention: Platform/Xiaomi/sm7325/lisa.dsc, current
# edk2-porting/edk2-msm. This board intentionally uses only SM7435 silicon,
# never rebrands SM7325 binaries or copies its ACPI table.
#
# Device provenance: boards/dizi.json and backed-up rooted Android 16
# backup/dizi/fdt (2026-10-20); physical splash 0xB8000000 size 0x02B00000,
# inherited BGRA8888 visible canvas 1600x2560, row stride 6400.
# CPU topology 4x Cortex-A55 + 4x Cortex-A78, GICv3 and counter 19.2MHz.
# None of these facts establishes ABL/Gunyah RAM ownership, cache coherency,
# GOP accessibility after UEFI handoff, or safety of storage initialization.
#
# Integration contract (worker-6): Platform/Qualcomm/sm7435/sm7435.{dsc,fdf}
# must implement genuine SM7435 silicon memory map/pre-PI and a conservative
# FV that omits unverified UFS/ACPI/SMI/foreign Qualcomm binary drivers.
#
[Defines]
  VENDOR_NAME                    = Xiaomi
  PLATFORM_NAME                  = dizi
  PLATFORM_GUID                  = 78f862a1-bf23-49b9-9dbd-075c60530435
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x00010019
  OUTPUT_DIRECTORY               = Build/$(PLATFORM_NAME)
  SUPPORTED_ARCHITECTURES        = AARCH64
  BUILD_TARGETS                  = DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT
  FLASH_DEFINITION               = Platform/Qualcomm/sm7435/sm7435.fdf
  DEVICE_DXE_FV_COMPONENTS       = Platform/Xiaomi/sm7435/dizi.fdf.inc

!include Platform/Qualcomm/sm7435/sm7435.dsc

[BuildOptions.common]
  # As in the upstream Xiaomi boards, enable firmware UI, but NOT
  # ENABLE_LINUX_SIMPLE_MASS_STORAGE or any vendor-specific UFS write path.
  GCC:*_*_AARCH64_CC_FLAGS = -DENABLE_SIMPLE_INIT

[PcdsFixedAtBuild.common]
  # IMPORTANT: Inherited display scanout only. No MIPI/DSI re-initialization.
  # Upstream SimpleFbDxe uses these PCDs to provide one GOP BGRA8888 mode.
  # 1600*4=6400 bytes per line, 1600*2560*4=0x00FA0000 < 0x02B00000.
  gQcomTokenSpaceGuid.PcdMipiFrameBufferAddress|0xB8000000
  gQcomTokenSpaceGuid.PcdMipiFrameBufferWidth|1600
  gQcomTokenSpaceGuid.PcdMipiFrameBufferHeight|2560
  gQcomTokenSpaceGuid.PcdMipiFrameBufferPixelBpp|32
  gQcomTokenSpaceGuid.PcdMipiFrameBufferVisibleWidth|1600
  gQcomTokenSpaceGuid.PcdMipiFrameBufferVisibleHeight|2560

  # Snapshot from FDT /soc/interrupt-controller@17200000 and /soc/timer.
  # Virtual timer PPI=27 and physical timer PPI=30. Parent Silicon must
  # select the virtual counter (USE_PHYSICAL_TIMER=FALSE).
  gArmTokenSpaceGuid.PcdGicDistributorBase|0x17200000
  gArmTokenSpaceGuid.PcdGicRedistributorsBase|0x17260000
  gArmTokenSpaceGuid.PcdArmArchTimerFreqInHz|19200000
  gArmTokenSpaceGuid.PcdArmArchTimerIntrNum|30
  gArmTokenSpaceGuid.PcdArmArchTimerVirtIntrNum|27

  # Board UI preference, not an assertion about physical panel DPI.
  gSimpleInitTokenSpaceGuid.PcdGuiDefaultDPI|240

  # Identity is in BoardEvidence.txt, NOT via unconsumed RenegadePkg PCDs:
  # the minimal public-source FV intentionally excludes PlatformSmbiosDxe
  # and EDK2 rejects those unused gRenegadePkgTokenSpaceGuid PCD overrides
  # with error F001 (not declared by packages referenced in the FV).

[Components.common]
  # Real EDK2 DXE driver, read-only GOP validation after SimpleFbDxe.
  Platform/Xiaomi/sm7435/DiziDiagDxe/DiziDiagDxe.inf
