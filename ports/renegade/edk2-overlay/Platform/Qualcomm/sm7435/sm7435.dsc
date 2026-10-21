## @file
# Renegade Project / edk2-msm SM7435 (Qualcomm Parrot) SoC parent.
# Source-only, integration candidate for Platform/Xiaomi/sm7435/dizi.dsc.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# Deliberately NOT !including QcomCommonDsc.inc: it unconditionally builds
# EFI_Binaries, device-specific touch/USB/storage drivers, and a donor-style
# GIC/Timer/SimpleFb integration without verified SM7435 ownership. All INF
# components here refer to open-source modules only.
#
# Saved dizi FDT: backup/dizi/fdt, SHA256 13107fc6...2f8a944.
# Observations alone do not authorize access to the addresses below.
# QcomPkg/PrePi/Pi.c reads 32-bit PcdSystemMemoryBase/PcdUefiMemPoolBase.
# Hence high 0x8c0000000 cannot back its unmodified PEI memory allocator.
# The 0x90000000..0x90ffffff window is a CANDIDATE only, exclusively
# admitted by Silicon/Qualcomm/sm7435/DiziSm7435PlanMemory (never by FDT
# membership alone). FD and pool positions are not independently attested.
##

[Defines]
  SOC_PLATFORM                  = SM7435
  USE_PHYSICAL_TIMER            = FALSE
  DEFINE DIZI_SM7435_ENABLE_CONSOLE_SHELL = FALSE

!include MdePkg/MdeLibs.dsc.inc

[BuildOptions.common]
  # Do not inherit the SM7325/SM8550 vendor CPU/clock overrides.
  GCC:*_*_AARCH64_CC_FLAGS      = -ffixed-x18 -fno-builtin -fno-common -fshort-wchar

[PcdsFeatureFlag.common]
  gEfiMdePkgTokenSpaceGuid.PcdComponentNameDisable|TRUE
  gEfiMdePkgTokenSpaceGuid.PcdDriverDiagnosticsDisable|TRUE
  gEmbeddedTokenSpaceGuid.PcdPrePiProduceMemoryTypeInformationHob|FALSE
  gEfiMdeModulePkgTokenSpaceGuid.PcdConOutGopSupport|FALSE
  gEfiMdeModulePkgTokenSpaceGuid.PcdConOutUgaSupport|FALSE

[PcdsFixedAtBuild.common]
  # Exactly the 16 MiB untrusted-until-verified RAM candidate from Silicon.
  # Do NOT substitute donor 0xb0400000 heap: it conflicts with dizi splash.
  gArmTokenSpaceGuid.PcdSystemMemoryBase|0x90000000
  gArmTokenSpaceGuid.PcdSystemMemorySize|0x01000000
  # Layout MUST match the four DISJOINT descriptors in SM7435 Silicon:
  #   FD [90000000,90400000) protected reserved FV, externally reviewed;
  #   FDT store [90400000,90401000), VBAR [90401000,90401800),
  #     remainder through 90410000 reserved for early boot;
  #   PEI conventional heap [90410000,90fc0000);
  #   SEC stack [90fc0000,91000000), excluded by HobConstructor.
  # PcdFdBaseAddress/FdSize and FvBaseAddress/FvSize are bound by the FDF.
  # QcomPkg/PrePi/ModuleEntryPoint.S WRITES FDT/exception vectors BEFORE
  # PlatformInitialize and its owner gate; an independently trusted external
  # entry wrapper MUST verify these PAs before SEC execution. Default fail.
  gQcomTokenSpaceGuid.PcdUefiMemPoolBase|0x90410000
  gQcomTokenSpaceGuid.PcdUefiMemPoolSize|0x00bf0000
  gSimpleInitTokenSpaceGuid.PcdDeviceTreeStore|0x90400000
  gEmbeddedTokenSpaceGuid.PcdPrePiStackBase|0x90fc0000
  gEmbeddedTokenSpaceGuid.PcdPrePiStackSize|0x00040000
  gEmbeddedTokenSpaceGuid.PcdPrePiCpuIoSize|44
  gArmTokenSpaceGuid.PcdCpuVectorBaseAddress|0x90401000
  gArmPlatformTokenSpaceGuid.PcdCPUCoresStackBase|0x90fc0000
  gArmPlatformTokenSpaceGuid.PcdCPUCorePrimaryStackSize|0x00020000
  # Single-core early diagnostics only; FDT lists 4x A55 + 4x A78, but no
  # secondary GICR/PSCI boot path has been validated for Renegade on dizi.
  gArmPlatformTokenSpaceGuid.PcdCoreCount|1
  gArmPlatformTokenSpaceGuid.PcdClusterCount|1

  # FDT /soc/interrupt-controller@17200000 and arm,armv8-timer:
  # secure PPI=29, physical PPI=30, virtual PPI=27, 19.2 MHz.
  # No ArmGicDxe is loaded until GIC ownership and GICR WAKER are reviewed.
  gArmTokenSpaceGuid.PcdGicDistributorBase|0x17200000
  gArmTokenSpaceGuid.PcdGicRedistributorsBase|0x17260000
  gArmTokenSpaceGuid.PcdArmArchTimerFreqInHz|19200000
  gArmTokenSpaceGuid.PcdArmArchTimerSecIntrNum|29
  gArmTokenSpaceGuid.PcdArmArchTimerIntrNum|30
  gArmTokenSpaceGuid.PcdArmArchTimerVirtIntrNum|27

  # Board-specific width/height/stride in dizi.dsc. This PCD is a physical
  # framebuffer address, NOT a writable/mapped GOP permit.
  gQcomTokenSpaceGuid.PcdMipiFrameBufferAddress|0xB8000000
  gQcomTokenSpaceGuid.PcdMipiFrameBufferWidth|1600
  gQcomTokenSpaceGuid.PcdMipiFrameBufferHeight|2560
  gQcomTokenSpaceGuid.PcdMipiFrameBufferPixelBpp|32

  gEfiMdeModulePkgTokenSpaceGuid.PcdFirmwareVendor|L"Renegade Project"
  gEfiMdeModulePkgTokenSpaceGuid.PcdFirmwareVersionString|L"SM7435 source-only"
  gEfiMdeModulePkgTokenSpaceGuid.PcdEmuVariableNvModeEnable|TRUE
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x0f
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80000000

[LibraryClasses.common]
  # Source-only canonical EDK2 libraries; no donor Silicon blobs.
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  BaseSynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  SafeIntLib|MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
  # CpuLib is already provided by MdePkg/MdeLibs.dsc.inc.
  CpuExceptionHandlerLib|ArmPkg/Library/ArmExceptionLib/ArmExceptionLib.inf
  DefaultExceptionHandlerLib|ArmPkg/Library/DefaultExceptionHandlerLib/DefaultExceptionHandlerLib.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  SerialPortLib|MdePkg/Library/BaseSerialPortLibNull/BaseSerialPortLibNull.inf
  ArmLib|ArmPkg/Library/ArmLib/ArmBaseLib.inf
  ArmDisassemblerLib|ArmPkg/Library/ArmDisassemblerLib/ArmDisassemblerLib.inf
  ArmMmuLib|ArmPkg/Library/ArmMmuLib/ArmMmuBaseLib.inf
  ArmGenericTimerCounterLib|ArmPkg/Library/ArmGenericTimerVirtCounterLib/ArmGenericTimerVirtCounterLib.inf
  ArmGicLib|ArmPkg/Drivers/ArmGic/ArmGicLib.inf
  ArmSmcLib|ArmPkg/Library/ArmSmcLib/ArmSmcLib.inf
  ArmHvcLib|ArmPkg/Library/ArmHvcLib/ArmHvcLib.inf
  TimerLib|ArmPkg/Library/ArmArchTimerLib/ArmArchTimerLib.inf
  CacheMaintenanceLib|ArmPkg/Library/ArmCacheMaintenanceLib/ArmCacheMaintenanceLib.inf
  CompilerIntrinsicsLib|ArmPkg/Library/CompilerIntrinsicsLib/CompilerIntrinsicsLib.inf
  NULL|ArmPkg/Library/CompilerIntrinsicsLib/CompilerIntrinsicsLib.inf
  DebugAgentLib|MdeModulePkg/Library/DebugAgentLibNull/DebugAgentLibNull.inf
  DebugAgentTimerLib|EmbeddedPkg/Library/DebugAgentTimerLibNull/DebugAgentTimerLibNull.inf
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  UefiBootManagerLib|MdeModulePkg/Library/UefiBootManagerLib/UefiBootManagerLib.inf
  # Null is intentional: the donor boot manager may attempt unverified I/O.
  PlatformBootManagerLib|MdeModulePkg/Library/PlatformBootManagerLibNull/PlatformBootManagerLibNull.inf
  VariablePolicyHelperLib|MdeModulePkg/Library/VariablePolicyHelperLib/VariablePolicyHelperLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiRuntimeLib|MdePkg/Library/UefiRuntimeLib/UefiRuntimeLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  DxeServicesLib|MdePkg/Library/DxeServicesLib/DxeServicesLib.inf
  DxeServicesTableLib|MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf
  HiiLib|MdeModulePkg/Library/UefiHiiLib/UefiHiiLib.inf
  UefiHiiServicesLib|MdeModulePkg/Library/UefiHiiServicesLib/UefiHiiServicesLib.inf
  FrameBufferBltLib|MdeModulePkg/Library/FrameBufferBltLib/FrameBufferBltLib.inf
  BmpSupportLib|MdeModulePkg/Library/BaseBmpSupportLib/BaseBmpSupportLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf
  PeCoffLib|MdePkg/Library/BasePeCoffLib/BasePeCoffLib.inf
  PeCoffExtraActionLib|MdePkg/Library/BasePeCoffExtraActionLibNull/BasePeCoffExtraActionLibNull.inf
  UefiDecompressLib|MdePkg/Library/BaseUefiDecompressLib/BaseUefiDecompressLib.inf
  PeCoffGetEntryPointLib|MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
  LzmaDecompressLib|MdeModulePkg/Library/LzmaCustomDecompressLib/LzmaCustomDecompressLib.inf
  ExtractGuidedSectionLib|MdePkg/Library/DxeExtractGuidedSectionLib/DxeExtractGuidedSectionLib.inf
  PerformanceLib|MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf
  PrePiLib|EmbeddedPkg/Library/PrePiLib/PrePiLib.inf
  PrePiHobListPointerLib|ArmPlatformPkg/Library/PrePiHobListPointerLib/PrePiHobListPointerLib.inf
  PrePiMemoryAllocationLib|EmbeddedPkg/Library/PrePiMemoryAllocationLib/PrePiMemoryAllocationLib.inf
  # QcomPkg/PrePi.inf directly consumes UfdtLib; QcomPkg MemoryInitPeiLib
  # consumes SimpleInitLib. These are OSS GPLDrivers dependencies, NOT XBL DXE.
  FdtLib|EmbeddedPkg/Library/FdtLib/FdtLib.inf
  UfdtLib|GPLDrivers/Library/SimpleInit/libs/libufdt/UfdtLib.inf
  SimpleInitLib|GPLDrivers/Library/SimpleInit/src/lib/SimpleInitLib.inf
  SimpleInitCompatible|GPLDrivers/Library/SimpleInit/libs/compatible/SimpleInitCompatible.inf
  MemoryInitPeiLib|Silicon/Qualcomm/QcomPkg/Library/MemoryInitPeiLib/PeiMemoryAllocationLib.inf
  MemoryMapHelperLib|Silicon/Qualcomm/QcomPkg/Library/MemoryMapHelperLib/MemoryMapHelperLib.inf
  # Actual dizi-only Silicon implementations from prior reviewed work.
  PlatformMemoryMapLib|Silicon/Qualcomm/sm7435/Library/PlatformMemoryMapLib/PlatformMemoryMapLib.inf
  PlatformPrePiLib|Silicon/Qualcomm/sm7435/Library/PlatformPrePiLib/PlatformPrePiLib.inf
  PlatformPeiLib|Silicon/Qualcomm/sm7435/Library/PlatformPeiLib/PlatformPeiLib.inf
  # EDK2 PSCI SMC reset matches FDT method=smc, but permission is untested.
  ResetSystemLib|ArmPkg/Library/ArmSmcPsciResetSystemLib/ArmSmcPsciResetSystemLib.inf
  HwResetSystemLib|ArmPkg/Library/ArmSmcPsciResetSystemLib/ArmSmcPsciResetSystemLib.inf
  RealTimeClockLib|EmbeddedPkg/Library/VirtualRealTimeClockLib/VirtualRealTimeClockLib.inf
  VariableFlashInfoLib|MdeModulePkg/Library/BaseVariableFlashInfoLib/BaseVariableFlashInfoLib.inf
  VarCheckLib|MdeModulePkg/Library/VarCheckLib/VarCheckLib.inf
  TpmMeasurementLib|MdeModulePkg/Library/TpmMeasurementLibNull/TpmMeasurementLibNull.inf
  SortLib|MdeModulePkg/Library/UefiSortLib/UefiSortLib.inf
  VariablePolicyLib|MdeModulePkg/Library/VariablePolicyLib/VariablePolicyLib.inf
  AuthVariableLib|MdeModulePkg/Library/AuthVariableLibNull/AuthVariableLibNull.inf
  NULL|MdePkg/Library/BaseStackCheckLib/BaseStackCheckLib.inf

[LibraryClasses.common.SEC]
  HobLib|EmbeddedPkg/Library/PrePiHobLib/PrePiHobLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  MemoryAllocationLib|EmbeddedPkg/Library/PrePiMemoryAllocationLib/PrePiMemoryAllocationLib.inf
  ExtractGuidedSectionLib|EmbeddedPkg/Library/PrePiExtractGuidedSectionLib/PrePiExtractGuidedSectionLib.inf
  ArmGicArchLib|ArmPkg/Library/ArmGicArchSecLib/ArmGicArchSecLib.inf

[LibraryClasses.common.DXE_CORE]
  DxeCoreEntryPoint|MdePkg/Library/DxeCoreEntryPoint/DxeCoreEntryPoint.inf
  HobLib|MdePkg/Library/DxeCoreHobLib/DxeCoreHobLib.inf
  MemoryAllocationLib|MdeModulePkg/Library/DxeCoreMemoryAllocationLib/DxeCoreMemoryAllocationLib.inf
  ExtractGuidedSectionLib|MdePkg/Library/DxeExtractGuidedSectionLib/DxeExtractGuidedSectionLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf

[LibraryClasses.common.DXE_DRIVER]
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  SecurityManagementLib|MdeModulePkg/Library/DxeSecurityManagementLib/DxeSecurityManagementLib.inf

[LibraryClasses.common.DXE_RUNTIME_DRIVER]
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  VariablePolicyLib|MdeModulePkg/Library/VariablePolicyLib/VariablePolicyLibRuntimeDxe.inf
  CapsuleLib|MdeModulePkg/Library/DxeCapsuleLibNull/DxeCapsuleLibNull.inf

[LibraryClasses.common.UEFI_DRIVER]
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf

[LibraryClasses.common.UEFI_APPLICATION]
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf

[Components.common]
  # Renegade QcomPkg early AArch64 entry; PlatformInitialize deadloops by
  # default absent verified live owner callback. Neither DMA nor GIC enabled.
  Silicon/Qualcomm/QcomPkg/PrePi/PrePi.inf
  MdeModulePkg/Core/Dxe/DxeMain.inf
  MdeModulePkg/Universal/PCD/Dxe/Pcd.inf
  ArmPkg/Drivers/CpuDxe/CpuDxe.inf
  MdeModulePkg/Core/RuntimeDxe/RuntimeDxe.inf
  MdeModulePkg/Universal/SecurityStubDxe/SecurityStubDxe.inf
  MdeModulePkg/Universal/Variable/RuntimeDxe/VariableRuntimeDxe.inf
  MdeModulePkg/Universal/HiiDatabaseDxe/HiiDatabaseDxe.inf
  MdeModulePkg/Universal/PrintDxe/PrintDxe.inf
  MdeModulePkg/Universal/DevicePathDxe/DevicePathDxe.inf
  MdeModulePkg/Universal/Console/ConPlatformDxe/ConPlatformDxe.inf
  MdeModulePkg/Universal/Console/ConSplitterDxe/ConSplitterDxe.inf
  MdeModulePkg/Universal/BdsDxe/BdsDxe.inf

  # NO ArmGicDxe, TimerDxe, SimpleFbDxe, ResetRuntimeDxe by default.
  # GICR ownership and console framebuffer mapping remain unverified;
  # upstream SimpleFbDxe zeroes full 16,384,000-byte framebuffer.
  # UI, Shell and GraphicsConsole are disabled until a genuine safe GOP,
  # GIC/timer and boot-device environment exists. Flag is FALSE by default.
!if $(DIZI_SM7435_ENABLE_CONSOLE_SHELL) == TRUE
  MdeModulePkg/Universal/Console/GraphicsConsoleDxe/GraphicsConsoleDxe.inf
  ShellPkg/Application/Shell/Shell.inf {
    <LibraryClasses>
      ShellCommandLib|ShellPkg/Library/UefiShellCommandLib/UefiShellCommandLib.inf
      NULL|ShellPkg/Library/UefiShellLevel1CommandsLib/UefiShellLevel1CommandsLib.inf
      NULL|ShellPkg/Library/UefiShellLevel2CommandsLib/UefiShellLevel2CommandsLib.inf
      NULL|ShellPkg/Library/UefiShellLevel3CommandsLib/UefiShellLevel3CommandsLib.inf
      NULL|ShellPkg/Library/UefiShellDriver1CommandsLib/UefiShellDriver1CommandsLib.inf
      NULL|ShellPkg/Library/UefiShellDebug1CommandsLib/UefiShellDebug1CommandsLib.inf
      NULL|ShellPkg/Library/UefiShellInstall1CommandsLib/UefiShellInstall1CommandsLib.inf
      HandleParsingLib|ShellPkg/Library/UefiHandleParsingLib/UefiHandleParsingLib.inf
      ShellLib|ShellPkg/Library/UefiShellLib/UefiShellLib.inf
      FileHandleLib|MdePkg/Library/UefiFileHandleLib/UefiFileHandleLib.inf
      BcfgCommandLib|ShellPkg/Library/UefiShellBcfgCommandLib/UefiShellBcfgCommandLib.inf
  }
!endif
