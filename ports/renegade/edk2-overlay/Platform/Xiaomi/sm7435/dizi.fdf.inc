## @file
# dizi-only FV payload. Included from Platform/Qualcomm/sm7435/sm7435.fdf
# within [FV.FvMain] through DEVICE_DXE_FV_COMPONENTS as in upstream lisa.
#
# The source-verified dizi frame buffer can be represented by existing
# Silicon/Qualcomm/QcomPkg/Drivers/SimpleFbDxe/SimpleFbDxe.inf ONLY when
# the separate SoC FDF deliberately includes it after proving the inherited
# framebuffer is writable and mapped. This FDF DOES NOT add that driver:
# upstream SimpleFbDxe clears framebuffer memory on startup, so merely
# having screen PCDs is NOT a safe/bootable GOP implementation.
#
# No SM7325/SM8550 proprietary binaries, UFS DXE, ACPI AML, storage/SMI,
# copied FDT, USB init or unverified button/PMIC/clock drivers. Those are
# blocked until their actual dizi interfaces are established. In particular
# the /tmp upstream lisa.fdf.inc is deliberately NOT copied.
#
# A small freeform record travels within this board's FV so a host can
# identify source/evidence without guessing that device drivers booted.
FILE FREEFORM = a7778303-0c3d-44ea-93a2-e59ec2b696c7 {
  SECTION RAW = Platform/Xiaomi/sm7435/BoardEvidence.txt
  SECTION UI = "DiziBoardEvidence"
}

  # True DXE driver built from source. Its DEPEX requires a real GOP and
  # checks the inherited physical framebuffer before printing via ConOut.
  INF Platform/Xiaomi/sm7435/DiziDiagDxe/DiziDiagDxe.inf
