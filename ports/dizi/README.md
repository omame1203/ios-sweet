# NT36532 firmware SRAM transfer support

`nt36532_fw.c` is a portable, freestanding image validator and SRAM packet
planner for the Novatek NT36532 touchscreen fitted to POCO Pad (`dizi`). The
same source is carried into the XNU build by
`xnu/patches/0104-dizi-nt36532-firmware.patch` as
`bsd/dev/dizi_nt36532_fw.c`; keep both copies byte-identical.

The published dizi BOE boot firmware is `novatek_ts_fw_boe.bin` (245,760
bytes, SHA-256 `5f93847e664b752b1a2bb2214e89fac9ceff95617eae5fbc2baf0c21e007c142`).
It was verified separately against the public Xiaomi dizi vendor blob at
`Efeisot/android_vendor_xiaomi_dizi` commit
`25fb7b93c780ab8296fa0ff61b5177626372ee2c`; the binary remains
ignored under `research/dizi-novatek-fw/` and is not distributed by this
repository. This device's saved display lockdown selects BOE, whereas
other variants may require CSOT, which must be independently validated.

`dizi_nvt_fw_parse` validates the sector-end marker (`NVT`/`MOD`), the
version/complement pair, cascade header, partition count, 24-bit SRAM
addresses, and byte-accurate image bounds. The vendor's header size fields
are inclusive (encoded length plus one actual transferred byte).
`dizi_nvt_fw_next` produces packets bounded by the 128-byte Novatek page,
and `dizi_nvt_fw_upload` passes them to an injected transport without
accessing registers or allocating memory. The driver callback must handle
the exact Novatek SPI page-set command and GPI/QUP DMA transfer. A callback
error stops immediately; there is no ambiguous automatic retry.

The firmware's header CRC fields represent the controller's hardware CRC,
not ordinary CRC32. **Successful parsing/upload alone is insufficient for
touch**: the full vendor bootloader handshake, hardware CRC comparison,
controller reset-completion and firmware event-page response must succeed.
The current XNU version only compiles the transport-independent component;
GPI DMA/SMMU, firmware source provisioning, reset and real-SPI callbacks
remain to be integrated. Do not turn on the touchscreen based solely on
the image validation results.

Host verification with the locally retained BOE blob:

```sh
cc -std=c11 -O1 -g -Wall -Wextra -Werror -pedantic \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  ports/dizi/nt36532_fw.c ports/dizi/nt36532_fw_test.c \
  -o /tmp/dizi-nvt-fw-test
/tmp/dizi-nvt-fw-test research/dizi-novatek-fw/novatek_ts_fw_boe.bin
```

The host test verifies exact virtual SRAM reconstruction and injected
transport failure, in addition to header corruption, version, marker,
bounds and overflow cases. It does not touch the tablet.
