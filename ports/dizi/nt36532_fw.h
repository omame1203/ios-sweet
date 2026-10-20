/* NT36532 SPI SRAM firmware image parser and transport-independent plan.
 * SPDX-License-Identifier: MIT
 * The binary firmware is a separate vendor-supplied asset and is not embedded.
 */
#ifndef DIZI_NT36532_FW_H
#define DIZI_NT36532_FW_H
#include <stddef.h>
#include <stdint.h>

#define DIZI_NVT_FW_MAX_PARTITIONS 64u
#define DIZI_NVT_FW_PAGE_SIZE 128u

struct dizi_nvt_fw_partition {
    uint32_t file_offset;
    uint32_t sram_address;
    uint32_t byte_count; /* Inclusive vendor header size + 1; 0 = reserved. */
    uint32_t expected_crc; /* Hardware CRC, not ordinary zlib CRC32. */
};

struct dizi_nvt_fw {
    const uint8_t *data;
    size_t size;
    uint32_t header_end;
    uint32_t partitions;
    uint8_t version;
    struct dizi_nvt_fw_partition part[DIZI_NVT_FW_MAX_PARTITIONS];
};

struct dizi_nvt_fw_cursor {
    uint32_t partition;
    uint32_t offset;
};

struct dizi_nvt_fw_packet {
    uint32_t sram_page;  /* 24-bit Novatek page selection address. */
    uint8_t page_offset; /* SRAM register offset for SPI write command. */
    const uint8_t *bytes;
    size_t length;
};

/* Return 0 on success, negative on a structurally invalid or unsafe image. */
int dizi_nvt_fw_parse(const uint8_t *bytes, size_t len, struct dizi_nvt_fw *out);

/* Return 1 for a valid packet, 0 for end, negative for corrupt plan/cursor.
 * Does not write registers, allocate memory, or issue SPI transactions.
 * Sender must validate the chip identity, establish safe DMA, select the
 * page and write [page_offset, bytes...] with its own verified transport.
 */
int dizi_nvt_fw_next(const struct dizi_nvt_fw *fw,
    struct dizi_nvt_fw_cursor *cursor, struct dizi_nvt_fw_packet *packet);

/* Transport adapter for a controller whose reset/identity and DMA rings
 * have independently been verified. The callbacks must return 0 on success.
 * No hardware ownership or reset is implied by this function; it stops at
 * the first failed callback. Caller must check controller HW CRC and the
 * post-start firmware handshake before declaring touch ready. */
struct dizi_nvt_fw_transport {
    void *context;
    int (*select_page)(void *context, uint32_t address);
    int (*write_sram)(void *context, uint8_t offset,
        const uint8_t *bytes, size_t len);
};

int dizi_nvt_fw_upload(const struct dizi_nvt_fw *fw,
    const struct dizi_nvt_fw_transport *transport);

#endif
