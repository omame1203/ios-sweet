/* Structural validator for the published Novatek NT36532 boot firmware.
 * This is a bounded translation of the Linux nt36xxx_fw_update.c header
 * format, including the optional cascade second header. No hardware writes.
 * SPDX-License-Identifier: MIT
 */
#include "nt36532_fw.h"
#include <string.h>

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int insert_part(struct dizi_nvt_fw *fw, uint32_t index,
    uint32_t source, uint32_t destination, uint32_t encoded_len, uint32_t crc)
{
    if (index >= DIZI_NVT_FW_MAX_PARTITIONS || destination > 0xffffffu)
        return -1;
    struct dizi_nvt_fw_partition *p = &fw->part[index];
    p->file_offset = source;
    p->sram_address = destination;
    p->expected_crc = crc;
    if (!encoded_len) return 0; /* Reserved partition in vendor format. */
    if (encoded_len == UINT32_MAX) return -1;
    uint32_t count = encoded_len + 1;
    /* 24-bit Novatek SRAM addressing; inclusive vendor length semantics. */
    if ((size_t)source > fw->size || (size_t)count > fw->size - source ||
        (uint64_t)destination + count > 0x1000000ull)
        return -1;
    p->byte_count = count;
    return 0;
}

int dizi_nvt_fw_parse(const uint8_t *bytes, size_t len, struct dizi_nvt_fw *out)
{
    if (!bytes || !out || len < 8192 || len % 4096 || len > UINT32_MAX)
        return -1;
    /* The vendor searches from the end for NVT/MOD; all recognized dizi
     * boot blobs have the marker at EOF. Refuse ambiguous truncated images. */
    if (memcmp(bytes + len - 3, "NVT", 3) &&
        memcmp(bytes + len - 3, "MOD", 3)) return -1;
    if (((unsigned)bytes[len - 4096] + bytes[len - 4095]) != 255u)
        return -1;
    uint32_t end = le32(bytes);
    if (end < 0x30 || end > len - 4096 || (end & 15u)) return -1;
    uint32_t second = !!(bytes[0x20] & 2u);
    uint32_t first_end = second ? end / 2u : end;
    if (first_end < 0x30 || (first_end - 0x30u) % 16u) return -1;
    uint32_t info_count = (first_end - 0x30u) / 16u + second;
    uint32_t overlay_count = (bytes[0x28] & 0x10u) ? (bytes[0x28] & 15u) : 0;
    uint32_t count = 2u + info_count + overlay_count;
    if (count > DIZI_NVT_FW_MAX_PARTITIONS) return -1;
    struct dizi_nvt_fw tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.data = bytes;
    tmp.size = len;
    tmp.header_end = end;
    tmp.version = bytes[len - 4096];
    tmp.partitions = count;
    for (uint32_t i = 0; i < 2; ++i) {
        const uint8_t *h = bytes + 12u * i;
        if (insert_part(&tmp, i, le32(h), le32(h + 4), le32(h + 8),
                le32(bytes + 0x18 + 4u * i))) return -1;
    }
    uint32_t find_header = 0;
    for (uint32_t i = 0; i < info_count; ++i) {
        uint32_t pos = 0x30u + i * 0x10u;
        if (find_header && second) pos = end - 0x10u;
        if ((uint64_t)pos + 16 > end) return -1;
        const uint8_t *h = bytes + pos;
        uint32_t dst = le32(h), size = le32(h + 4), src = le32(h + 8);
        if (insert_part(&tmp, i + 2u, src, dst, size, le32(h + 12)))
            return -1;
        if (src < end && size) find_header = 1;
    }
    for (uint32_t i = 0; i < overlay_count; ++i) {
        const struct dizi_nvt_fw_partition *dlm = &tmp.part[1];
        uint64_t pos = (uint64_t)dlm->file_offset + (uint64_t)i * 16u;
        if (pos + 16u > len) return -1;
        const uint8_t *h = bytes + (size_t)pos;
        if (insert_part(&tmp, i + 2u + info_count, le32(h + 8),
                le32(h), le32(h + 4), le32(h + 12))) return -1;
    }
    if (!tmp.part[0].byte_count || !tmp.part[1].byte_count) return -1;
    *out = tmp;
    return 0;
}

int dizi_nvt_fw_next(const struct dizi_nvt_fw *fw,
    struct dizi_nvt_fw_cursor *cursor, struct dizi_nvt_fw_packet *packet)
{
    if (!fw || !fw->data || !cursor || !packet ||
        fw->partitions > DIZI_NVT_FW_MAX_PARTITIONS) return -1;
    while (cursor->partition < fw->partitions) {
        const struct dizi_nvt_fw_partition *p = &fw->part[cursor->partition];
        if (cursor->offset > p->byte_count) return -1;
        if (cursor->offset == p->byte_count) {
            ++cursor->partition;
            cursor->offset = 0;
            continue;
        }
        uint64_t dst = (uint64_t)p->sram_address + cursor->offset;
        uint64_t src = (uint64_t)p->file_offset + cursor->offset;
        if (dst > 0xffffffu || src >= fw->size) return -1;
        unsigned offset = (unsigned)(dst & (DIZI_NVT_FW_PAGE_SIZE - 1u));
        uint32_t remaining = p->byte_count - cursor->offset;
        size_t n = DIZI_NVT_FW_PAGE_SIZE - offset;
        if (n > remaining) n = remaining;
        if (n > fw->size - (size_t)src) return -1;
        packet->sram_page = (uint32_t)(dst & ~127ull);
        packet->page_offset = (uint8_t)offset;
        packet->bytes = fw->data + src;
        packet->length = n;
        cursor->offset += (uint32_t)n;
        return 1;
    }
    return cursor->partition == fw->partitions ? 0 : -1;
}

int dizi_nvt_fw_upload(const struct dizi_nvt_fw *fw,
    const struct dizi_nvt_fw_transport *transport)
{
    if (!fw || !transport || !transport->select_page ||
        !transport->write_sram) return -1;
    struct dizi_nvt_fw_cursor cursor = {0, 0};
    struct dizi_nvt_fw_packet pkt;
    uint32_t page = UINT32_MAX;
    int rc;
    while ((rc = dizi_nvt_fw_next(fw, &cursor, &pkt)) == 1) {
        if (pkt.sram_page != page) {
            if (transport->select_page(transport->context, pkt.sram_page))
                return -1;
            page = pkt.sram_page;
        }
        if (transport->write_sram(transport->context,
                pkt.page_offset, pkt.bytes, pkt.length)) return -1;
    }
    return rc;
}
