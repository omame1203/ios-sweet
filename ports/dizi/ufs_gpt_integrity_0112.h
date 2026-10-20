/* SPDX-License-Identifier: MIT
 * POCO Pad (dizi) UFS GPT integrity checks. Pure, read-only, portable C.
 * Verify an already-read primary header BEFORE reusing the UFS DMA bounce,
 * then verify the already-read entry array BEFORE parsing any partition.
 * No UFS commands, allocation, writes, MMIO or machine-endian assumptions.
 */
#ifndef DIZI_UFS_GPT_INTEGRITY_0112_H
#define DIZI_UFS_GPT_INTEGRITY_0112_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct dizi_gpt_integrity_0112 {
    uint64_t table_lba;
    uint64_t first_usable;
    uint64_t last_usable;
    uint64_t alternate_lba;
    uint32_t entry_count;
    uint32_t entry_size;
    uint32_t entries_crc32;
    uint32_t table_blocks;
};

static inline uint32_t
dizi_gpt_0112_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
        (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static inline uint64_t
dizi_gpt_0112_le64(const uint8_t *p)
{
    return (uint64_t)dizi_gpt_0112_le32(p) |
        (uint64_t)dizi_gpt_0112_le32(p + 4) << 32;
}

/* GPT uses reflected IEEE/ISO-HDLC CRC32, initial/final XOR FFFFFFFF.
 * Logical zeroing of header checksum bytes avoids mutating bounce data. */
static inline uint32_t
dizi_gpt_0112_crc(const uint8_t *data, size_t size,
    size_t zero_start, size_t zero_length)
{
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < size; ++i) {
        uint8_t value = i >= zero_start && i - zero_start < zero_length ? 0 : data[i];
        crc ^= value;
        for (unsigned bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ ((crc & 1u) ? 0xedb88320u : 0u);
        }
    }
    return crc ^ UINT32_MAX;
}

static inline bool
dizi_gpt_0112_nonzero_guid(const uint8_t *guid)
{
    uint8_t any = 0;
    for (unsigned i = 0; i < 16; ++i) {
        any |= guid[i];
    }
    return any != 0;
}

/* Primary GPT header at expected device LBA 1, one 4KiB UFS block.
 * All byte offsets follow UEFI GPT. Only 128-byte entries are supported by
 * the existing sweet_ufs.c partition-name parser (do not silently broaden).
 * Require the full table to fit a *single* READ(10) into the 1MiB bounce.
 * Real device capacity is not known here; we can still enforce READ(10) and
 * all GPT-declared usable bounds. This intentionally never falls back to a
 * corrupt backup GPT when opt-in verification is enabled. */
static inline bool
dizi_gpt_0112_header(const uint8_t *data, size_t available,
    uint32_t block_size, uint32_t bounce_size, uint64_t expected_lba,
    struct dizi_gpt_integrity_0112 *out)
{
    static const uint8_t sig[8] = { 'E','F','I',' ','P','A','R','T' };
    if (!data || !out || block_size < 512 || block_size > 65536 ||
        (block_size & (block_size - 1u)) != 0 || available < block_size ||
        bounce_size < block_size || expected_lba != 1) {
        return false;
    }
    for (unsigned i = 0; i < 8; ++i) {
        if (data[i] != sig[i]) return false;
    }
    uint32_t version = dizi_gpt_0112_le32(data + 8);
    uint32_t header_size = dizi_gpt_0112_le32(data + 12);
    if (version != 0x00010000u || header_size < 92 ||
        header_size > block_size || dizi_gpt_0112_le32(data + 20) != 0 ||
        dizi_gpt_0112_crc(data, header_size, 16, 4) !=
        dizi_gpt_0112_le32(data + 16) ||
        !dizi_gpt_0112_nonzero_guid(data + 56)) {
        return false;
    }
    uint64_t current = dizi_gpt_0112_le64(data + 24);
    uint64_t alternate = dizi_gpt_0112_le64(data + 32);
    uint64_t first = dizi_gpt_0112_le64(data + 40);
    uint64_t last = dizi_gpt_0112_le64(data + 48);
    uint64_t table = dizi_gpt_0112_le64(data + 72);
    uint32_t count = dizi_gpt_0112_le32(data + 80);
    uint32_t entry_size = dizi_gpt_0112_le32(data + 84);
    if (current != expected_lba || alternate <= current ||
        alternate > UINT32_MAX || first <= current || last < first ||
        last >= alternate || entry_size != 128 || count == 0 ||
        count > bounce_size / entry_size || table < 2 || table > UINT32_MAX) {
        return false;
    }
    uint64_t bytes = (uint64_t)count * entry_size;
    uint64_t blocks = (bytes + block_size - 1u) / block_size;
    if (blocks == 0 || blocks > bounce_size / block_size ||
        blocks > (uint64_t)UINT32_MAX - table + 1u ||
        table + blocks > first || table + blocks > alternate) {
        return false;
    }
    struct dizi_gpt_integrity_0112 result = {
        .table_lba = table, .first_usable = first,
        .last_usable = last, .alternate_lba = alternate,
        .entry_count = count, .entry_size = entry_size,
        .entries_crc32 = dizi_gpt_0112_le32(data + 88),
        .table_blocks = (uint32_t)blocks
    };
    *out = result;
    return true;
}

/* Must be called after ufs_read_blocks(header.table_lba, table_blocks) and
 * before scanning names or trusting partition extents. Validate only the
 * declared entry bytes, not padding at the end of the last UFS block. */
static inline bool
dizi_gpt_0112_entries(const uint8_t *data, size_t available,
    const struct dizi_gpt_integrity_0112 *header)
{
    if (!data || !header || header->entry_size != 128 ||
        header->entry_count == 0 ||
        header->entry_count > SIZE_MAX / header->entry_size) return false;
    size_t size = (size_t)header->entry_count * header->entry_size;
    if (size > available ||
        dizi_gpt_0112_crc(data, size, 0, 0) != header->entries_crc32) {
        return false;
    }
    for (uint32_t i = 0; i < header->entry_count; ++i) {
        const uint8_t *e = data + (size_t)i * header->entry_size;
        if (!dizi_gpt_0112_nonzero_guid(e)) continue; /* unused GPT entry */
        uint64_t first = dizi_gpt_0112_le64(e + 32);
        uint64_t last = dizi_gpt_0112_le64(e + 40);
        if (!dizi_gpt_0112_nonzero_guid(e + 16) ||
            first < header->first_usable || last < first ||
            last > header->last_usable || last > UINT32_MAX) return false;
    }
    return true;
}
#endif /* DIZI_UFS_GPT_INTEGRITY_0112_H */
