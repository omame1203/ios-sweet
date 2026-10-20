/* SPDX-License-Identifier: MIT
 * Bounds shared with XNU's polled SWEET/dizi UFS root path.
 * Pure integer checks; no storage, MMIO or DMA access.
 */
#ifndef DIZI_UFS_GPT_BOUNDS_H
#define DIZI_UFS_GPT_BOUNDS_H

#include <stdbool.h>
#include <stdint.h>

/* UFS uses READ/WRITE(10), so even an otherwise valid GPT extent may be
 * unreachable. Refuse any extent outside the actual command address space. */
static inline bool
dizi_ufs_lba10_bounds(uint64_t lba, uint32_t count)
{
    return count != 0 && lba <= UINT32_MAX &&
        (uint64_t)count <= (uint64_t)UINT32_MAX - lba + 1;
}

/* Reject overflow of nent*entry_size BEFORE doing that multiplication or
 * requesting DMA into a fixed-size bounce buffer. This driver deliberately
 * supports the 128-byte GPT entry format it already parsed before. */
static inline bool
dizi_ufs_gpt_table_bounds(uint64_t entry_lba, uint32_t nent,
    uint32_t entry_size, uint32_t block_size, uint32_t bounce_size,
    uint32_t *blocks_out)
{
    if (!blocks_out || !block_size || !bounce_size || entry_size != 128 ||
        nent == 0 || nent > bounce_size / entry_size || entry_lba < 2) {
        return false;
    }
    uint64_t bytes = (uint64_t)nent * entry_size;
    uint64_t blocks = (bytes + block_size - 1) / block_size;
    if (!blocks || blocks > UINT32_MAX ||
        !dizi_ufs_lba10_bounds(entry_lba, (uint32_t)blocks)) {
        return false;
    }
    *blocks_out = (uint32_t)blocks;
    return true;
}

static inline bool
dizi_ufs_gpt_partition_bounds(uint64_t first, uint64_t last,
    uint64_t *blocks_out)
{
    if (!blocks_out || first == 0 || last < first || last > UINT32_MAX) {
        return false;
    }
    *blocks_out = last - first + 1;
    return *blocks_out != 0;
}

/* buf_blkno is signed. Casting a negative value to u64 and multiplying
 * before checking it may wrap back into the partition's valid byte range. */
static inline bool
dizi_ufs_partition_offset(int64_t block_no, uint32_t sector_size,
    uint64_t partition_bytes, uint64_t *offset_out)
{
    if (!offset_out || block_no < 0 || sector_size == 0 ||
        (uint64_t)block_no > partition_bytes / sector_size) {
        return false;
    }
    *offset_out = (uint64_t)block_no * sector_size;
    return true;
}

#endif
