/* SPDX-License-Identifier: MIT */
#include "ufs_gpt_bounds.h"
#include <assert.h>
#include <stdio.h>

static unsigned checks;
#define CHECK(cond) do { assert(cond); checks++; } while (0)

int main(void)
{
    uint32_t pages = 0;
    uint64_t out = 0;
    const uint32_t block = 4096, bounce = 1u << 20;

    CHECK(dizi_ufs_gpt_table_bounds(2, 128, 128, block, bounce, &pages));
    CHECK(pages == 4); /* conventional 128-entry GPT at 4KiB/block */
    CHECK(dizi_ufs_gpt_table_bounds(2, 8192, 128, block, bounce, &pages));
    CHECK(pages == 256);
    CHECK(!dizi_ufs_gpt_table_bounds(2, UINT32_MAX, 128, block, bounce, &pages));
    CHECK(!dizi_ufs_gpt_table_bounds(2, 8193, 128, block, bounce, &pages));
    CHECK(!dizi_ufs_gpt_table_bounds(2, 128, UINT32_MAX, block, bounce, &pages));
    CHECK(!dizi_ufs_gpt_table_bounds(2, 0, 128, block, bounce, &pages));
    CHECK(!dizi_ufs_gpt_table_bounds(1, 128, 128, block, bounce, &pages));
    CHECK(!dizi_ufs_gpt_table_bounds(UINT64_MAX, 128, 128, block, bounce, &pages));
    CHECK(!dizi_ufs_gpt_table_bounds(UINT32_MAX - 2, 128, 128, block, bounce, &pages));
    CHECK(dizi_ufs_gpt_table_bounds(UINT32_MAX - 3, 128, 128, block, bounce, &pages));
    CHECK(!dizi_ufs_gpt_table_bounds(2, 128, 128, 0, bounce, &pages));
    CHECK(!dizi_ufs_gpt_table_bounds(2, 128, 128, block, 0, &pages));
    CHECK(!dizi_ufs_gpt_table_bounds(2, 128, 128, block, bounce, NULL));

    CHECK(dizi_ufs_lba10_bounds(0, 1));
    CHECK(dizi_ufs_lba10_bounds(UINT32_MAX, 1));
    CHECK(dizi_ufs_lba10_bounds(UINT32_MAX - 1, 2));
    CHECK(!dizi_ufs_lba10_bounds(UINT32_MAX - 1, 3));
    CHECK(!dizi_ufs_lba10_bounds(UINT64_MAX, 1));
    CHECK(!dizi_ufs_lba10_bounds(0, 0));

    CHECK(dizi_ufs_gpt_partition_bounds(2048, 4095, &out));
    CHECK(out == 2048);
    CHECK(dizi_ufs_gpt_partition_bounds(UINT32_MAX, UINT32_MAX, &out));
    CHECK(out == 1);
    CHECK(!dizi_ufs_gpt_partition_bounds(0, 1, &out));
    CHECK(!dizi_ufs_gpt_partition_bounds(100, 99, &out));
    CHECK(!dizi_ufs_gpt_partition_bounds(1, UINT64_MAX, &out));
    CHECK(!dizi_ufs_gpt_partition_bounds(1, 20, NULL));

    CHECK(dizi_ufs_partition_offset(0, 512, 1048576, &out));
    CHECK(out == 0);
    CHECK(dizi_ufs_partition_offset(2048, 512, 1048576, &out));
    CHECK(out == 1048576);
    CHECK(!dizi_ufs_partition_offset(-1, 512, 1048576, &out));
    CHECK(!dizi_ufs_partition_offset(INT64_MIN, 512, 1048576, &out));
    CHECK(!dizi_ufs_partition_offset(INT64_MAX, 512, 1048576, &out));
    CHECK(!dizi_ufs_partition_offset(2049, 512, 1048576, &out));
    CHECK(!dizi_ufs_partition_offset(1, 0, 1048576, &out));
    CHECK(!dizi_ufs_partition_offset(1, 512, 1048576, NULL));
    puts("PASS offline dizi UFS/GPT read/write-bound helpers");
    printf("Assertions: %u\n", checks);
    return 0;
}
