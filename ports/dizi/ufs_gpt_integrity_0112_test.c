/* SPDX-License-Identifier: MIT - real pure validator with synthetic GPT data. */
#include "ufs_gpt_integrity_0112.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define BLOCK 4096u
#define BOUNCE (1u << 20)
static uint8_t header[BLOCK];
static uint8_t entries[BLOCK * 2];
static unsigned assertions;
#define CHECK(x) do { assert(x); ++assertions; } while (0)

static void le32(uint8_t *p, uint32_t x)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(x >> (8 * i));
}
static void le64(uint8_t *p, uint64_t x)
{
    le32(p, (uint32_t)x); le32(p + 4, (uint32_t)(x >> 32));
}
static void header_crc(void)
{
    le32(header + 16, dizi_gpt_0112_crc(header,
        dizi_gpt_0112_le32(header + 12), 16, 4));
}
static void entries_crc(void)
{
    le32(header + 88, dizi_gpt_0112_crc(entries,
        (size_t)dizi_gpt_0112_le32(header + 80) * 128, 0, 0));
    header_crc();
}
static void make_gpt(void)
{
    memset(header, 0, sizeof(header));
    memset(entries, 0xa5, sizeof(entries));
    memcpy(header, "EFI PART", 8);
    le32(header + 8, 0x00010000);
    le32(header + 12, 92);
    le64(header + 24, 1);      /* primary GPT header LBA */
    le64(header + 32, 65535);  /* backup header, no physical read */
    le64(header + 40, 34);
    le64(header + 48, 65000);
    header[56] = 0x33;        /* disk GUID */
    le64(header + 72, 2);
    le32(header + 80, 3);     /* 384 bytes, padded to 4096 by READ(10) */
    le32(header + 84, 128);
    memset(entries, 0, sizeof(entries));
    entries[0] = 0x51; entries[16] = 0x52;
    le64(entries + 32, 2048); le64(entries + 40, 4095);
    entries[128] = 0x53; entries[144] = 0x54;
    le64(entries + 128 + 32, 4096); le64(entries + 128 + 40, 8191);
    entries_crc();
}
static bool good(struct dizi_gpt_integrity_0112 *out)
{
    return dizi_gpt_0112_header(header, sizeof(header), BLOCK, BOUNCE, 1, out);
}
static void header_failures(void)
{
    struct dizi_gpt_integrity_0112 parsed = {0};
    const struct dizi_gpt_integrity_0112 sentinel = {
        .table_lba = 0xabcdef, .entry_count = 0xdeadbeef };
    make_gpt();
    CHECK(good(&parsed));
    CHECK(parsed.table_lba == 2 && parsed.table_blocks == 1 &&
        parsed.entry_count == 3 && parsed.entry_size == 128);
    CHECK(parsed.first_usable == 34 && parsed.last_usable == 65000 &&
        parsed.alternate_lba == 65535);
    CHECK(dizi_gpt_0112_entries(entries, sizeof(entries), &parsed));
    CHECK(dizi_gpt_0112_crc((const uint8_t *)"123456789", 9, 0, 0) == 0xcbf43926u);
    CHECK(!dizi_gpt_0112_header(NULL, BLOCK, BLOCK, BOUNCE, 1, &parsed));
    CHECK(!dizi_gpt_0112_header(header, BLOCK, BLOCK, BOUNCE, 1, NULL));
    CHECK(!dizi_gpt_0112_header(header, BLOCK - 1, BLOCK, BOUNCE, 1, &parsed));
    CHECK(!dizi_gpt_0112_header(header, BLOCK, BLOCK, BOUNCE, 2, &parsed));
    CHECK(!dizi_gpt_0112_header(header, BLOCK, 4000, BOUNCE, 1, &parsed));
    CHECK(!dizi_gpt_0112_header(header, BLOCK, BLOCK, 4095, 1, &parsed));
    uint8_t byte = header[0]; header[0] ^= 1;
    CHECK(!good(&parsed)); header[0] = byte;
    byte = header[91]; header[91] ^= 1;
    CHECK(!good(&parsed)); header[91] = byte;
    CHECK(good(&parsed)); /* malformed CRC failed but read-only bounce unchanged */
    header[16] ^= 0x80;
    CHECK(!good(&parsed)); /* even the checksum field must be verified */
    header[16] ^= 0x80;
    struct dizi_gpt_integrity_0112 not_modified = sentinel;
    header[0] ^= 1;
    CHECK(!good(&not_modified));
    CHECK(not_modified.table_lba == sentinel.table_lba &&
        not_modified.entry_count == sentinel.entry_count);
    header[0] ^= 1;

    /* Each malformed field is tested with a recomputed, correct header CRC:
     * structural validation must not depend solely on checksum failure. */
#define INVALID32(off,val) do { make_gpt(); le32(header + off, val); header_crc(); CHECK(!good(&parsed)); } while (0)
#define INVALID64(off,val) do { make_gpt(); le64(header + off, val); header_crc(); CHECK(!good(&parsed)); } while (0)
    INVALID32(8, 0x20000);       /* unsupported GPT revision */
    INVALID32(12, 91);          /* too short */
    make_gpt(); le32(header + 12, BLOCK + 1);
    CHECK(!good(&parsed));      /* header size > block, do not CRC overrun */
    INVALID32(20, 1);           /* required reserved value */
    INVALID64(24, 2);           /* wrong current LBA */
    INVALID64(32, 1);           /* alternate == current */
    INVALID64(32, 300);         /* backup overlaps usable */
    INVALID64(32, UINT64_MAX);  /* READ(10) range */
    INVALID64(40, 1);           /* first usable includes GPT header */
    INVALID64(40, 2);           /* first usable includes table */
    INVALID64(48, 33);          /* invalid usable interval */
    INVALID64(48, 65535);       /* usable includes backup header */
    INVALID64(72, 1);           /* table overlaps header */
    INVALID64(72, 34);          /* table overlaps first usable */
    INVALID64(72, UINT32_MAX);  /* table extends past usable */
    INVALID64(72, UINT64_MAX);  /* impossible READ(10) LBA */
    INVALID32(80, 0);           /* no entries */
    INVALID32(80, 8193);        /* >1MiB bounce for 128B entries */
    INVALID32(80, UINT32_MAX);  /* multiplication overflow attempt */
    INVALID32(84, 64);          /* preexisting parser requires 128 */
    INVALID32(84, UINT32_MAX);
#undef INVALID32
#undef INVALID64
    make_gpt(); memset(header + 56, 0, 16); header_crc();
    CHECK(!good(&parsed));      /* zero disk GUID */
    make_gpt(); le32(header + 12, 100); header_crc();
    CHECK(good(&parsed));       /* valid extended CRC header */
    make_gpt(); le32(header + 80, 8192); le64(header + 40, 258);
    header_crc();
    CHECK(good(&parsed));       /* maximum 1MiB entry array is bounded */
    CHECK(parsed.table_blocks == 256 && parsed.entry_count == 8192);
    make_gpt();
}
static void entry_failures(void)
{
    struct dizi_gpt_integrity_0112 parsed = {0};
    CHECK(good(&parsed));
    CHECK(!dizi_gpt_0112_entries(NULL, sizeof(entries), &parsed));
    CHECK(!dizi_gpt_0112_entries(entries, sizeof(entries), NULL));
    CHECK(!dizi_gpt_0112_entries(entries, 383, &parsed));
    entries[1] ^= 0x40;
    CHECK(!dizi_gpt_0112_entries(entries, sizeof(entries), &parsed));
    entries[1] ^= 0x40;
    CHECK(dizi_gpt_0112_entries(entries, sizeof(entries), &parsed));
    /* The declared CRC EXCLUDES padding. */
    entries[4095] ^= 0xff;
    CHECK(dizi_gpt_0112_entries(entries, sizeof(entries), &parsed));
    entries[4095] ^= 0xff;
    /* Valid CRC but invalid entry extent, including second occupied entry. */
#define INVALID_ENTRY(off,val) do { make_gpt(); le64(entries + off, val); entries_crc(); CHECK(good(&parsed)); CHECK(!dizi_gpt_0112_entries(entries, BLOCK, &parsed)); } while (0)
    INVALID_ENTRY(32, 33);           /* below first usable */
    INVALID_ENTRY(40, 65535);       /* includes backup header */
    INVALID_ENTRY(40, UINT64_MAX);  /* > READ(10) */
    INVALID_ENTRY(40, 100);         /* end before start */
    INVALID_ENTRY(128 + 32, 33);   /* invalid second used entry */
    INVALID_ENTRY(128 + 40, 65534);
#undef INVALID_ENTRY
    make_gpt(); memset(entries + 16, 0, 16); entries_crc();
    CHECK(good(&parsed));
    CHECK(!dizi_gpt_0112_entries(entries, BLOCK, &parsed)); /* no unique GUID */
    make_gpt(); memset(entries, 0, 16); entries_crc();
    CHECK(good(&parsed));
    CHECK(dizi_gpt_0112_entries(entries, BLOCK, &parsed)); /* unused slot ignored */
    make_gpt();
    CHECK(good(&parsed));
    CHECK(dizi_gpt_0112_entries(entries, BLOCK, &parsed));
}
int main(void)
{
    header_failures();
    entry_failures();
    printf("PASS 0112 GPT header/entries strict integrity, synthetic CRC, bounce, malformed metadata: %u assertions\n", assertions);
    return 0;
}
