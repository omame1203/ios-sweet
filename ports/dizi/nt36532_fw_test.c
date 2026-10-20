/* Host-only parser test. Uses local ignored public vendor firmware blob.
 * SPDX-License-Identifier: MIT
 */
#include "nt36532_fw.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fake_bus {
    uint8_t *sram;
    size_t size;
    uint32_t page;
    unsigned writes, selects, fail_at;
};

static int fake_page(void *ctx, uint32_t addr)
{
    struct fake_bus *bus = ctx;
    if ((addr & 127u) || addr >= bus->size) return -1;
    bus->page = addr;
    ++bus->selects;
    return 0;
}

static int fake_write(void *ctx, uint8_t offset, const uint8_t *bytes, size_t len)
{
    struct fake_bus *bus = ctx;
    ++bus->writes;
    if (bus->fail_at && bus->writes == bus->fail_at) return -1;
    if (!len || len > 128 || (size_t)offset + len > 128 ||
        (size_t)bus->page + offset + len > bus->size) return -1;
    memcpy(bus->sram + bus->page + offset, bytes, len);
    return 0;
}

static void test_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    assert(f);
    assert(fseek(f, 0, SEEK_END) == 0);
    long n = ftell(f);
    assert(n == 245760);
    rewind(f);
    uint8_t *b = malloc((size_t)n), *copy = malloc((size_t)n);
    assert(b && copy);
    assert(fread(b, 1, (size_t)n, f) == (size_t)n);
    assert(fclose(f) == 0);
    struct dizi_nvt_fw fw;
    assert(dizi_nvt_fw_parse(b, (size_t)n, &fw) == 0);
    assert(fw.header_end == 0x200);
    assert(fw.partitions == 16);
    assert(fw.version == 0x12);
    assert(fw.part[0].file_offset == 0x200);
    assert(fw.part[0].sram_address == 0);
    assert(fw.part[0].byte_count == 121256);
    assert(fw.part[0].expected_crc == 0x79a3d571);
    assert(fw.part[1].file_offset == 0x22000);
    assert(fw.part[1].sram_address == 0x100000);
    assert(fw.part[1].byte_count == 82232);
    assert(fw.part[1].expected_crc == 0x1b545c8f);
    size_t total = 0, packets = 0, switches = 0;
    struct dizi_nvt_fw_cursor cur = {0, 0};
    struct dizi_nvt_fw_packet pkt;
    int prev = -1, res;
    while ((res = dizi_nvt_fw_next(&fw, &cur, &pkt)) == 1) {
        assert(pkt.length && pkt.length <= 128);
        assert((unsigned)pkt.page_offset + pkt.length <= 128);
        assert(pkt.sram_page <= 0xffff80u);
        assert(pkt.bytes >= b && pkt.bytes + pkt.length <= b + n);
        if (prev != (int)pkt.sram_page) switches++;
        prev = (int)pkt.sram_page;
        packets++;
        total += pkt.length;
        assert(packets < 10000);
    }
    assert(res == 0);
    size_t expected = 0;
    for (size_t i = 0; i < fw.partitions; ++i)
        expected += fw.part[i].byte_count;
    assert(expected == total);
    assert(total > 200000 && packets > 1500 && switches > 1500);
    assert(dizi_nvt_fw_next(&fw, &cur, &pkt) == 0);

    struct fake_bus bus = {0};
    bus.size = 0x200000;
    bus.sram = calloc(bus.size, 1);
    assert(bus.sram);
    struct dizi_nvt_fw_transport transport = {&bus, fake_page, fake_write};
    assert(dizi_nvt_fw_upload(&fw, &transport) == 0);
    assert(bus.selects == switches);
    assert(bus.writes == packets);
    for (size_t i = 0; i < fw.partitions; ++i) {
        const struct dizi_nvt_fw_partition *p = &fw.part[i];
        if (!p->byte_count) continue;
        assert(memcmp(bus.sram + p->sram_address, b + p->file_offset,
            p->byte_count) == 0);
    }
    /* A single transport failure must abort immediately without retries. */
    bus.writes = 0;
    bus.selects = 0;
    bus.fail_at = 6;
    assert(dizi_nvt_fw_upload(&fw, &transport) < 0);
    assert(bus.writes == 6);
    free(bus.sram);
    cur.partition = 0;
    cur.offset = UINT32_MAX;
    assert(dizi_nvt_fw_next(&fw, &cur, &pkt) < 0);

    memcpy(copy, b, (size_t)n);
    copy[n - 3] = 'Z';
    assert(dizi_nvt_fw_parse(copy, (size_t)n, &fw) < 0);
    memcpy(copy, b, (size_t)n);
    copy[n - 4095] ^= 1;
    assert(dizi_nvt_fw_parse(copy, (size_t)n, &fw) < 0);
    memcpy(copy, b, (size_t)n);
    memset(copy, 0xff, 4);
    assert(dizi_nvt_fw_parse(copy, (size_t)n, &fw) < 0);
    memcpy(copy, b, (size_t)n);
    /* DLM file offset outside image, without corrupting header-end field. */
    memset(copy + 12, 0xff, 4);
    assert(dizi_nvt_fw_parse(copy, (size_t)n, &fw) < 0);
    memcpy(copy, b, (size_t)n);
    /* ILM SRAM overflow beyond 24-bit controller space. */
    memset(copy + 4, 0xff, 4);
    assert(dizi_nvt_fw_parse(copy, (size_t)n, &fw) < 0);
    memcpy(copy, b, (size_t)n);
    /* Header section must fit within the sector-verified firmware length. */
    copy[0xf0 + 4] = 0xff;
    copy[0xf0 + 5] = 0xff;
    copy[0xf0 + 6] = 0xff;
    copy[0xf0 + 7] = 0x7f;
    assert(dizi_nvt_fw_parse(copy, (size_t)n, &fw) < 0);

    assert(dizi_nvt_fw_parse(NULL, (size_t)n, &fw) < 0);
    assert(dizi_nvt_fw_parse(b, 4096, &fw) < 0);
    assert(dizi_nvt_fw_parse(b, (size_t)n - 1, &fw) < 0);
    assert(dizi_nvt_fw_parse(b, (size_t)n, NULL) < 0);
    printf("PASS NT36532 BOE v%u header; %zu bytes, %zu SRAM packets, %zu page selects; negative cases\n",
           0x12u, total, packets, switches);
    free(copy);
    free(b);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s path-to-ignored-BOE-firmware.bin\n", argv[0]);
        return 2;
    }
    test_file(argv[1]);
    return 0;
}
