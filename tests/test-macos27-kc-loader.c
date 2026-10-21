#include "../ports/macos27/kc_loader.h"
#include "../ports/macos27/boot_args.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE UINT64_C(0xfffffe0007004000)
#define PHYS UINT64_C(0x8c0000000)
#define MEMORY UINT64_C(0xb0000000)
#define FILE_BYTES 0xc000

static void put32(unsigned char *b, uint32_t v)
{ for (unsigned i = 0; i < 4; i++) b[i] = (unsigned char)(v >> (8 * i)); }
static void put64(unsigned char *b, uint64_t v)
{ for (unsigned i = 0; i < 8; i++) b[i] = (unsigned char)(v >> (8 * i)); }
static void seg(unsigned char *b, const char *name, uint64_t va, uint64_t vs,
                uint64_t fo, uint64_t fs, uint32_t prot)
{
    put32(b, 0x19); put32(b + 4, 72); strcpy((char *)b + 8, name);
    put64(b + 24, va); put64(b + 32, vs); put64(b + 40, fo); put64(b + 48, fs);
    put32(b + 56, prot); put32(b + 60, prot);
}
static void fixture(unsigned char *b)
{
    memset(b, 0, FILE_BYTES);
    put32(b, 0xfeedfacf); put32(b + 4, 0x100000c); put32(b + 8, 0xc0000002);
    put32(b + 12, 12); put32(b + 16, 5); put32(b + 20, 504);
    seg(b + 32, "__TEXT", BASE, 0x8000, 0, 0x8000, 1);
    seg(b + 104, "__TEXT_EXEC", BASE + 0x8000, 0x8000, 0x8000, 0x4000, 5);
    put32(b + 176, 5); put32(b + 180, 288); put32(b + 184, 6); put32(b + 188, 68);
    put64(b + 176 + 16 + 32 * 8, BASE + 0x8000);
    put32(b + 464, 0x80000034); put32(b + 468, 16); put32(b + 472, 0x7000); put32(b + 476, 64);
    put32(b + 480, 0x80000035); put32(b + 484, 56); put64(b + 488, BASE + 0x4000);
    put64(b + 496, 0x4000); put32(b + 504, 32); strcpy((char *)b + 512, "com.apple.kernel");
    put32(b + 0x4000, 0xfeedfacf); put32(b + 0x4004, 0x100000c); put32(b + 0x400c, 2);
    put32(b + 0x4010, 1); put32(b + 0x4014, 72); put32(b + 0x4018, 0x80000000);
    seg(b + 0x4020, "__TEXT", BASE + 0x4000, 0x4000, 0x4000, 0x4000, 1);
    memset(b + 0x7000, 0x5a, 64);  /* Opaque chain bytes must never be rewritten. */
    memset(b + 0x8000, 0xcc, 0x4000);
}

static void reject(unsigned char *file, unsigned char *ram, size_t capacity)
{
    struct mac27_kc_plan p;
    memset(&p, 0xa5, sizeof(p)); memset(ram, 0xa5, capacity);
    assert(mac27_kc_load(file, FILE_BYTES, PHYS, MEMORY, ram, capacity, &p) != 0);
    for (size_t i = 0; i < sizeof(p); i++) assert(((unsigned char *)&p)[i] == 0xa5);
    for (size_t i = 0; i < capacity; i++) assert(ram[i] == 0xa5);
}

static void synthetic(void)
{
    unsigned char *allocation = malloc(FILE_BYTES + 1); assert(allocation);
    unsigned char *file = allocation + 1; fixture(file);
    struct mac27_kc_plan p;
    assert(mac27_kc_plan(file, FILE_BYTES, PHYS, MEMORY, &p) == 0);
    assert(p.segment_count == 2 && p.fileset_count == 1);
    assert(p.virt_base == (BASE & ~(MAC27_KC_BLOCK - 1)));
    size_t capacity = (size_t)p.occupied_size;
    unsigned char *ram = malloc(capacity + 1); assert(ram); memset(ram, 0xa5, capacity + 1);
    assert(mac27_kc_load(file, FILE_BYTES, PHYS, MEMORY, ram, capacity, &p) == 0);
    uint64_t prefix = BASE - p.virt_base;
    assert(ram[prefix - 1] == 0xa5 && ram[capacity] == 0xa5);
    assert(!memcmp(ram + prefix, file, 0x8000));
    assert(!memcmp(ram + prefix + 0x8000, file + 0x8000, 0x4000));
    assert(!memcmp(ram + (p.fixups_pa - PHYS), file + 0x7000, 64));
    for (uint64_t i = prefix + 0xc000; i < p.occupied_size; i++) assert(ram[i] == 0);
    const struct { size_t offset; uint64_t value; unsigned wide; } cases[] = {
        {16, 4097, 0}, {20, FILE_BYTES, 0}, {36, 0, 0}, {96, UINT32_MAX, 0},
        {64, 0xc000, 1}, {80, 0x8001, 1}, {128, UINT64_MAX - 0x3fff, 1},
        {188, 67, 0}, {448, BASE + 0x10000, 1}, {496, FILE_BYTES, 1},
        {488, BASE + 0x4004, 1}, {504, 0, 0}, {472, FILE_BYTES - 16, 0},
        {0x4018, 0, 0}, {0x4038, BASE, 1}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        fixture(file);
        if (cases[i].wide) put64(file + cases[i].offset, cases[i].value);
        else put32(file + cases[i].offset, (uint32_t)cases[i].value);
        reject(file, ram, capacity);
    }
    fixture(file);
    assert(mac27_kc_plan(file, 31, PHYS, MEMORY, &p) == MAC27_KC_RANGE);
    assert(mac27_kc_plan(file, FILE_BYTES, PHYS + 0x4000, MEMORY, &p) == MAC27_KC_RANGE);
    assert(mac27_kc_plan(file, FILE_BYTES, PHYS, 0x4000, &p) == MAC27_KC_CAPACITY);
    reject(file, ram, capacity - 1);
    assert(mac27_kc_load(file, FILE_BYTES, PHYS, MEMORY, file, FILE_BYTES, &p) == MAC27_KC_ARGUMENT);
    free(ram); free(allocation);
    puts("PASS KC loader: unaligned input, image/BSS copy, opaque fixups, untouched gaps and transactional rejection");
}

static void real_file(const char *name, const char *mapped, const char *report)
{
    FILE *f = fopen(name, "rb"); assert(f); assert(!fseek(f, 0, SEEK_END));
    long count = ftell(f); assert(count > 0 && (uint64_t)count <= MAC27_KC_MAX_BYTES);
    rewind(f); unsigned char *file = malloc((size_t)count); assert(file);
    assert(fread(file, (size_t)count, 1, f) == 1); assert(!fclose(f));
    struct mac27_kc_plan p;
    assert(mac27_kc_plan(file, (size_t)count, PHYS, MEMORY, &p) == 0);
    unsigned char *ram = malloc((size_t)p.occupied_size); assert(ram);
    memset(ram, 0xa5, (size_t)p.occupied_size);
    assert(mac27_kc_load(file, (size_t)count, PHYS, MEMORY, ram, (size_t)p.occupied_size, &p) == 0);
    struct mac27_boot_params args = {0}; struct mac27_boot_args encoded;
    args.virt_base = p.virt_base; args.phys_base = PHYS; args.mem_size = args.mem_size_actual = MEMORY;
    args.device_tree_pa = p.kernel_end_pa; args.device_tree_length = 64; /* placement test, not an ADT */
    args.boot_args_pa = p.kernel_end_pa + 0x4000; args.top_of_kernel_data = args.boot_args_pa + 0x4000;
    assert(!mac27_encode_boot_args(&encoded, sizeof(encoded), &args));
    f = fopen(mapped, "wb"); assert(f); assert(fwrite(ram, (size_t)p.occupied_size, 1, f) == 1); assert(!fclose(f));
    f = fopen(report, "w"); assert(f);
    assert(fprintf(f, "{\"virt_base\":%" PRIu64 ",\"entry_pa\":%" PRIu64 ",\"kernel_header_pa\":%" PRIu64
                   ",\"fixups_pa\":%" PRIu64 ",\"fixups_size\":%u,\"segments\":%u,\"providers\":%u,\"occupied_size\":%" PRIu64 "}\n",
                   p.virt_base, p.entry_pa, p.kernel_header_pa, p.fixups_pa, p.fixups_size,
                   p.segment_count, p.fileset_count, p.occupied_size) > 0);
    assert(!fclose(f)); free(ram); free(file);
    puts("PASS real KC copied into owned host RAM, modern boot-argument placement accepted; no execution");
}

int main(int argc, char **argv)
{
    synthetic();
    if (argc == 4) real_file(argv[1], argv[2], argv[3]);
    return 0;
}
