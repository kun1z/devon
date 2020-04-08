#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
//----------------------------------------------------------------------------------------------------------------------
#include "devon_hash.h"
//----------------------------------------------------------------------------------------------------------------------
static void hash0(void * const, void const * const, void const * const, struct devon_hash_keys const * const);
static void hash1(void * const, void const * const, void const * const, struct devon_hash_keys const * const);
static void hash2(void * const, void const * const, void const * const, struct devon_hash_keys const * const);
static void hash3(void * const, void const * const, void const * const, struct devon_hash_keys const * const);
static void combo0(void * const, void const * const, void const * const, const ui, struct devon_hash_keys const * const);
static void combo1(void * const, void const * const, void const * const, const ui, struct devon_hash_keys const * const);
static void combo2(void * const, void const * const, void const * const, const ui, struct devon_hash_keys const * const);
//----------------------------------------------------------------------------------------------------------------------
static void (* const hash[HASHES])(void * const, void const * const, void const * const, struct devon_hash_keys const * const) = { hash0, hash1, hash2, hash3 };
//----------------------------------------------------------------------------------------------------------------------
void devon_hash_all_4(void * const out, void const * const in, void const * const in2, const ui select, struct devon_hash_keys const * const keys)
{
    if (select >= 24) exit(1);

    const ui valid_selections[24] =
    {
        7, 10, 15, 20, 25, 28, 40, 43, 46, 52, 56, 60,
        71, 75, 79, 85, 88, 91, 103, 106, 111, 116, 121, 124
    };

    combo1(out, in, in2, valid_selections[select], keys);
}
//----------------------------------------------------------------------------------------------------------------------
void devon_hash(void * const out, void const * const in, void const * const in2, const ui select, struct devon_hash_keys const * const keys)
{
    combo2(out, in, in2, select, keys);
}
//----------------------------------------------------------------------------------------------------------------------
static void combo0(void * const out, void const * const in, void const * const in2, const ui select, struct devon_hash_keys const * const keys)
{
    u8 o1[64], o2[64];

    if (select >= COMBO0) exit(1);

    ui x = select / (HASHES - 1);
    ui y = select % (HASHES - 1);
    if (y >= x) y++;

    hash[x](o1, in, in2, keys);
    hash[y](o2, in,  o1, keys);

    for (ui i=0;i<64;i++)
    {
        u8 * const restrict o = out;
        o[i] = o1[i] ^ o2[i];
    }
}
//----------------------------------------------------------------------------------------------------------------------
static void combo1(void * const out, void const * const in, void const * const in2, const ui select, struct devon_hash_keys const * const keys)
{
    u8 o1[64], o2[64];

    if (select >= COMBO1) exit(1);

    ui x = select / (COMBO0 - 1);
    ui y = select % (COMBO0 - 1);
    if (y >= x) y++;

    combo0(o1, in, in2, x, keys);
    combo0(o2, in,  o1, y, keys);

    for (ui i=0;i<64;i++)
    {
        u8 * const restrict o = out;
        o[i] = o1[i] ^ o2[i];
    }
}
//----------------------------------------------------------------------------------------------------------------------
static void combo2(void * const out, void const * const in, void const * const in2, const ui select, struct devon_hash_keys const * const keys)
{
    u8 o1[64], o2[64];

    if (select >= COMBO2) exit(1);

    ui x = select / (COMBO1 - 1);
    ui y = select % (COMBO1 - 1);
    if (y >= x) y++;

    combo1(o1, in, in2, x, keys);
    combo1(o2, in,  o1, y, keys);

    for (ui i=0;i<64;i++)
    {
        u8 * const restrict o = out;
        o[i] = o1[i] ^ o2[i];
    }
}
//----------------------------------------------------------------------------------------------------------------------
static void hash0(void * const out, void const * const in, void const * const in2, struct devon_hash_keys const * const keys)
{
    blake2b_mod2(out, in, in2, keys->blake2b_mod2_key128);
}
//----------------------------------------------------------------------------------------------------------------------
static void hash1(void * const out, void const * const in, void const * const in2, struct devon_hash_keys const * const keys)
{
    sha2_512mod2(out, in, in2, keys->sha2_512mod2_key64, keys->sha2_512mod2_key640);
}
//----------------------------------------------------------------------------------------------------------------------
static void hash2(void * const out, void const * const in, void const * const in2, struct devon_hash_keys const * const keys)
{
    sha3_512mod2(out, in, in2, keys->sha3_512mod2_key72, keys->sha3_512mod2_key192);
}
//----------------------------------------------------------------------------------------------------------------------
static void hash3(void * const out, void const * const in, void const * const in2, struct devon_hash_keys const * const keys)
{
    whirlpool_mod2(out, in, in2, keys->whirlpool_mod2_key80);
}
//----------------------------------------------------------------------------------------------------------------------
void bench_hashes(void)
{
    const u64 size = 100 * 1024 * 1024;
    const u64 blocks = size / 64;

    u8 * const mem = malloc(size);
    if (!mem) exit(1);

    struct devon_hash_keys * const hash_keys = malloc(sizeof(struct devon_hash_keys));
    if (!hash_keys) exit(1);
    memset(hash_keys, 0xA5, sizeof(struct devon_hash_keys));

    struct timespec start, end;
    r64 ds, de;
    s8 const * const hash_names[4] = { "blake2b_mod2", "sha2_512mod2", "sha3_512mod2", "whirlpool_mod2" };

    printf("Begin testing...\n");

    for (ui i=0;i<4;i++)
    {
        sleep(1);
        clock_gettime(CLOCK_MONOTONIC, &start);

        hash[i](mem, mem, 0, hash_keys);

        for (u64 j=0;j<blocks-1;j++)
        {
            hash[i](&mem[(j + 1) * 64], &mem[j * 64], 0, hash_keys);
        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        ds = (start.tv_sec * 1000.) + (start.tv_nsec / 1000000.);
        de = (end.tv_sec * 1000.) + (end.tv_nsec / 1000000.);

        printf("%s: %.2f MB/s\n", hash_names[i], (size / 1048576.) / ((de - ds) / 1000.));
    }

    printf("Done testing\n");

    free(mem);
    free(hash_keys);
}
//----------------------------------------------------------------------------------------------------------------------