#pragma once
//----------------------------------------------------------------------------------------------------------------------
#include <assert.h>
#include <limits.h>
static_assert(CHAR_BIT == 8, "This code requires [char] to be exactly 8 bits.");
static_assert(sizeof(int) >= 4, "This code requires [int] to be at least 32 bits.");
//----------------------------------------------------------------------------------------------------------------------
#include <stdint.h>
typedef unsigned int ui; typedef int si;
typedef unsigned char u8; typedef char s8;
typedef uint16_t u16; typedef int16_t s16;
typedef uint32_t u32; typedef int32_t s32;
typedef uint64_t u64; typedef int64_t s64;
typedef float r32; typedef double r64;
typedef __uint128_t u128; typedef __int128_t s128;
//----------------------------------------------------------------------------------------------------------------------
#include "blake2bmod2.h"
#include "sha2-512mod2.h"
#include "sha3-512mod2.h"
#include "whirlpoolmod2.h"
//----------------------------------------------------------------------------------------------------------------------
#define HASHES 4
#define COMBO0 (HASHES * (HASHES - 1))
#define COMBO1 (COMBO0 * (COMBO0 - 1))
#define COMBO2 (COMBO1 * (COMBO1 - 1))
//----------------------------------------------------------------------------------------------------------------------
struct devon_hash_keys
{
    u8 blake2b_mod2_key128[128];
    u8 sha2_512mod2_key64[64];
    u8 sha2_512mod2_key640[640];
    u8 sha3_512mod2_key72[72];
    u8 sha3_512mod2_key192[192];
    u8 whirlpool_mod2_key80[80];
};
static_assert(sizeof(struct devon_hash_keys) == 1176, "This code requires [struct devon_hash_keys] to be exactly 1176 bytes.");
//----------------------------------------------------------------------------------------------------------------------
void devon_hash_all_4(void * const, void const * const, void const * const, const ui, struct devon_hash_keys const * const);
void devon_hash(void * const, void const * const, void const * const, const ui, struct devon_hash_keys const * const);
void bench_hashes(void);
//----------------------------------------------------------------------------------------------------------------------