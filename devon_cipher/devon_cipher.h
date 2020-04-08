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
#include "..\devon_hash\devon_hash.h"
//----------------------------------------------------------------------------------------------------------------------
#define ROUNDS 24
#define KEY_SIZE_IN_BYTES 1304
//----------------------------------------------------------------------------------------------------------------------
struct devon_cipher_state
{
    u16 sbox[ROUNDS][65536];
    u16 sibx[ROUNDS][65536];
    u8 pbox[ROUNDS][32];
    u8 key_schedule[ROUNDS+1][32];
    u8 cntr_block64[64];
    u16 hash_block64[32];
    struct devon_hash_keys const * hash_keys;
    u64 select;
    ui p;
};
//----------------------------------------------------------------------------------------------------------------------
ui init_devon_cipher(struct devon_cipher_state * const, const u8 [128], const u8 [128], struct devon_hash_keys const * const);
void devon_cipher_enc(struct devon_cipher_state * const, void * const, void const * const, const u128);
void devon_cipher_dec(struct devon_cipher_state * const, void * const, void const * const, const u128);
//----------------------------------------------------------------------------------------------------------------------