#include <string.h>
#include "devon_cipher.h"
//----------------------------------------------------------------------------------------------------------------------
#define swap(a, b) do { const typeof(a) t = (a); (a) = (b); (b) = t; } while (0)
#define min(a, b) ({ const typeof(a) _a = (a); const typeof(b) _b = (b); _a < _b ? _a : _b; })
#define popui(a) __builtin_popcount(a)
//----------------------------------------------------------------------------------------------------------------------
static void sbox_shuffle(struct devon_cipher_state * const, u16 [65536]);
static void pbox_shuffle(struct devon_cipher_state * const, u8 [16]);
static void init_key_schedule(struct devon_cipher_state * const, const u8 [128], const u8 [128]);
static void init_sboxes(struct devon_cipher_state * const);
static void init_sibxes(struct devon_cipher_state * const);
static void init_pboxes(struct devon_cipher_state * const);
static void substitute(u16 [16], const u16 [65536]);
static void permutate(u16 [16], const u8 [32], void const * const);
static void permutate_inv(u16 [16], const u8 [32], void const * const);
static void xor_blocks(void * const restrict, void const * const restrict);
static void block_index_shuffle(u8 const * const, u8 [3][ROUNDS]);
static ui no_potential_valid_swaps_exist(u16 [65536], const ui);
static void recover_sbox(struct devon_cipher_state * const, u16 [65536], const ui);
static u16 rng(struct devon_cipher_state * const, const u16);
static u16 rng_word(struct devon_cipher_state * const);
static ui sanity_check_sbox(u16 [ROUNDS][65536]);
static ui sanity_check_pbox(u8 [ROUNDS][32]);
//----------------------------------------------------------------------------------------------------------------------
ui init_devon_cipher(struct devon_cipher_state * const cipher_state, const u8 iv128[128], const u8 master_key128[128], struct devon_hash_keys const * const hash_keys)
{
    u64 select1, select2, selectX;
    memcpy(&select1, &master_key128[ 0], 8);
    memcpy(&select2, &master_key128[ 8], 8);
    memcpy(&selectX, &master_key128[16], 8);

    cipher_state->p         = 0;
    cipher_state->select    = selectX;
    cipher_state->hash_keys = hash_keys;

    devon_hash_all_4(cipher_state->cntr_block64, &master_key128[ 0], &iv128[ 0], select1 % 24, hash_keys);
    devon_hash_all_4(cipher_state->hash_block64, &master_key128[64], &iv128[64], select2 % 24, hash_keys);

    init_sboxes(cipher_state);
    init_sibxes(cipher_state);

    cipher_state->p = cipher_state->hash_block64[11] & 31;
    devon_hash_all_4(cipher_state->hash_block64, cipher_state->hash_block64, &master_key128[ 0], rng(cipher_state, 23), hash_keys);

    init_pboxes(cipher_state);

    cipher_state->p = cipher_state->hash_block64[23] & 31;
    devon_hash_all_4(cipher_state->hash_block64, cipher_state->hash_block64, &master_key128[64], rng(cipher_state, 23), hash_keys);

    init_key_schedule (cipher_state, master_key128, iv128);

    devon_hash_all_4(cipher_state->cntr_block64, cipher_state->cntr_block64, cipher_state->hash_block64, rng(cipher_state, 23), hash_keys);

    memset(cipher_state->hash_block64, 0, 64);
    cipher_state->p      = 0;
    cipher_state->select = 0;

    if (!sanity_check_sbox(cipher_state->sbox)) return 0;
    if (!sanity_check_sbox(cipher_state->sibx)) return 0;
    if (!sanity_check_pbox(cipher_state->pbox)) return 0;

    return 1;
}
//----------------------------------------------------------------------------------------------------------------------
void devon_cipher_enc(struct devon_cipher_state * const cipher_state, void * const out32, void const * const in32, const u128 unique_block_id)
{
    u8 encasement_block64[64], round_shuffle[3][ROUNDS];
    u16 block32[16];
    u128 temp_block_id64[4];

    memcpy(block32, in32, 32);

    memcpy(temp_block_id64, cipher_state->cntr_block64, 64);
    temp_block_id64[0] += unique_block_id;

    devon_hash_all_4(encasement_block64, temp_block_id64, cipher_state->hash_block64, temp_block_id64[0] % 24, cipher_state->hash_keys);
    block_index_shuffle(encasement_block64, round_shuffle);

    xor_blocks(block32, encasement_block64);

    for (ui r=0;r<ROUNDS;r++)
    {
        xor_blocks(block32, cipher_state->key_schedule[round_shuffle[0][r]]);
        substitute(block32, cipher_state->sbox[round_shuffle[1][r]]);
        permutate(block32, cipher_state->pbox[round_shuffle[2][r]], &encasement_block64[(r & 15) * 4]);
    }

    xor_blocks(block32, cipher_state->key_schedule[ROUNDS]);
    xor_blocks(block32, &encasement_block64[32]);

    memcpy(out32, block32, 32);
}
//----------------------------------------------------------------------------------------------------------------------
void devon_cipher_dec(struct devon_cipher_state * const cipher_state, void * const out32, void const * const in32, const u128 unique_block_id)
{
    u8 encasement_block64[64], round_shuffle[3][ROUNDS];
    u16 block32[16];
    u128 temp_block_id64[4];

    memcpy(block32, in32, 32);

    memcpy(temp_block_id64, cipher_state->cntr_block64, 64);
    temp_block_id64[0] += unique_block_id;

    devon_hash_all_4(encasement_block64, temp_block_id64, cipher_state->hash_block64, temp_block_id64[0] % 24, cipher_state->hash_keys);
    block_index_shuffle(encasement_block64, round_shuffle);

    xor_blocks(block32, &encasement_block64[32]);
    xor_blocks(block32, cipher_state->key_schedule[ROUNDS]);

    for (si r=ROUNDS-1;r>=0;r--)
    {
        permutate_inv(block32, cipher_state->pbox[round_shuffle[2][r]], &encasement_block64[(r & 15) * 4]);
        substitute(block32, cipher_state->sibx[round_shuffle[1][r]]);
        xor_blocks(block32, cipher_state->key_schedule[round_shuffle[0][r]]);
    }

    xor_blocks(block32, encasement_block64);

    memcpy(out32, block32, 32);
}
//----------------------------------------------------------------------------------------------------------------------
static void block_index_shuffle(u8 const * const rng_bytes64, u8 round_shuffle[3][ROUNDS])
{
    for (ui i=0;i<ROUNDS;i++)
    {
        round_shuffle[0][i] = i;
    }

    memcpy(round_shuffle[1], round_shuffle[0], ROUNDS);
    memcpy(round_shuffle[2], round_shuffle[0], ROUNDS);

    if (ROUNDS > 1)
    {
        u64 x, y, z;
        memcpy(&x, &rng_bytes64[ 0], 8);
        memcpy(&y, &rng_bytes64[24], 8);
        memcpy(&z, &rng_bytes64[48], 8);

        ui i = ROUNDS - 1;

        while(1)
        {
            swap(round_shuffle[0][i], round_shuffle[0][x % (i + 1)]);
            swap(round_shuffle[1][i], round_shuffle[1][y % (i + 1)]);
            swap(round_shuffle[2][i], round_shuffle[2][z % (i + 1)]);

            if (i-- == 1) return;

            x ^= x << 13;
            y ^= y << 13;
            z ^= z << 13;

            x ^= x >> 7;
            y ^= y >> 7;
            z ^= z >> 7;

            x ^= x << 17;
            y ^= y << 17;
            z ^= z << 17;
        }
    }
}
//----------------------------------------------------------------------------------------------------------------------
static void substitute(u16 block32[16], const u16 sbox[65536])
{
    for (ui i=0;i<16;i++)
    {
        block32[i] = sbox[block32[i]];
    }
}
//----------------------------------------------------------------------------------------------------------------------
static void permutate(u16 block32[16], const u8 pbox[32], void const * const rng_bytes4)
{
    u128 pht[2];
    memcpy(pht, block32, 32);

    #define PHT(a, b) do {           \
        const u128 an = a + b;       \
        const u128 bn = a + (2 * b); \
        a = an; b = bn;              \
    } while(0)

    #define ROL128(v, c) v = v << c | v >> (128 - c)

    u32 rotate_rng;
    memcpy(&rotate_rng, rng_bytes4, 4);

    const ui r1 = 56 + (rotate_rng & 15);
    const ui r2 = 29 + ((rotate_rng >> 8) & 7);
    const ui r3 = 14 + ((rotate_rng >> 16) & 3);

    PHT(pht[0], pht[1]);
    ROL128(pht[0], r1);
    PHT(pht[0], pht[1]);
    ROL128(pht[0], r2);
    PHT(pht[0], pht[1]);
    ROL128(pht[0], r3);
    PHT(pht[0], pht[1]);

    #undef PHT
    #undef ROL128

    for (ui i=0;i<32;i++)
    {
        u8 const * const restrict src = (u8 const * const restrict)pht;
        u8 * const restrict dst = (u8 * const restrict)block32;
        dst[pbox[i]] = src[i];
    }
}
//----------------------------------------------------------------------------------------------------------------------
static void permutate_inv(u16 block32[16], const u8 pbox[32], void const * const rng_bytes4)
{
    u128 pht[2];

    for (ui i=0;i<32;i++)
    {
        u8 const * const restrict src = (u8 const * const restrict)block32;
        u8 * const restrict dst = (u8 * const restrict)pht;
        dst[i] = src[pbox[i]];
    }

    #define PHTI(an, bn) do {         \
        const u128 a = (2 * an) - bn; \
        const u128 b = bn - an;       \
        an = a; bn = b;               \
    } while(0)

    #define ROR128(v, c) v = v >> c | v << (128 - c)

    u32 rotate_rng;
    memcpy(&rotate_rng, rng_bytes4, 4);

    const ui r1 = 56 + (rotate_rng & 15);
    const ui r2 = 29 + ((rotate_rng >> 8) & 7);
    const ui r3 = 14 + ((rotate_rng >> 16) & 3);

    PHTI(pht[0], pht[1]);
    ROR128(pht[0], r3);
    PHTI(pht[0], pht[1]);
    ROR128(pht[0], r2);
    PHTI(pht[0], pht[1]);
    ROR128(pht[0], r1);
    PHTI(pht[0], pht[1]);

    #undef PHTI
    #undef ROR128

    memcpy(block32, pht, 32);
}
//----------------------------------------------------------------------------------------------------------------------
static void init_sboxes(struct devon_cipher_state * const cipher_state)
{
    for (ui i=0;i<65536;i++)
    {
        cipher_state->sbox[0][i] = i;
    }

    for (ui i=0;i<ROUNDS-1;i++)
    {
        memcpy(cipher_state->sbox[i + 1], cipher_state->sbox[i], 65536 * 2);
    }

    for (ui i=0;i<ROUNDS;i++)
    {
        sbox_shuffle(cipher_state, cipher_state->sbox[i]);
    }
}
//----------------------------------------------------------------------------------------------------------------------
static void init_sibxes(struct devon_cipher_state * const cipher_state)
{
    for (ui r=0;r<ROUNDS;r++)
    {
        for (ui i=0;i<65536;i++)
        {
            cipher_state->sibx[r][cipher_state->sbox[r][i]] = i;
        }
    }
}
//----------------------------------------------------------------------------------------------------------------------
static void init_pboxes(struct devon_cipher_state * const cipher_state)
{
    u8 (* const pbox2D)[2][16] = (u8 (* const)[2][16])cipher_state->pbox;

    for (ui i=0;i<32;i++)
    {
        cipher_state->pbox[0][i] = i;
    }

    for (ui r=0;r<ROUNDS-1;r++)
    {
        memcpy(cipher_state->pbox[r + 1], cipher_state->pbox[r], 32);
    }

    for (ui r=0;r<ROUNDS;r++)
    {
        pbox_shuffle(cipher_state, pbox2D[r][0]);
        pbox_shuffle(cipher_state, pbox2D[r][1]);
    }

    for (ui r=0;r<ROUNDS;r++)
    {
        for (ui i=0,rngi=rng_word(cipher_state);rngi;i++,rngi>>=1)
        {
            if (rngi & 1)
            {
                swap(pbox2D[r][0][i], pbox2D[r][1][i]);
            }
        }
    }

    for (ui r=0;r<ROUNDS;r++)
    {
        u8 temp[2][16];
        memcpy(temp, cipher_state->pbox[r], 32);

        for (ui i=0;i<16;i++)
        {
            cipher_state->pbox[r][(i * 2) + 0] = temp[0][i];
            cipher_state->pbox[r][(i * 2) + 1] = temp[1][i];
        }
    }
}
//----------------------------------------------------------------------------------------------------------------------
static void init_key_schedule(struct devon_cipher_state * const cipher_state, const u8 master_key128[128], const u8 iv128[128])
{
    u8 key_iv[256];
    memcpy(&key_iv[  0], master_key128, 128);
    memcpy(&key_iv[128],         iv128, 128);

    const ui key_blocks = ROUNDS + 1;
    const ui key_init = min(8, key_blocks);

    // Init the first 2..8 blocks with the Key and IV
    for (ui k=0;k<key_init;k++)
    {
        memcpy(cipher_state->key_schedule[k], &key_iv[k * 32], 32);
    }

    // Init the remainder with some random junk
    if (key_blocks > 8)
    {
        u8 hash_block64[64];
        memset(hash_block64, 0xA5, 64);

        for (ui k=0;k<key_blocks - 8;k++)
        {
            devon_hash_all_4(hash_block64, hash_block64, &master_key128[ 0], rng(cipher_state, 23), cipher_state->hash_keys);
            devon_hash_all_4(hash_block64, hash_block64, &master_key128[64], rng(cipher_state, 23), cipher_state->hash_keys);
            devon_hash_all_4(hash_block64, hash_block64,         &iv128[ 0], rng(cipher_state, 23), cipher_state->hash_keys);
            devon_hash_all_4(hash_block64, hash_block64,         &iv128[64], rng(cipher_state, 23), cipher_state->hash_keys);

            memcpy(cipher_state->key_schedule[k + 8], hash_block64, 32);
        }

        cipher_state->p = hash_block64[7] & 31;
        devon_hash_all_4(cipher_state->hash_block64, cipher_state->hash_block64, hash_block64, hash_block64[29] % 24, cipher_state->hash_keys);
    }

    // Mix the entire key schedule from above with XOR'd rng words 69,420 times
    for (ui r=0;r<69420;r++)
    {
        for (ui k=0;k<key_blocks;k++)
        {
            for (ui i=0;i<16;i++)
            {
                u16 x;
                memcpy(&x, &cipher_state->key_schedule[k][i * 2], 2);
                const u16 y = rng_word(cipher_state);
                const u16 x_xor_y = x ^ y;
                memcpy(&cipher_state->key_schedule[k][i * 2], &x_xor_y, 2);
            }
        }

        if (!(r & 15))
        {
            cipher_state->p = cipher_state->hash_block64[3] & 31;
            devon_hash_all_4(cipher_state->hash_block64, cipher_state->hash_block64, master_key128, rng(cipher_state, 23), cipher_state->hash_keys);
        }
    }
}
//----------------------------------------------------------------------------------------------------------------------
static void xor_blocks(void * const restrict out32, void const * const restrict in32)
{
    for (ui i=0;i<32;i++)
    {
        u8       * const restrict po = out32;
        u8 const * const restrict pi = in32;
        po[i] ^= pi[i];
    }
}
//----------------------------------------------------------------------------------------------------------------------
static ui no_potential_valid_swaps_exist(u16 sbox[65536], const ui i)
{
    for (ui j=0;j<=i;j++)
    {
        const ui p = popui(sbox[j] ^ i);

        if (p >= 7 && p <= 9)
        {
            return 0;
        }
    }

    return 1;
}
//----------------------------------------------------------------------------------------------------------------------
static void recover_sbox(struct devon_cipher_state * const cipher_state, u16 sbox[65536], const ui n)
{
    for (ui i=0;i<=n;i++)
    {
        while (1)
        {
            const ui j = rng(cipher_state, 65534 - n) + 1;
            swap(sbox[i], sbox[j]);

            const ui pi = popui(sbox[i] ^ i);
            const ui pj = popui(sbox[j] ^ j);

            if (pi < 7 || pi > 9 || pj < 7 || pj > 9)
            {
                swap(sbox[i], sbox[j]);
            }
            else break;
        }
    }
}
//----------------------------------------------------------------------------------------------------------------------
static void sbox_shuffle(struct devon_cipher_state * const cipher_state, u16 sbox[65536])
{
    for (ui i=65535;i>0;i--)
    {
        while (1)
        {
            const ui j = rng(cipher_state, i);
            swap(sbox[i], sbox[j]);

            const ui p = popui(sbox[i] ^ i);

            if (p < 7 || p > 9)
            {
                if (no_potential_valid_swaps_exist(sbox, i))
                {
                    recover_sbox(cipher_state, sbox, i);
                    return;
                }
            }
            else break;
        }
    }

    const ui p0 = popui(sbox[0]);

    if (p0 >= 7 && p0 <= 9)
    {
        return;
    }
    else
    {
        recover_sbox(cipher_state, sbox, 0);
        return;
    }
}
//----------------------------------------------------------------------------------------------------------------------
static void pbox_shuffle(struct devon_cipher_state * const cipher_state, u8 pbox[16])
{
    for (ui i=15;i>0;i--)
    {
        const ui r = rng(cipher_state, i);
        swap(pbox[i], pbox[r]);
    }
}
//----------------------------------------------------------------------------------------------------------------------
static u16 rng(struct devon_cipher_state * const cipher_state, const u16 n)
{
    u16 mask = n - 1;

    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8;

    mask |= mask + 1;

    u16 r;
    do r = rng_word(cipher_state) & mask;
    while (r > n);

    return r;
}
//----------------------------------------------------------------------------------------------------------------------
static u16 rng_word(struct devon_cipher_state * const cipher_state)
{
    if (cipher_state->p >= 32)
    {
        cipher_state->p = 0;
        cipher_state->select++;
        devon_hash_all_4(cipher_state->hash_block64, cipher_state->hash_block64, cipher_state->cntr_block64, cipher_state->select % 24, cipher_state->hash_keys);
    }

    return cipher_state->hash_block64[cipher_state->p++];
}
//----------------------------------------------------------------------------------------------------------------------
static ui sanity_check_sbox(u16 sbox[ROUNDS][65536])
{
    for (ui r=0;r<ROUNDS;r++)
    {
        u32 count[65536] = { 0 };

        for (ui i=0;i<65536;i++)
        {
            count[sbox[r][i]]++;

            const ui pop = popui(sbox[r][i] ^ i);

            if (pop < 7 || pop > 9)
            {
                return 0;
            }
        }

        for (ui i=0;i<65536;i++)
        {
            if (count[i] != 1)
            {
                return 0;
            }
        }
    }

    return 1;
}
//----------------------------------------------------------------------------------------------------------------------
static ui sanity_check_pbox(u8 pbox[ROUNDS][32])
{
    for (ui r=0;r<ROUNDS;r++)
    {
        u8 count[32] = { 0 };

        for (ui i=0;i<32;i+=2)
        {
            count[pbox[r][i + 0]]++;
            count[pbox[r][i + 1]]++;

            if ((pbox[r][i] < 16 && pbox[r][i + 1] < 16) || (pbox[r][i] >= 16 && pbox[r][i + 1] >= 16))
            {
                return 0;
            }
        }

        for (ui i=0;i<32;i++)
        {
            if (count[i] != 1)
            {
                return 0;
            }
        }
    }

    return 1;
}
//----------------------------------------------------------------------------------------------------------------------