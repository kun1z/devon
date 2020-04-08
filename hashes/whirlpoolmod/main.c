#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "whirlpoolmod.h"
//----------------------------------------------------------------------------------------------------------------------
void print_bytes(void const * const, const uint16_t);
//----------------------------------------------------------------------------------------------------------------------
int main(void)
{
    uint8_t i[64] = {0}, o[64];

    whirlpool_mod(o, i);
    print_bytes(o, 64);
    printf("88BC907AAEBC9E311E776A2A49D04EF917F0DC65D46A020B3458E8EA8B9416A94002C28AED2C71EE38EB8360CBA8AC52AACC6F034AF8A8BD3125014FB2633925\n\n");

    whirlpool_mod(o, i);
    print_bytes(o, 64);
    printf("88BC907AAEBC9E311E776A2A49D04EF917F0DC65D46A020B3458E8EA8B9416A94002C28AED2C71EE38EB8360CBA8AC52AACC6F034AF8A8BD3125014FB2633925\n\n");

    i[0] = 0x69;
    whirlpool_mod(o, i);
    print_bytes(o, 64);
    printf("723FCDCB4971693F5E1E2BE17AD863FD7E036A279B6A1A67D2DE17BDEEE30675BCCA5F917DAE3AE92FC853B76010DEEBFCC464A16238A3E17D4A211DB7A4AF1C\n\n");

    i[0] = 1; i[1] = 2; i[2] = 3; i[3] = 4;
    whirlpool_mod(o, i);
    print_bytes(o, 64);
    printf("1B7AA108C4B5D3F3EA54502347AFD4F53BFEF0A2456E73A2CD54CC27FE61905FF1D6F8DCD84D613B37A3CC7622433168F8ABD7BA801C5DF996C2EBAE7B2FC2BD\n\n");

    sleep(-1U);
    return 0;
}
//----------------------------------------------------------------------------------------------------------------------
void print_bytes(void const * const ptr, const uint16_t length)
{
    uint8_t const * const bytes = ptr;

    for (uint32_t i=0;i<length;i++)
    {
        printf("%02X", bytes[i]);
    }

    printf("\n");
}
//----------------------------------------------------------------------------------------------------------------------