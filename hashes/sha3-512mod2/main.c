#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "sha3-512mod2.h"
//----------------------------------------------------------------------------------------------------------------------
void print_bytes(void const * const, const uint16_t);
//----------------------------------------------------------------------------------------------------------------------
int main(void)
{
    uint8_t i[64] = {0}, i2[64] = {0}, k[72] = {0}, k2[192] = {0}, o[64] = {0};

    sha3_512mod2(o, i, i2, k, k2);
    print_bytes(o, 64);
    printf("E7DDE140798F25F18A47C033F9CCD584EEA95AA61E2698D54D49806F304715BD57D05362054E288BD46F8E7F2DA497FFC44746A4A0E5FE90762E19D60CDA5B8C\n\n");

    sha3_512mod2(o, i, i2, k, k2);
    print_bytes(o, 64);
    printf("E7DDE140798F25F18A47C033F9CCD584EEA95AA61E2698D54D49806F304715BD57D05362054E288BD46F8E7F2DA497FFC44746A4A0E5FE90762E19D60CDA5B8C\n\n");

    i[0] = 1; i2[0] = 2; k[0] = 3; k2[0] = 4;
    sha3_512mod2(o, i, i2, k, k2);
    print_bytes(o, 64);
    printf("1279CAC8CA192D5CE875E47068C98F279117DA0C8B5D80AB0FF7E6E404FF31714BF76533249F9A605391672C35C861D98B2C9643B2986DF86C0269B9B7825F04\n\n");

    i[0] = 5; i2[0] = 6; k[0] = 7; k2[0] = 8;
    sha3_512mod2(o, i, i2, k, k2);
    print_bytes(o, 64);
    printf("2141E6560AE83FEE9E28E25B4341C8BC257893890A0F11DB90BF2FFD0CFA1647F1FDBBB3A37744A9B631C1E60BCF704CC4F95B6BA797FC7090FD4193018B0C55\n\n");

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