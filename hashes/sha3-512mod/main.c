#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "sha3-512mod.h"
//----------------------------------------------------------------------------------------------------------------------
void print_bytes(void const * const, const uint16_t);
//----------------------------------------------------------------------------------------------------------------------
int main(void)
{
    printf("Start\n\n");

    uint8_t i[64] = {0};
    uint8_t o[64] = {0};

    sha3_512mod(o, i);
    print_bytes(i, 64);
    print_bytes(o, 64);
    printf("E7DDE140798F25F18A47C033F9CCD584EEA95AA61E2698D54D49806F304715BD57D05362054E288BD46F8E7F2DA497FFC44746A4A0E5FE90762E19D60CDA5B8C\n\n");

    memset(i, 0, 64);
    memset(o, 0, 64);

    sha3_512mod(o, i);
    print_bytes(i, 64);
    print_bytes(o, 64);
    printf("E7DDE140798F25F18A47C033F9CCD584EEA95AA61E2698D54D49806F304715BD57D05362054E288BD46F8E7F2DA497FFC44746A4A0E5FE90762E19D60CDA5B8C\n\n");

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