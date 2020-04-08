#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "sha2-512mod2.h"
//----------------------------------------------------------------------------------------------------------------------
void print_bytes(void const * const, const uint16_t);
//----------------------------------------------------------------------------------------------------------------------
int main(void)
{
    uint8_t i[64] = {0}, i2[64] = {0}, k[64] = {0}, k2[640] = {0}, o[64] = {0};

    sha2_512mod2(o, i, i2, k, k2);
    print_bytes(o, 64);
    printf("E8CB4A77D58178CF7080C7FBE0623353DA0E46879D636702B03159E840CB8630A323A08852C97D71E0B5E04CC1B2BA960B3EE3EA04FEC46FEE8B66BD0CD8F491\n\n");

    sha2_512mod2(o, i, i2, k, k2);
    print_bytes(o, 64);
    printf("E8CB4A77D58178CF7080C7FBE0623353DA0E46879D636702B03159E840CB8630A323A08852C97D71E0B5E04CC1B2BA960B3EE3EA04FEC46FEE8B66BD0CD8F491\n\n");

    i[0] = 1; i2[0] = 2; k[0] = 3; k2[0] = 4;
    sha2_512mod2(o, i, i2, k, k2);
    print_bytes(o, 64);
    printf("AF9134F046862470A1D8FC6BCEB987EF69B6C92982F88317248C566E71689C273BEA93E57EF98FBDC92272EAF67D3952D840B47E03A08934205559006327C711\n\n");

    i[0] = 5; i2[0] = 6; k[0] = 7; k2[0] = 8;
    sha2_512mod2(o, i, i2, k, k2);
    print_bytes(o, 64);
    printf("6E75DFCB1199796FE9BF1243E1C3D8B9850F8BD67F990A82781D86C399EB774634D05A914DAD708D2BEED3E96A6962D2062ADEFD8C1CDD54FE10F97A65065596\n\n");

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