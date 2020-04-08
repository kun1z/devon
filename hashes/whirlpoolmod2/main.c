#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "whirlpoolmod2.h"
//----------------------------------------------------------------------------------------------------------------------
void print_bytes(void const * const, const uint16_t);
//----------------------------------------------------------------------------------------------------------------------
int main(void)
{
    uint8_t i[64] = {0}, i2[64] = {0}, k[80] = {0}, o[64] = {0};

    whirlpool_mod2(o, i, i2, k);
    print_bytes(o, 64);
    printf("88BC907AAEBC9E311E776A2A49D04EF917F0DC65D46A020B3458E8EA8B9416A94002C28AED2C71EE38EB8360CBA8AC52AACC6F034AF8A8BD3125014FB2633925\n\n");

    whirlpool_mod2(o, i, i2, k);
    print_bytes(o, 64);
    printf("88BC907AAEBC9E311E776A2A49D04EF917F0DC65D46A020B3458E8EA8B9416A94002C28AED2C71EE38EB8360CBA8AC52AACC6F034AF8A8BD3125014FB2633925\n\n");

    i[0] = 1; i2[0] = 2; k[0] = 3;
    whirlpool_mod2(o, i, i2, k);
    print_bytes(o, 64);
    printf("382A72584593EE9828BE3C27D56E3818B824CFAE73DF4C52F5018510CF422EAC74FFAB08A4702469AF08461A0EFCF6638D59C931F7F071EA5140ACF3D94C5AAB\n\n");

    i[0] = 4; i2[0] = 5; k[0] = 6;
    whirlpool_mod2(o, i, i2, k);
    print_bytes(o, 64);
    printf("D6E18B23962E957FAFA4BCB59450EE13E250974C2E9B154E4B14D4EE0E407AA6995DE27919F49840458DAE47CF1803E1BC0D84B8656AB1F8EB13CC7BDAEA98BB\n\n");

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