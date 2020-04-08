#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "blake2bmod2.h"
//----------------------------------------------------------------------------------------------------------------------
void print_bytes(void const * const, const uint16_t);
//----------------------------------------------------------------------------------------------------------------------
int main(void)
{
    uint8_t i[64] = {0}, i2[64] = {0}, k[128] = {0}, o[64] = {0};

    blake2b_mod2(o, i, i2, k);
    print_bytes(o, 64);
    printf("C577A8FA7CDDAD9FFF0CC48159E3CB7F2B216354BCF38826C5D09B7B3755FFD8608EF8020D19E3A570D8511BCC492D0B25359CC1267FA6F8EBB41318830B4CEB\n\n");

    blake2b_mod2(o, i, i2, k);
    print_bytes(o, 64);
    printf("C577A8FA7CDDAD9FFF0CC48159E3CB7F2B216354BCF38826C5D09B7B3755FFD8608EF8020D19E3A570D8511BCC492D0B25359CC1267FA6F8EBB41318830B4CEB\n\n");

    i[0] = 1; i2[0] = 2; k[0] = 3;
    blake2b_mod2(o, i, i2, k);
    print_bytes(o, 64);
    printf("9F9EDC7C84F7AE474629F579EC6C300A29E22DABB0894B67738717086BE8F659D331567152FFABD762FD7584BFEF06A845D0F66D1A69352E513FEF48180AF3AB\n\n");

    i[0] = 4; i2[0] = 5; k[0] = 6;
    blake2b_mod2(o, i, i2, k);
    print_bytes(o, 64);
    printf("598AC3DC074BF8434BDB9B55AD406D5704B50EB0AE00A75BACE08346686441E52D9D3030FD79486A4062358A21815CE0A71C0B0C86FFA138CCB06610E0A9EC35\n\n");

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