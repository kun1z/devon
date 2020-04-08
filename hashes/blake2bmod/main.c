#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "blake2bmod.h"
//----------------------------------------------------------------------------------------------------------------------
void print_bytes(void const * const, const uint16_t);
//----------------------------------------------------------------------------------------------------------------------
int main(void)
{
    printf("Start\n\n");

    uint8_t i[64] = {0};
    uint8_t o[64] = {0};

    blake2b_mod(o, i);
    print_bytes(i, 64);
    print_bytes(o, 64);
    printf("5E81F7441C8A32F19CEC8DEEA95448E7AF60D7CF700668452E951F365CB7B472D5781ABB081899BF523D95E8E9165E4CF8891B6F125CD0DCF4FE36B218BC1F64\n\n");

    memset(i, 0, 64);
    memset(o, 0, 64);

    blake2b_mod(o, i);
    print_bytes(i, 64);
    print_bytes(o, 64);
    printf("5E81F7441C8A32F19CEC8DEEA95448E7AF60D7CF700668452E951F365CB7B472D5781ABB081899BF523D95E8E9165E4CF8891B6F125CD0DCF4FE36B218BC1F64\n\n");

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