#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "sha2-512mod.h"
//----------------------------------------------------------------------------------------------------------------------
void print_bytes(void const * const, const uint16_t);
//----------------------------------------------------------------------------------------------------------------------
int main(void)
{
    printf("Start\n\n");

    uint8_t i[64] = {0};
    uint8_t o[64] = {0};

    sha2_512mod(o, i);
    print_bytes(i, 64);
    print_bytes(o, 64);
    printf("E8CB4A77D58178CF7080C7FBE0623353DA0E46879D636702B03159E840CB8630A323A08852C97D71E0B5E04CC1B2BA960B3EE3EA04FEC46FEE8B66BD0CD8F491\n\n");

    memset(i, 0, 64);
    memset(o, 0, 64);

    sha2_512mod(o, i);
    print_bytes(i, 64);
    print_bytes(o, 64);
    printf("E8CB4A77D58178CF7080C7FBE0623353DA0E46879D636702B03159E840CB8630A323A08852C97D71E0B5E04CC1B2BA960B3EE3EA04FEC46FEE8B66BD0CD8F491\n\n");

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