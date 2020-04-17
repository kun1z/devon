#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//----------------------------------------------------------------------------------------------------------------------
#include "..\devon_cipher\devon_cipher.h"
//----------------------------------------------------------------------------------------------------------------------
si main(si argc, s8 **argv)
{
    // Initialize from command line params
    if (argc != 3)
    {
        printf("\n\tUsage: %s <64-bit seed 1> <64-bit seed 2>\n", argv[0]);
        printf("\tThis tool outputs random data to stdout.\n");
        printf("\tExample: \"%s 12345 67890\"\n\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Get the seed
    const u64 seed1 = atoll(argv[1]);
    const u64 seed2 = atoll(argv[2]);

    // Init a basic cipher state
    u8 iv[128] = { 0 };
    u8 master_key[128] = { 0 };
    const struct devon_hash_keys hash_keys = {{ 0 }};
    struct devon_cipher_state * const cipher_state = malloc(sizeof(struct devon_cipher_state));
    memcpy(master_key, &seed1, sizeof(seed1));
    memcpy(        iv, &seed2, sizeof(seed2));
    init_devon_cipher(cipher_state, master_key, iv, &hash_keys);

    u128 counter = 0;

    while(1)
    {
        const u8 read_block[32] = { 0 };
        u8 buffer[32];
        devon_cipher_enc(cipher_state, buffer, read_block, counter++);
        fwrite(buffer, 1, 32, stdout);
    }

    __builtin_unreachable();
}
//----------------------------------------------------------------------------------------------------------------------