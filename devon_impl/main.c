#include "main.h"
//----------------------------------------------------------------------------------------------------------------------
si main(si argc, s8 **argv)
{
    // Initialize from command line params
    if (argc != 5)
    {
        printf("\n   Usage: %s <mode> <key file (1,304 bytes)> <input> <output>\n", argv[0]);
        printf("    Mode: 0 to encrypt, 1 to decrypt\n\n");
        printf(" Example: To encrypt a file named input.bin type\n");
        printf("          \"%s 0 my_key.bin input.bin output.bin\"\n\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Check all 4 params
    ui err = 0;

    s8 const * const mode = argv[1];
    s8 const * const keyfile = argv[2];
    s8 const * const infile = argv[3];
    s8 const * const outfile = argv[4];

    if (*mode != '0' && *mode != '1')
    {
        printf("Incorrect mode seleted.\n");
        err = 1;
    }

    FILE * const keyf = fopen(keyfile, "rb");
    if (keyf)
    {
        fseeko(keyf, 0, SEEK_END);
        if (ftello(keyf) != KEY_SIZE_IN_BYTES)
        {
            printf("key file size must be %u bytes large.\n", KEY_SIZE_IN_BYTES);
            err = 1;
        }
        fclose(keyf);
    }
    else
    {
        printf("key file could not be opened.\n");
        err = 1;
    }

    FILE * const inf = fopen(infile, "rb");
    if (inf)
    {
        fseeko(inf, 0, SEEK_END);
        if (!ftello(inf))
        {
            printf("input file size must be at least 1 byte.\n");
            err = 1;
        }
        fclose(inf);
    }
    else
    {
        printf("input file could not be opened.\n");
        err = 1;
    }

    FILE * const outf = fopen(outfile, "wb");
    if (outf)
    {
        u8 buf[1] = { 0 };
        if (fwrite(buf, 1, 1, outf) != 1)
        {
            printf("output file could not be written.\n");
            err = 1;
        }
        fclose(outf);
        remove(outfile);
    }
    else
    {
        printf("output file could not be created.\n");
        err = 1;
    }

    if (err)
    {
        exit(EXIT_FAILURE);
    }

    // Encrypt or Decrypt a file
    u32 time;

    if (*mode == '0')
    {
        printf("Encrypting...\n");
        const u32 start_tick = tick();
        encrypt_file(keyfile, infile, outfile);
        time = tick() - start_tick;
    }
    else
    {
        printf("Decrypting...\n");
        const u32 start_tick = tick();
        decrypt_file(keyfile, infile, outfile);
        time = tick() - start_tick;
    }

    // Print some time stats
    s8 const * const tstr[3] = { "hours", "seconds", "minutes" };
    const double tdbl[3] = { 3600000, 1000, 60000 };
    ui s = 0;
    if (time <= 600000) s = 1;
    else if (time <= 3600000) s = 2;
    printf("Completed in %.2f %s.\n", time / tdbl[s], tstr[s]);

    exit(EXIT_SUCCESS);
}
//----------------------------------------------------------------------------------------------------------------------
void encrypt_file(s8 const * const kfile, s8 const * const ifile, s8 const * const ofile)
{
    FILE * const input = fopen(ifile, "rb");
    FILE * const output = fopen(ofile, "wb");

    u8 key_buffer[KEY_SIZE_IN_BYTES];
    FILE * const keyfile = fopen(kfile, "rb");
    fread(key_buffer, 1, KEY_SIZE_IN_BYTES, keyfile);
    fclose(keyfile);

    u8 iv[128];
    FILE * const ivf = fopen("/dev/urandom", "rb");
    if (ivf)
    {
        if (fread(iv, 1, sizeof(iv), ivf) != sizeof(iv))
        {
            printf("An IV could not be generated.\n");
            exit(EXIT_FAILURE);
        }
        fclose(ivf);
    }
    else
    {
        printf("An IV could not be generated.\n");
        exit(EXIT_FAILURE);
    }

    u8 master_key[128];
    struct devon_hash_keys * const hash_keys = malloc(sizeof(struct devon_hash_keys));
    if (!hash_keys)
    {
        printf("hash_keys malloc failed.\n");
        exit(EXIT_FAILURE);
    }

    memcpy(master_key, key_buffer, sizeof(master_key));
    memcpy(hash_keys, &key_buffer[sizeof(master_key)], sizeof(struct devon_hash_keys));

    struct devon_cipher_state * const cipher_state = malloc(sizeof(struct devon_cipher_state));
    if (!cipher_state)
    {
        printf("cipher_state malloc failed.\n");
        exit(EXIT_FAILURE);
    }

    ui res = init_devon_cipher(cipher_state, master_key, iv, hash_keys);
    if (!res)
    {
        printf("init_devon_cipher failed.\n");
        exit(EXIT_FAILURE);
    }

    fseeko(input, 0, SEEK_END);
    const u64 filesize = ftello(input);
    rewind(input);

    if (filesize)
    {
        fwrite(iv, 1, sizeof(iv), output);

        const u64 buffer_size = min(filesize, CHUNK_SIZE);
        u8 * const buffer = malloc(buffer_size);
        if (!buffer)
        {
            printf("buffer malloc failed.\n");
            exit(EXIT_FAILURE);
        }

        u64 rem = filesize;
        const u64 unpadded_blocks = filesize / 32;

        for (u64 block_count,block_counter=0;block_counter<unpadded_blocks;block_counter+=block_count)
        {
            const u64 requested = min(CHUNK_SIZE, (unpadded_blocks - block_counter) * 32);
            const u64 read_in = fread(buffer, 1, requested, input);
            if (read_in & 31 || read_in != requested)
            {
                printf("read_in error: %lu of %lu\n", read_in, requested);
                exit(EXIT_FAILURE);
            }

            rem -= read_in;
            block_count = read_in / 32;

            for (u64 i=0;i<block_count;i++)
            {
                devon_cipher_enc(cipher_state, &buffer[i * 32], &buffer[i * 32], block_counter + i);
            }

            fwrite(buffer, 1, read_in, output);
        }

        free(buffer);

        u8 final_block[32] = { 0 };
        if (rem) fread(final_block, 1, rem, input);
        else rem = 32;

        final_block[31] = rem;
        devon_cipher_enc(cipher_state, final_block, final_block, unpadded_blocks);
        fwrite(final_block, 1, 32, output);
    }

    free(hash_keys);
    free(cipher_state);

    fclose(input);
    fclose(output);
}
//----------------------------------------------------------------------------------------------------------------------
void decrypt_file(s8 const * const kfile, s8 const * const ifile, s8 const * const ofile)
{
    FILE * const input = fopen(ifile, "rb");
    FILE * const output = fopen(ofile, "wb");

    u8 key_buffer[KEY_SIZE_IN_BYTES];
    FILE * const keyfile = fopen(kfile, "rb");
    fread(key_buffer, 1, KEY_SIZE_IN_BYTES, keyfile);
    fclose(keyfile);

    fseeko(input, 0, SEEK_END);
    const u64 filesize = ftello(input);
    rewind(input);

    u8 iv[128];
    if (fread(iv, 1, sizeof(iv), input) != sizeof(iv))
    {
        printf("An IV could not be generated.\n");
        exit(EXIT_FAILURE);
    }

    u8 master_key[128];
    struct devon_hash_keys * const hash_keys = malloc(sizeof(struct devon_hash_keys));
    if (!hash_keys)
    {
        printf("hash_keys malloc failed.\n");
        exit(EXIT_FAILURE);
    }

    memcpy(master_key, key_buffer, sizeof(master_key));
    memcpy(hash_keys, &key_buffer[sizeof(master_key)], sizeof(struct devon_hash_keys));

    struct devon_cipher_state * const cipher_state = malloc(sizeof(struct devon_cipher_state));
    if (!cipher_state)
    {
        printf("cipher_state malloc failed.\n");
        exit(EXIT_FAILURE);
    }

    ui res = init_devon_cipher(cipher_state, master_key, iv, hash_keys);
    if (!res)
    {
        printf("init_devon_cipher failed.\n");
        exit(EXIT_FAILURE);
    }

    if (filesize & 31 || filesize < 160)
    {
        printf("input file size is invalid.\n");
        exit(EXIT_FAILURE);
    }

    if (filesize)
    {
        const u64 buffer_size = min(filesize, CHUNK_SIZE);
        u8 * const buffer = malloc(buffer_size);
        if (!buffer)
        {
            printf("buffer malloc failed.\n");
            exit(EXIT_FAILURE);
        }

        const u64 unpadded_blocks = (filesize - 32 - 128) / 32;

        for (u64 block_count,block_counter=0;block_counter<unpadded_blocks;block_counter+=block_count)
        {
            const u64 requested = min(CHUNK_SIZE, (unpadded_blocks - block_counter) * 32);
            const u64 read_in = fread(buffer, 1, requested, input);
            if (read_in & 31 || read_in != requested)
            {
                printf("read_in error: %lu of %lu\n", read_in, requested);
                exit(EXIT_FAILURE);
            }

            block_count = read_in / 32;

            for (u64 i=0;i<block_count;i++)
            {
                devon_cipher_dec(cipher_state, &buffer[i * 32], &buffer[i * 32], block_counter + i);
            }

            fwrite(buffer, 1, read_in, output);
        }

        free(buffer);

        u8 final_block[32] = { 0 };
        fread(final_block, 1, 32, input);

        devon_cipher_dec(cipher_state, final_block, final_block, unpadded_blocks);
        fwrite(final_block, 1, final_block[31] & 31, output);
    }

    free(hash_keys);
    free(cipher_state);

    fclose(input);
    fclose(output);
}
//----------------------------------------------------------------------------------------------------------------------
u32 tick(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec * 1000) + (now.tv_nsec / 1000000);
}
//----------------------------------------------------------------------------------------------------------------------