#include "main.h"
//----------------------------------------------------------------------------------------------------------------------
si main(si argc, s8 **argv)
{
    // Initialize from command line params
    if (argc != 5 && argc != 7)
    {
        printf("\n    Usage: %s <mode> <cpu bias> <memory> <key file (1,304 bytes)> <input> <output>\n\n", argv[0]);
        printf("     Mode: 0 to encrypt, 1 to decrypt\n");
        printf(" CPU Bias: 0.1 to 1000.0\n");
        printf("   Memory: 20 to 64. 20 = 1MB ram, 24 = 16MB ram, 32 = 4GB ram, etc... (Power of 2)\n\n");
        printf("  Example: To encrypt a file named input.bin using default CPU Bias and 64MB of ram type:\n\n");
        printf("          \"%s 0 1.0 26 my_key.bin input.bin output.bin\"\n\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Check all params
    ui err = 0;
    s8 const * const mode = argv[1];

    // Check mode
    if (*mode != '0' && *mode != '1')
    {
        printf("Incorrect mode seleted.\n");
        err = 1;
    }

    double cpu_bias;
    ui mem_hard;
    s8 * keyfile;
    s8 * infile;
    s8 * outfile;

    if (argc == 5 && *mode == '1')
    {
        keyfile = argv[2];
        infile = argv[3];
        outfile = argv[4];
    }
    else
    {
        cpu_bias = atof(argv[2]);
        mem_hard = atol(argv[3]);
        keyfile = argv[4];
        infile = argv[5];
        outfile = argv[6];

        // Check CPU Bias range
        if (cpu_bias < 0.1 || cpu_bias > 1000)
        {
            printf("Incorrect CPU Bias seleted.\n");
            err = 1;
        }

        // Check memory range
        if (mem_hard < 20 || mem_hard > 64)
        {
            printf("Incorrect memory range.\n");
            err = 1;
        }
    }

    // Check key file params
    FILE * const keyf = fopen(keyfile, "rb");
    if (keyf)
    {
        if (fseeko(keyf, 0, SEEK_END))
        {
            printf("fseeko() failed on keyfile.\n");
            exit(EXIT_FAILURE);
        }
        if (ftello(keyf) != KEY_SIZE_IN_BYTES)
        {
            printf("key file size must be %u bytes large.\n", KEY_SIZE_IN_BYTES);
            err = 1;
        }
        if (fclose(keyf))
        {
            printf("fclose() failed on keyfile.\n");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        printf("key file could not be opened.\n");
        err = 1;
    }

    // Check infile params
    FILE * const inf = fopen(infile, "rb");
    if (inf)
    {
        if (fseeko(inf, 0, SEEK_END))
        {
            printf("fseeko() failed on infile.\n");
            exit(EXIT_FAILURE);
        }
        if (!ftello(inf))
        {
            printf("input file size must be at least 1 byte.\n");
            err = 1;
        }
        if (fclose(inf))
        {
            printf("fclose() failed on infile.\n");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        printf("input file could not be opened.\n");
        err = 1;
    }

    // Check  outfile params
    FILE * const outf = fopen(outfile, "wb");
    if (outf)
    {
        u8 buf[1] = { 0 };
        if (fwrite(buf, 1, 1, outf) != 1)
        {
            printf("output file could not be written.\n");
            err = 1;
        }
        if (fclose(outf))
        {
            printf("fclose() failed on outfile.\n");
            exit(EXIT_FAILURE);
        }
        if (remove(outfile))
        {
            printf("remove() failed on outfile.\n");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        printf("output file could not be created.\n");
        err = 1;
    }

    // If anything failed from above bail out.
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
        encrypt_file(keyfile, infile, outfile, cpu_bias, mem_hard);
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
void encrypt_file(s8 const * const kfile, s8 const * const ifile, s8 const * const ofile, const double cpu_bias, const ui mem_hard)
{
    // Open input file
    FILE * const input = fopen(ifile, "rb");
    if (!input)
    {
        printf("input file could not be opened.\n");
        exit(EXIT_FAILURE);
    }

    // Open output file
    FILE * const output = fopen(ofile, "wb");
    if (!output)
    {
        printf("output file could not be opened.\n");
        exit(EXIT_FAILURE);
    }

    // Open and load the key buffer
    u8 key_buffer[KEY_SIZE_IN_BYTES];
    FILE * const keyfile = fopen(kfile, "rb");
    if (!keyfile)
    {
        printf("keyfile could not be opened.\n");
        exit(EXIT_FAILURE);
    }
    if (fread(key_buffer, 1, KEY_SIZE_IN_BYTES, keyfile) != KEY_SIZE_IN_BYTES)
    {
        printf("keyfile read error. Possibly incorrect size.\n");
        exit(EXIT_FAILURE);
    }
    if (fclose(keyfile))
    {
        printf("fclose() failed on keyfile.\n");
        exit(EXIT_FAILURE);
    }

    // Create a unique IV
    u8 iv[128];
    FILE * const ivf = fopen("/dev/urandom", "rb");
    if (ivf)
    {
        if (fread(iv, 1, sizeof(iv), ivf) != sizeof(iv))
        {
            printf("An IV could not be generated.\n");
            exit(EXIT_FAILURE);
        }
        if (fclose(ivf))
        {
            printf("fclose() failed on iv.\n");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        printf("An IV could not be generated.\n");
        exit(EXIT_FAILURE);
    }

    // Set up the keys
    u8 master_key[128];
    struct devon_hash_keys * const hash_keys = malloc(sizeof(struct devon_hash_keys));
    if (!hash_keys)
    {
        printf("hash_keys malloc failed.\n");
        exit(EXIT_FAILURE);
    }
    memcpy(master_key, key_buffer, sizeof(master_key));
    memcpy(hash_keys, &key_buffer[sizeof(master_key)], sizeof(struct devon_hash_keys));

    // Initialize the cipher state
    struct devon_cipher_state * const cipher_state = malloc(sizeof(struct devon_cipher_state));
    if (!cipher_state)
    {
        printf("cipher_state malloc failed.\n");
        exit(EXIT_FAILURE);
    }
    ui res = init_devon_cipher(cipher_state, master_key, iv, hash_keys, cpu_bias, mem_hard);
    if (!res)
    {
        printf("init_devon_cipher failed.\n");
        exit(EXIT_FAILURE);
    }

    // Get the input file size
    if (fseeko(input, 0, SEEK_END))
    {
        printf("fseeko() failed on input file.\n");
        exit(EXIT_FAILURE);
    }
    const off_t temp_filesize = ftello(input);
    if (temp_filesize <= 0)
    {
        printf("ftello() failed on input file.\n");
        exit(EXIT_FAILURE);
    }
    rewind(input);
    const u64 filesize = temp_filesize;

    // Write the IV to the start of the file
    if (fwrite(iv, 1, sizeof(iv), output) != sizeof(iv))
    {
        printf("could not write the IV to file.\n");
        exit(EXIT_FAILURE);
    }

    // Write the CPU Bias to the start of the file
    if (fwrite(&cpu_bias, 1, sizeof(cpu_bias), output) != sizeof(cpu_bias))
    {
        printf("could not write the CPU Bias to file.\n");
        exit(EXIT_FAILURE);
    }

    // Write the mem_hard to the start of the file
    u8 temp_mh = mem_hard;
    if (fwrite(&temp_mh, 1, sizeof(temp_mh), output) != sizeof(temp_mh))
    {
        printf("could not write the CPU Bias to file.\n");
        exit(EXIT_FAILURE);
    }

    // Create a file buffer in memory that is CHUNK_SIZE (or if the file is small, large enough for the entire file)
    const u64 buffer_size = min(filesize, CHUNK_SIZE);
    u8 * const buffer = malloc(buffer_size);
    if (!buffer)
    {
        printf("buffer malloc failed.\n");
        exit(EXIT_FAILURE);
    }

    u64 rem = filesize;
    const u64 unpadded_blocks = filesize / 32;

    // Encrypt all full (unpadded) blocks
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

        if (fwrite(buffer, 1, read_in, output) != read_in)
        {
            printf("could not write data to the outfile.\n");
            exit(EXIT_FAILURE);
        }
    }

    free(buffer);

    // Set up the padding and encrypt the final block. There is always 1 padded block regardless
    // of input file size.
    u8 final_block[32] = { 0 };
    if (rem)
    {
        if (fread(final_block, 1, rem, input) != rem)
        {
            printf("could not read data fromt the input file.\n");
            exit(EXIT_FAILURE);
        }
    }
    else rem = 32;

    final_block[31] = rem;
    devon_cipher_enc(cipher_state, final_block, final_block, unpadded_blocks);
    if (fwrite(final_block, 1, sizeof(final_block), output) != sizeof(final_block))
    {
        printf("could not write data to the outfile.\n");
        exit(EXIT_FAILURE);
    }

    // Free & close everything
    free(hash_keys);
    free(cipher_state);

    if (fclose(input))
    {
        printf("fclose() failed on input file.\n");
        exit(EXIT_FAILURE);
    }

    if (fclose(output))
    {
        printf("fclose() failed on output file.\n");
        exit(EXIT_FAILURE);
    }
}
//----------------------------------------------------------------------------------------------------------------------
void decrypt_file(s8 const * const kfile, s8 const * const ifile, s8 const * const ofile)
{
    // Open input file
    FILE * const input = fopen(ifile, "rb");
    if (!input)
    {
        printf("input file could not be opened.\n");
        exit(EXIT_FAILURE);
    }

    // Open output file
    FILE * const output = fopen(ofile, "wb");
    if (!output)
    {
        printf("output file could not be opened.\n");
        exit(EXIT_FAILURE);
    }

    // Open and load the key buffer
    u8 key_buffer[KEY_SIZE_IN_BYTES];
    FILE * const keyfile = fopen(kfile, "rb");
    if (!keyfile)
    {
        printf("keyfile could not be opened.\n");
        exit(EXIT_FAILURE);
    }
    if (fread(key_buffer, 1, KEY_SIZE_IN_BYTES, keyfile) != KEY_SIZE_IN_BYTES)
    {
        printf("keyfile read error. Possibly incorrect size.\n");
        exit(EXIT_FAILURE);
    }
    if (fclose(keyfile))
    {
        printf("fclose() failed on keyfile.\n");
        exit(EXIT_FAILURE);
    }

    // Get the input file size
    if (fseeko(input, 0, SEEK_END))
    {
        printf("fseeko() failed on input file.\n");
        exit(EXIT_FAILURE);
    }
    const off_t temp_filesize = ftello(input);
    if (temp_filesize <= 0)
    {
        printf("ftello() failed on input file.\n");
        exit(EXIT_FAILURE);
    }
    rewind(input);
    const u64 filesize = temp_filesize;
    if ((filesize % 32) != 9 || filesize < 169)
    {
        printf("input file size is invalid.\n");
        exit(EXIT_FAILURE);
    }

    // Read in the IV from the start of the file
    u8 iv[128];
    if (fread(iv, 1, sizeof(iv), input) != sizeof(iv))
    {
        printf("An IV could not be read.\n");
        exit(EXIT_FAILURE);
    }

    // Read in the CPU Bias from the start of the file
    double cpu_bias;
    if (fread(&cpu_bias, 1, sizeof(cpu_bias), input) != sizeof(cpu_bias))
    {
        printf("CPU Bias could not be read.\n");
        exit(EXIT_FAILURE);
    }

    // Check CPU Bias range
    if (cpu_bias < 0.1 || cpu_bias > 1000)
    {
        printf("Incorrect CPU Bias loaded.\n");
        exit(EXIT_FAILURE);
    }

    // Read in the mem_hard from the start of the file
    u8 mem_hard;
    if (fread(&mem_hard, 1, sizeof(mem_hard), input) != sizeof(mem_hard))
    {
        printf("mem_hard could not be read.\n");
        exit(EXIT_FAILURE);
    }

    // Check memory range
    if (mem_hard < 20 || mem_hard > 64)
    {
        printf("Incorrect memory range loaded.\n");
        exit(EXIT_FAILURE);
    }

    // Set up the keys
    u8 master_key[128];
    struct devon_hash_keys * const hash_keys = malloc(sizeof(struct devon_hash_keys));
    if (!hash_keys)
    {
        printf("hash_keys malloc failed.\n");
        exit(EXIT_FAILURE);
    }
    memcpy(master_key, key_buffer, sizeof(master_key));
    memcpy(hash_keys, &key_buffer[sizeof(master_key)], sizeof(struct devon_hash_keys));

    // Initialize the cipher state
    struct devon_cipher_state * const cipher_state = malloc(sizeof(struct devon_cipher_state));
    if (!cipher_state)
    {
        printf("cipher_state malloc failed.\n");
        exit(EXIT_FAILURE);
    }
    ui res = init_devon_cipher(cipher_state, master_key, iv, hash_keys, cpu_bias, mem_hard);
    if (!res)
    {
        printf("init_devon_cipher failed.\n");
        exit(EXIT_FAILURE);
    }

    // Create a file buffer in memory that is CHUNK_SIZE (or if the file is small, large enough for the entire file)
    const u64 buffer_size = min(filesize, CHUNK_SIZE);
    u8 * const buffer = malloc(buffer_size);
    if (!buffer)
    {
        printf("buffer malloc failed.\n");
        exit(EXIT_FAILURE);
    }

    const u64 unpadded_blocks = (filesize - 32 - 128 - 8 - 1) / 32;

    // Decrypt all full (unpadded) blocks
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

        if (fwrite(buffer, 1, read_in, output) != read_in)
        {
            printf("could not write data to the outfile.\n");
            exit(EXIT_FAILURE);
        }
    }

    free(buffer);

    // Read in the padding and decrypt the final block. There is always 1 padded block regardless
    // of input file size.
    u8 final_block[32] = { 0 };
    if (fread(final_block, 1, sizeof(final_block), input) != sizeof(final_block))
    {
        printf("could not read data fromt the input file.\n");
        exit(EXIT_FAILURE);
    }

    devon_cipher_dec(cipher_state, final_block, final_block, unpadded_blocks);
    const ui rem = final_block[31] & 31;
    if (fwrite(final_block, 1, rem, output) != rem)
    {
        printf("could not write data to the outfile.\n");
        exit(EXIT_FAILURE);
    }

    // Free & close everything
    free(hash_keys);
    free(cipher_state);

    if (fclose(input))
    {
        printf("fclose() failed on input file.\n");
        exit(EXIT_FAILURE);
    }

    if (fclose(output))
    {
        printf("fclose() failed on output file.\n");
        exit(EXIT_FAILURE);
    }
}
//----------------------------------------------------------------------------------------------------------------------
u32 tick(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now))
    {
        printf("clock_gettime() failed.\n");
        exit(EXIT_FAILURE);
    }
    return (now.tv_sec * 1000) + (now.tv_nsec / 1000000);
}
//----------------------------------------------------------------------------------------------------------------------