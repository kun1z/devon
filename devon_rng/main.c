#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/sysinfo.h>
//----------------------------------------------------------------------------------------------------------------------
#include "..\devon_cipher\devon_cipher.h"
#define CHUNK_SIZE ((u64)(1048576))
struct thread_info
{
    u64 block_start;
    u64 block_count;
    struct devon_cipher_state * cipher_state;
    u8 * buffer;
};
void * thread(void *);
//----------------------------------------------------------------------------------------------------------------------
si main(si argc, s8 **argv)
{
    // Initialize from command line params
    if (argc != 4)
    {
        printf("\n\tUsage: %s <threads> <64-bit seed 1> <64-bit seed 2>\n", argv[0]);
        printf("\tThis tool outputs random data to stdout.\n");
        printf("\tSet threads to 0 to use all available CPU threads.\n");
        printf("\tExample: \"%s 0 12345 67890\"\n\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Get the starting params
    const u64 temp_threads = atoll(argv[1]);
    if (temp_threads >= 1024)
    {
        printf("Incorrect thread count.\n");
        exit(EXIT_FAILURE);
    }
    const u64 threads = temp_threads ? temp_threads : get_nprocs();
    const u64 seed1 = atoll(argv[2]);
    const u64 seed2 = atoll(argv[3]);

    // Init a basic cipher state
    u8 iv[128] = { 0 };
    u8 master_key[128] = { 0 };
    const struct devon_hash_keys hash_keys = {{ 0 }};
    struct devon_cipher_state * const cipher_state = malloc(sizeof(struct devon_cipher_state));
    memcpy(master_key, &seed1, sizeof(seed1));
    memcpy(        iv, &seed2, sizeof(seed2));
    init_devon_cipher(cipher_state, master_key, iv, &hash_keys, 1.0, 20);

    // Set up the thread data
    u8 * const buffer = malloc(CHUNK_SIZE * threads);
    if (!buffer)
    {
        printf("Could not allocate a memory buffer.\n");
        exit(EXIT_FAILURE);
    }
    struct thread_info ti[threads];
    for (u64 i=0;i<threads;i++)
    {
        ti[i].block_count = CHUNK_SIZE / 32;
        ti[i].cipher_state = cipher_state;
        ti[i].buffer = &buffer[CHUNK_SIZE * i];
    }

    u64 counter = 0;

    while (1)
    {
        pthread_t ht[threads];

        for (u64 i=0;i<threads;i++)
        {
            ti[i].block_start = counter;
            counter += ti[i].block_count;

            if (pthread_create(&ht[i], 0, thread, &ti[i]))
            {
                printf("pthread_create() failed.\n");
                exit(EXIT_FAILURE);
            }
        }

        for (u64 i=0;i<threads;i++)
        {
            if (pthread_join(ht[i], 0))
            {
                printf("pthread_join() failed.\n");
                exit(EXIT_FAILURE);
            }
        }

        fwrite(buffer, 1, CHUNK_SIZE * threads, stdout);
    }

    __builtin_unreachable();
}
//----------------------------------------------------------------------------------------------------------------------
void * thread(void * pthread_info)
{
    struct thread_info * const ti = pthread_info;
    u8 block[32] = { 0 };

    for (u64 i=0;i<ti->block_count;i++)
    {
        devon_cipher_enc(ti->cipher_state, &ti->buffer[i * 32], block, ti->block_start + i);
    }

    return 0;
}
//----------------------------------------------------------------------------------------------------------------------