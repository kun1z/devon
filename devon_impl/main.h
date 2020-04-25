#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
//----------------------------------------------------------------------------------------------------------------------
#include "..\devon_cipher\devon_cipher.h"
#define min(a, b) ({ const u64 _a = (a); const u64 _b = (b); _a < _b ? _a : _b; })
#define CHUNK_SIZE ((u64)(8 * 1024 * 1024)) // 8MB file memory buffer
static_assert(!(CHUNK_SIZE & 31), "This code requires [CHUNK_SIZE] to be a multiple of 32.");
static_assert(sizeof(off_t) >= 8, "This code requires [off_t] to be at least 8 bytes.");
static_assert(sizeof(size_t) >= 8, "This code requires [size_t] to be at least 8 bytes.");
static_assert(sizeof(double) == 8, "This code requires [double] to be exactly 8 bytes.");
//----------------------------------------------------------------------------------------------------------------------
void encrypt_file(s8 const * const, s8 const * const, s8 const * const, const double, const ui);
void decrypt_file(s8 const * const, s8 const * const, s8 const * const);
u32 tick(void);
//----------------------------------------------------------------------------------------------------------------------