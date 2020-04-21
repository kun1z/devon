#!/usr/bin/bash
set -u

declare -r HASH="../devon_hash/"
declare -r CIPH="../devon_cipher/"

declare -r HASHFILES="${HASH}devon_hash.c ${HASH}blake2bmod2.c ${HASH}sha2-512mod2.c ${HASH}sha3-512mod2.c ${HASH}whirlpoolmod2.c"
declare -r CIPHFILES="${CIPH}devon_cipher.c"

clang \
-D "dbgv(x)=printf(#x\"=%lld\n\",(long long)x);" \
-I ${HASH} -I ${CIPH} \
${HASHFILES} \
${CIPHFILES} \
main.c \
-o devon_impl.exe \
-Wall -Werror -Wfatal-errors \
-O3 -fomit-frame-pointer -march=native -mtune=native