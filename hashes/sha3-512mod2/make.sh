#!/usr/bin/bash
clang sha3-512mod2.c main.c -o test -Wall -Werror -Wfatal-errors -O3 -fomit-frame-pointer -march=native -mtune=native