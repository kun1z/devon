#!/usr/bin/bash
clang blake2bmod2.c main.c -o test -Wall -Werror -Wfatal-errors -O3 -fomit-frame-pointer -march=native -mtune=native