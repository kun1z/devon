#!/usr/bin/bash
clang whirlpoolmod2.c main.c -o test.exe -Wall -Werror -Wfatal-errors -O3 -fomit-frame-pointer -march=native -mtune=native