#!/usr/bin/bash
clang sha2-512mod.c main.c -o test -Wall -Werror -Wfatal-errors -O3 -fomit-frame-pointer -march=native -mtune=native