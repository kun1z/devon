HASH := ../devon_hash
CIPH := ../devon_cipher

# NOTE: I'm just doing *.c instead of listing the files because I'm lazy
HASHFILES := $(wildcard $(HASH)/*.c)
CIPHFILES := $(wildcard $(CIPH)/*.c)

CC := clang

# Note: Some people use CFLAGS for everything, but technically these are for the preprocessor
CPPFLAGS += -D "dbgv(x)=printf(\#x\"=%lld\n\",(long long)x);"
CPPFLAGS += -I ${HASH} -I ${CIPH}
# Note: Here's the magic for telling the compiler to generate the .d dependency files
CPPFLAGS += -MP -MMD

CFLAGS += -pthread -std=c18 -Wall -Werror -Wfatal-errors -O3 -fomit-frame-pointer -march=native -mtune=native

# And here's the key.  This will link devon_rng using all the object files, which will be compiled from all the C files of the same name.
devon_rng.exe : main.o $(HASHFILES:.c=.o) $(CIPHFILES:.c=.o)
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

# Note: more magic to use the .d files generated last time make was run
-include main.d $(HASHFILES:.c=.d) $(CIPHFILES:.c=.d)

.PHONY: clean
clean:
	rm $(HASH)/*.o $(CIPH)/*.o *.o $(HASH)/*.d $(CIPH)/*.d *.d devon_rng.exe