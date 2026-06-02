# SPDX-License-Identifier: Apache-2.0 OR MIT
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
all: test
test: test_asm.c axonos_rfc0006_encode.S fuzz_cross.c ../c-ffi/axonos_rfc0006.c
	$(CC) $(CFLAGS) test_asm.c axonos_rfc0006_encode.S -o test_asm
	./test_asm
	$(CC) $(CFLAGS) fuzz_cross.c ../c-ffi/axonos_rfc0006.c axonos_rfc0006_encode.S -I../c-ffi -lm -o fuzz_cross
	./fuzz_cross
clean:
	rm -f test_asm fuzz_cross
.PHONY: all test clean
