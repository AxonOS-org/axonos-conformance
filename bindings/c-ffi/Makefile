# SPDX-License-Identifier: Apache-2.0 OR MIT
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
all: libaxonos_rfc0006.so test
libaxonos_rfc0006.so: axonos_rfc0006.c axonos_rfc0006.h
	$(CC) $(CFLAGS) -fPIC -shared $< -lm -o $@
test: libaxonos_rfc0006.so test_ffi.c
	$(CC) $(CFLAGS) test_ffi.c -L. -laxonos_rfc0006 -lm -o test_ffi
	LD_LIBRARY_PATH=. ./test_ffi
	python3 test_ffi_ctypes.py
clean:
	rm -f libaxonos_rfc0006.so test_ffi
.PHONY: all test clean
