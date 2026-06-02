/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Cross-checks the x86-64 assembly encoder against the portable C
 * implementation on many random inputs (deterministic seed). */
#include "axonos_rfc0006.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef struct {
    uint64_t timestamp_us; uint64_t session_id;
    uint16_t kind_tag; uint16_t quality_raw; uint8_t discriminant; uint8_t attestation[8];
} axonos_enc_args;
_Static_assert(offsetof(axonos_enc_args, kind_tag) == 16, "layout");
_Static_assert(offsetof(axonos_enc_args, attestation) == 21, "layout");
extern void axonos_rfc0006_encode_asm(const axonos_enc_args *in, uint8_t *out);
int main(void) {
    srand(0x4178);
    const long N = 200000; long mism = 0;
    for (long i = 0; i < N; i++) {
        uint16_t kind = (uint16_t)(1 + (rand() % 3));
        uint8_t  disc = (uint8_t)(rand() & 0xff);
        uint16_t q    = (uint16_t)(rand() & 0xffff);
        uint64_t ts   = ((uint64_t)(unsigned)rand() << 32) ^ (unsigned)rand();
        uint64_t sid  = ((uint64_t)(unsigned)rand() << 32) ^ (unsigned)rand();
        uint8_t att[8]; for (int j = 0; j < 8; j++) att[j] = (uint8_t)(rand() & 0xff);
        uint8_t a[32], b[32];
        axonos_rfc0006_encode(kind, disc, q, ts, sid, att, a);   /* portable C */
        axonos_enc_args s; memset(&s, 0, sizeof s);
        s.timestamp_us = ts; s.session_id = sid; s.kind_tag = kind;
        s.quality_raw = q; s.discriminant = disc; memcpy(s.attestation, att, 8);
        axonos_rfc0006_encode_asm(&s, b);                         /* assembly */
        if (memcmp(a, b, 32) != 0) { if (mism < 3) printf("  mismatch at i=%ld kind=%u\n", i, kind); mism++; }
    }
    printf("  cross-check asm vs C-FFI: %ld/%ld identical%s\n", N - mism, N, mism ? "  — FAIL" : "");
    return mism ? 1 : 0;
}
