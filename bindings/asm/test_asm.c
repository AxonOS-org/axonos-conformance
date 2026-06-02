/* SPDX-License-Identifier: Apache-2.0 OR MIT - drives the asm encoder. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef struct {
    uint64_t timestamp_us;   /* 0  */
    uint64_t session_id;     /* 8  */
    uint16_t kind_tag;       /* 16 */
    uint16_t quality_raw;    /* 18 */
    uint8_t  discriminant;   /* 20 */
    uint8_t  attestation[8]; /* 21 */
} axonos_enc_args;
_Static_assert(offsetof(axonos_enc_args, timestamp_us) == 0,  "ts off");
_Static_assert(offsetof(axonos_enc_args, session_id)   == 8,  "sid off");
_Static_assert(offsetof(axonos_enc_args, kind_tag)     == 16, "kind off");
_Static_assert(offsetof(axonos_enc_args, quality_raw)  == 18, "q off");
_Static_assert(offsetof(axonos_enc_args, discriminant) == 20, "disc off");
_Static_assert(offsetof(axonos_enc_args, attestation)  == 21, "att off");

extern void axonos_rfc0006_encode_asm(const axonos_enc_args *in, uint8_t *out);

static const uint8_t ATT[8] = {0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7};
static int chk(const char *id, uint16_t kind, uint8_t disc, uint16_t q, uint64_t ts, const char *exp) {
    axonos_enc_args a; memset(&a, 0, sizeof a);
    a.timestamp_us = ts; a.session_id = 0x0102030405060708ULL;
    a.kind_tag = kind; a.quality_raw = q; a.discriminant = disc;
    memcpy(a.attestation, ATT, 8);
    uint8_t out[32]; char hex[65];
    axonos_rfc0006_encode_asm(&a, out);
    for (int i = 0; i < 32; i++) sprintf(hex + 2*i, "%02x", out[i]);
    if (strcmp(hex, exp) != 0) { printf("  [FAIL] %s\n    want %s\n    got  %s\n", id, exp, hex); return 1; }
    printf("  [PASS] %s\n", id); return 0;
}
int main(void) {
    int f = 0;
    f += chk("dir_up",           1, 0, 65535, 1000, "e8030000000000000100ffff000000000807060504030201a0a1a2a3a4a5a6a7");
    f += chk("load_high",        2, 2, 32768, 2000, "d00700000000000002000080020000000807060504030201a0a1a2a3a4a5a6a7");
    f += chk("quality_high",     3, 0, 0,     3000, "b80b0000000000000300ffff000000000807060504030201a0a1a2a3a4a5a6a7");
    f += chk("quality_nosignal", 3, 3, 0,     3000, "b80b0000000000000300ffff030000000807060504030201a0a1a2a3a4a5a6a7");
    f += chk("q016_round_093",   1, 0, 60948, 1000, "e803000000000000010014ee000000000807060504030201a0a1a2a3a4a5a6a7");
    printf(f ? "\nASM (x86-64): %d FAILED\n" : "\nASM (x86-64): all pass\n", f);
    return f ? 1 : 0;
}
