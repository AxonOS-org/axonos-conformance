/* SPDX-License-Identifier: Apache-2.0 OR MIT - links the shared library. */
#include "axonos_rfc0006.h"
#include <stdio.h>
#include <string.h>
static const uint8_t ATT[8] = {0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7};
static const uint64_t SID = 0x0102030405060708ULL;
static int chk(const char *id, uint16_t kind, uint8_t disc, uint16_t q, uint64_t ts, const char *exp) {
    uint8_t out[32]; char hex[65];
    int r = axonos_rfc0006_encode(kind, disc, q, ts, SID, ATT, out);
    if (r != AXONOS_OK) { printf("  [FAIL] %s: encode rc=%d\n", id, r); return 1; }
    for (int i = 0; i < 32; i++) sprintf(hex + 2*i, "%02x", out[i]);
    /* round-trip */
    axonos_rfc0006_obs o; axonos_rfc0006_decode(out, &o);
    uint8_t out2[32]; axonos_rfc0006_encode(o.kind_tag, o.discriminant, o.quality_raw, o.timestamp_us, o.session_id, o.attestation, out2);
    if (memcmp(out, out2, 32) != 0) { printf("  [FAIL] %s: round-trip\n", id); return 1; }
    if (strcmp(hex, exp) != 0) { printf("  [FAIL] %s\n    want %s\n    got  %s\n", id, exp, hex); return 1; }
    printf("  [PASS] %s\n", id); return 0;
}
int main(void) {
    int f = 0;
    f += chk("dir_up",           1, 0, 65535, 1000, "e8030000000000000100ffff000000000807060504030201a0a1a2a3a4a5a6a7");
    f += chk("load_high",        2, 2, 32768, 2000, "d00700000000000002000080020000000807060504030201a0a1a2a3a4a5a6a7");
    f += chk("quality_high",     3, 0, 0,     3000, "b80b0000000000000300ffff000000000807060504030201a0a1a2a3a4a5a6a7");
    f += chk("quality_nosignal", 3, 3, 0,     3000, "b80b0000000000000300ffff030000000807060504030201a0a1a2a3a4a5a6a7");
    f += chk("q016_round_093",   1, 0, axonos_q016_from_float(0.93), 1000, "e803000000000000010014ee000000000807060504030201a0a1a2a3a4a5a6a7");
    if (axonos_q016_from_float(0.93) != 60948) { printf("  [FAIL] q016 round %u != 60948\n", axonos_q016_from_float(0.93)); f++; }
    else printf("  [PASS] q016_round (0.93 -> 60948)\n");
    printf(f ? "\nC-FFI: %d FAILED\n" : "\nC-FFI: all pass\n", f);
    return f ? 1 : 0;
}
