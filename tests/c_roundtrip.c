/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Verifies the C header produces byte-identical output to the reference vectors. */
#include "axonos_rfc0006.h"
#include <stdio.h>
#include <string.h>

static int check(const char *name, axonos_observation_t *o, const char *expected) {
    uint8_t buf[AXONOS_OBSERVATION_SIZE];
    char got[2 * AXONOS_OBSERVATION_SIZE + 1];
    int i;
    axonos_observation_encode(o, buf);
    for (i = 0; i < AXONOS_OBSERVATION_SIZE; i++) sprintf(got + 2 * i, "%02x", buf[i]);
    if (strcmp(got, expected) != 0) {
        printf("  [FAIL] %s\n    expected %s\n    got      %s\n", name, expected, got);
        return 1;
    }
    /* round-trip */
    axonos_observation_t d;
    axonos_observation_decode(buf, &d);
    if (d.timestamp_us != o->timestamp_us || d.kind_tag != o->kind_tag ||
        d.quality_raw != o->quality_raw || memcmp(d.payload, o->payload, 4) != 0 ||
        d.session_id != o->session_id || memcmp(d.attestation, o->attestation, 8) != 0) {
        printf("  [FAIL] %s: round-trip mismatch\n", name);
        return 1;
    }
    printf("  [PASS] %s\n", name);
    return 0;
}

int main(void) {
    uint8_t att[8] = {0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7};
    int fails = 0;
    axonos_observation_t o;

    /* dir_up: Direction.Up @ conf=1.0 */
    memset(&o, 0, sizeof o);
    o.timestamp_us = 1000; o.kind_tag = AXONOS_KIND_DIRECTION; o.quality_raw = AXONOS_Q016_ONE;
    o.payload[0] = AXONOS_DIR_UP; o.session_id = 0x0102030405060708ULL; memcpy(o.attestation, att, 8);
    fails += check("dir_up", &o, "e8030000000000000100ffff000000000807060504030201a0a1a2a3a4a5a6a7");

    /* quality_high: Quality.High, confidence forced to MAX */
    memset(&o, 0, sizeof o);
    o.timestamp_us = 3000; o.kind_tag = AXONOS_KIND_QUALITY; o.quality_raw = AXONOS_Q016_ONE;
    o.payload[0] = AXONOS_QUALITY_HIGH; o.session_id = 0x0102030405060708ULL; memcpy(o.attestation, att, 8);
    fails += check("quality_high", &o, "b80b0000000000000300ffff000000000807060504030201a0a1a2a3a4a5a6a7");

    /* q016 rounding: from_float(0.93) must equal 60948 (round, not truncate) */
    if (axonos_quality_from_float(0.93f) != 60948) {
        printf("  [FAIL] q016_round: from_float(0.93)=%u, expected 60948\n",
               axonos_quality_from_float(0.93f));
        fails++;
    } else {
        printf("  [PASS] q016_round (0.93 -> 60948)\n");
    }

    printf(fails ? "\nC CONFORMANCE: %d FAILED\n" : "\nC CONFORMANCE: all pass\n", fails);
    return fails ? 1 : 0;
}
