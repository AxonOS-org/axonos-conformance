/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "axonos_rfc0006.h"
#include <math.h>

static void put_u16le(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v & 0xff); p[1] = (uint8_t)((v >> 8) & 0xff); }
static void put_u64le(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xff); }
static uint16_t get_u16le(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static uint64_t get_u64le(const uint8_t *p) { uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i); return v; }

uint16_t axonos_q016_from_float(double c) {
    if (c <= 0.0) return 0;
    if (c >= 1.0) return AXONOS_Q016_ONE;
    long n = lround(c * (double)AXONOS_Q016_ONE);
    if (n < 0) n = 0;
    if (n > (long)AXONOS_Q016_ONE) n = (long)AXONOS_Q016_ONE;
    return (uint16_t)n;
}
double axonos_q016_to_float(uint16_t raw) { return (double)raw / (double)AXONOS_Q016_ONE; }

int axonos_rfc0006_encode(uint16_t kind_tag, uint8_t disc, uint16_t quality_raw,
                          uint64_t ts, uint64_t session,
                          const uint8_t att[8], uint8_t out[32]) {
    if (!att || !out) return AXONOS_ERR_NULL;
    if (kind_tag < 1 || kind_tag > 3) return AXONOS_ERR_KIND;
    uint16_t q = (kind_tag == AXONOS_KIND_QUALITY) ? AXONOS_Q016_ONE : quality_raw;
    put_u64le(out + 0, ts);
    put_u16le(out + 8, kind_tag);
    put_u16le(out + 10, q);
    out[12] = disc; out[13] = 0; out[14] = 0; out[15] = 0;
    put_u64le(out + 16, session);
    for (int i = 0; i < 8; i++) out[24 + i] = att[i];
    return AXONOS_OK;
}
int axonos_rfc0006_decode(const uint8_t in[32], axonos_rfc0006_obs *o) {
    if (!in || !o) return AXONOS_ERR_NULL;
    o->timestamp_us = get_u64le(in + 0);
    o->kind_tag     = get_u16le(in + 8);
    o->quality_raw  = get_u16le(in + 10);
    o->discriminant = in[12];
    o->session_id   = get_u64le(in + 16);
    for (int i = 0; i < 8; i++) o->attestation[i] = in[24 + i];
    return AXONOS_OK;
}
