/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Part of the AxonOS project - https://github.com/AxonOS-org
 *
 * RFC-0006 - IntentObservation wire format (C FFI reference header).
 *
 * The 32-byte, 8-byte-aligned, little-endian record exchanged at the kernel
 * boundary. This header is byte-for-byte equivalent to the Rust axonos-sdk and
 * is checked against the reference vectors in CI.
 *
 *   offset  size  field
 *   ------  ----  -----------------------------------------------
 *      0      8    timestamp_us  (u64)
 *      8      2    kind_tag      (u16)  1=Direction, 2=Load, 3=Quality
 *     10      2    quality_raw   (u16)  Q0.16 confidence (0..65535)
 *     12      4    payload       (u8[4]) payload[0] = kind discriminant
 *     16      8    session_id    (u64)
 *     24      8    attestation   (u8[8]) truncated HMAC
 *
 * Note on strict decoding: this header validates length and layout. Whether a
 * decoder must reject an unknown kind_tag or a non-canonical discriminant is
 * governed by the RFC-0006 normative text, not by this header; helpers are
 * provided but no policy is silently imposed.
 */
#ifndef AXONOS_RFC0006_H
#define AXONOS_RFC0006_H

#include <stdint.h>
#include <stddef.h>

#define AXONOS_OBSERVATION_SIZE   32
#define AXONOS_OBSERVATION_ALIGN  8
#define AXONOS_Q016_ONE           65535u

typedef enum {
    AXONOS_KIND_DIRECTION = 1,
    AXONOS_KIND_LOAD      = 2,
    AXONOS_KIND_QUALITY   = 3
} axonos_kind_t;

/* payload[0] discriminants */
typedef enum { AXONOS_DIR_UP = 0, AXONOS_DIR_RIGHT = 1, AXONOS_DIR_DOWN = 2,
               AXONOS_DIR_LEFT = 3, AXONOS_DIR_NEUTRAL = 4 } axonos_direction_t;
typedef enum { AXONOS_LOAD_LOW = 0, AXONOS_LOAD_MODERATE = 1, AXONOS_LOAD_HIGH = 2 } axonos_load_t;
typedef enum { AXONOS_QUALITY_HIGH = 0, AXONOS_QUALITY_MODERATE = 1,
               AXONOS_QUALITY_LOW = 2, AXONOS_QUALITY_NOSIGNAL = 3 } axonos_quality_t;

typedef struct {
    uint64_t timestamp_us;    /* offset 0  */
    uint16_t kind_tag;        /* offset 8  */
    uint16_t quality_raw;     /* offset 10 */
    uint8_t  payload[4];      /* offset 12 */
    uint64_t session_id;      /* offset 16 */
    uint8_t  attestation[8];  /* offset 24 */
} axonos_observation_t;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(axonos_observation_t) == AXONOS_OBSERVATION_SIZE,
               "IntentObservation must be exactly 32 bytes");
_Static_assert(_Alignof(axonos_observation_t) == AXONOS_OBSERVATION_ALIGN,
               "IntentObservation must be 8-byte aligned");
_Static_assert(offsetof(axonos_observation_t, timestamp_us) == 0,  "timestamp_us @ 0");
_Static_assert(offsetof(axonos_observation_t, kind_tag)     == 8,  "kind_tag @ 8");
_Static_assert(offsetof(axonos_observation_t, quality_raw)  == 10, "quality_raw @ 10");
_Static_assert(offsetof(axonos_observation_t, payload)      == 12, "payload @ 12");
_Static_assert(offsetof(axonos_observation_t, session_id)   == 16, "session_id @ 16");
_Static_assert(offsetof(axonos_observation_t, attestation)  == 24, "attestation @ 24");
#endif

/* Encode to a 32-byte little-endian buffer (endian-independent). Returns 0 on success. */
static inline int axonos_observation_encode(const axonos_observation_t *obs,
                                            uint8_t out[AXONOS_OBSERVATION_SIZE]) {
    int i;
    if (!obs || !out) return -1;
    for (i = 0; i < 8; i++) out[i]      = (uint8_t)(obs->timestamp_us >> (8 * i));
    out[8]  = (uint8_t)(obs->kind_tag & 0xFF);
    out[9]  = (uint8_t)(obs->kind_tag >> 8);
    out[10] = (uint8_t)(obs->quality_raw & 0xFF);
    out[11] = (uint8_t)(obs->quality_raw >> 8);
    for (i = 0; i < 4; i++) out[12 + i] = obs->payload[i];
    for (i = 0; i < 8; i++) out[16 + i] = (uint8_t)(obs->session_id >> (8 * i));
    for (i = 0; i < 8; i++) out[24 + i] = obs->attestation[i];
    return 0;
}

/* Decode from a 32-byte little-endian buffer (endian-independent). Returns 0 on success. */
static inline int axonos_observation_decode(const uint8_t in[AXONOS_OBSERVATION_SIZE],
                                            axonos_observation_t *out) {
    int i;
    if (!in || !out) return -1;
    out->timestamp_us = 0; out->session_id = 0;
    for (i = 0; i < 8; i++) out->timestamp_us |= (uint64_t)in[i]      << (8 * i);
    out->kind_tag    = (uint16_t)(in[8]  | ((uint16_t)in[9]  << 8));
    out->quality_raw = (uint16_t)(in[10] | ((uint16_t)in[11] << 8));
    for (i = 0; i < 4; i++) out->payload[i] = in[12 + i];
    for (i = 0; i < 8; i++) out->session_id |= (uint64_t)in[16 + i] << (8 * i);
    for (i = 0; i < 8; i++) out->attestation[i] = in[24 + i];
    return 0;
}

/* Q0.16 helpers. from_float ROUNDS to nearest (matches the SDK), not truncate. */
static inline float    axonos_quality_to_float(uint16_t raw) { return (float)raw / 65535.0f; }
static inline uint16_t axonos_quality_from_float(float c) {
    if (c <= 0.0f) return 0;
    if (c >= 1.0f) return AXONOS_Q016_ONE;
    return (uint16_t)(c * 65535.0f + 0.5f);  /* round, not truncate */
}

static inline int axonos_kind_is_known(uint16_t kind_tag) {
    return kind_tag == AXONOS_KIND_DIRECTION || kind_tag == AXONOS_KIND_LOAD
        || kind_tag == AXONOS_KIND_QUALITY;
}

#endif /* AXONOS_RFC0006_H */
