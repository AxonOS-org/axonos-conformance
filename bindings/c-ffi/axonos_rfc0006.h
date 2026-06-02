/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Part of the AxonOS project - https://github.com/AxonOS-org
 * RFC-0006 IntentObservation wire codec - stable C ABI (FFI surface).
 * 32-byte little-endian; byte-for-byte equivalent to axonos-sdk. Other
 * languages (Python ctypes, Rust, Go, etc.) bind against this ABI. */
#ifndef AXONOS_RFC0006_H
#define AXONOS_RFC0006_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define AXONOS_RFC0006_SIZE 32u
#define AXONOS_Q016_ONE     65535u

enum { AXONOS_KIND_DIRECTION = 1, AXONOS_KIND_LOAD = 2, AXONOS_KIND_QUALITY = 3 };
enum {
    AXONOS_OK = 0,
    AXONOS_ERR_NULL = -1,
    AXONOS_ERR_KIND = -2,
    AXONOS_ERR_QUALITY_RANGE = -3
};

/* Q0.16 helpers: saturating round of a [0,1] confidence to/from u16. */
uint16_t axonos_q016_from_float(double confidence);
double   axonos_q016_to_float(uint16_t raw);

/* Encode a 32-byte observation (little-endian). When kind_tag == Quality the
 * quality field is forced to u16::MAX regardless of quality_raw. Returns
 * AXONOS_OK or a negative AXONOS_ERR_*. */
int axonos_rfc0006_encode(uint16_t kind_tag, uint8_t discriminant, uint16_t quality_raw,
                          uint64_t timestamp_us, uint64_t session_id,
                          const uint8_t attestation[8], uint8_t out[32]);

typedef struct {
    uint64_t timestamp_us;
    uint64_t session_id;
    uint16_t kind_tag;
    uint16_t quality_raw;
    uint8_t  discriminant;
    uint8_t  attestation[8];
} axonos_rfc0006_obs;

int axonos_rfc0006_decode(const uint8_t in[32], axonos_rfc0006_obs *out);

#ifdef __cplusplus
}
#endif
#endif /* AXONOS_RFC0006_H */
