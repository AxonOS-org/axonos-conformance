<div align="center">

# AxonOS Protocol Conformance

### Executable, verified conformance vectors for the AxonOS kernel-boundary wire formats.

[![conformance](https://github.com/AxonOS-org/axonos-conformance/actions/workflows/ci.yml/badge.svg)](https://github.com/AxonOS-org/axonos-conformance/actions/workflows/ci.yml)
&nbsp;![verified](https://img.shields.io/badge/verified%20against-axonos--sdk-0d7a5f?style=flat-square)
&nbsp;![parity](https://img.shields.io/badge/Rust%20%E2%89%A1%20Python%20%E2%89%A1%20C%20%E2%89%A1%20JS%20%E2%89%A1%20Java-byte--identical-0d7a5f?style=flat-square)
&nbsp;![deps](https://img.shields.io/badge/dependencies-none-475569?style=flat-square)
&nbsp;![license](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-475569?style=flat-square)

</div>

This repository is the **ground truth** for two formats every AxonOS application
touches at the kernel boundary:

- **RFC-0006** — the 32-byte `IntentObservation` wire record.
- **RFC-0005** — the `u32` capability-manifest bitfield.

It exists so that *any* implementation — Rust, C, Python, or a third party — can
prove byte-for-byte conformance against a single, dependency-free reference. The
reference codec in [`validator.py`](validator.py) is checked byte-identical to
the Rust `axonos-sdk` on every push, and the [C header](include/axonos_rfc0006.h)
is checked byte-identical to the reference by the compiler (`_Static_assert` on
every field offset) and a round-trip test.

> Provenance matters here: these vectors are **derived from the shipping
> implementation and verified in CI**, not authored by hand. A conformance suite
> that doesn't match the real kernel is worse than none.

## Run it

```bash
# Python: validate the vectors against the reference codec (zero dependencies)
python validator.py

# C: prove the FFI layout and encoding (static_assert + byte parity + round-trip)
gcc -std=c11 -Wall -Wextra -Iinclude tests/c_roundtrip.c -o c_roundtrip && ./c_roundtrip

# Regenerate the canonical vectors from the reference (should be a no-op in CI)
python validator.py --emit vectors
```

## RFC-0006 — `IntentObservation` (32 bytes, little-endian, `repr(C, align(8))`)

| offset | size | field | notes |
|:------:|:----:|:------|:------|
| 0  | 8 | `timestamp_us` | `u64`, full range |
| 8  | 2 | `kind_tag` | `u16` — `1` Direction, `2` Load, `3` Quality |
| 10 | 2 | `quality_raw` | `u16` Q0.16 confidence; Quality records carry `u16::MAX` |
| 12 | 4 | `payload` | `payload[0]` = kind discriminant; bytes 1–3 reserved |
| 16 | 8 | `session_id` | `u64` |
| 24 | 8 | `attestation` | truncated HMAC |

Discriminants — Direction `Up=0,Right=1,Down=2,Left=3,Neutral=4`; Load
`Low=0,Moderate=1,High=2`; Quality `High=0,Moderate=1,Low=2,NoSignal=3`.

## RFC-0005 — Capability manifest (`u32` little-endian bitfield)

| bit | capability | kernel rate limit |
|:---:|:-----------|:-----------------:|
| 0 | `Navigation` | 50 Hz |
| 1 | `WorkloadAdvisory` | 1 Hz |
| 2 | `SessionQuality` | 2 Hz |
| 3 | `ArtifactEvents` | 10 Hz |

Bits 4–31 are reserved and **must be zero**; a manifest that sets any reserved
bit is rejected at construction.

## Coverage

| Suite | Valid / boundary | Rejection (normative) | Rejection (RFC-governed) |
|:------|:----------------:|:---------------------:|:------------------------:|
| RFC-0006 | 19 | 3 (size ×2, range) | 2 (strict, labelled) |
| RFC-0005 | 10 | 4 (reserved ×3, size) | — |

## Language bindings

Standalone, dependency-free RFC-0006 codecs, each checked byte-identical to the
reference vectors in CI:

| Language | File | Run |
|:---------|:-----|:----|
| C        | [`include/axonos_rfc0006.h`](include/axonos_rfc0006.h) | `gcc -std=c11 -Iinclude tests/c_roundtrip.c -o t && ./t` |
| JavaScript | [`bindings/javascript/axonos_rfc0006.js`](bindings/javascript/axonos_rfc0006.js) | `node bindings/javascript/test.js` |
| Java     | [`bindings/java/AxonosRfc0006.java`](bindings/java/AxonosRfc0006.java) | `java bindings/java/AxonosRfc0006.java` |
| Python   | [`validator.py`](validator.py) | `python validator.py` |

All use `kind_tag` `1=Direction, 2=Load, 3=Quality`, place the kind discriminant
in `payload[0]`, and **round** Q0.16 confidence (Swift and WASM bindings welcome —
open a PR with a matching byte test).

## A note on strict rejection

This reference is authoritative for **byte layout, field encoding, round-trip
identity, size rejection, and value-range rejection**. Whether a decoder must
*strictly reject* an unknown `kind_tag`, a non-canonical discriminant, or
non-zero reserved bytes is governed by the **RFC-0006 normative text** — those
cases are labelled `rfc_normative` in the vectors and are not silently asserted
here. Decode in this reference is intentionally forward-compatible.

---

<div align="center">

**The AxonOS Project** · [axonos.org](https://axonos.org) · connect@axonos.org · security@axonos.org
[github.com/AxonOS-org](https://github.com/AxonOS-org) · part of the AxonOS real-time neural OS

Licensed under Apache-2.0 OR MIT

</div>
