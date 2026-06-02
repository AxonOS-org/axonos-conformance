#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Part of the AxonOS project - https://github.com/AxonOS-org
"""AxonOS protocol conformance validator (RFC-0006 + RFC-0005).

Self-contained, zero-dependency reference implementation and validator for the
two on-wire formats AxonOS exposes at the kernel boundary:

  * **RFC-0006** - the 32-byte ``IntentObservation`` wire record.
  * **RFC-0005** - the ``u32`` capability-manifest bitfield.

The codecs below are byte-for-byte equivalents of the Rust ``axonos-sdk`` (and
its ``axonos-sdk-python`` port) and are checked against it in CI.

    python validator.py                  # validate the bundled vectors/ (CI entry-point)
    python validator.py --validate DIR   # validate the vector files in DIR
    python validator.py --emit DIR       # (re)generate the canonical vector files

Scope note: this validator is authoritative for the byte layout, field
encoding, round-trip identity, size rejection, and value-range rejection.
"Strict rejection" of an unknown kind discriminant or non-zero reserved bytes
is governed by the RFC normative text; such cases are labelled and not
silently asserted here.
"""
from __future__ import annotations
import argparse
import json
import os
import struct
import sys

# ===========================================================================
# RFC-0006 - IntentObservation (32 bytes, little-endian, repr(C, align(8)))
#   0  8  timestamp_us (u64)
#   8  2  kind_tag     (u16)  1=Direction, 2=Load, 3=Quality
#  10  2  quality_raw  (u16)  Q0.16 confidence
#  12  4  payload      ([u8;4]) payload[0] = kind discriminant
#  16  8  session_id   (u64)
#  24  8  attestation  ([u8;8])
# ===========================================================================
OBSERVATION_SIZE = 32
_WIRE_OBS = "<QHH4sQ8s"
assert struct.calcsize(_WIRE_OBS) == OBSERVATION_SIZE
Q016_ONE = 65535
KIND = {"direction": 1, "load": 2, "quality": 3}
KIND_NAME = {v: k for k, v in KIND.items()}
DISCRIMINANT = {
    "direction": {"Up": 0, "Right": 1, "Down": 2, "Left": 3, "Neutral": 4},
    "load": {"Low": 0, "Moderate": 1, "High": 2},
    "quality": {"High": 0, "Moderate": 1, "Low": 2, "NoSignal": 3},
}


def q016_to_raw(value: float) -> int:
    if value <= 0.0:
        return 0
    if value >= 1.0:
        return Q016_ONE
    return round(value * Q016_ONE)


def obs_encode(kind, value, confidence_raw, timestamp_us, session_id, attestation):
    if kind not in KIND:
        raise ValueError(f"unknown kind {kind!r}")
    disc = DISCRIMINANT[kind][value] if isinstance(value, str) else int(value)
    if not 0 <= disc <= 0xFF:
        raise ValueError("discriminant out of byte range")
    qraw = Q016_ONE if kind == "quality" else int(confidence_raw)  # Quality forces u16::MAX
    if not 0 <= qraw <= Q016_ONE:
        raise ValueError(f"quality_raw out of Q0.16 range [0,{Q016_ONE}]")
    if not 0 <= timestamp_us <= (1 << 64) - 1:
        raise ValueError("timestamp_us out of u64 range")
    if not 0 <= session_id <= (1 << 64) - 1:
        raise ValueError("session_id out of u64 range")
    attestation = bytes(attestation)
    if len(attestation) != 8:
        raise ValueError("attestation must be 8 bytes")
    return struct.pack(_WIRE_OBS, timestamp_us, KIND[kind], qraw,
                       bytes([disc, 0, 0, 0]), session_id, attestation)


def obs_decode(data: bytes) -> dict:
    if len(data) != OBSERVATION_SIZE:
        raise ValueError(f"observation must be {OBSERVATION_SIZE} bytes, got {len(data)}")
    ts, kind_tag, qraw, payload, session_id, attest = struct.unpack(_WIRE_OBS, data)
    kind = KIND_NAME.get(kind_tag, "unknown")
    value = None
    if kind != "unknown":
        value = {v: k for k, v in DISCRIMINANT[kind].items()}.get(payload[0])
    return {"timestamp_us": ts, "kind_tag": kind_tag, "kind": kind, "value": value,
            "discriminant": payload[0], "quality_raw": qraw,
            "reserved": list(payload[1:]), "session_id": session_id,
            "attestation": attest.hex()}


# ===========================================================================
# RFC-0005 - CapabilitySet manifest (u32 little-endian bitfield)
#   bit 0 Navigation  bit 1 WorkloadAdvisory  bit 2 SessionQuality  bit 3 ArtifactEvents
#   bits 4..31 reserved (must be zero)
# ===========================================================================
CAP_BIT = {"Navigation": 1 << 0, "WorkloadAdvisory": 1 << 1,
           "SessionQuality": 1 << 2, "ArtifactEvents": 1 << 3}
CAP_VALID_MASK = 0xF


def cap_encode(capabilities) -> bytes:
    bits = 0
    for c in capabilities:
        if c not in CAP_BIT:
            raise ValueError(f"unknown capability {c!r}")
        bits |= CAP_BIT[c]
    return struct.pack("<I", bits)


def cap_decode(data: bytes):
    if len(data) != 4:
        raise ValueError(f"manifest wire length must be 4, got {len(data)}")
    (bits,) = struct.unpack("<I", data)
    has_reserved = (bits & ~CAP_VALID_MASK) != 0
    caps = [n for n, b in CAP_BIT.items() if bits & b]
    return {"raw": bits, "capabilities": caps, "has_reserved_bits": has_reserved}


def manifest_is_valid(bits: int) -> bool:
    """RFC-0005: a manifest setting any reserved bit (4..31) is rejected."""
    return (bits & ~CAP_VALID_MASK) == 0


# ===========================================================================
# Canonical vectors
# ===========================================================================
_A = "a0a1a2a3a4a5a6a7"
_SID = 0x0102030405060708


def _ev(vid, desc, kind, value, conf, ts, sid, att, note=None):
    d = {"id": vid, "desc": desc,
         "input": {"kind": kind, "value": value, "confidence_raw": conf,
                   "timestamp_us": ts, "session_id": sid, "attestation": att},
         "expected_hex": obs_encode(kind, value, conf, ts, sid, bytes.fromhex(att)).hex()}
    if note:
        d["note"] = note
    return d


def intent_vectors():
    valid, boundary, reject = [], [], []
    for d in DISCRIMINANT["direction"]:
        valid.append(_ev(f"dir_{d.lower()}", f"Direction.{d} @ conf=1.0", "direction", d, Q016_ONE, 1000, _SID, _A))
    for ld in DISCRIMINANT["load"]:
        valid.append(_ev(f"load_{ld.lower()}", f"Load.{ld} @ conf=0.5", "load", ld, q016_to_raw(0.5), 2000, _SID, _A))
    for q in DISCRIMINANT["quality"]:
        valid.append(_ev(f"quality_{q.lower()}", f"Quality.{q} (confidence forced to u16::MAX)",
                         "quality", q, 0, 3000, _SID, _A, "quality_raw must be 65535 regardless of input"))
    for label, raw in [("q016_zero", 0), ("q016_lsb", 1), ("q016_half", 32768),
                       ("q016_max", Q016_ONE), ("q016_round_093", q016_to_raw(0.93))]:
        boundary.append(_ev(label, f"Direction.Up @ quality_raw={raw}", "direction", "Up", raw, 1000, _SID, _A))
    boundary.append(_ev("ts_zero", "timestamp_us = 0", "direction", "Up", Q016_ONE, 0, _SID, _A))
    boundary.append(_ev("ts_u64max", "timestamp_us = u64::MAX (full 64-bit, no 2^48 bound)",
                        "direction", "Up", Q016_ONE, (1 << 64) - 1, _SID, _A))
    boundary.append(_ev("session_u64max", "session_id = u64::MAX", "load", "High", q016_to_raw(0.71), 4000, (1 << 64) - 1, _A))

    good = obs_encode("direction", "Up", Q016_ONE, 1000, _SID, bytes.fromhex(_A))
    reject.append({"id": "len_31", "desc": "31-byte record rejected", "class": "size",
                   "authority": "normative", "wire_hex": good[:31].hex(), "reason": "length 31 != 32"})
    reject.append({"id": "len_33", "desc": "33-byte record rejected", "class": "size",
                   "authority": "normative", "wire_hex": (good + b"\x00").hex(), "reason": "length 33 != 32"})
    reject.append({"id": "q016_overflow", "desc": "quality_raw = 65536 out of Q0.16 range", "class": "range",
                   "authority": "normative", "reason": "Q0.16 raw must be <= 65535"})
    # spec-dependent (governed by RFC-0006 normative text, not by this implementation)
    unk = struct.pack(_WIRE_OBS, 1000, 0x00FF, Q016_ONE, bytes(4), _SID, bytes.fromhex(_A)).hex()
    nz = struct.pack(_WIRE_OBS, 1000, 1, Q016_ONE, bytes([0, 9, 9, 9]), _SID, bytes.fromhex(_A)).hex()
    reject.append({"id": "strict_unknown_kind", "desc": "kind_tag=0x00FF",
                   "class": "strict_optional", "authority": "rfc_normative", "wire_hex": unk,
                   "note": "this reference decodes kind=unknown; reject only if RFC-0006 mandates strict"})
    reject.append({"id": "strict_nonzero_reserved", "desc": "reserved payload bytes != 0",
                   "class": "strict_optional", "authority": "rfc_normative", "wire_hex": nz,
                   "note": "this reference ignores reserved bytes; reject only if RFC-0006 mandates strict"})
    return {"rfc": "RFC-0006", "title": "IntentObservation wire format", "abi_version": 1,
            "observation_size": OBSERVATION_SIZE, "wire": _WIRE_OBS,
            "provenance": "byte-for-byte equivalent of axonos-sdk; verified in CI",
            "valid_vectors": valid, "boundary_vectors": boundary, "rejection_vectors": reject}


def capability_vectors():
    valid, reject = [], []

    def cv(vid, caps, desc):
        return {"id": vid, "desc": desc, "input": {"capabilities": caps},
                "expected_hex": cap_encode(caps).hex(),
                "expected": {"raw": int.from_bytes(cap_encode(caps), "little"), "valid": True}}

    valid.append(cv("empty", [], "Empty manifest"))
    for c in CAP_BIT:
        valid.append(cv(f"single_{c.lower()}", [c], f"Singleton: {c}"))
    valid.append(cv("nav_quality", ["Navigation", "SessionQuality"], "Navigation + SessionQuality"))
    valid.append(cv("all", list(CAP_BIT), "Full catalogue (all four)"))

    for vid, bits, desc in [("reserved_bit4", 0x10, "reserved bit 4 set"),
                            ("reserved_bit7", 0x80, "reserved bit 7 set"),
                            ("reserved_high", 0xFFFFFFF0, "all reserved bits set")]:
        reject.append({"id": vid, "desc": desc, "class": "reserved_bits", "authority": "normative",
                       "wire_hex": struct.pack("<I", bits).hex(), "reason": "reserved bits (4..31) must be zero"})
    reject.append({"id": "len_3", "desc": "3-byte manifest rejected", "class": "size",
                   "authority": "normative", "wire_hex": "000000", "reason": "length 3 != 4"})
    return {"rfc": "RFC-0005", "title": "Capability manifest bitfield", "wire": "<I",
            "valid_mask": CAP_VALID_MASK, "bits": {"Navigation": 0, "WorkloadAdvisory": 1, "SessionQuality": 2, "ArtifactEvents": 3},
            "provenance": "byte-for-byte equivalent of axonos-sdk; verified in CI",
            "valid_vectors": valid, "rejection_vectors": reject}


# ===========================================================================
# Validation
# ===========================================================================
def _validate_intent(doc) -> tuple[int, int]:
    ok = bad = 0
    for vec in doc.get("valid_vectors", []) + doc.get("boundary_vectors", []):
        i = vec["input"]
        got = obs_encode(i["kind"], i["value"], i["confidence_raw"], i["timestamp_us"],
                         i["session_id"], bytes.fromhex(i["attestation"])).hex()
        if got != vec["expected_hex"]:
            bad += 1; print(f"    [FAIL] {vec['id']}: encode mismatch\n       want {vec['expected_hex']}\n       got  {got}"); continue
        d = obs_decode(bytes.fromhex(vec["expected_hex"]))
        re = obs_encode(d["kind"], d["value"] if d["value"] is not None else d["discriminant"],
                        d["quality_raw"], d["timestamp_us"], d["session_id"], bytes.fromhex(d["attestation"])).hex()
        if re != vec["expected_hex"]:
            bad += 1; print(f"    [FAIL] {vec['id']}: round-trip mismatch"); continue
        ok += 1
    for r in doc.get("rejection_vectors", []):
        if r.get("authority") != "normative":
            continue
        try:
            if r["class"] == "size":
                obs_decode(bytes.fromhex(r["wire_hex"])); bad += 1; print(f"    [FAIL] {r['id']}: not rejected")
            elif r["class"] == "range":
                obs_encode("direction", "Up", 65536, 0, 0, bytes(8)); bad += 1; print(f"    [FAIL] {r['id']}: not rejected")
            else:
                ok += 1
        except ValueError:
            ok += 1
    return ok, bad


def _validate_capability(doc) -> tuple[int, int]:
    ok = bad = 0
    for vec in doc.get("valid_vectors", []):
        caps = vec["input"]["capabilities"]
        got = cap_encode(caps).hex()
        if got != vec["expected_hex"]:
            bad += 1; print(f"    [FAIL] {vec['id']}: encode mismatch"); continue
        dec = cap_decode(bytes.fromhex(vec["expected_hex"]))
        if dec["has_reserved_bits"] or sorted(dec["capabilities"]) != sorted(caps):
            bad += 1; print(f"    [FAIL] {vec['id']}: decode mismatch"); continue
        ok += 1
    for r in doc.get("rejection_vectors", []):
        bits = int.from_bytes(bytes.fromhex(r["wire_hex"]), "little") if "wire_hex" in r else None
        if r["class"] == "reserved_bits":
            (ok := ok + 1) if not manifest_is_valid(bits) else (print(f"    [FAIL] {r['id']}: reserved not caught"))
            if manifest_is_valid(bits): bad += 1
        elif r["class"] == "size":
            try:
                cap_decode(bytes.fromhex(r["wire_hex"])); bad += 1; print(f"    [FAIL] {r['id']}: bad length not rejected")
            except ValueError:
                ok += 1
    return ok, bad


def validate_dir(d: str) -> int:
    total_ok = total_bad = 0
    for fname, validate in [("rfc0006_intent.json", _validate_intent),
                            ("rfc0005_capability.json", _validate_capability)]:
        path = os.path.join(d, fname)
        if not os.path.exists(path):
            print(f"  [MISS] {fname} not found in {d}"); total_bad += 1; continue
        doc = json.load(open(path))
        print(f"  {doc['rfc']} - {doc['title']}")
        ok, bad = validate(doc)
        print(f"    {ok} checks passed, {bad} failed")
        total_ok += ok; total_bad += bad
    print(f"\n  TOTAL: {total_ok} passed, {total_bad} failed")
    return 1 if total_bad else 0


def emit_dir(d: str) -> None:
    os.makedirs(d, exist_ok=True)
    json.dump(intent_vectors(), open(os.path.join(d, "rfc0006_intent.json"), "w"), indent=2)
    json.dump(capability_vectors(), open(os.path.join(d, "rfc0005_capability.json"), "w"), indent=2)
    print(f"  wrote rfc0006_intent.json + rfc0005_capability.json to {d}/")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="AxonOS RFC-0006 / RFC-0005 conformance validator")
    ap.add_argument("--validate", metavar="DIR", help="validate vector files in DIR")
    ap.add_argument("--emit", metavar="DIR", help="regenerate canonical vector files into DIR")
    args = ap.parse_args()
    if args.emit:
        emit_dir(args.emit); sys.exit(0)
    target = args.validate or os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")
    print(f"Validating AxonOS conformance vectors in {target}/\n")
    sys.exit(validate_dir(target))
