// SPDX-License-Identifier: Apache-2.0 OR MIT
// Part of the AxonOS project - https://github.com/AxonOS-org
// RFC-0006 IntentObservation wire codec (32-byte little-endian). Byte-for-byte
// equivalent to axonos-sdk; verified against the reference vectors in CI.
'use strict';
const OBSERVATION_SIZE = 32, Q016_ONE = 65535;
const KIND = { direction: 1, load: 2, quality: 3 };
const KIND_NAME = { 1: 'direction', 2: 'load', 3: 'quality' };
const DISC = {
  direction: { Up: 0, Right: 1, Down: 2, Left: 3, Neutral: 4 },
  load: { Low: 0, Moderate: 1, High: 2 },
  quality: { High: 0, Moderate: 1, Low: 2, NoSignal: 3 },
};
function qualityFromFloat(c) { if (c <= 0) return 0; if (c >= 1) return Q016_ONE; return Math.round(c * Q016_ONE); }
function qualityToFloat(raw) { return raw / Q016_ONE; }

function encode({ kind, value, confidenceRaw = 0, timestampUs = 0n, sessionId = 0n, attestation }) {
  if (!(kind in KIND)) throw new Error(`unknown kind ${kind}`);
  const disc = typeof value === 'string' ? DISC[kind][value] : value;
  if (disc == null || disc < 0 || disc > 0xff) throw new Error('bad discriminant');
  const qraw = kind === 'quality' ? Q016_ONE : confidenceRaw; // Quality forces u16::MAX
  if (qraw < 0 || qraw > Q016_ONE) throw new Error('quality_raw out of Q0.16 range');
  if (attestation.length !== 8) throw new Error('attestation must be 8 bytes');
  const buf = new Uint8Array(OBSERVATION_SIZE), dv = new DataView(buf.buffer);
  dv.setBigUint64(0, BigInt(timestampUs), true);
  dv.setUint16(8, KIND[kind], true);
  dv.setUint16(10, qraw, true);
  buf[12] = disc & 0xff; // payload[1..3] stay zero
  dv.setBigUint64(16, BigInt(sessionId), true);
  for (let i = 0; i < 8; i++) buf[24 + i] = attestation[i];
  return buf;
}
function decode(buf) {
  if (buf.length !== OBSERVATION_SIZE) throw new Error(`observation must be ${OBSERVATION_SIZE} bytes`);
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const kindTag = dv.getUint16(8, true);
  const kind = KIND_NAME[kindTag] || 'unknown';
  const disc = buf[12];
  let value = null;
  if (kind !== 'unknown') value = Object.entries(DISC[kind]).find(([, v]) => v === disc)?.[0] ?? null;
  return {
    timestampUs: dv.getBigUint64(0, true), kindTag, kind, value, discriminant: disc,
    qualityRaw: dv.getUint16(10, true), sessionId: dv.getBigUint64(16, true),
    attestation: Array.from(buf.slice(24, 32)),
  };
}
function toHex(u8) { return Array.from(u8, b => b.toString(16).padStart(2, '0')).join(''); }
module.exports = { OBSERVATION_SIZE, Q016_ONE, KIND, DISC, encode, decode, toHex, qualityFromFloat, qualityToFloat };
