// SPDX-License-Identifier: Apache-2.0 OR MIT
const A = require('./axonos_rfc0006.js');
const SID = 0x0102030405060708n;
const ATT = [0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7];
const fixtures = {
  dir_up:           A.encode({ kind:'direction', value:'Up',       confidenceRaw:65535, timestampUs:1000n, sessionId:SID, attestation:ATT }),
  load_high:        A.encode({ kind:'load',      value:'High',     confidenceRaw:32768, timestampUs:2000n, sessionId:SID, attestation:ATT }),
  quality_high:     A.encode({ kind:'quality',   value:'High',     confidenceRaw:0,     timestampUs:3000n, sessionId:SID, attestation:ATT }),
  quality_nosignal: A.encode({ kind:'quality',   value:'NoSignal', confidenceRaw:0,     timestampUs:3000n, sessionId:SID, attestation:ATT }),
  q016_round_093:   A.encode({ kind:'direction', value:'Up',       confidenceRaw:A.qualityFromFloat(0.93), timestampUs:1000n, sessionId:SID, attestation:ATT }),
};
const expected = {
  dir_up:           'e8030000000000000100ffff000000000807060504030201a0a1a2a3a4a5a6a7',
  load_high:        'd00700000000000002000080020000000807060504030201a0a1a2a3a4a5a6a7',
  quality_high:     'b80b0000000000000300ffff000000000807060504030201a0a1a2a3a4a5a6a7',
  quality_nosignal: 'b80b0000000000000300ffff030000000807060504030201a0a1a2a3a4a5a6a7',
  q016_round_093:   'e803000000000000010014ee000000000807060504030201a0a1a2a3a4a5a6a7',
};
let fails = 0;
for (const k of Object.keys(expected)) {
  const got = A.toHex(fixtures[k]);
  if (got !== expected[k]) { fails++; console.log(`  [FAIL] ${k}\n    want ${expected[k]}\n    got  ${got}`); }
  else { console.log(`  [PASS] ${k}`); }
  // round-trip
  const d = A.decode(fixtures[k]);
  if (A.toHex(A.encode({ kind:d.kind, value:d.value ?? d.discriminant, confidenceRaw:d.qualityRaw, timestampUs:d.timestampUs, sessionId:d.sessionId, attestation:d.attestation })) !== expected[k]) {
    fails++; console.log(`  [FAIL] ${k}: round-trip`);
  }
}
if (A.qualityFromFloat(0.93) !== 60948) { fails++; console.log(`  [FAIL] q016 round: ${A.qualityFromFloat(0.93)} != 60948`); }
else console.log('  [PASS] q016_round (0.93 -> 60948)');
console.log(fails ? `\nJS CONFORMANCE: ${fails} FAILED` : '\nJS CONFORMANCE: all pass');
process.exit(fails ? 1 : 0);
