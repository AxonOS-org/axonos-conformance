// SPDX-License-Identifier: Apache-2.0 OR MIT
// Part of the AxonOS project - https://github.com/AxonOS-org
// RFC-0006 IntentObservation wire codec (32-byte little-endian). Byte-for-byte
// equivalent to axonos-sdk; verified against the reference vectors in CI.
// Run directly:  java AxonosRfc0006.java
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HexFormat;

public final class AxonosRfc0006 {
    public static final int OBSERVATION_SIZE = 32;
    public static final int Q016_ONE = 65535;
    public static final int KIND_DIRECTION = 1, KIND_LOAD = 2, KIND_QUALITY = 3;

    public static int qualityFromFloat(double c) {
        if (c <= 0) return 0;
        if (c >= 1) return Q016_ONE;
        return (int) Math.round(c * Q016_ONE); // round, not truncate
    }
    public static double qualityToFloat(int raw) { return raw / (double) Q016_ONE; }

    public static byte[] encode(int kindTag, int discriminant, int qualityRaw,
                                long timestampUs, long sessionId, byte[] attestation) {
        if (attestation.length != 8) throw new IllegalArgumentException("attestation must be 8 bytes");
        int qraw = (kindTag == KIND_QUALITY) ? Q016_ONE : qualityRaw; // Quality forces u16::MAX
        if (qraw < 0 || qraw > Q016_ONE) throw new IllegalArgumentException("quality_raw out of Q0.16 range");
        ByteBuffer b = ByteBuffer.allocate(OBSERVATION_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        b.putLong(timestampUs);
        b.putShort((short) kindTag);
        b.putShort((short) qraw);
        byte[] payload = new byte[4];
        payload[0] = (byte) discriminant;        // payload[1..3] stay zero
        b.put(payload);
        b.putLong(sessionId);
        b.put(attestation);
        return b.array();
    }

    public record Observation(long timestampUs, int kindTag, int qualityRaw,
                              int discriminant, long sessionId, byte[] attestation) {}

    public static Observation decode(byte[] buf) {
        if (buf.length != OBSERVATION_SIZE) throw new IllegalArgumentException("observation must be 32 bytes");
        ByteBuffer b = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN);
        long ts = b.getLong();
        int kindTag = b.getShort() & 0xFFFF;
        int qraw = b.getShort() & 0xFFFF;
        byte[] payload = new byte[4]; b.get(payload);
        long sid = b.getLong();
        byte[] att = new byte[8]; b.get(att);
        return new Observation(ts, kindTag, qraw, payload[0] & 0xFF, sid, att);
    }

    public static void main(String[] args) {
        long SID = 0x0102030405060708L;
        byte[] ATT = {(byte)0xa0,(byte)0xa1,(byte)0xa2,(byte)0xa3,(byte)0xa4,(byte)0xa5,(byte)0xa6,(byte)0xa7};
        HexFormat hex = HexFormat.of();
        record T(String id, byte[] bytes, String exp) {}
        T[] tests = {
            new T("dir_up",           encode(1, 0, 65535, 1000, SID, ATT), "e8030000000000000100ffff000000000807060504030201a0a1a2a3a4a5a6a7"),
            new T("load_high",        encode(2, 2, 32768, 2000, SID, ATT), "d00700000000000002000080020000000807060504030201a0a1a2a3a4a5a6a7"),
            new T("quality_high",     encode(3, 0, 0,     3000, SID, ATT), "b80b0000000000000300ffff000000000807060504030201a0a1a2a3a4a5a6a7"),
            new T("quality_nosignal", encode(3, 3, 0,     3000, SID, ATT), "b80b0000000000000300ffff030000000807060504030201a0a1a2a3a4a5a6a7"),
            new T("q016_round_093",   encode(1, 0, qualityFromFloat(0.93), 1000, SID, ATT), "e803000000000000010014ee000000000807060504030201a0a1a2a3a4a5a6a7"),
        };
        int fails = 0;
        for (T t : tests) {
            String got = hex.formatHex(t.bytes());
            if (!got.equals(t.exp())) { fails++; System.out.println("  [FAIL] " + t.id() + "\n    want " + t.exp() + "\n    got  " + got); }
            else System.out.println("  [PASS] " + t.id());
            Observation o = decode(t.bytes());
            byte[] re = encode(o.kindTag(), o.discriminant(), o.qualityRaw(), o.timestampUs(), o.sessionId(), o.attestation());
            if (!hex.formatHex(re).equals(t.exp())) { fails++; System.out.println("  [FAIL] " + t.id() + ": round-trip"); }
        }
        if (qualityFromFloat(0.93) != 60948) { fails++; System.out.println("  [FAIL] q016 round"); }
        else System.out.println("  [PASS] q016_round (0.93 -> 60948)");
        System.out.println(fails > 0 ? "\nJAVA CONFORMANCE: " + fails + " FAILED" : "\nJAVA CONFORMANCE: all pass");
        if (fails > 0) System.exit(1);
    }
}
