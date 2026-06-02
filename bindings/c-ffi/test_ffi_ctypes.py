# SPDX-License-Identifier: Apache-2.0 OR MIT
# Proves the C-ABI FFI surface from another language: Python loads the shared
# library via ctypes and gets byte-identical observations.
import ctypes, os, sys
lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__) or ".", "libaxonos_rfc0006.so"))
u8p = ctypes.POINTER(ctypes.c_uint8)
lib.axonos_rfc0006_encode.restype = ctypes.c_int
lib.axonos_rfc0006_encode.argtypes = [ctypes.c_uint16, ctypes.c_uint8, ctypes.c_uint16,
                                      ctypes.c_uint64, ctypes.c_uint64, u8p, u8p]
lib.axonos_q016_from_float.restype = ctypes.c_uint16
lib.axonos_q016_from_float.argtypes = [ctypes.c_double]
ATT = (ctypes.c_uint8 * 8)(0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7)
SID = 0x0102030405060708
def enc(kind, disc, q, ts):
    out = (ctypes.c_uint8 * 32)()
    r = lib.axonos_rfc0006_encode(kind, disc, q, ts, SID,
                                  ctypes.cast(ATT, u8p), ctypes.cast(out, u8p))
    assert r == 0, f"encode rc={r}"
    return bytes(out).hex()
fix = [
    ("dir_up",           1, 0, 65535, 1000, "e8030000000000000100ffff000000000807060504030201a0a1a2a3a4a5a6a7"),
    ("load_high",        2, 2, 32768, 2000, "d00700000000000002000080020000000807060504030201a0a1a2a3a4a5a6a7"),
    ("quality_high",     3, 0, 0,     3000, "b80b0000000000000300ffff000000000807060504030201a0a1a2a3a4a5a6a7"),
    ("quality_nosignal", 3, 3, 0,     3000, "b80b0000000000000300ffff030000000807060504030201a0a1a2a3a4a5a6a7"),
    ("q016_round_093",   1, 0, lib.axonos_q016_from_float(0.93), 1000, "e803000000000000010014ee000000000807060504030201a0a1a2a3a4a5a6a7"),
]
fails = 0
for id, kind, disc, q, ts, exp in fix:
    got = enc(kind, disc, q, ts)
    if got != exp: fails += 1; print(f"  [FAIL] {id}\n    want {exp}\n    got  {got}")
    else: print(f"  [PASS] {id}")
if lib.axonos_q016_from_float(0.93) != 60948: fails += 1; print("  [FAIL] q016 round")
else: print("  [PASS] q016_round (0.93 -> 60948)")
print(f"\nPython/ctypes FFI: {'all pass' if not fails else str(fails)+' FAILED'}")
sys.exit(1 if fails else 0)
