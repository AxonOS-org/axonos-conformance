# x86-64 assembly — RFC-0006 encoder

The RFC-0006 serialization in hand-written x86-64 assembly (System V AMD64 ABI,
GNU `as` syntax). The 32-byte little-endian layout maps directly to native
stores; `Quality` forces `0xFFFF` with a conditional move. Verified byte-identical
to the reference vectors, and cross-checked against the C implementation on
200,000 random inputs.

```sh
make            # assembles, links the C harness, runs byte-parity + cross-check
```
