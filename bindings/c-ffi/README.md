# C-ABI FFI — RFC-0006 codec

A stable, dependency-free C ABI that other languages bind against (Python
ctypes, Rust, Go, …). Byte-identical to the reference vectors; checked in CI
from **C** and from **Python/ctypes** against the same shared library.

```sh
make            # builds libaxonos_rfc0006.so and runs the C + Python tests
```

ABI: see [`axonos_rfc0006.h`](axonos_rfc0006.h). `kind_tag` `1=Direction, 2=Load,
3=Quality`; the discriminant goes in `payload[0]`; `Quality` forces the quality
field to `0xFFFF`; `axonos_q016_from_float` rounds confidence to Q0.16.
