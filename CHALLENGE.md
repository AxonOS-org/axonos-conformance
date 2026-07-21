# The Independent Implementer Challenge

*A standing, open bounty: build a byte-identical RFC-0006 codec in a language this repository doesn't have one in yet.*

## Why this exists

A specification's real test isn't whether the team that wrote it can implement it — it's whether a stranger can, working from nothing but the published RFC and the public vectors, with no help from anyone at AxonOS. That's a harder, more honest bar than a changelog full of "spec compliant" claims, because it can't be self-graded: either an independently-built implementation produces byte-identical output against vectors derived from the shipping kernel, or it doesn't. CI decides, not a maintainer's opinion.

This repository already proves that bar internally, six times over: Python, C, JavaScript, Java, a C-ABI shared library, and raw x86-64 assembly all encode and decode `RFC-0006` and land byte-for-byte identical in CI on every push. What hasn't happened yet is someone *outside* the project clearing that same bar. This challenge exists to make that concrete, public, and worth doing.

## The scope

Implement an `RFC-0006` `IntentObservation` codec — encode and decode, both directions — in a language not already covered below.

**Already done** (not open — pick something else): Python (the reference), C, JavaScript, Java, C-ABI FFI, x86-64 assembly.

**Suggested next targets, in rough order of strategic interest to AxonOS:**
- **Swift** — no iOS/macOS path exists yet, and a consumer or clinical BCI companion app will eventually need one.
- **Kotlin** (JVM-native, not a JNI wrapper around the existing Java binding) — same logic, native Android path.
- **Go** — common in backend/gateway tooling; several BCI acquisition bridges in the open BCI field are written in it.
- **WASM**, as a standalone target rather than "recompile the Rust SDK" — genuinely useful for a from-scratch, dependency-free browser codec distinct from what already exists.

Any other language is fair game too. The four above are suggestions, not a restriction — the only real requirement is that the language isn't already on the list.

## What "independent" means here

Every existing binding in this repository is public. Pretending a "no-peeking" rule is enforceable, or that it's even the right test, would be dishonest — anyone finding this challenge has almost certainly seen the repo it lives in. The actual bar isn't secrecy, it's this: **the implementation has to be authored by you, from the RFC text and the byte-layout table, and its correctness is decided entirely by whether it reproduces the published vectors byte-for-byte** — not by how it was written, not by anyone's judgment call. That's a stronger test than an honor-system NDA, because it's the one CI can actually verify.

## The exact target

`RFC-0006` is a 32-byte, little-endian, 8-byte-aligned record:

| offset | size | field | notes |
|:------:|:----:|:------|:------|
| 0  | 8 | `timestamp_us` | `u64`, full range |
| 8  | 2 | `kind_tag` | `u16` — `1` Direction, `2` Load, `3` Quality |
| 10 | 2 | `quality_raw` | `u16`, Q0.16 confidence; Quality-kind records force `u16::MAX` |
| 12 | 4 | `payload` | byte 0 = kind discriminant; bytes 1–3 reserved, must be zero |
| 16 | 8 | `session_id` | `u64` |
| 24 | 8 | `attestation` | truncated HMAC, opaque 8 bytes |

Discriminants: Direction `Up=0, Right=1, Down=2, Left=3, Neutral=4`; Load `Low=0, Moderate=1, High=2`; Quality `High=0, Moderate=1, Low=2, NoSignal=3`.

24 test cases decide it: 19 valid/boundary encodings, 3 normative rejections (wrong size, out-of-range fields), and 2 RFC-governed rejections (labelled `rfc_normative` in the vectors, since decode behavior here is intentionally forward-compatible and the RFC text — not this reference — governs whether strict rejection is required). All 24 are in [`vectors/rfc0006_intent.json`](vectors/rfc0006_intent.json), already checked into this repo, in the exact format the existing six bindings are tested against.

## How to submit

Open a pull request against `axonos-conformance` containing:

1. `bindings/<language>/` — an encoder and decoder with no runtime dependencies beyond the language's own standard library, matching the pattern of any existing binding (the JavaScript one is 48 lines and the shortest — a reasonable model for scope).
2. A test that loads `vectors/rfc0006_intent.json` and asserts byte-for-byte equality, both directions, for every vector.
3. One new job added to `.github/workflows/ci.yml`, following the shape of the five that already exist, running that test on every push.

If the job goes green, the PR is conformant by definition — that's the whole point of building it this way. No separate review gate decides correctness; CI already did.

## What you get

- Your binding lands in the same table as the reference implementations, permanently, in this repository's own README — not a hall-of-fame page off to the side.
- A dedicated write-up: how you approached it, where the spec was clear, where it wasn't. Published on [medium.com/@AxonOS](https://medium.com/@AxonOS), your name on it.
- First-mover credit in `axonos-standard` and the AxonOS-org front page as the independent reference for that language — the thing future implementers in that ecosystem get pointed to.
- If AxonOS is raising or in active investor conversations when your PR lands, your binding is exactly the kind of evidence that gets shown to them, cited by name.

This is a standing bounty, not a deadline — it stays open until every reasonable language is covered. First correct, independently-authored submission for a given language gets the credit above; a second submission for a language that's already covered is still welcome as a PR, just without the "first" framing.

---

Questions about the spec, not sure if your approach counts as "independent enough," or found a gap in the RFC text while implementing — open an issue. Ambiguity you hit while implementing is itself useful signal about where the standard needs to be sharper, and it gets fixed either way.
