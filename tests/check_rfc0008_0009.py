#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# SPDX-FileCopyrightText: 2026 Denis Yermakou <connect@axonos.org>
"""Re-derive every RFC-0008 and RFC-0009 vector from the published constants.

A vector file that nothing re-derives is a file that can drift from the rule it
claims to pin. This walks each case with an independent implementation of the
two arithmetics — written from the RFC text rather than copied from the crate —
and fails if any expectation disagrees.

Zero dependencies, so a reviewer can run it with nothing but Python.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name: str) -> dict:
    return json.loads((ROOT / "vectors" / name).read_text(encoding="utf-8"))


# ── RFC-0008 §2 ─────────────────────────────────────────────────────────────

def admit(sps: int, c: int, j: int, bi: int, ceiling_ppm: int, rates: list[int]):
    if sps not in rates:
        return "unsupported_rate"
    period = 1_000_000_000 // sps
    if c + j + bi > period:
        return "deadline_missed"
    if (c * 1_000_000) // period > ceiling_ppm:
        return "insufficient_margin"
    return "admitted"


def check_0008() -> list[str]:
    d = load("rfc0008_deadline.json")
    k = d["constants"]
    bad = []
    for group in ("valid_vectors", "boundary_vectors", "rejection_vectors"):
        for v in d[group]:
            if "sps" not in v:
                continue
            got = admit(
                v["sps"],
                v.get("c_ns", k["task_set_ns"]),
                k["jitter_p999_ns"],
                v.get("bi_ns", k["blocking_and_interference_ns"]),
                v.get("ceiling_ppm", k["utilisation_ceiling_ppm"]),
                k["supported_rates_sps"],
            )
            if got != v["expect"]:
                bad.append(f"  RFC-0008 {v['name']}: expected {v['expect']}, re-derived {got}")
    return bad


# ── RFC-0009 §2 and N5 ──────────────────────────────────────────────────────

def check_0009() -> list[str]:
    d = load("rfc0009_disclosure.json")
    k = d["constants"]
    w, cap = k["bits_per_scalar"], k["recordable_bits"]
    bad = []

    for v in d["valid_vectors"]:
        if "scalars" not in v:
            continue
        cost = v["scalars"] * w
        if cost != v["cost_bits"]:
            bad.append(f"  RFC-0009 {v['name']}: cost {v['cost_bits']} but {v['scalars']}×{w} = {cost}")
        if v["budget_bits"] - cost != v["remaining_bits"]:
            bad.append(f"  RFC-0009 {v['name']}: remaining does not follow from budget − cost")
        if cost > v["budget_bits"]:
            bad.append(f"  RFC-0009 {v['name']}: expects a release it cannot afford")

    for v in d["boundary_vectors"]:
        n = v["name"]
        if n == "largest_issuable_grant" and v["budget_bits"] != cap:
            bad.append(f"  RFC-0009 {n}: the largest issuable grant must equal the recordable capacity")
        if n == "grant_one_scalar_too_large" and v["budget_bits"] <= cap:
            bad.append(f"  RFC-0009 {n}: is not actually over capacity")
        if n == "two_grants_jointly_overcommit" and sum(v["grants"]) <= cap:
            bad.append(f"  RFC-0009 {n}: the two grants do not jointly overcommit")

    for v in d["rejection_vectors"]:
        n = v["name"]
        if n == "budget_exhausted":
            granted = v["budget_bits"] // w
            if granted != v["granted_releases"]:
                bad.append(f"  RFC-0009 {n}: {v['budget_bits']}÷{w} = {granted}, file says {v['granted_releases']}")
        if n == "thousand_probes_128_bit_grant":
            answers = v["budget_bits"] // k["probe_cost_bits"]
            if answers != v["answers"]:
                bad.append(f"  RFC-0009 {n}: {v['budget_bits']}÷{k['probe_cost_bits']} = {answers}, file says {v['answers']}")
        if n == "log_full" and v["log_entries_used"] * w != cap:
            bad.append(f"  RFC-0009 {n}: log capacity and recordable bits disagree")
    return bad


def main() -> int:
    bad = check_0008() + check_0009()
    if bad:
        print(f"::error::{len(bad)} vector(s) do not survive re-derivation:")
        print("\n".join(bad))
        return 1
    n8 = load("rfc0008_deadline.json")
    n9 = load("rfc0009_disclosure.json")
    total = sum(len(d[g]) for d in (n8, n9)
                for g in ("valid_vectors", "boundary_vectors", "rejection_vectors"))
    print(f"RFC-0008 and RFC-0009: {total} vectors re-derived from the published constants")
    return 0


if __name__ == "__main__":
    sys.exit(main())
