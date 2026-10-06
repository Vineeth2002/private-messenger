#!/usr/bin/env python3
"""Compare Rust and Go parity dumps: python3 tools/compare_parity.py rust.json go.json
Each file maps "positive:<id>" -> encoded hex and "negative:<id>" -> error category,
as produced by the Rust/Go vector tests when PM_PARITY_OUT is set. Any difference fails."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
rust, go = (json.load(open(p, encoding="utf-8")) for p in sys.argv[1:3])
vec = json.load(open(os.path.join(HERE, "..", "test-vectors", "v1", "cbor_canonical_codec.json"), encoding="utf-8"))
expected = {f"positive:{p['id']}": p["cbor_hex"] for p in vec["positive"]}
expected.update({f"negative:{n['id']}": n["error"] for n in vec["negative"]})
bad = []
for k in sorted(set(rust) | set(go) | set(expected)):
    r, g, e = rust.get(k), go.get(k), expected.get(k)
    if not (r == g == e):
        bad.append(f"{k}: rust={r!r} go={g!r} expected={e!r}")
if bad:
    print("PARITY FAILURE"); [print(" -", b) for b in bad]; sys.exit(1)
print(f"parity OK: {len(expected)} vectors identical across Rust, Go and the vector file")
