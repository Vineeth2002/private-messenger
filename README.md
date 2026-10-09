# Sovereign Private Messenger

A global private messenger engineered in India: persistent application data hosted in India, E2EE
with client-owned cryptographic state, server as delivery/control plane only.

**Status: Phase A is complete.** The Phase A gate was met on 2026-10-05 on a real Windows machine (Rust 1.81.0, Go 1.22.6):
both builds, both CBOR test suites, the independent Python vector checker and 101-vector Rust/Go parity all passed.
Phase B (PM-BI-X3DH-1, Double Ratchet, media AEAD, HPKE push, transparency) is **unlocked and in progress** (PM-BI-X3DH-1, the core Double Ratchet state machine, and deterministic reorder/replay vectors are implemented and verified in Rust; media, HPKE push cryptographic boundary is implemented and verified; transparency integration remains); it proceeds one
boundary at a time, each proven against `test-vectors/v1/` before the next. Not for production use. Not audited.

## Non-claims
Hosted-in-India is not "all packets stay in India". APNs/FCM are external boundaries. Ed25519/X25519
hardware execution is not universally available. Push is not authenticated content. Unit tests are not
certification. Zeroization is limited by managed runtimes. PM-BI-X3DH-1 is proprietary and not Signal-
interoperable. An independent cryptographic audit is required. See `docs/phase0/02-threat-model.md`.

## Validate

Windows + VS Code (Command Prompt), the exact commands that passed on a real machine; full guide in `docs/LOCAL_SETUP_WINDOWS.md`:
```
py -m pip install cryptography
py tools\gen_vectors.py
py tools\check_vectors.py
py tools\build_normal_linear_vectors.py
py tools\build_reorder_vectors.py
py tools\build_hpke_push_vectors.py
py tools\check_normal_vectors.py
py tools\check_reorder_vectors.py
py tools\check_hpke_push_vectors.py
cd native\crypto-core
cargo test --locked
cd ..\..\services\gateway
go test ./...
```
Linux / macOS (bash):
```bash
python3 -m pip install cryptography
python3 tools/gen_vectors.py && git diff --exit-code test-vectors   # vectors reproducible
python3 tools/check_vectors.py                                     # independent Python reference
cargo test --locked --manifest-path native/crypto-core/Cargo.toml  # Rust (1.81.0)
(cd services/gateway && go mod download && go mod verify && go test ./...)   # Go (1.22.6)
bash tools/run_all.sh                                              # everything + parity, writes build-report.txt
```
Rust/Go parity (`parity OK: 101 vectors identical across Rust, Go and the vector file`) is documented step by step in `docs/LOCAL_SETUP_WINDOWS.md`.
Gate record: `docs/PHASE_B_GATE.md`. Decisions, assumptions and the few open items: `docs/IMPLEMENTATION_NOTES.md`.
