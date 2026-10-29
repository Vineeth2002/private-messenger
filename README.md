# Sovereign Private Messenger

A global private messenger engineered in India: persistent application data hosted in India, E2EE
with client-owned cryptographic state, server as delivery/control plane only.

**Status snapshot: 2026-10-24. Phase A gate: complete. Phase B: in progress.** The initial Phase A gate passed on a real Windows machine; the current `main` commit is `10c6772e8095d5c3db9a22e557aac92a64ff1a45`.
GitHub Actions on that commit passed Android build/lint/unit tests/emulator startup, Android identity-storage instrumentation, and the Rust/Go/shared-vector parity workflow. See the current [Android build run](https://github.com/Vineeth2002/private-messenger/actions/runs/40108208245), [identity run](https://github.com/Vineeth2002/private-messenger/actions/runs/40108208230), and [vector parity run](https://github.com/Vineeth2002/private-messenger/actions/runs/40108208237).

The Rust core contains PM-BI-X3DH-1 and Cert_dh verification, Double Ratchet core and reorder/replay handling, media chunk AEAD, HPKE push cryptography, Key Transparency V1 verification, and authorization primitives. The Go gateway has PostgreSQL-backed demo message delivery, device-directory reads, some transparency storage/proof services, and authorization packages. Android builds and exercises identity persistence through the Rust bridge.

**This is not yet a usable end-to-end messaging app.** Android currently presents a diagnostics/identity screen; its client does not yet complete session establishment, ratchet send/receive, network delivery, and durable ratchet-state restoration as one flow. The current HTTP surface is not a complete authenticated per-device enrollment, recovery, transparency-proof and messaging API. iOS has no checked-in Xcode project and its platform key-protection implementation remains unimplemented. Real-device two-user validation, crash/recovery testing, deployment/operations hardening, formal analysis, and an independent cryptographic audit remain open. Not for production use. Not audited.
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
