# Reproducibility

Pins come from the architecture record. They are reproducibility pins, NOT claims of newest releases.

| Component | Pin | Where | Verified |
|---|---|---|---|
| Rust | 1.81.0 | `rust-toolchain.toml`, CI | yes: `cargo 1.81.0 (2dbb1af80 2024-08-20)` on Windows |
| Go | 1.22.6 | `services/gateway/go.mod`, CI | yes: `go1.22.6 windows/amd64` |
| fxamacker/cbor | v2.7.0 (+ x448/float16 v0.8.4) | `go.mod`, `go.sum` (committed) | yes: build, vet, tests |
| Rust crates | exact `=` pins; full tree in `Cargo.lock` (49 packages, committed) | `native/crypto-core/Cargo.toml` | yes: 13 tests |
| Python tooling | 3.9 or newer (CI uses 3.12) + `cryptography` | `tools/` | yes: Linux Python 3.12 + cryptography 46.0.6, Windows Python 3.14 + cryptography 50.0.2 |
| PostgreSQL | 16 | `services/gateway/migrations/0001_init.sql` | NO: never executed |
| Android (AGP 8.5.2, Kotlin 1.9.24, Compose BOM 2024.06.00) | skeleton | `apps/android` | NO: never built |
| iOS (Swift/SwiftUI) | skeleton | `apps/ios` | NO: never built |
| GitHub Actions workflow | `.github/workflows/test-vectors-parity.yml` | CI | NO: not pushed yet |

## Vector reproducibility
The vector files are generated, not hand-written: `py tools\gen_vectors.py` then `certutil -hashfile test-vectors\v1\manifest.json SHA256`.
The SHA-256 of `manifest.json` is `39f6a02a360705c027f5d639a7770ba4d96b130694f9b5a70696ed7f7c57fa46` on both Linux and Windows (the manifest contains the hash of every other vector file),
so the output does not depend on the OS, the Python version (3.12 / 3.14) or the `cryptography` version (46 / 50). On Linux CI: `python tools/gen_vectors.py && git diff --exit-code -- test-vectors`.

## Lockfiles (committed)
`Cargo.lock` was generated ONCE with a newer Cargo using the MSRV-aware resolver, because Cargo 1.81 cannot pick "newest version compatible with 1.81" (the first resolve chose `base64ct 1.8.3`,
which needs edition 2024). The newer toolchain was used only for resolution (stable, rustc 1.99.0 at the time); builds use the pinned 1.81.0. `Cargo.toml` declares `rust-version = "1.81"`.
Builds must use `cargo test --locked`. `unicode-normalization` is pinned `=0.1.22` because `bip39 =2.0.0` requires exactly that version.

Regenerate ONLY in a dedicated, reviewed change (see `DEPENDENCY_UPGRADE_POLICY.md`):
```
cd native\crypto-core
del Cargo.lock
rustup toolchain install stable --profile minimal
set CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback
cargo +stable generate-lockfile
set CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=
cargo test --locked
```
(Linux/macOS: `export CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback` and `unset` afterwards.) `go.sum` is maintained by `go mod tidy` in `services/gateway` in a reviewed change; CI runs `go mod verify`.
