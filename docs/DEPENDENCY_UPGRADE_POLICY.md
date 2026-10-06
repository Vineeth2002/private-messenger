# Dependency Upgrade Policy

1. No silent upgrades of security-sensitive dependencies (crypto crates, CBOR libraries, toolchains).
   Rust crates use exact `=` versions; Go modules are pinned in `go.sum`; commit lockfiles.
2. An upgrade is its own change set: pin bump + changelog review + full vector suite (Rust, Go, Python
   reference) + parity job green. Vector files must not change as a side effect of an upgrade; if they
   must, that is an ARCHITECTURAL DECISION requiring explicit sign-off.
3. Security advisories (RustSec, Go vulnerability DB) trigger an out-of-cycle upgrade with the same gates.
4. Toolchain bumps (Rust, Go, UniFFI) require updating `rust-toolchain.toml`, `go.mod`, CI env and
   `docs/REPRODUCIBILITY.md` in one commit.
5. Never replace a library primitive with custom cryptography to avoid an upgrade.
6. Review cadence: at minimum quarterly, and before every external audit milestone.
7. `Cargo.lock` and `go.sum` are committed and CI builds with `--locked` / `go mod verify`. `Cargo.lock` changes only via the documented MSRV-aware procedure in `docs/REPRODUCIBILITY.md`
   (a newer Cargo may be used for resolution only; builds stay on the pinned toolchain), in its own reviewed change set.
