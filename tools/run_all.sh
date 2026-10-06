#!/usr/bin/env bash
# Runs every Phase A check. Never stops at the first failure. Writes build-report.txt (paste it back).
# Works on Linux/macOS and in Git Bash on Windows.
cd "$(dirname "$0")/.." || exit 1
OUT=build-report.txt; : > "$OUT"
say() { echo "$@" | tee -a "$OUT"; }
step() { # step "name" command...
  local name="$1"; shift
  say ""; say "=== $name"
  if "$@" >>"$OUT" 2>&1; then say "PASS: $name"; else say "FAIL: $name  (details in $OUT)"; fi
}
have() { command -v "$1" >/dev/null 2>&1; }

# First working Python >= 3.9 (skips the Windows Store stub, which exists but cannot run).
PY=""
for c in python3 py python; do
  if have "$c" && "$c" -c "import sys; assert sys.version_info >= (3, 9)" >/dev/null 2>&1; then PY="$c"; break; fi
done
# Native Windows programs need C:/... paths, not /c/... (Git Bash).
ROOT="$PWD"; have cygpath && ROOT="$(cygpath -m "$PWD")"

say "toolchains:"
{ [ -n "$PY" ] && "$PY" --version || echo "missing: python 3.9+"; git --version; rustc --version; cargo --version; go version; } 2>&1 | tee -a "$OUT"
mkdir -p parity-out

if [ -n "$PY" ]; then
  step "python: vectors reproducible + valid" bash -c "$PY tools/gen_vectors.py && git diff --exit-code -- test-vectors && $PY tools/check_vectors.py"
else say "FAIL: no working Python 3.9+ found (install Python 3.12 and 'pip install cryptography')"; fi
if have cargo; then
  step "rust: cargo test (all)" cargo test --locked --manifest-path native/crypto-core/Cargo.toml
  step "rust: parity output" env PM_PARITY_OUT="$ROOT/parity-out/rust.json" cargo test --locked --manifest-path native/crypto-core/Cargo.toml --test cbor_vectors
else say "SKIP: cargo not installed (see docs/LOCAL_SETUP_WINDOWS.md)"; fi
if have go; then
  step "go: mod verify" bash -c "cd services/gateway && go mod download && go mod verify"
  step "go: vet" bash -c "cd services/gateway && go vet ./..."
  step "go: test (all)" bash -c "cd services/gateway && go test ./..."
  step "go: parity output" bash -c "cd services/gateway && PM_PARITY_OUT=\"$ROOT/parity-out/go.json\" go test ./internal/cbor -run TestSharedVectors -count=1"
else say "SKIP: go not installed"; fi
if [ -n "$PY" ] && [ -f parity-out/rust.json ] && [ -f parity-out/go.json ]; then
  step "parity: rust == go == vector file" "$PY" tools/compare_parity.py parity-out/rust.json parity-out/go.json
else say "SKIP: parity comparison (needs Python plus both rust.json and go.json)"; fi
say ""; say "Done. Open $OUT, and paste its contents back to Claude."
