# Local setup and validation: Windows 10/11 + VS Code (Command Prompt)

Everything below is typed into the VS Code terminal (Terminal > New Terminal, a Command Prompt). The commands marked "verified" were run on a real Windows machine (2026-10-05).
NOT verified: `tools\run_all.ps1`, Android/iOS builds, the GitHub Actions workflow.

## 1. Install the tools (once) - verified
```
winget install -e --id Microsoft.VisualStudio.2022.BuildTools --accept-package-agreements --accept-source-agreements --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
winget install -e --id Rustlang.Rustup --accept-package-agreements --accept-source-agreements
winget install -e --id GoLang.Go --version 1.22.6
winget install -e --id Python.Python.3.12
```
Close EVERY VS Code window, reopen VS Code and the project folder, open a new terminal, then:
```
rustup toolchain install 1.81.0 --profile minimal -c rustfmt -c clippy
cargo --version        (cargo 1.81.0 once you are inside the project)
go version             (go version go1.22.6 windows/amd64)
py --version
py -m pip install cryptography
```
If `go` is still not found: `set PATH=%PATH%;C:\Program Files\Go\bin` (this terminal only; reopening VS Code fixes it permanently).

## 2. The project folder
The repository lives in `C:\private-messenger`. Every new terminal starts in whatever folder VS Code was opened with, so start each session with:
```
cd C:\private-messenger
```
Creating files: `type nul > path\to\file`, then double-click the file in the Explorer, paste, and Ctrl+S. Do NOT type a full path into the Explorer's New File box while a folder is selected
(VS Code appends it to that folder and creates nested junk folders). Check a copied file with its line count and hash:
```
find /c /v "" tools\check_vectors.py
certutil -hashfile tools\check_vectors.py SHA256
```

## 3. Validate - verified
```
cd C:\private-messenger
py tools\gen_vectors.py
```
prints `positive=51 negative=50 quarantined=1 files=10`, and
```
certutil -hashfile test-vectors\v1\manifest.json SHA256
```
must start with `39f6a02a` (proof that every vector file is byte-identical to the reference).
```
py tools\check_vectors.py
```
prints `vector check OK: 51 positive, 50 negative CBOR vectors; ed25519 + recovery fixtures verified; manifest hashes OK`.
```
cd native\crypto-core
cargo test --locked
```
runs 8 library tests, 2 `cbor_vectors` tests and 3 `recovery_vectors` tests (all `ok`).
```
cd C:\private-messenger\services\gateway
go test ./...
```
prints `ok` for `internal/cbor`, `internal/cbor/typed` and `internal/http`.

## 4. Rust/Go parity - verified
```
cd C:\private-messenger
mkdir parity-out
set PM_PARITY_OUT=C:\private-messenger\parity-out\rust.json
cd native\crypto-core
cargo test --locked --test cbor_vectors
set PM_PARITY_OUT=
cd C:\private-messenger\services\gateway
set PM_PARITY_OUT=C:\private-messenger\parity-out\go.json
go test ./internal/cbor -run TestSharedVectors -count=1
set PM_PARITY_OUT=
cd C:\private-messenger
py tools\compare_parity.py parity-out\rust.json parity-out\go.json
```
The last line must be `parity OK: 101 vectors identical across Rust, Go and the vector file`. `parity-out\` is ignored by Git.

## 5. Git
```
git config --global user.name "Your Real Name"
git config --global user.email "your-github-email@example.com"
git status
git add .
git commit -m "message"
```
Publish with Source Control (Ctrl+Shift+G) > Publish Branch > private repository. `target\`, `parity-out\` and `__pycache__\` are ignored; `Cargo.lock` and `go.sum` are committed.
The two `git config` values above are placeholders: set your real name and email BEFORE the first push if you want commits attributed to your GitHub account (changing them after a push means rewriting history).

## 6. Problems seen on a real machine, and fixes
- `'cargo' is not recognized`: Rust is not installed yet, or VS Code was not restarted after installing it.
- `could not find Cargo.toml` / `go.mod file not found`: the terminal is in the wrong folder; `cd` into `native\crypto-core` (Rust) or `services\gateway` (Go).
- `failed to select a version for unicode-normalization`: `Cargo.toml` must pin `unicode-normalization = "=0.1.22"` (required by `bip39 =2.0.0`).
- `feature edition2024 is required` (base64ct): use the committed `Cargo.lock`; to regenerate it follow `docs/REPRODUCIBILITY.md`.
- `go` not found right after installing: reopen VS Code (or the temporary `set PATH` above).
- Junk folders such as `code services` inside `native\crypto-core`: caused by typing a path into the Explorer's New File box; delete them and recreate the files with `type nul > ...`.
- Do not edit anything under `test-vectors\` by hand; they are generated and hashed.

PM-BI-X3DH-1 implementation starts only after the gate in `docs/PHASE_B_GATE.md` (met on 2026-10-05) and your explicit go-ahead.

## 7. More problems seen on a real machine
- A command seems to hang and the screen fills with `~` (Git's pager `less`): press `q`; if the terminal does not respond, close it and open a new one. Prevent it: `git config --global core.pager cat`.
- A strange file such as `t --locked` appears in `git status`: it was created by typing a command into the pager. Delete it with `del "t --locked"`; never commit it.
- `git status` shows a workflow or doc file as modified although you did not mean to edit it: opening and saving a file in VS Code can add a trailing blank line. Check with `git diff`, then `git restore <file>`.
- After adding a Rust dependency, follow `docs/REPRODUCIBILITY.md` ("Adding a dependency"), not a plain `cargo test`.
