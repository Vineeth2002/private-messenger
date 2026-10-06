# Windows PowerShell version of run_all.sh. NOT yet executed anywhere (no PowerShell in the authoring
# sandbox); prefer `bash tools/run_all.sh` in Git Bash. Writes build-report.txt (paste it back).
# Run:  powershell -ExecutionPolicy Bypass -File tools\run_all.ps1
Set-Location (Join-Path $PSScriptRoot "..")
$Out = Join-Path $PWD.Path "build-report.txt"
Set-Content -Path $Out -Value "" -Encoding utf8
function Say($m) { Write-Host $m; Add-Content -Path $Out -Value $m -Encoding utf8 }
function Have($c) { [bool](Get-Command $c -ErrorAction SilentlyContinue) }
function Find-Python {   # first working Python >= 3.9 (skips the Windows Store stub)
  foreach ($c in @("py", "python", "python3")) {
    if (Have $c) {
      & $c -c "import sys; assert sys.version_info >= (3, 9)" 2>$null | Out-Null
      if ($LASTEXITCODE -eq 0) { return $c }
    }
  }
  return $null
}
function Step($name, [scriptblock]$cmd) {
  Say ""; Say "=== $name"
  $global:LASTEXITCODE = 0
  $o = & $cmd 2>&1 | Out-String
  $code = $LASTEXITCODE
  Add-Content -Path $Out -Value $o -Encoding utf8
  if ($code -eq 0) { Say "PASS: $name" } else { Say "FAIL: $name  (details in $Out)" }
}
$py = Find-Python
Say "toolchains:"
if ($py) { Say ((& $py --version 2>&1 | Out-String).Trim()) } else { Say "missing: python 3.9+" }
foreach ($c in @("git --version", "rustc --version", "cargo --version", "go version")) {
  try { Say ((Invoke-Expression $c 2>&1 | Out-String).Trim()) } catch { Say "missing: $c" }
}
New-Item -ItemType Directory -Force parity-out | Out-Null

if ($py) {
  Step "python: vectors reproducible + valid" {
    & $py tools/gen_vectors.py
    if ($LASTEXITCODE -eq 0) { git diff --exit-code -- test-vectors }
    if ($LASTEXITCODE -eq 0) { & $py tools/check_vectors.py }
  }
} else { Say "FAIL: no working Python 3.9+ found" }
if (Have "cargo") {
  Step "rust: cargo test (all)" { cargo test --locked --manifest-path native/crypto-core/Cargo.toml }
  Step "rust: parity output" {
    $env:PM_PARITY_OUT = Join-Path $PWD.Path "parity-out\rust.json"
    try { cargo test --locked --manifest-path native/crypto-core/Cargo.toml --test cbor_vectors }
    finally { Remove-Item Env:PM_PARITY_OUT -ErrorAction SilentlyContinue }
  }
} else { Say "SKIP: cargo not installed" }
if (Have "go") {
  Step "go: mod verify" { Push-Location services/gateway; try { go mod download; go mod verify } finally { Pop-Location } }
  Step "go: vet" { Push-Location services/gateway; try { go vet ./... } finally { Pop-Location } }
  Step "go: test (all)" { Push-Location services/gateway; try { go test ./... } finally { Pop-Location } }
  Step "go: parity output" {
    $env:PM_PARITY_OUT = Join-Path $PWD.Path "parity-out\go.json"
    Push-Location services/gateway
    try { go test ./internal/cbor -run TestSharedVectors -count=1 }
    finally { Pop-Location; Remove-Item Env:PM_PARITY_OUT -ErrorAction SilentlyContinue }
  }
} else { Say "SKIP: go not installed" }
if ($py -and (Test-Path parity-out/rust.json) -and (Test-Path parity-out/go.json)) {
  Step "parity: rust == go == vector file" { & $py tools/compare_parity.py parity-out/rust.json parity-out/go.json }
} else { Say "SKIP: parity comparison (needs Python plus both rust.json and go.json)" }
Say ""; Say "Done. Open $Out and paste its contents back to Claude."
