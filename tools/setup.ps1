# Z-BACS developer toolchain setup (Windows 10/11, PowerShell 5+)  — task Z-0.D.2
# Run in an elevated PowerShell if winget prompts for it.
#   powershell -ExecutionPolicy Bypass -File tools\setup.ps1
#   powershell -ExecutionPolicy Bypass -File tools\setup.ps1 -Check
param([switch]$Check)
$ErrorActionPreference = "Stop"

function Have($cmd) { return [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }
function Log($m) { Write-Host "[setup] $m" -ForegroundColor Cyan }
function Ok($m)  { Write-Host "   ok  $m" -ForegroundColor Green }
function Miss($m){ Write-Host "  miss $m" -ForegroundColor Red }

function Report {
  Log "toolchain status"
  if (Have rustc) { Ok ("rustc " + (rustc --version)) } else { Miss "rustc" }
  if (Have cargo) { Ok "cargo" } else { Miss "cargo" }
  if (Have forge) { Ok ("forge " + ((forge --version) | Select-Object -First 1)) } else { Miss "forge" }
  if (Have node)  { Ok ("node " + (node --version)) } else { Miss "node >= 22" }
  if (Get-Command "cargo" -EA SilentlyContinue) {
    try { cargo tauri --version | Out-Null; Ok "tauri-cli" } catch { Miss "tauri-cli" }
  }
  $vs = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\VisualStudio\SxS\VS7" -EA SilentlyContinue
  if ($vs) { Ok "Visual Studio Build Tools" } else { Miss "VS Build Tools (C++ workload) — required by rustc msvc" }
}

if ($Check) { Report; exit 0 }

# 1. Visual Studio Build Tools (C++), WebView2 runtime
if (-not (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\VisualStudio\SxS\VS7" -EA SilentlyContinue)) {
  Log "installing VS Build Tools (C++ workload) via winget"
  winget install --id Microsoft.VisualStudio.2022.BuildTools --silent --accept-package-agreements --accept-source-agreements `
    --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
}
if (-not (Test-Path "$env:ProgramFiles (x86)\Microsoft\EdgeWebView")) {
  Log "installing WebView2 runtime"; winget install --id Microsoft.EdgeWebView2Runtime --silent --accept-package-agreements --accept-source-agreements
}

# 2. Rust
if (-not (Have rustc)) {
  Log "installing rustup"
  Invoke-WebRequest https://win.rustup.rs/x86_64 -OutFile "$env:TEMP\rustup-init.exe"
  & "$env:TEMP\rustup-init.exe" -y --default-toolchain stable
  $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
}
rustup component add clippy rustfmt | Out-Null
foreach ($c in @(@("tauri","tauri-cli","--version","^2"), @("audit","cargo-audit"), @("fuzz","cargo-fuzz"))) {
  try { & cargo $c[0] --version | Out-Null; Ok $c[1] } catch { Log "cargo install $($c[1])"; & cargo install $c[1..($c.Length-1)] --locked }
}

# 3. Foundry (Windows: foundryup is bash-only; use the release archive)
if (-not (Have forge)) {
  Log "installing Foundry from GitHub release"
  $dir = "$env:USERPROFILE\.foundry\bin"; New-Item -ItemType Directory -Force $dir | Out-Null
  $zip = "$env:TEMP\foundry.zip"
  Invoke-WebRequest "https://github.com/foundry-rs/foundry/releases/latest/download/foundry_stable_win32_amd64.zip" -OutFile $zip
  Expand-Archive $zip -DestinationPath $dir -Force
  [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path","User") + ";$dir", "User")
  $env:Path = "$dir;$env:Path"
}

# 4. Node >= 22
if (-not (Have node)) { Log "installing Node.js LTS"; winget install --id OpenJS.NodeJS.LTS --silent --accept-package-agreements --accept-source-agreements }

Report
Log "done. Open a new terminal so PATH changes apply."
