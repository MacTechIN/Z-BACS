#!/usr/bin/env bash
# Z-BACS developer toolchain setup (Linux / macOS)  — task Z-0.D.2
#
# Installs (idempotent, safe to re-run):
#   - Rust stable via rustup            (~/.cargo)
#   - Tauri 2 system deps (apt, Linux)   [sudo]
#   - tauri-cli, cargo-audit, cargo-fuzz
#   - Foundry: forge / anvil / cast / chisel via foundryup (~/.foundry)
#   - Node.js >= 22 check (not installed here; use nvm/fnm/volta)
#
# Usage:
#   bash tools/setup.sh            # install everything
#   bash tools/setup.sh --check    # only report what is present / missing
#   SKIP_APT=1 bash tools/setup.sh # skip the sudo apt step
set -euo pipefail

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

export PATH="$HOME/.cargo/bin:$HOME/.foundry/bin:$PATH"

MIN_RUST="1.85.0"
MIN_NODE="22"

log()  { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m  ok \033[0m %s\n' "$*"; }
miss() { printf '\033[1;31m miss\033[0m %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

OS="$(uname -s)"

# ---------------------------------------------------------------- system deps
install_apt_deps() {
  [[ "$OS" != "Linux" ]] && return 0
  [[ "${SKIP_APT:-0}" == "1" ]] && { log "SKIP_APT=1, skipping apt"; return 0; }
  if ! have apt-get; then log "non-apt Linux: install Tauri deps manually (see https://v2.tauri.app/start/prerequisites/)"; return 0; fi
  local pkgs=(build-essential pkg-config libssl-dev curl wget file git
              libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev)
  local missing=()
  for p in "${pkgs[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
  if ((${#missing[@]})); then
    log "installing apt packages: ${missing[*]}"
    sudo apt-get update -qq
    sudo apt-get install -y -qq "${missing[@]}"
  else
    ok "apt packages present"
  fi
}

install_macos_deps() {
  [[ "$OS" != "Darwin" ]] && return 0
  xcode-select -p >/dev/null 2>&1 || { log "installing Xcode CLT"; xcode-select --install || true; }
}

# ---------------------------------------------------------------------- rust
install_rust() {
  if have rustc && version_ge "$(rustc --version | awk '{print $2}')" "$MIN_RUST"; then
    ok "rust $(rustc --version | awk '{print $2}')"
  else
    log "installing rust via rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile default
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi
  rustup component add clippy rustfmt >/dev/null 2>&1 || true
}

install_cargo_tool() { # name, crate, [extra args]
  local bin="$1" crate="$2"; shift 2
  if have "$bin" || cargo "$bin" --version >/dev/null 2>&1; then ok "$crate"; return 0; fi
  log "cargo install $crate"
  cargo install "$crate" --locked "$@"
}

# ------------------------------------------------------------------- foundry
install_foundry() {
  if have forge; then ok "foundry $(forge --version 2>/dev/null | head -1 | awk '{print $3}')"; return 0; fi
  if [[ ! -x "$HOME/.foundry/bin/foundryup" ]]; then
    log "installing foundryup"
    curl -L https://foundry.paradigm.xyz | bash
  fi
  log "running foundryup"
  "$HOME/.foundry/bin/foundryup"
}

ensure_path_line() { # file, line
  local f="$1" line="$2"
  [[ -f "$f" ]] || touch "$f"
  grep -qF -- "$line" "$f" || printf '\n# Foundry (added by Z-BACS tools/setup.sh)\n%s\n' "$line" >> "$f"
}

# --------------------------------------------------------------------- check
report() {
  log "toolchain status"
  have rustc  && ok "rustc  $(rustc --version | awk '{print $2}')"   || miss "rustc"
  have cargo  && ok "cargo  $(cargo --version | awk '{print $2}')"   || miss "cargo"
  cargo tauri --version >/dev/null 2>&1 && ok "tauri-cli $(cargo tauri --version | awk '{print $2}')" || miss "tauri-cli"
  cargo audit --version >/dev/null 2>&1 && ok "cargo-audit" || miss "cargo-audit"
  cargo fuzz  --version >/dev/null 2>&1 && ok "cargo-fuzz"  || miss "cargo-fuzz (needs nightly at run time: rustup toolchain install nightly)"
  have forge  && ok "forge  $(forge --version 2>/dev/null | head -1 | awk '{print $3}')" || miss "forge"
  have anvil  && ok "anvil"  || miss "anvil"
  have cast   && ok "cast"   || miss "cast"
  if have node; then
    local nv; nv="$(node --version | tr -d v | cut -d. -f1)"
    ((nv >= MIN_NODE)) && ok "node $(node --version)" || miss "node >= $MIN_NODE (have $(node --version))"
  else miss "node >= $MIN_NODE (install via nvm/fnm/volta)"; fi
  have python3 && ok "python3 $(python3 --version | awk '{print $2}')" || miss "python3"
  have gh && ok "gh cli" || log "gh cli optional"
}

# ---------------------------------------------------------------------- main
if ((CHECK_ONLY)); then report; exit 0; fi

install_apt_deps
install_macos_deps
install_rust
install_cargo_tool tauri tauri-cli --version '^2'
install_cargo_tool audit cargo-audit
install_cargo_tool fuzz  cargo-fuzz
install_foundry

ensure_path_line "$HOME/.bashrc" 'export PATH="$HOME/.foundry/bin:$PATH"'
[[ -f "$HOME/.zshrc" ]] && ensure_path_line "$HOME/.zshrc" 'export PATH="$HOME/.foundry/bin:$PATH"'

report
log "done. Open a new shell (or: source ~/.bashrc) so PATH changes apply."
