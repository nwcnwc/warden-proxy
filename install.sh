#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────
# Warden Proxy — Install Script
# ──────────────────────────────────────────────

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
DIM='\033[2m'
RESET='\033[0m'

WARDEN_HOME="${HOME}/.warden"
WARDEN_BIN="${HOME}/.local/bin/warden"
SYSTEMD_DIR="${HOME}/.config/systemd/user"

info()  { echo -e "${GREEN}[+]${RESET} $1"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $1"; }
error() { echo -e "${RED}[x]${RESET} $1"; }
step()  { echo -e "\n${BOLD}$1${RESET}"; }

# ── Detect source directory ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "${SCRIPT_DIR}/Cargo.toml" ]]; then
    error "This script must be run from the warden-proxy source directory."
    exit 1
fi

echo -e "\n${BOLD}Warden Proxy Installer${RESET}"
echo -e "${DIM}────────────────────────────────────${RESET}\n"

# ── Step 1: Check dependencies ──
step "Checking dependencies..."

if ! command -v cargo &>/dev/null; then
    error "Rust toolchain not found. Install from https://rustup.rs"
    exit 1
fi
info "Rust toolchain found: $(rustc --version)"

# ── Step 2: Build from source ──
step "Building from source..."

cd "${SCRIPT_DIR}"
cargo build --release 2>&1 | tail -5

if [[ ! -f target/release/warden ]]; then
    error "Build failed — binary not found at target/release/warden"
    exit 1
fi
info "Build successful"

# ── Step 3: Install binary ──
step "Installing binary..."

mkdir -p "$(dirname "${WARDEN_BIN}")"

# Check if we should use /usr/local/bin (if --system flag)
if [[ "${1:-}" == "--system" ]]; then
    WARDEN_BIN="/usr/local/bin/warden"
    info "Installing to ${WARDEN_BIN} (requires sudo)"
    sudo cp target/release/warden "${WARDEN_BIN}"
    sudo chmod +x "${WARDEN_BIN}"
else
    cp target/release/warden "${WARDEN_BIN}"
    chmod +x "${WARDEN_BIN}"
fi

info "Binary installed to ${WARDEN_BIN}"

# Ensure ~/.local/bin is in PATH
if [[ "${WARDEN_BIN}" == "${HOME}/.local/bin/warden" ]]; then
    if ! echo "$PATH" | grep -q "${HOME}/.local/bin"; then
        warn "\${HOME}/.local/bin is not in your PATH"
        warn "Add to your shell profile:  export PATH=\"\${HOME}/.local/bin:\${PATH}\""
    fi
fi

# ── Step 4: Initialize config ──
step "Initializing Warden..."

if [[ ! -d "${WARDEN_HOME}" ]]; then
    "${WARDEN_BIN}" init
    info "Created ${WARDEN_HOME}/"
else
    info "${WARDEN_HOME}/ already exists, skipping init"
fi

# ── Step 5: Copy public files (launchpad + apps) ──
step "Installing launchpad and bundled apps..."

SITES_DIR="${WARDEN_HOME}/sites"
mkdir -p "${SITES_DIR}"

if [[ -d "${SCRIPT_DIR}/public" ]]; then
    cp -r "${SCRIPT_DIR}/public/"* "${SITES_DIR}/"
    info "Copied public files to ${SITES_DIR}/"

    # Count installed apps
    APP_COUNT=$(find "${SITES_DIR}/apps" -name "index.html" 2>/dev/null | wc -l)
    info "Installed ${APP_COUNT} bundled apps"
else
    warn "No public/ directory found — skipping frontend install"
fi

# ── Step 6: Set up systemd user service ──
step "Setting up systemd service..."

if command -v systemctl &>/dev/null && systemctl --user status 2>/dev/null | head -1 &>/dev/null; then
    mkdir -p "${SYSTEMD_DIR}"
    cp "${SCRIPT_DIR}/warden.service" "${SYSTEMD_DIR}/warden.service"

    # Update ExecStart path if using --system install
    if [[ "${WARDEN_BIN}" != "${HOME}/.local/bin/warden" ]]; then
        sed -i "s|%h/.local/bin/warden|${WARDEN_BIN}|g" "${SYSTEMD_DIR}/warden.service"
    fi

    systemctl --user daemon-reload
    info "Systemd service installed"

    # Enable and start
    systemctl --user enable warden.service 2>/dev/null || true
    systemctl --user restart warden.service 2>/dev/null || true

    # Check if it started
    sleep 1
    if systemctl --user is-active warden.service &>/dev/null; then
        info "Warden service is running"
    else
        warn "Service installed but may not have started (check: systemctl --user status warden)"
    fi
else
    warn "systemd user session not available — skipping service setup"
    warn "Start manually with: ${WARDEN_BIN} start"
fi

# ── Done ──
echo -e "\n${BOLD}${GREEN}Installation complete!${RESET}"
echo -e "${DIM}────────────────────────────────────${RESET}"
echo ""
echo -e "  ${BOLD}Binary:${RESET}    ${WARDEN_BIN}"
echo -e "  ${BOLD}Config:${RESET}    ${WARDEN_HOME}/config.json"
echo -e "  ${BOLD}Launchpad:${RESET} http://localhost:7400"
echo -e "  ${BOLD}Sites:${RESET}     ${SITES_DIR}/"
echo ""
echo -e "  ${BOLD}Usage:${RESET}"
echo -e "    warden start                    ${DIM}# Start the proxy${RESET}"
echo -e "    warden status                   ${DIM}# Check if running${RESET}"
echo -e "    warden add-key openai \\         ${DIM}# Add an API key${RESET}"
echo -e "      --base-url https://api.openai.com \\"
echo -e "      --source env --reference OPENAI_API_KEY \\"
echo -e "      --prefix 'Bearer '"
echo -e "    warden list-keys                ${DIM}# List configured keys${RESET}"
echo -e "    warden test-key openai          ${DIM}# Test key resolution${RESET}"
echo ""
echo -e "  ${BOLD}Systemd:${RESET}"
echo -e "    systemctl --user status warden  ${DIM}# Check service status${RESET}"
echo -e "    systemctl --user restart warden ${DIM}# Restart after config changes${RESET}"
echo -e "    journalctl --user -u warden -f  ${DIM}# View logs${RESET}"
echo ""
