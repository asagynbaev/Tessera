#!/usr/bin/env bash
#
# initialize-devnet.sh — OPTIONAL one-time call of identity_registry `initialize(admin)`.
#
# Creates the singleton RegistryConfig PDA and records the admin pubkey that gates issuer
# registration. NOT required by the devnet smoke tests: register_did / update_root /
# bump_revocation are owner-signed and consult no RegistryConfig. Run this only if you will
# exercise register_issuer / deactivate_issuer (governance / issuer-onboarding flows).
#
# Run deploy-devnet.sh first so the program is deployed and the program keypair exists.
#
# Usage:
#   ./scripts/initialize-devnet.sh [ADMIN_PUBKEY]
#     ADMIN_PUBKEY  optional; defaults to the deploy wallet's own pubkey.
#
# Resolves config from (env override → sensible default):
#   TESSERA_SOLANA_RPC            RPC URL (default https://api.devnet.solana.com)
#   TESSERA_SOLANA_PROGRAM_ID     program id (default: derived from target/deploy keypair)
#   TESSERA_SOLANA_PAYER_KEYPAIR  payer keypair path (default: Anchor.toml [provider].wallet)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOLANA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ANCHOR_TOML="$SOLANA_DIR/Anchor.toml"
PROGRAM_KEYPAIR="$SOLANA_DIR/target/deploy/identity_registry-keypair.json"

step() { printf '\n\033[1;36m==>\033[0m \033[1m%s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

step "Preflight"
command -v solana >/dev/null 2>&1 || die "solana CLI not found on PATH. Install: https://docs.solanalabs.com/cli/install"
command -v node   >/dev/null 2>&1 || die "node not found on PATH. Anchor projects need Node.js (https://nodejs.org)."
command -v npm    >/dev/null 2>&1 || die "npm not found on PATH (ships with Node.js)."

# Payer keypair: env override, else Anchor.toml [provider].wallet, else the CLI default.
WALLET="${TESSERA_SOLANA_PAYER_KEYPAIR:-}"
if [ -z "$WALLET" ]; then
  WALLET="$(awk -F'"' '/^[[:space:]]*wallet[[:space:]]*=/ {print $2; exit}' "$ANCHOR_TOML")"
  WALLET="${WALLET:-$HOME/.config/solana/id.json}"
fi
WALLET="${WALLET/#\~/$HOME}"
[ -f "$WALLET" ] || die "payer keypair not found: $WALLET (set TESSERA_SOLANA_PAYER_KEYPAIR)."

# Program id: env override, else derive from the program keypair produced by deploy-devnet.sh.
PROGRAM_ID="${TESSERA_SOLANA_PROGRAM_ID:-}"
if [ -z "$PROGRAM_ID" ]; then
  [ -f "$PROGRAM_KEYPAIR" ] || die "no program keypair at $PROGRAM_KEYPAIR — run ./scripts/deploy-devnet.sh first, or set TESSERA_SOLANA_PROGRAM_ID."
  PROGRAM_ID="$(solana address -k "$PROGRAM_KEYPAIR")"
fi

RPC_URL="${TESSERA_SOLANA_RPC:-https://api.devnet.solana.com}"
ADMIN="${1:-}"

info "rpc:        $RPC_URL"
info "program id: $PROGRAM_ID"
info "payer:      $WALLET"
info "admin:      ${ADMIN:-<payer pubkey>}"

# Install the single JS dependency (@solana/web3.js) on first run.
if [ ! -d "$SOLANA_DIR/node_modules/@solana/web3.js" ]; then
  step "Installing JS dependency (@solana/web3.js)"
  ( cd "$SOLANA_DIR" && npm install --no-audit --no-fund )
fi

step "Calling initialize(admin)"
TESSERA_SOLANA_RPC="$RPC_URL" \
TESSERA_SOLANA_PROGRAM_ID="$PROGRAM_ID" \
TESSERA_SOLANA_PAYER_KEYPAIR="$WALLET" \
  node "$SCRIPT_DIR/initialize.js" ${ADMIN:+"$ADMIN"}
