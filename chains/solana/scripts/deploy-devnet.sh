#!/usr/bin/env bash
#
# deploy-devnet.sh — one-command deploy of the identity-registry Anchor program to a
# Solana cluster (devnet by default). Takes a clean checkout to a deployed program and
# prints the program id you feed the C# smoke tests.
#
# Flow (the `anchor keys sync` step is done explicitly so it is visible and scriptable;
# the keypair is generated up front so the program id is known BEFORE the build — that
# lets us build exactly once with the correct id, and avoids `anchor build` choking while
# parsing a placeholder program id out of Anchor.toml):
#
#   1. preflight  — require the solana + anchor toolchain on PATH (fail loudly otherwise).
#   2. keypair    — ensure target/deploy/identity_registry-keypair.json exists (generate
#                   it on a clean checkout) so the program id is known up front.
#   3. id         — read the program id derived from that keypair (anchor keys list).
#   4. patch      — write that id into declare_id!() in src/lib.rs AND the [programs.*]
#                   entries of Anchor.toml, BEFORE building.
#   5. anchor build  → compile once, with the correct id already baked in.
#   6. anchor deploy → upload to the cluster (re-running upgrades in place).
#   7. summary    → print the program id, an explorer link, and the three env vars the
#                   devnet smoke tests need.
#
# Idempotent: the program id is deterministic from the keypair, so steps 3–4 converge to
# the same value on every run and step 6 redeploys/upgrades the same address.
#
# Scope note: the declare_id! / Anchor.toml edits are LOCAL working-tree changes for this
# deploy — the repo intentionally keeps the placeholder id committed. The C# client reads
# the program id from $TESSERA_SOLANA_PROGRAM_ID at runtime, so nothing on the .NET side
# is rebuilt after a deploy; only the on-chain (Rust) program carries a hardcoded id.
#
# Usage:
#   ./scripts/deploy-devnet.sh [CLUSTER]
#     CLUSTER  devnet (default) | testnet | mainnet | localnet
#
set -euo pipefail

CLUSTER="${1:-devnet}"

# ── resolve paths (run-from-anywhere) ────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOLANA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_RS="$SOLANA_DIR/programs/identity-registry/src/lib.rs"
ANCHOR_TOML="$SOLANA_DIR/Anchor.toml"

# ── pretty output helpers ────────────────────────────────────────────────────
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
step() { printf '\n\033[1;36m==>\033[0m \033[1m%s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Per-cluster RPC + explorer query suffix.
case "$CLUSTER" in
  devnet)            RPC_URL="https://api.devnet.solana.com";        EXPLORER_Q="?cluster=devnet" ;;
  testnet)           RPC_URL="https://api.testnet.solana.com";       EXPLORER_Q="?cluster=testnet" ;;
  mainnet|mainnet-beta) RPC_URL="https://api.mainnet-beta.solana.com"; EXPLORER_Q="" ;;
  localnet|localhost) RPC_URL="http://127.0.0.1:8899";               EXPLORER_Q="?cluster=custom&customUrl=http://127.0.0.1:8899" ;;
  *) die "unknown cluster '$CLUSTER' (expected: devnet | testnet | mainnet | localnet)" ;;
esac

# ── 1. preflight ─────────────────────────────────────────────────────────────
step "Preflight — checking the Solana/Anchor toolchain"
command -v solana >/dev/null 2>&1 || die "solana CLI not found on PATH. Install: https://docs.solanalabs.com/cli/install"
command -v anchor >/dev/null 2>&1 || die "anchor CLI not found on PATH. Install: 'avm install 0.30.1 && avm use 0.30.1' (https://www.anchor-lang.com/docs/installation)"
command -v cargo  >/dev/null 2>&1 || die "cargo (Rust) not found on PATH. Install: https://rustup.rs"
[ -f "$LIB_RS" ]      || die "cannot find $LIB_RS — run this from inside the repo."
[ -f "$ANCHOR_TOML" ] || die "cannot find $ANCHOR_TOML — run this from inside the repo."
info "solana $(solana --version 2>/dev/null | awk '{print $2}')"
info "anchor $(anchor --version 2>/dev/null | awk '{print $2}')"
info "target cluster: $CLUSTER ($RPC_URL)"

# Best-effort funding check against the wallet Anchor will pay with (non-fatal).
WALLET="$(awk -F'"' '/^[[:space:]]*wallet[[:space:]]*=/ {print $2; exit}' "$ANCHOR_TOML")"
WALLET="${WALLET:-$HOME/.config/solana/id.json}"
WALLET="${WALLET/#\~/$HOME}"
info "deploy wallet (Anchor.toml [provider].wallet): $WALLET"
if [ -f "$WALLET" ]; then
  if BAL="$(solana balance -k "$WALLET" -u "$CLUSTER" 2>/dev/null)"; then
    info "wallet balance: $BAL"
    case "$BAL" in
      "0 SOL"|0\ SOL*) warn "deploy wallet has 0 SOL. Fund it before deploying, e.g.: solana airdrop 2 -k \"$WALLET\" -u $CLUSTER" ;;
    esac
  else
    warn "could not read wallet balance (continuing). If deploy fails for funds: solana airdrop 2 -k \"$WALLET\" -u $CLUSTER"
  fi
else
  warn "deploy wallet $WALLET does not exist yet. Create + fund it:"
  warn "  solana-keygen new -o \"$WALLET\" --no-bip39-passphrase && solana airdrop 2 -k \"$WALLET\" -u $CLUSTER"
fi

cd "$SOLANA_DIR"

# ── 2. ensure the program keypair exists (generated on a clean checkout) ──────
KEYPAIR="$SOLANA_DIR/target/deploy/identity_registry-keypair.json"
step "Ensuring the program keypair exists"
if [ -f "$KEYPAIR" ]; then
  info "using existing $KEYPAIR"
else
  mkdir -p "$SOLANA_DIR/target/deploy"
  solana-keygen new --no-bip39-passphrase --silent --outfile "$KEYPAIR"
  info "generated $KEYPAIR"
fi

# ── 3. read the program id derived from the program keypair ──────────────────
step "Reading the program id (anchor keys list)"
PROGRAM_ID="$(anchor keys list 2>/dev/null | awk -F'[: ]+' '/identity_registry/ {print $2; exit}' | tr -d '[:space:]')"
# Fallback: read it straight off the keypair if `anchor keys list` is unavailable
# (e.g. it failed to parse a placeholder id still in Anchor.toml on a fresh checkout).
[ -n "$PROGRAM_ID" ] || PROGRAM_ID="$(solana address -k "$KEYPAIR" 2>/dev/null | tr -d '[:space:]')"
[ -n "$PROGRAM_ID" ] || die "could not determine the program id from $KEYPAIR."
info "program id: $PROGRAM_ID"

# ── 4. patch declare_id! + Anchor.toml to the real id, BEFORE building ─────────
# Done before the build so the program id is valid + correct everywhere and the .so
# embeds it on the first (only) compile.
step "Patching declare_id!() in programs/identity-registry/src/lib.rs"
sed -i.bak -E "s/declare_id!\(\"[^\"]*\"\)/declare_id!(\"${PROGRAM_ID}\")/" "$LIB_RS"
rm -f "$LIB_RS.bak"
info "$(grep -n 'declare_id!' "$LIB_RS" | head -1)"

step "Patching [programs.*] identity_registry id in Anchor.toml"
# Rewrites every 'identity_registry = "..."' line (localnet + devnet) — the program id is
# the same across clusters because it is the keypair's pubkey.
sed -i.bak -E "s/^([[:space:]]*identity_registry[[:space:]]*=[[:space:]]*)\"[^\"]*\"/\1\"${PROGRAM_ID}\"/" "$ANCHOR_TOML"
rm -f "$ANCHOR_TOML.bak"
grep -nE '^[[:space:]]*identity_registry[[:space:]]*=' "$ANCHOR_TOML" | while read -r l; do info "$l"; done

# ── 5. build once, with the correct id already in place ───────────────────────
# --no-idl: the on-chain IDL is not consumed by anything here — the C# client
# (src/Tessera.Chains.Solana) and scripts/initialize.js both encode the Anchor
# discriminators + account metas directly. Generating the IDL drives anchor-syn 0.30.1's
# `proc_macro2::Span::source_file()` path, a nightly API removed from current proc-macro2,
# which fails the build on the Anchor 0.30.1 / Solana 1.18 toolchain. Skipping it compiles
# the program cleanly and is sufficient for deploy + the devnet smoke tests.
step "anchor build (--no-idl)"
anchor build --no-idl

# ── 6. deploy ────────────────────────────────────────────────────────────────
step "anchor deploy --provider.cluster $CLUSTER"
info "(re-running this script later upgrades the same program id in place)"
anchor deploy --provider.cluster "$CLUSTER"

# ── 7. summary ───────────────────────────────────────────────────────────────
EXPLORER="https://explorer.solana.com/address/${PROGRAM_ID}${EXPLORER_Q}"
step "Deployed"
bold "  Program id : $PROGRAM_ID"
bold "  Explorer   : $EXPLORER"
printf '\n'
info "Record the program id + sample tx signatures in chains/solana/DEPLOYMENT.md."
printf '\n'
bold "Next — point the C# smoke tests at this deployment and run them:"
cat <<EOF

  export TESSERA_SOLANA_RPC="$RPC_URL"
  export TESSERA_SOLANA_PROGRAM_ID="$PROGRAM_ID"
  export TESSERA_SOLANA_PAYER_KEYPAIR="$WALLET"

  dotnet test src/Tessera.Chains.Solana.Tests \\
    --filter "FullyQualifiedName~Smoke.SolanaDevnetSmokeTests"

EOF
info "initialize(admin) is only needed for issuer-registration flows — see ./scripts/initialize-devnet.sh."
