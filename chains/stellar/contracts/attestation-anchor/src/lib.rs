#![no_std]
// soroban-sdk 26.1 deprecated `Events::publish` in favour of the `#[contractevent]` macro.
// We keep the existing event emission (migrating changes the on-chain event ABI and would
// require redeploying this already-deployed contract); the lint is suppressed deliberately.
#![allow(deprecated)]
//! # AttestationAnchor
//!
//! Soroban DID anchor for the Tessera identity layer — the Stellar counterpart of the
//! Solana `identity-registry` program and the EVM `IdentityRegistry` contract. It stores
//! only the Merkle **attestation root** and a monotonic **revocation epoch** keyed by
//! `did_hash` (`SHA-256(utf8(did))`). DID documents, attestations, names, balances, and any
//! PII stay off-chain. The contract verifies **no** proofs — that is the job of the
//! off-chain `Tessera.Attestations` layer. The companion `attestation-verifier` contract
//! handles issuer-signature verification; this contract is purely the anchor store.
//!
//! ## Data model (parity with Solana `DidAnchor`)
//! Each DID maps to an [`Anchor`] holding `owner`, `root`, `epoch`, and timestamps. The
//! `owner` is the Stellar account that first anchored the DID; it is the only principal
//! that may update the root or bump revocation thereafter.
//!
//! ## Authorization
//! `did_hash` is public, so an unauthenticated write would let anyone squat a DID and have
//! the off-chain verifier trust their root. Every write therefore requires the `owner`'s
//! authorization (`require_auth`), the Soroban-native equivalent of the EVM controller
//! signature and the Solana `owner: Signer` constraint:
//! - `anchor_root` — first call binds the DID to the calling `owner` (epoch 0); later calls
//!   require that same `owner` to authorize, then replace the root (epoch unchanged).
//! - `bump_revocation` — loads the anchor and requires the stored `owner` to authorize.
//!
//! State lives in **persistent** storage (per-DID, unbounded count) and its TTL is extended
//! on every write so active anchors are not archived.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, Address, BytesN, Env,
    Symbol,
};

/// ~5s per ledger ⇒ ~17,280 ledgers/day. Used to size persistent-entry TTLs.
const DAY_LEDGERS: u32 = 17_280;
/// Extend anchor entries to ~30 days of TTL on every write.
const ANCHOR_TTL: u32 = DAY_LEDGERS * 30;
/// Bump when fewer than ~29 days remain, so a long-lived anchor never silently expires.
const ANCHOR_TTL_THRESHOLD: u32 = ANCHOR_TTL - DAY_LEDGERS;

#[contract]
pub struct AttestationAnchor;

/// Persistent-storage keys. One [`Anchor`] entry per DID, keyed by its `did_hash`.
#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// Anchor record for a DID, keyed by `SHA-256(utf8(did))`.
    Anchor(BytesN<32>),
}

/// On-chain anchor record for a single DID. Mirrors the Solana `DidAnchor` layout
/// (`owner`, `attestation_root`, `revocation_epoch`, `created_at`, `updated_at`).
#[contracttype]
#[derive(Clone)]
pub struct Anchor {
    /// Account that controls this DID anchor (set on first `anchor_root`).
    pub owner: Address,
    /// Current Merkle attestation root (32 bytes).
    pub root: BytesN<32>,
    /// Monotonic revocation epoch; presentations anchored below the current epoch are stale.
    pub epoch: u64,
    /// Ledger timestamp (seconds) of the first `anchor_root`.
    pub created_at: u64,
    /// Ledger timestamp (seconds) of the most recent write.
    pub updated_at: u64,
}

/// Error codes for anchor administration failures.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AnchorError {
    /// The caller is not the `owner` recorded for this DID anchor.
    NotOwner = 1,
    /// No anchor exists for the given `did_hash`.
    AnchorNotFound = 2,
    /// The revocation epoch would overflow `u64`.
    EpochOverflow = 3,
}

#[contractimpl]
impl AttestationAnchor {
    /// Anchor (create or update) the attestation root for a DID.
    ///
    /// The first call for a `did_hash` creates the anchor at epoch 0 and binds it to
    /// `owner`. Subsequent calls require that same `owner` to authorize and replace the
    /// root, leaving the revocation epoch unchanged (use [`Self::bump_revocation`] for that).
    ///
    /// # Panics
    /// Traps with [`AnchorError::NotOwner`] if an existing anchor is owned by a different
    /// account.
    pub fn anchor_root(env: Env, owner: Address, did_hash: BytesN<32>, root: BytesN<32>) {
        owner.require_auth();

        let key = DataKey::Anchor(did_hash.clone());
        let now = env.ledger().timestamp();

        let anchor = match env.storage().persistent().get::<DataKey, Anchor>(&key) {
            Some(mut existing) => {
                if existing.owner != owner {
                    panic_with_error!(&env, AnchorError::NotOwner);
                }
                existing.root = root.clone();
                existing.updated_at = now;
                existing
            }
            None => Anchor {
                owner: owner.clone(),
                root: root.clone(),
                epoch: 0,
                created_at: now,
                updated_at: now,
            },
        };

        env.storage().persistent().set(&key, &anchor);
        env.storage()
            .persistent()
            .extend_ttl(&key, ANCHOR_TTL_THRESHOLD, ANCHOR_TTL);

        env.events().publish(
            (Symbol::new(&env, "anchor_root"), did_hash),
            (owner, root, anchor.epoch),
        );
    }

    /// Increment the revocation epoch for a DID, signaling that prior presentations are stale.
    /// Returns the new epoch. Requires the anchor's `owner` to authorize. `reason` is emitted
    /// in the event but not stored (parity with the Solana program).
    ///
    /// # Panics
    /// Traps with [`AnchorError::AnchorNotFound`] if no anchor exists, or
    /// [`AnchorError::EpochOverflow`] if the epoch would overflow `u64`.
    pub fn bump_revocation(env: Env, did_hash: BytesN<32>, reason: u32) -> u64 {
        let key = DataKey::Anchor(did_hash.clone());
        let mut anchor: Anchor = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, AnchorError::AnchorNotFound));

        anchor.owner.require_auth();

        anchor.epoch = anchor
            .epoch
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(&env, AnchorError::EpochOverflow));
        anchor.updated_at = env.ledger().timestamp();

        env.storage().persistent().set(&key, &anchor);
        env.storage()
            .persistent()
            .extend_ttl(&key, ANCHOR_TTL_THRESHOLD, ANCHOR_TTL);

        env.events().publish(
            (Symbol::new(&env, "bump_revocation"), did_hash),
            (anchor.epoch, reason),
        );

        anchor.epoch
    }

    /// Read the current anchor record for a DID, or `None` if it has never been anchored.
    pub fn get_anchor(env: Env, did_hash: BytesN<32>) -> Option<Anchor> {
        env.storage()
            .persistent()
            .get(&DataKey::Anchor(did_hash))
    }
}

#[cfg(test)]
mod test;
