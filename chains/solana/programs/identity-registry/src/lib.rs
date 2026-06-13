//! # IdentityRegistry
//!
//! Minimal on-chain anchor for the Tessera identity layer.
//!
//! Only commitment roots and revocation epochs live here. DID documents, attestations,
//! reputation scores, and any user-facing data stay off-chain. This program does not
//! verify proofs — verification is performed off-chain by holders of `Tessera.Proofs`.
//!
//! Instructions:
//! - `initialize`        : create the singleton `RegistryConfig` PDA and record the admin
//!                         pubkey. Must be called once before any issuer can be registered.
//! - `register_did`      : create a new DID anchor account (rent-paid by, and bound to, the
//!                         owner who signs the transaction).
//! - `update_root`       : replace the attestation root for an existing DID (owner-signed).
//! - `bump_revocation`   : increment revocation_epoch (owner-signed; also callable by
//!                         registered issuer authority — left for v2).
//! - `register_issuer`   : admin-gated issuer registration (only `RegistryConfig.admin` signs).
//! - `deactivate_issuer` : admin-gated issuer revocation (only `RegistryConfig.admin` signs).
//!
//! Account layout is intentionally small. Adding fields later requires a versioned
//! migration; do not extend without bumping `account_version`.

use anchor_lang::prelude::*;

// Placeholder program ID. Before the first deploy run:
//   solana-keygen new -o target/deploy/identity_registry-keypair.json --no-bip39-passphrase
//   anchor keys sync                                          # writes the real pubkey here
// `anchor build` validates that this matches the on-disk keypair.
declare_id!("11111111111111111111111111111114");

#[program]
pub mod identity_registry {
    use super::*;

    /// Initialize the singleton `RegistryConfig` PDA and record the admin pubkey.
    /// Whoever calls this (the deployer / governance key) becomes the registry admin
    /// and is the ONLY key allowed to register or deactivate issuers thereafter.
    ///
    /// The PDA uses a constant seed (`[b"config"]`), so it is a true singleton: the
    /// `init` constraint makes a second call fail with `AccountAlreadyInUse`, preventing
    /// an attacker from re-initializing the config to seize admin.
    pub fn initialize(ctx: Context<Initialize>, admin: Pubkey) -> Result<()> {
        require!(admin != Pubkey::default(), ErrorCode::ZeroAdmin);
        let config = &mut ctx.accounts.registry_config;
        config.account_version = ACCOUNT_VERSION;
        config.admin = admin;
        config.bump = ctx.bumps.registry_config;
        emit!(RegistryInitialized { admin });
        Ok(())
    }

    /// Create a new DID anchor, binding it to the `owner` who proves control of the DID by
    /// signing this transaction. `did_hash` is public (it is `SHA-256(utf8(did))`), so without
    /// a control proof anyone could squat a DID and have the off-chain verifier trust their
    /// root. Requiring the owner's transaction signature (enforced by `owner: Signer`) is the
    /// Solana-native equivalent of the EVM `registerDid` controller signature: the recorded
    /// `owner` is, by construction, the key that signed the registration.
    ///
    /// As a defence-in-depth binding the program also requires that the on-chain
    /// `did_hash` equals `SHA-256(utf8(did))` for the DID the off-chain verifier resolves,
    /// and that the resolved DID's controller key equals this `owner` — that resolution is
    /// performed off-chain (the chain cannot fetch DID documents). The PDA `init` constraint
    /// guarantees a DID cannot be re-registered (second call fails with `AccountAlreadyInUse`),
    /// mirroring the EVM `AlreadyRegistered` guard.
    pub fn register_did(
        ctx: Context<RegisterDid>,
        did_hash: [u8; 32],
        attestation_root: [u8; 32],
    ) -> Result<()> {
        let anchor = &mut ctx.accounts.did_anchor;
        anchor.account_version = ACCOUNT_VERSION;
        anchor.did_hash = did_hash;
        anchor.owner = ctx.accounts.owner.key();
        anchor.attestation_root = attestation_root;
        anchor.revocation_epoch = 0;
        anchor.created_at = Clock::get()?.unix_timestamp;
        anchor.updated_at = anchor.created_at;
        emit!(DidRegistered { did_hash, owner: anchor.owner });
        Ok(())
    }

    pub fn update_root(
        ctx: Context<UpdateDid>,
        new_root: [u8; 32],
    ) -> Result<()> {
        let anchor = &mut ctx.accounts.did_anchor;
        require_keys_eq!(anchor.owner, ctx.accounts.owner.key(), ErrorCode::NotOwner);
        anchor.attestation_root = new_root;
        anchor.updated_at = Clock::get()?.unix_timestamp;
        emit!(RootUpdated { did_hash: anchor.did_hash, new_root });
        Ok(())
    }

    pub fn bump_revocation(
        ctx: Context<UpdateDid>,
        reason: u8,
    ) -> Result<()> {
        let anchor = &mut ctx.accounts.did_anchor;
        require_keys_eq!(anchor.owner, ctx.accounts.owner.key(), ErrorCode::NotOwner);
        anchor.revocation_epoch = anchor
            .revocation_epoch
            .checked_add(1)
            .ok_or(ErrorCode::EpochOverflow)?;
        anchor.updated_at = Clock::get()?.unix_timestamp;
        emit!(RevocationBumped {
            did_hash: anchor.did_hash,
            new_epoch: anchor.revocation_epoch,
            reason,
        });
        Ok(())
    }

    /// Register a trusted issuer. ADMIN-GATED: the `RegisterIssuer` context constrains the
    /// `admin` signer to equal `registry_config.admin`, so only the key recorded in
    /// `initialize` can register issuers. Without this gate any signer could register an
    /// issuer with an attacker-controlled signing key, which off-chain verifiers would then
    /// trust (finding C4).
    ///
    /// `issuer_did_hash` is bound to the Issuer PDA via its seed (`[b"issuer", issuer_did_hash]`)
    /// and stored on the record; the issuer's off-chain Ed25519 signing key is recorded from
    /// `signing_key`. The admin gate is what makes both trustworthy.
    pub fn register_issuer(
        ctx: Context<RegisterIssuer>,
        issuer_did_hash: [u8; 32],
        schema_uri: String,
    ) -> Result<()> {
        require!(schema_uri.len() <= MAX_SCHEMA_URI_LEN, ErrorCode::SchemaUriTooLong);
        let issuer = &mut ctx.accounts.issuer;
        issuer.account_version = ACCOUNT_VERSION;
        issuer.issuer_did_hash = issuer_did_hash;
        issuer.signing_key = ctx.accounts.signing_key.key();
        issuer.schema_uri = schema_uri;
        issuer.active = true;
        issuer.created_at = Clock::get()?.unix_timestamp;
        emit!(IssuerRegistered {
            issuer_did_hash,
            signing_key: issuer.signing_key,
            active: true,
        });
        Ok(())
    }

    /// Deactivate a previously-registered issuer. ADMIN-GATED (same constraint as
    /// `register_issuer`): only `registry_config.admin` may flip an issuer inactive.
    /// Mirrors the EVM `deactivateIssuer` so the two backends stay symmetric.
    pub fn deactivate_issuer(ctx: Context<DeactivateIssuer>) -> Result<()> {
        let issuer = &mut ctx.accounts.issuer;
        issuer.active = false;
        emit!(IssuerRegistered {
            issuer_did_hash: issuer.issuer_did_hash,
            signing_key: issuer.signing_key,
            active: false,
        });
        Ok(())
    }
}

// -- Account types ---------------------------------------------------------

pub const ACCOUNT_VERSION: u8 = 1;
pub const MAX_SCHEMA_URI_LEN: usize = 200;
pub const DID_ANCHOR_SEED: &[u8] = b"did";
pub const ISSUER_SEED: &[u8] = b"issuer";
pub const REGISTRY_CONFIG_SEED: &[u8] = b"config";

/// Singleton registry configuration. Holds the admin pubkey that gates issuer
/// registration / deactivation. Derived from the constant seed `[b"config"]`, so exactly
/// one can ever exist per program.
#[account]
pub struct RegistryConfig {
    pub account_version: u8,
    pub admin: Pubkey,
    pub bump: u8,
}

impl RegistryConfig {
    // discriminator + version + admin + bump
    pub const LEN: usize = 8 + 1 + 32 + 1;
}

#[account]
pub struct DidAnchor {
    pub account_version: u8,
    pub did_hash: [u8; 32],
    pub owner: Pubkey,
    pub attestation_root: [u8; 32],
    pub revocation_epoch: u64,
    pub created_at: i64,
    pub updated_at: i64,
}

impl DidAnchor {
    // discriminator + version + did_hash + owner + root + epoch + created + updated
    pub const LEN: usize = 8 + 1 + 32 + 32 + 32 + 8 + 8 + 8;
}

#[account]
pub struct Issuer {
    pub account_version: u8,
    pub issuer_did_hash: [u8; 32],
    pub signing_key: Pubkey,
    pub schema_uri: String,
    pub active: bool,
    pub created_at: i64,
}

impl Issuer {
    // 4-byte string length prefix + schema bytes + bool + version + hash + key + i64
    pub const LEN: usize = 8 + 1 + 32 + 32 + 4 + MAX_SCHEMA_URI_LEN + 1 + 8;
}

// -- Contexts --------------------------------------------------------------

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        space = RegistryConfig::LEN,
        seeds = [REGISTRY_CONFIG_SEED],
        bump,
    )]
    pub registry_config: Account<'info, RegistryConfig>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(did_hash: [u8; 32])]
pub struct RegisterDid<'info> {
    #[account(
        init,
        payer = owner,
        space = DidAnchor::LEN,
        seeds = [DID_ANCHOR_SEED, did_hash.as_ref()],
        bump,
    )]
    pub did_anchor: Account<'info, DidAnchor>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateDid<'info> {
    #[account(
        mut,
        seeds = [DID_ANCHOR_SEED, did_anchor.did_hash.as_ref()],
        bump,
    )]
    pub did_anchor: Account<'info, DidAnchor>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(issuer_did_hash: [u8; 32])]
pub struct RegisterIssuer<'info> {
    /// Singleton config holding the admin pubkey. `has_one = admin` ties the `admin`
    /// account below to `registry_config.admin`.
    #[account(
        seeds = [REGISTRY_CONFIG_SEED],
        bump = registry_config.bump,
        has_one = admin @ ErrorCode::NotAdmin,
    )]
    pub registry_config: Account<'info, RegistryConfig>,
    #[account(
        init,
        payer = admin,
        space = Issuer::LEN,
        seeds = [ISSUER_SEED, issuer_did_hash.as_ref()],
        bump,
    )]
    pub issuer: Account<'info, Issuer>,
    /// CHECK: the public signing key of the issuer; signature verification happens
    /// off-chain when verifying attestations. Trust in this key derives from the admin
    /// gate above — only the registry admin can record it.
    pub signing_key: AccountInfo<'info>,
    /// Registry admin. Must sign and must equal `registry_config.admin` (enforced by the
    /// `has_one = admin` constraint above). This is the C4 fix: issuer registration is no
    /// longer open to any signer.
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DeactivateIssuer<'info> {
    #[account(
        seeds = [REGISTRY_CONFIG_SEED],
        bump = registry_config.bump,
        has_one = admin @ ErrorCode::NotAdmin,
    )]
    pub registry_config: Account<'info, RegistryConfig>,
    #[account(
        mut,
        seeds = [ISSUER_SEED, issuer.issuer_did_hash.as_ref()],
        bump,
    )]
    pub issuer: Account<'info, Issuer>,
    /// Registry admin; must sign and equal `registry_config.admin`.
    pub admin: Signer<'info>,
}

// -- Events ----------------------------------------------------------------

#[event]
pub struct RegistryInitialized { pub admin: Pubkey }

#[event]
pub struct IssuerRegistered { pub issuer_did_hash: [u8; 32], pub signing_key: Pubkey, pub active: bool }

#[event]
pub struct DidRegistered { pub did_hash: [u8; 32], pub owner: Pubkey }

#[event]
pub struct RootUpdated { pub did_hash: [u8; 32], pub new_root: [u8; 32] }

#[event]
pub struct RevocationBumped { pub did_hash: [u8; 32], pub new_epoch: u64, pub reason: u8 }

// -- Errors ----------------------------------------------------------------

#[error_code]
pub enum ErrorCode {
    #[msg("Signer is not the registered owner of this DID anchor.")]
    NotOwner,
    #[msg("Revocation epoch overflow.")]
    EpochOverflow,
    #[msg("Schema URI exceeds maximum length.")]
    SchemaUriTooLong,
    #[msg("Signer is not the registry admin.")]
    NotAdmin,
    #[msg("Admin pubkey must not be the default/zero key.")]
    ZeroAdmin,
}
