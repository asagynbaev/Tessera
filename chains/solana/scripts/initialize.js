#!/usr/bin/env node
//
// initialize.js — call identity_registry `initialize(admin)` to create the singleton
// RegistryConfig PDA (seed ["config"]) and record the admin pubkey that gates issuer
// registration / deactivation.
//
// OPTIONAL. The devnet smoke tests exercise register_did / update_root / bump_revocation,
// which are owner-signed and need no RegistryConfig — so they do NOT require this. Run it
// only when you will use register_issuer / deactivate_issuer.
//
// Normally invoked via ./scripts/initialize-devnet.sh, which resolves the env below.
// Depends only on @solana/web3.js (see package.json) — the Anchor instruction is encoded
// by hand: 8-byte discriminator sha256("global:initialize")[..8] ++ admin pubkey (32 bytes).
//
// Env:
//   TESSERA_SOLANA_RPC            RPC URL (default https://api.devnet.solana.com)
//   TESSERA_SOLANA_PROGRAM_ID     deployed identity-registry program id, base58 (required)
//   TESSERA_SOLANA_PAYER_KEYPAIR  path to the Solana CLI JSON keypair that pays + signs (required)
// Args:
//   argv[2]  admin pubkey, base58 (optional; defaults to the payer's pubkey)

const fs = require("fs");
const crypto = require("crypto");
const {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  sendAndConfirmTransaction,
} = require("@solana/web3.js");

function reqEnv(name) {
  const v = process.env[name];
  if (!v || !v.trim()) {
    console.error(`error: missing required env ${name}`);
    process.exit(1);
  }
  return v.trim();
}

async function main() {
  const rpc = (process.env.TESSERA_SOLANA_RPC || "https://api.devnet.solana.com").trim();
  const programId = new PublicKey(reqEnv("TESSERA_SOLANA_PROGRAM_ID"));
  const keypairPath = reqEnv("TESSERA_SOLANA_PAYER_KEYPAIR");

  const secret = Uint8Array.from(JSON.parse(fs.readFileSync(keypairPath, "utf8")));
  if (secret.length !== 64) {
    console.error(`error: expected a 64-byte Solana CLI keypair at ${keypairPath} (got ${secret.length}).`);
    process.exit(1);
  }
  const payer = Keypair.fromSecretKey(secret);
  const admin = process.argv[2] ? new PublicKey(process.argv[2]) : payer.publicKey;

  // RegistryConfig is a singleton PDA seeded by the constant ["config"] — must match the
  // REGISTRY_CONFIG_SEED in programs/identity-registry/src/lib.rs.
  const [configPda] = PublicKey.findProgramAddressSync([Buffer.from("config")], programId);

  const conn = new Connection(rpc, "confirmed");

  console.log(`RPC:            ${rpc}`);
  console.log(`Program:        ${programId.toBase58()}`);
  console.log(`RegistryConfig: ${configPda.toBase58()}`);
  console.log(`Payer:          ${payer.publicKey.toBase58()}`);
  console.log(`Admin:          ${admin.toBase58()}`);

  // Idempotent: the constant seed means a second initialize would fail with
  // AccountAlreadyInUse. If the config already exists, report and exit cleanly.
  const existing = await conn.getAccountInfo(configPda);
  if (existing) {
    console.log(`\nRegistryConfig already initialized — nothing to do.`);
    return;
  }

  // Anchor call data: discriminator ++ Borsh(admin: Pubkey). A Pubkey is 32 raw bytes with
  // no length prefix, so concatenation is the full Borsh encoding of the single arg.
  const disc = crypto.createHash("sha256").update("global:initialize").digest().subarray(0, 8);
  const data = Buffer.concat([disc, admin.toBuffer()]);

  // Account order must match the Initialize<'info> context in src/lib.rs:
  //   registry_config (PDA, writable) ▸ payer (signer, writable) ▸ system_program.
  const ix = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: configPda, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });

  const sig = await sendAndConfirmTransaction(conn, new Transaction().add(ix), [payer], {
    commitment: "confirmed",
  });

  console.log(`\ninitialize tx:  ${sig}`);
  console.log(`Explorer:       https://explorer.solana.com/tx/${sig}?cluster=devnet`);
}

main().catch((e) => {
  console.error(`error: ${e && e.message ? e.message : e}`);
  process.exit(1);
});
