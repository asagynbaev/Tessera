using System.Security.Cryptography;
using Tessera.Attestations;
using Tessera.Chains;
using Tessera.Chains.Cardano;
using Tessera.Core;
using Tessera.Did;
using Tessera.Sdk;
using Tessera.Signing;

// ─────────────────────────────────────────────────────────────────────────────
// Cardano credit-line demo.
//
//   issuer commits annual_income (Pedersen)  →  signs an attestation carrying it
//   holder anchors the attestation root on Cardano preprod (Validator mode)
//   holder proves income ≥ 50,000 with a Bulletproof bound to that commitment
//   verifier checks the presentation + the on-chain root + revocation epoch
//   → "credit line approved"
//
// Runs with only two environment variables:
//   TESSERA_CARDANO_BLOCKFROST_KEY  — a Blockfrost preprod project id
//   TESSERA_CARDANO_SKEY            — a funded preprod payment mnemonic (faucet)
// ─────────────────────────────────────────────────────────────────────────────

var blockfrostKey = Environment.GetEnvironmentVariable("TESSERA_CARDANO_BLOCKFROST_KEY");
var signingKey = Environment.GetEnvironmentVariable("TESSERA_CARDANO_SKEY");

if (string.IsNullOrWhiteSpace(blockfrostKey) || string.IsNullOrWhiteSpace(signingKey))
{
    Console.WriteLine("""
        This demo anchors on the Cardano preprod testnet, so it needs two env vars:

          TESSERA_CARDANO_BLOCKFROST_KEY = <your Blockfrost preprod project id>
          TESSERA_CARDANO_SKEY           = <a funded preprod payment mnemonic>

        Get a Blockfrost preprod key at https://blockfrost.io and fund the wallet
        address (printed by the adapter) from https://docs.cardano.org/cardano-testnets/tools/faucet.
        See chains/cardano/DEPLOYMENT.md for the full walkthrough.
        """);
    return 1;
}

// ── 1. On-chain anchor (Cardano preprod, Validator mode) ─────────────────────
using var anchor = new CardanoChainAnchor(new CardanoAnchorOptions
{
    Network = CardanoNetwork.Preprod,
    BlockfrostProjectId = blockfrostKey,
    SigningKey = signingKey,
    AnchorMode = AnchorMode.Validator,
});
Console.WriteLine($"Anchoring on chain: {anchor.ChainId}");

// ── 2. Issuer: commit the income value and sign an attestation carrying it ────
var signatureVerifier = new Ed25519Verifier();
var registry = new InMemoryIssuerRegistry();

var (issuerPriv, _) = Ed25519.GenerateKeypair();
using var issuerSigner = new Ed25519IssuerSigner(issuerPriv);
var issuer = new Issuer(new DidId("did:tessera:credit-bureau"), issuerSigner);
registry.Register(issuer.BuildRegistryRecord(schemaUri: "https://schemas.tessera/income/v1"));

const long annualIncome = 72_000;
const long required = 50_000;

var proof = new CredentialProof();
var (commitment, opening) = proof.CommitValue(annualIncome);
Console.WriteLine($"Issuer committed annual_income (hidden). Threshold to clear: {required:N0}.");

// ── 3. Holder: accept the attestation, anchor the root on Cardano ────────────
var (holderPriv, holderPub) = Ed25519.GenerateKeypair();
var holder = await Holder.CreateAsync(holderPub, new HolderOptions
{
    Store = new InMemoryDidStore(),
    SignatureVerifier = signatureVerifier,
    ChainAnchor = anchor,
});
Console.WriteLine($"Holder DID: {holder.Did}");

var attestation = issuer.Issue(
    AttestationTypes.Accredited,
    holder.Did,
    new AttestationPayload { Method = "annual_income", Commitment = commitment });
holder.AcceptAttestation(attestation);

Console.WriteLine("Anchoring the attestation root on Cardano preprod (this submits a Plutus tx and awaits a block)…");
AnchorTxResult tx;
try
{
    tx = await holder.AnchorRootAsync();
}
catch (Exception ex)
{
    Console.WriteLine($"Anchoring failed: {ex.Message}");
    Console.WriteLine("Ensure the controller wallet holds preprod test ADA (fees + collateral).");
    return 1;
}
Console.WriteLine($"  anchored — tx {tx.TxId}");

// ── 4. Holder proves income ≥ 50,000 without revealing it ────────────────────
// Standalone proof (the prompt's literal ProveMinimum):
var standalone = proof.ProveMinimum(annualIncome, required, "income");
Console.WriteLine($"  ProveMinimum verifies: {proof.Verify(standalone)}");

// Attestation-bound proof (the sound path the verifier policy accepts):
var bound = proof.ProveBoundMinimum(annualIncome, required, opening, "income");
Console.WriteLine($"  ProveBoundMinimum bound to the attested commitment: {proof.VerifyBound(commitment, bound)}");

// ── 5. Build the presentation, attaching the bound predicate proof ───────────
var lender = new DidId("did:tessera:lender-app");
var sessionNonce = RandomNumberGenerator.GetBytes(16);

var bundle = new AttestationBundle(holder.Attestations);
var disclosure = bundle.DisclosureFor(0) with { PredicateProof = PredicateProofCodec.Encode(bound) };
var presentation = new Presentation
{
    Holder = holder.Did,
    Disclosures = new[] { disclosure },
    Binding = new PresentationBinding
    {
        Verifier = lender,
        SessionNonce = sessionNonce,
        AsOfRevocationEpoch = 0,
        Chain = anchor.ChainId,
        HolderSignature = Array.Empty<byte>(), // placeholder, replaced below
        HolderPublicKey = holderPub,
        CreatedAt = DateTimeOffset.UtcNow,
    },
};

// The presenter authenticates by signing the canonical challenge with the holder controller key.
presentation = presentation with
{
    Binding = presentation.Binding with
    {
        HolderSignature = Ed25519.Sign(holderPriv, PresentationChallenge.Compute(presentation)),
    },
};

// ── 6. Verifier: check the presentation + on-chain root + revocation epoch ───
var verifier = new Verifier(new VerifierOptions
{
    IssuerRegistry = registry,
    SignatureVerifier = signatureVerifier,
    ChainAnchor = anchor, // reads the anchored root + revocation epoch from Cardano
});

var result = await verifier.VerifyPresentationAsync(presentation, new VerificationPolicy
{
    ExpectedVerifier = lender,
    ExpectedSessionNonce = sessionNonce,
    RequireCurrentRevocationEpoch = true,
    RequiredTypes = new[] { AttestationTypes.Accredited },
    PredicateRequirements = new[]
    {
        new PredicateRequirement { Type = AttestationTypes.Accredited, Label = "income", ProofType = CredentialProofType.Minimum, Threshold = required },
    },
});

Console.WriteLine();
if (result.Valid)
{
    Console.WriteLine("credit line approved");
    return 0;
}

Console.WriteLine($"credit line denied: {result.Reason}");
return 2;
