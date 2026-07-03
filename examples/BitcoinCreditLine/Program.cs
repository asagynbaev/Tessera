using System.Security.Cryptography;
using System.Text;
using NBitcoin;
using NBitcoin.Crypto;
using Tessera.Attestations;
using Tessera.Chains;
using Tessera.Chains.Cardano;
using Tessera.Core;
using Tessera.Did;
using Tessera.Sdk;
using Tessera.Signing;
using Tessera.Sources.Bitcoin;

// ─────────────────────────────────────────────────────────────────────────────
// Bitcoin proof-of-balance credit-line demo.
//
//   holder proves control of a testnet BTC address (BIP-137 signed challenge)
//   issuer commits the confirmed balance (Pedersen) → signs a btc_balance attestation
//   holder anchors the attestation root on Cardano preprod
//   holder proves btc_balance ≥ 1 BTC with a Bulletproof bound to that commitment
//   verifier checks the presentation + the on-chain root + revocation epoch
//   → "proof of bitcoin verified"
//
// Anchoring runs on a live testnet, so it needs:
//   TESSERA_CARDANO_BLOCKFROST_KEY  — a Blockfrost preprod project id
//   TESSERA_CARDANO_SKEY            — a funded preprod payment mnemonic (faucet)
//   TESSERA_CARDANO_ANCHOR_MODE     — optional; "metadata" for the cheaper fallback (default: validator)
//
// The Bitcoin control proof and the Bulletproof are fully real. The on-chain BTC *balance* is a
// fixed simulated holding (funding ≥1 BTC on testnet isn't practical); the live EsploraBitcoinProvider
// read is exercised by the env-gated integration test (TESSERA_BITCOIN_E2E=1).
// ─────────────────────────────────────────────────────────────────────────────

var blockfrostKey = Environment.GetEnvironmentVariable("TESSERA_CARDANO_BLOCKFROST_KEY");
var signingKey = Environment.GetEnvironmentVariable("TESSERA_CARDANO_SKEY");

if (string.IsNullOrWhiteSpace(blockfrostKey) || string.IsNullOrWhiteSpace(signingKey))
{
    Console.WriteLine("""
        This demo anchors on the Cardano preprod testnet, so it needs two env vars:

          TESSERA_CARDANO_BLOCKFROST_KEY = <your Blockfrost preprod project id>
          TESSERA_CARDANO_SKEY           = <a funded preprod payment mnemonic>

        Optional:
          TESSERA_CARDANO_ANCHOR_MODE    = metadata   # cheaper fallback (default: validator)

        Get a Blockfrost preprod key at https://blockfrost.io and fund the wallet address
        (printed by the adapter) from https://docs.cardano.org/cardano-testnets/tools/faucet.
        See chains/cardano/DEPLOYMENT.md for the full walkthrough.
        """);
    return 1;
}

var anchorMode = string.Equals(Environment.GetEnvironmentVariable("TESSERA_CARDANO_ANCHOR_MODE"), "metadata", StringComparison.OrdinalIgnoreCase)
    ? AnchorMode.Metadata
    : AnchorMode.Validator;

// ── 1. On-chain anchor (Cardano preprod) ─────────────────────────────────────
using var anchor = new CardanoChainAnchor(new CardanoAnchorOptions
{
    Network = CardanoNetwork.Preprod,
    BlockfrostProjectId = blockfrostKey,
    SigningKey = signingKey,
    AnchorMode = anchorMode,
});
Console.WriteLine($"Anchoring on chain: {anchor.ChainId} (mode: {anchorMode})");

// ── 2. Issuer ────────────────────────────────────────────────────────────────
var signatureVerifier = new Ed25519Verifier();
var registry = new InMemoryIssuerRegistry();

var (issuerPriv, _) = Ed25519.GenerateKeypair();
using var issuerSigner = new Ed25519IssuerSigner(issuerPriv);
var issuer = new Issuer(new DidId("did:tessera:proof-of-bitcoin"), issuerSigner);
registry.Register(issuer.BuildRegistryRecord(schemaUri: BitcoinSchemas.SchemaNamespace));

// ── 3. Holder ────────────────────────────────────────────────────────────────
var (holderPriv, holderPub) = Ed25519.GenerateKeypair();
var holder = await Holder.CreateAsync(holderPub, new HolderOptions
{
    Store = new InMemoryDidStore(),
    SignatureVerifier = signatureVerifier,
    ChainAnchor = anchor,
});
Console.WriteLine($"Holder DID: {holder.Did}");

// ── 4. Bitcoin control proof: holder signs a challenge with their testnet wallet ──
const string audience = "tessera-proof-of-bitcoin";
var wallet = new Key(); // the holder's Bitcoin wallet (kept secret; only the signature is shared)
var btcAddress = wallet.PubKey.GetAddress(ScriptPubKeyType.Segwit, Network.TestNet).ToString();
Console.WriteLine($"Holder Bitcoin address (testnet, P2WPKH): {btcAddress}");

var challenge = BitcoinChallenge.Create(holder.Did, audience, TimeSpan.FromMinutes(10));
var signature = BitcoinWallet.SignChallenge(wallet, challenge.ToCanonicalString());

// Single-node demo: an in-memory nonce store is fine here. Production must pass a shared,
// durable store (Redis / a database) so a replayed (address, signature) tuple can't be
// accepted after a restart or on a second node.
var control = new BitcoinControlVerifier(new Tessera.Sources.Bitcoin.InMemoryNonceStore());
var controlResult = await control.VerifyAsync(challenge, audience, btcAddress, signature, BitcoinNetwork.Testnet);
if (!controlResult.IsValid)
{
    Console.WriteLine($"Bitcoin control proof failed: {controlResult.Reason}");
    return 2;
}
Console.WriteLine($"  control proven for a {controlResult.AddressType} address (BIP-137 signature verified)");

// ── 5. Facts → drafts (btc_control / btc_balance / btc_hodl_age) ──────────────
// Simulated holding for the demo (see header). The control signature and the proof below are real.
const long simulatedSats = 150_000_000; // 1.5 BTC
var provider = new SimulatedBitcoinProvider(btcAddress, simulatedSats, ageDays: 400);
var source = new BitcoinAttestationSource(provider);
var result = await source.ResolveForAsync(holder.Did, new[] { controlResult.Verified! });

var balanceDraft = result.Drafts.Single(d => d.Type == BitcoinAttestationTypes.Balance);
var balanceOpening = result.Openings[BitcoinAttestationTypes.Balance];
Console.WriteLine($"  issuer committed btc_balance (hidden). hodl age ≈ {result.Facts.HodlAgeDays} days, {result.Facts.AddressCount} address proven.");

// ── 6. Issue the btc_balance attestation; holder accepts + anchors the root ───
var attestation = issuer.Issue(balanceDraft.Type, holder.Did, balanceDraft.Payload);
holder.AcceptAttestation(attestation);

Console.WriteLine("Anchoring the attestation root on Cardano preprod (submits a tx and awaits a block)…");
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

// ── 7. Holder proves btc_balance ≥ 1 BTC without revealing it ─────────────────
const long oneBtc = 100_000_000;
var cp = new CredentialProof();
var bound = cp.ProveBoundMinimum(result.Facts.TotalSats, oneBtc, balanceOpening, "btc_balance");
Console.WriteLine($"  ProveBoundMinimum bound to the committed balance: {cp.VerifyBound(balanceDraft.Payload.Commitment!, bound)}");

// ── 8. Build the presentation, attaching the bound predicate proof ────────────
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

// ── 9. Verifier: presentation + on-chain root + the btc_balance ≥ 1 BTC predicate ──
var verifier = new Verifier(new VerifierOptions
{
    IssuerRegistry = registry,
    SignatureVerifier = signatureVerifier,
    ChainAnchor = anchor, // reads the anchored root + revocation epoch from Cardano
});

var verification = await verifier.VerifyPresentationAsync(presentation, new VerificationPolicy
{
    ExpectedVerifier = lender,
    ExpectedSessionNonce = sessionNonce,
    RequireCurrentRevocationEpoch = true,
    RequiredTypes = new[] { BitcoinAttestationTypes.Balance },
    PredicateRequirements = new[]
    {
        new PredicateRequirement { Type = BitcoinAttestationTypes.Balance, Label = "btc_balance", ProofType = CredentialProofType.Minimum, Threshold = oneBtc },
    },
});

Console.WriteLine();
if (verification.Valid)
{
    Console.WriteLine("proof of bitcoin verified — balance ≥ 1 BTC, never revealed");
    return 0;
}

Console.WriteLine($"verification failed: {verification.Reason}");
return 2;

// ─────────────────────────────────────────────────────────────────────────────

/// <summary>Signs a Tessera challenge the way a holder's wallet <c>signmessage</c> would (BIP-137, P2WPKH header).</summary>
static class BitcoinWallet
{
    public static string SignChallenge(Key key, string canonical)
    {
        var headerBytes = Encoding.UTF8.GetBytes("Bitcoin Signed Message:\n");
        var msgBytes = Encoding.UTF8.GetBytes(canonical);
        using var ms = new MemoryStream();
        WriteVarInt(ms, (ulong)headerBytes.Length);
        ms.Write(headerBytes, 0, headerBytes.Length);
        WriteVarInt(ms, (ulong)msgBytes.Length);
        ms.Write(msgBytes, 0, msgBytes.Length);

        var hash = Hashes.DoubleSHA256(ms.ToArray());
        var cs = key.SignCompact(hash);
        var full = new byte[65];
        full[0] = (byte)(27 + cs.RecoveryId + 4 + 8); // compressed P2WPKH BIP-137 header (39–42)
        cs.Signature.CopyTo(full, 1);
        return Convert.ToBase64String(full);
    }

    private static void WriteVarInt(Stream s, ulong v)
    {
        if (v < 0xFD) { s.WriteByte((byte)v); }
        else { s.WriteByte(0xFD); s.WriteByte((byte)v); s.WriteByte((byte)(v >> 8)); }
    }
}

/// <summary>A fixed-holding <see cref="IBitcoinProvider"/> for the demo (see the file header).</summary>
sealed class SimulatedBitcoinProvider : IBitcoinProvider
{
    private readonly string _address;
    private readonly long _sats;
    private readonly int _ageDays;

    public SimulatedBitcoinProvider(string address, long sats, int ageDays)
        => (_address, _sats, _ageDays) = (address, sats, ageDays);

    public Task<BitcoinAddressSummary> GetAddressSummaryAsync(string address, CancellationToken ct = default)
        => Task.FromResult(new BitcoinAddressSummary { Address = address, ConfirmedSats = address == _address ? _sats : 0 });

    public Task<IReadOnlyList<BitcoinUtxo>> GetUtxosAsync(string address, CancellationToken ct = default)
    {
        if (address != _address)
            return Task.FromResult((IReadOnlyList<BitcoinUtxo>)Array.Empty<BitcoinUtxo>());
        var blockTime = DateTimeOffset.UtcNow.AddDays(-_ageDays).ToUnixTimeSeconds();
        var utxo = new BitcoinUtxo
        {
            TxId = "demo000000000000000000000000000000000000000000000000000000000000",
            Vout = 0,
            ValueSats = _sats,
            BlockHeight = 1,
            BlockTime = blockTime,
        };
        return Task.FromResult((IReadOnlyList<BitcoinUtxo>)new[] { utxo });
    }

    public Task<BitcoinChainTip> GetChainTipAsync(CancellationToken ct = default)
        => Task.FromResult(new BitcoinChainTip
        {
            BlockHeight = 2_580_000, // a plausible testnet tip for the demo
            BlockHash = "00000000000000000000000000000000000000000000000000000000deadbeef",
            BlockTimeUtc = DateTimeOffset.UtcNow,
        });
}
