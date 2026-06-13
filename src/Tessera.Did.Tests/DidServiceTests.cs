using System.Security.Cryptography;
using Tessera.Core;
using Tessera.Did;

namespace Tessera.Did.Tests;

public class DidServiceTests
{
    /// <summary>
    /// Test keyring: maps public keys to private keys so a single stub verifier can
    /// verify signatures from multiple identities (DID controller AND wallets).
    /// Signatures are SHA-256(privKey || message). Not real Ed25519 — just enough
    /// to exercise the service plumbing.
    /// </summary>
    private sealed class TestKeyring
    {
        private readonly Dictionary<string, byte[]> _privBySerializedPub = new();

        public (byte[] Pub, byte[] Priv) NewKey()
        {
            var priv = RandomNumberGenerator.GetBytes(32);
            var pub = SHA256.HashData(priv);
            _privBySerializedPub[Convert.ToHexString(pub)] = priv;
            return (pub, priv);
        }

        public byte[] Sign(byte[] privateKey, byte[] message)
        {
            var input = new byte[privateKey.Length + message.Length];
            Buffer.BlockCopy(privateKey, 0, input, 0, privateKey.Length);
            Buffer.BlockCopy(message, 0, input, privateKey.Length, message.Length);
            return SHA256.HashData(input);
        }

        public ISignatureVerifier Verifier => new Ed25519SignatureVerifier((pk, msg, sig) =>
        {
            if (!_privBySerializedPub.TryGetValue(Convert.ToHexString(pk), out var priv)) return false;
            var expected = Sign(priv, msg.ToArray());
            return sig.SequenceEqual(expected);
        });
    }

    [Fact]
    public async Task Create_DerivesStableDid()
    {
        var kr = new TestKeyring();
        var (pub, _) = kr.NewKey();
        var svc = new DidService(new InMemoryDidStore(), kr.Verifier);

        var doc = await svc.CreateAsync(pub);
        Assert.True(doc.Id.IsWellFormed);
        Assert.Equal(doc.Id, doc.Controller);
        Assert.Single(doc.VerificationMethods);
        Assert.Equal("Ed25519VerificationKey2020", doc.VerificationMethods[0].Type);
    }

    [Fact]
    public async Task Create_SameKey_FailsBecauseDidAlreadyExists()
    {
        var kr = new TestKeyring();
        var (pub, _) = kr.NewKey();
        var svc = new DidService(new InMemoryDidStore(), kr.Verifier);

        await svc.CreateAsync(pub);
        await Assert.ThrowsAsync<InvalidOperationException>(() => svc.CreateAsync(pub));
    }

    [Fact]
    public async Task Create_RequiresThirtyTwoByteKey()
    {
        var svc = new DidService(new InMemoryDidStore(), new TestKeyring().Verifier);
        await Assert.ThrowsAsync<ArgumentException>(() => svc.CreateAsync(new byte[16]));
    }

    [Fact]
    public async Task BindWallet_AcceptsValidSignature()
    {
        var kr = new TestKeyring();
        var (didPub, _) = kr.NewKey();
        var (walletPub, walletPriv) = kr.NewKey();
        var svc = new DidService(new InMemoryDidStore(), kr.Verifier);
        var doc = await svc.CreateAsync(didPub);

        var nonce = RandomNumberGenerator.GetBytes(16);
        var expiry = DateTimeOffset.UtcNow.AddMinutes(5);

        // A real Solana address is Base58(pubkey); the control verifier requires this.
        var solanaAddress = Base58.Encode(walletPub);

        var unsigned = new WalletBindingRequest
        {
            Chain = "solana",
            Address = solanaAddress,
            WalletPublicKey = walletPub,
            Nonce = nonce,
            Expiry = expiry,
            Signature = Array.Empty<byte>(),
        };

        var sig = kr.Sign(walletPriv, DidService.BuildWalletChallenge(doc.Id, unsigned));
        var request = unsigned with { Signature = sig };

        var updated = await svc.BindWalletAsync(doc.Id, request);
        Assert.Single(updated.Wallets);
        Assert.Equal("solana", updated.Wallets[0].Chain);
        Assert.Equal(solanaAddress, updated.Wallets[0].Address);
    }

    [Fact]
    public async Task BindWallet_RejectsAddressNotDerivedFromKey()
    {
        // C2/H5: the signature only proves control of the key; an address that is NOT
        // derivable from the wallet public key must be rejected even with a valid signature.
        var kr = new TestKeyring();
        var (didPub, _) = kr.NewKey();
        var (walletPub, walletPriv) = kr.NewKey();
        var svc = new DidService(new InMemoryDidStore(), kr.Verifier);
        var doc = await svc.CreateAsync(didPub);

        var unsigned = new WalletBindingRequest
        {
            Chain = "solana",
            Address = "SomeoneElsesAddress111111111111111111111111", // not Base58(walletPub)
            WalletPublicKey = walletPub,
            Nonce = RandomNumberGenerator.GetBytes(16),
            Expiry = DateTimeOffset.UtcNow.AddMinutes(5),
            Signature = Array.Empty<byte>(),
        };

        // Sign correctly so the signature check passes — control check must still reject.
        var sig = kr.Sign(walletPriv, DidService.BuildWalletChallenge(doc.Id, unsigned));
        var request = unsigned with { Signature = sig };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => svc.BindWalletAsync(doc.Id, request));
        Assert.Contains("not provably controlled", ex.Message);
    }

    [Fact]
    public async Task BindWallet_RejectsUnknownChain_FailClosed()
    {
        // DefaultWalletControlVerifier fails closed on chains it does not understand.
        var kr = new TestKeyring();
        var (didPub, _) = kr.NewKey();
        var (walletPub, walletPriv) = kr.NewKey();
        var svc = new DidService(new InMemoryDidStore(), kr.Verifier);
        var doc = await svc.CreateAsync(didPub);

        var unsigned = new WalletBindingRequest
        {
            Chain = "ethereum",
            Address = "0x" + Convert.ToHexString(walletPub),
            WalletPublicKey = walletPub,
            Nonce = RandomNumberGenerator.GetBytes(16),
            Expiry = DateTimeOffset.UtcNow.AddMinutes(5),
            Signature = Array.Empty<byte>(),
        };

        var sig = kr.Sign(walletPriv, DidService.BuildWalletChallenge(doc.Id, unsigned));
        var request = unsigned with { Signature = sig };

        await Assert.ThrowsAsync<InvalidOperationException>(() => svc.BindWalletAsync(doc.Id, request));
    }

    [Fact]
    public async Task BindWallet_RejectsReplayedNonce_WhenNonceStoreConfigured()
    {
        // MEDIUM: signed nonce must be single-use when an INonceStore is supplied.
        var kr = new TestKeyring();
        var (didPub, _) = kr.NewKey();
        var (walletPub, walletPriv) = kr.NewKey();
        var svc = new DidService(
            new InMemoryDidStore(), kr.Verifier, clock: null,
            walletControl: null, nonceStore: new InMemoryNonceStore());
        var doc = await svc.CreateAsync(didPub);

        var solanaAddress = Base58.Encode(walletPub);
        var unsigned = new WalletBindingRequest
        {
            Chain = "solana",
            Address = solanaAddress,
            WalletPublicKey = walletPub,
            Nonce = RandomNumberGenerator.GetBytes(16),
            Expiry = DateTimeOffset.UtcNow.AddMinutes(5),
            Signature = Array.Empty<byte>(),
        };
        var sig = kr.Sign(walletPriv, DidService.BuildWalletChallenge(doc.Id, unsigned));
        var request = unsigned with { Signature = sig };

        // First binding succeeds.
        await svc.BindWalletAsync(doc.Id, request);

        // Replaying the exact same signed challenge (same nonce) must be rejected.
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => svc.BindWalletAsync(doc.Id, request));
        Assert.Contains("replay", ex.Message);
    }

    [Fact]
    public async Task BindWallet_RejectsBadSignature()
    {
        var kr = new TestKeyring();
        var (didPub, _) = kr.NewKey();
        var (walletPub, _) = kr.NewKey();
        var svc = new DidService(new InMemoryDidStore(), kr.Verifier);
        var doc = await svc.CreateAsync(didPub);

        var request = new WalletBindingRequest
        {
            Chain = "solana",
            Address = "Wallet1",
            WalletPublicKey = walletPub,
            Nonce = new byte[16],
            Expiry = DateTimeOffset.UtcNow.AddMinutes(5),
            Signature = new byte[32],
        };

        await Assert.ThrowsAsync<InvalidOperationException>(() => svc.BindWalletAsync(doc.Id, request));
    }

    [Fact]
    public async Task BindWallet_RejectsExpiredChallenge()
    {
        var kr = new TestKeyring();
        var (didPub, _) = kr.NewKey();
        var (walletPub, _) = kr.NewKey();
        var svc = new DidService(new InMemoryDidStore(), kr.Verifier);
        var doc = await svc.CreateAsync(didPub);

        var request = new WalletBindingRequest
        {
            Chain = "solana",
            Address = "WalletExp",
            WalletPublicKey = walletPub,
            Nonce = new byte[16],
            Expiry = DateTimeOffset.UtcNow.AddMinutes(-1),
            Signature = new byte[32],
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => svc.BindWalletAsync(doc.Id, request));
        Assert.Contains("expired", ex.Message);
    }

    [Fact]
    public async Task Revoke_MarksDocumentRevoked()
    {
        var kr = new TestKeyring();
        var (didPub, didPriv) = kr.NewKey();
        var svc = new DidService(new InMemoryDidStore(), kr.Verifier);
        var doc = await svc.CreateAsync(didPub);

        var revokeMsg = DidService.BuildRevokeChallenge(doc.Id, doc.Version);
        var sig = kr.Sign(didPriv, revokeMsg);
        var updated = await svc.RevokeAsync(doc.Id, sig);

        Assert.True(updated.Revoked);
        Assert.Equal(doc.Version + 1, updated.Version);
    }

    [Fact]
    public async Task GetActiveAsync_ReturnsNull_ForRevokedDid()
    {
        // HIGH (defense-in-depth): revoked DIDs must not resolve as active.
        var kr = new TestKeyring();
        var (didPub, didPriv) = kr.NewKey();
        var svc = new DidService(new InMemoryDidStore(), kr.Verifier);
        var doc = await svc.CreateAsync(didPub);

        // Active before revoke.
        Assert.NotNull(await svc.GetActiveAsync(doc.Id));

        var sig = kr.Sign(didPriv, DidService.BuildRevokeChallenge(doc.Id, doc.Version));
        await svc.RevokeAsync(doc.Id, sig);

        // GetAsync still returns the (revoked) doc; GetActiveAsync returns null.
        Assert.NotNull(await svc.GetAsync(doc.Id));
        Assert.Null(await svc.GetActiveAsync(doc.Id));
    }

    [Fact]
    public async Task GetActiveAsync_ReturnsNull_ForUnknownDid()
    {
        var svc = new DidService(new InMemoryDidStore(), new TestKeyring().Verifier);
        Assert.Null(await svc.GetActiveAsync(new DidId("did:tessera:nope")));
    }

    [Fact]
    public async Task AddChannelBinding_Authenticated_RequiresControllerSignature()
    {
        // HIGH: authenticated overload must reject a missing/invalid controller signature.
        var kr = new TestKeyring();
        var (didPub, didPriv) = kr.NewKey();
        var svc = new DidService(new InMemoryDidStore(), kr.Verifier);
        var doc = await svc.CreateAsync(didPub);

        var binding = new ChannelBinding
        {
            Type = "email",
            Commitment = RandomNumberGenerator.GetBytes(32),
            Issuer = doc.Id,
            IssuedAt = DateTimeOffset.UtcNow,
        };

        // Wrong signature is rejected.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => svc.AddChannelBindingAsync(doc.Id, binding, new byte[32]));

        // Correct controller signature over the canonical challenge is accepted.
        var sig = kr.Sign(didPriv, DidService.BuildChannelBindChallenge(doc.Id, doc.Version, binding.Type, binding.Commitment));
        var updated = await svc.AddChannelBindingAsync(doc.Id, binding, sig);
        Assert.Single(updated.Bindings);
        Assert.Equal(doc.Version + 1, updated.Version);
    }

    [Fact]
    public async Task RemoveChannelBinding_Authenticated_RequiresControllerSignature()
    {
        var kr = new TestKeyring();
        var (didPub, didPriv) = kr.NewKey();
        var svc = new DidService(new InMemoryDidStore(), kr.Verifier);
        var doc = await svc.CreateAsync(didPub);

        var commitment = RandomNumberGenerator.GetBytes(32);
        var binding = new ChannelBinding
        {
            Type = "telegram",
            Commitment = commitment,
            Issuer = doc.Id,
            IssuedAt = DateTimeOffset.UtcNow,
        };
        // Seed via the trusted-caller overload.
        var withBinding = await svc.AddChannelBindingAsync(doc.Id, binding);

        // Wrong signature rejected.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => svc.RemoveChannelBindingAsync(doc.Id, "telegram", commitment, new byte[32]));

        // Correct controller signature accepted; binding removed.
        var sig = kr.Sign(didPriv, DidService.BuildChannelUnbindChallenge(doc.Id, withBinding.Version, "telegram", commitment));
        var updated = await svc.RemoveChannelBindingAsync(doc.Id, "telegram", commitment, sig);
        Assert.Empty(updated.Bindings);
    }

    [Fact]
    public void Base58_RoundTrip()
    {
        var data = new byte[] { 0x00, 0x01, 0x02, 0xFF, 0x7F, 0x42 };
        var s = Base58.Encode(data);
        var back = Base58.Decode(s);
        Assert.Equal(data, back);
    }
}
