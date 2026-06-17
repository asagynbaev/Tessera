using System.Security.Cryptography;
using Tessera.Attestations;
using Tessera.Core;

namespace Tessera.Attestations.Tests;

public class AttestationTests
{
    private sealed class StubSigner : IIssuerSigner
    {
        private readonly byte[] _priv;
        public StubSigner(byte[] priv, byte[] pub) { _priv = priv; PublicKey = pub; }
        public string Algorithm => "ed25519";
        public byte[] PublicKey { get; }
        public byte[] Sign(ReadOnlySpan<byte> message)
        {
            var buf = new byte[_priv.Length + message.Length];
            Buffer.BlockCopy(_priv, 0, buf, 0, _priv.Length);
            message.CopyTo(buf.AsSpan(_priv.Length));
            return SHA256.HashData(buf);
        }
    }

    private sealed class StubVerifier : ISignatureVerifier
    {
        private readonly byte[] _priv;
        private readonly byte[] _pub;
        public StubVerifier(byte[] priv, byte[] pub) { _priv = priv; _pub = pub; }
        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            if (!publicKey.SequenceEqual(_pub)) return false;
            var buf = new byte[_priv.Length + message.Length];
            Buffer.BlockCopy(_priv, 0, buf, 0, _priv.Length);
            message.CopyTo(buf.AsSpan(_priv.Length));
            var expected = SHA256.HashData(buf);
            return signature.SequenceEqual(expected);
        }
    }

    /// <summary>
    /// A holder controller keypair backed by the same SHA-256(priv ‖ message) stub scheme. The 32-byte
    /// public key doubles as the controller key, so <see cref="DidId.FromControllerKey"/> derives the
    /// holder DID and the matching <see cref="StubVerifier"/> authenticates the presentation signature.
    /// </summary>
    private static (byte[] priv, byte[] pub, DidId did, StubVerifier verifier) BuildHolder()
    {
        var priv = RandomNumberGenerator.GetBytes(32);
        var pub = SHA256.HashData(priv); // exactly 32 bytes → valid controller key
        return (priv, pub, DidId.FromControllerKey(pub), new StubVerifier(priv, pub));
    }

    /// <summary>Sign the canonical presentation challenge with the holder stub signer.</summary>
    private static byte[] SignChallenge(byte[] holderPriv, Presentation presentation)
    {
        var challenge = PresentationChallenge.Compute(presentation);
        var buf = new byte[holderPriv.Length + challenge.Length];
        Buffer.BlockCopy(holderPriv, 0, buf, 0, holderPriv.Length);
        Buffer.BlockCopy(challenge, 0, buf, holderPriv.Length, challenge.Length);
        return SHA256.HashData(buf);
    }

    private static (DidId issuerDid, AttestationIssuer issuer, AttestationVerifier verifier, IssuerRecord record)
        BuildPair(string algorithm = "ed25519")
    {
        var priv = RandomNumberGenerator.GetBytes(32);
        var pub = SHA256.HashData(priv);
        var signer = new StubSigner(priv, pub);
        var verifier = new StubVerifier(priv, pub);
        var issuerDid = new DidId("did:tessera:" + Convert.ToHexString(SHA256.HashData(pub)));
        var record = new IssuerRecord
        {
            Did = issuerDid,
            PublicKey = pub,
            Algorithm = algorithm,
            SchemaUri = "https://schemas.tessera/attestation/v1",
            Active = true,
        };
        var registry = new InMemoryIssuerRegistry();
        registry.Register(record);
        return (issuerDid, new AttestationIssuer(issuerDid, signer), new AttestationVerifier(registry, verifier), record);
    }

    [Fact]
    public async Task IssueAndVerify_HumanVerified()
    {
        var (issuerDid, issuer, verifier, _) = BuildPair();
        var subject = new DidId("did:tessera:subject1");

        var att = issuer.Issue(
            AttestationTypes.HumanVerified,
            subject,
            new AttestationPayload { Method = "humanity_check_v2" });

        Assert.Equal(issuerDid, att.Issuer);
        Assert.Equal(subject, att.Subject);

        var result = await verifier.VerifyAsync(att);
        Assert.True(result.Valid);
    }

    [Fact]
    public async Task Verify_TamperedSchema_Fails()
    {
        var (_, issuer, verifier, _) = BuildPair();
        var subject = new DidId("did:tessera:subject1");
        var att = issuer.Issue("phone_verified", subject, new AttestationPayload { Method = "twilio_v1" });

        var tampered = att with { Schema = "https://schemas.tessera/attestation/v9999" };
        var result = await verifier.VerifyAsync(tampered);
        Assert.False(result.Valid);
        Assert.Equal("bad_signature", result.Reason);
    }

    [Fact]
    public async Task Verify_UnknownIssuer_Fails()
    {
        var (_, _, verifier, _) = BuildPair();
        var otherIssuer = new DidId("did:tessera:totally-different");
        var bogus = new Attestation
        {
            Schema = "https://schemas.tessera/attestation/v1",
            Type = "human_verified",
            Issuer = otherIssuer,
            Subject = new DidId("did:tessera:subject"),
            IssuedAt = DateTimeOffset.UtcNow,
            Nonce = new byte[16],
            Payload = new AttestationPayload { Method = "fake" },
            Signature = new AttestationSignature { Algorithm = "ed25519", Value = new byte[32] },
        };
        var result = await verifier.VerifyAsync(bogus);
        Assert.False(result.Valid);
        Assert.Equal("unknown_issuer", result.Reason);
    }

    [Fact]
    public async Task Verify_Expired_Fails()
    {
        var (_, issuer, verifier, _) = BuildPair();
        var att = issuer.Issue(
            "phone_verified",
            new DidId("did:tessera:s"),
            new AttestationPayload { Method = "twilio" },
            validity: TimeSpan.FromMilliseconds(1));
        await Task.Delay(50);
        var result = await verifier.VerifyAsync(att);
        Assert.False(result.Valid);
        Assert.Equal("expired", result.Reason);
    }

    [Fact]
    public async Task Verify_AlgorithmTag_IsCaseInsensitive()
    {
        // Issuer registered as "ED25519"; signature tag is the canonical lowercase "ed25519". The tag
        // is metadata (not part of the signed canonical input), so a case difference must NOT reject.
        var (_, issuer, verifier, _) = BuildPair(algorithm: "ED25519");
        var att = issuer.Issue("human_verified", new DidId("did:tessera:s"), new AttestationPayload { Method = "civic" });
        var result = await verifier.VerifyAsync(att);
        Assert.True(result.Valid, result.Reason);
    }

    private static (AttestationIssuer issuer, AttestationVerifier verifier) BuildPairWithOptions(
        TimeSpan? maxAge = null, bool requireExpiry = false)
    {
        var priv = RandomNumberGenerator.GetBytes(32);
        var pub = SHA256.HashData(priv);
        var issuerDid = new DidId("did:tessera:" + Convert.ToHexString(SHA256.HashData(pub)));
        var registry = new InMemoryIssuerRegistry();
        registry.Register(new IssuerRecord
        {
            Did = issuerDid,
            PublicKey = pub,
            Algorithm = "ed25519",
            SchemaUri = "https://schemas.tessera/attestation/v1",
            Active = true,
        });
        return (
            new AttestationIssuer(issuerDid, new StubSigner(priv, pub)),
            new AttestationVerifier(registry, new StubVerifier(priv, pub),
                maxAttestationAge: maxAge, requireExpiry: requireExpiry));
    }

    [Fact]
    public async Task Verify_TooOld_WhenMaxAgeExceeded()
    {
        var (issuer, verifier) = BuildPairWithOptions(maxAge: TimeSpan.FromMilliseconds(1));
        var att = issuer.Issue("phone_verified", new DidId("did:tessera:s"), new AttestationPayload { Method = "twilio" });
        await Task.Delay(50);
        var result = await verifier.VerifyAsync(att);
        Assert.False(result.Valid);
        Assert.Equal("too_old", result.Reason);
    }

    [Fact]
    public async Task Verify_MissingExpiry_WhenRequired_Fails()
    {
        var (issuer, verifier) = BuildPairWithOptions(requireExpiry: true);
        var att = issuer.Issue("human_verified", new DidId("did:tessera:s"), new AttestationPayload { Method = "civic" });
        var result = await verifier.VerifyAsync(att);
        Assert.False(result.Valid);
        Assert.Equal("missing_expiry", result.Reason);
    }

    [Fact]
    public async Task Verify_WithExpiry_SatisfiesRequireExpiry()
    {
        var (issuer, verifier) = BuildPairWithOptions(requireExpiry: true);
        var att = issuer.Issue("human_verified", new DidId("did:tessera:s"),
            new AttestationPayload { Method = "civic" }, validity: TimeSpan.FromHours(1));
        var result = await verifier.VerifyAsync(att);
        Assert.True(result.Valid, result.Reason);
    }

    [Fact]
    public void MerkleTree_RoundTripInclusion()
    {
        var leaves = Enumerable.Range(0, 7)
            .Select(i => System.Text.Encoding.UTF8.GetBytes($"leaf-{i}"))
            .ToArray();

        var root = MerkleTree.ComputeRoot(leaves);
        for (int i = 0; i < leaves.Length; i++)
        {
            var (proofRoot, path) = MerkleTree.BuildInclusionProof(leaves, i);
            Assert.Equal(root, proofRoot);
            var leafHash = MerkleTree.HashLeaf(leaves[i]);
            Assert.True(MerkleTree.VerifyInclusion(leafHash, path, (ulong)i, root));
        }
    }

    [Fact]
    public void MerkleTree_TamperedPath_FailsVerification()
    {
        var leaves = new[] { "a", "b", "c", "d", "e" }.Select(System.Text.Encoding.UTF8.GetBytes).ToArray();
        var (root, path) = MerkleTree.BuildInclusionProof(leaves, 2);
        var leafHash = MerkleTree.HashLeaf(leaves[2]);

        // Flip a byte in the first sibling.
        var tampered = path.ToList();
        tampered[0] = (byte[])tampered[0].Clone();
        tampered[0][0] ^= 0xFF;

        Assert.False(MerkleTree.VerifyInclusion(leafHash, tampered, 2, root));
    }

    [Fact]
    public async Task Bundle_Disclosure_VerifiesEndToEnd()
    {
        var (_, issuer, attestationVerifier, _) = BuildPair();
        var (holderPriv, holderPub, holder, holderVerifier) = BuildHolder();

        var atts = new[]
        {
            issuer.Issue(AttestationTypes.HumanVerified, holder, new AttestationPayload { Method = "civic" }),
            issuer.Issue(AttestationTypes.PhoneVerified, holder, new AttestationPayload { Method = "twilio" }),
            issuer.Issue(AttestationTypes.NonUsUser, holder, new AttestationPayload { Method = "geoip" }),
        };
        var bundle = new AttestationBundle(atts);

        var disclosure = bundle.DisclosureFor(1); // phone_verified
        var presentation = new Presentation
        {
            Holder = holder,
            Disclosures = new[] { disclosure },
            Binding = new PresentationBinding
            {
                Verifier = new DidId("did:tessera:verifier1"),
                SessionNonce = new byte[16],
                AsOfRevocationEpoch = 0,
                Chain = "solana",
                HolderSignature = new byte[64], // placeholder, replaced below
                HolderPublicKey = holderPub,
                CreatedAt = DateTimeOffset.UtcNow,
            },
        };
        presentation = presentation with
        {
            Binding = presentation.Binding with { HolderSignature = SignChallenge(holderPriv, presentation) },
        };

        var verifier = new PresentationVerifier(attestationVerifier, holderVerifier);
        var result = await verifier.VerifyAsync(presentation, bundle.Root);
        Assert.True(result.Valid, result.Reason);
    }

    [Fact]
    public async Task Bundle_WrongRoot_Fails()
    {
        var (_, issuer, attestationVerifier, _) = BuildPair();
        var (holderPriv, holderPub, holder, holderVerifier) = BuildHolder();
        var atts = new[]
        {
            issuer.Issue("phone_verified", holder, new AttestationPayload { Method = "x" }),
            issuer.Issue("human_verified", holder, new AttestationPayload { Method = "y" }),
        };
        var bundle = new AttestationBundle(atts);
        var presentation = new Presentation
        {
            Holder = holder,
            Disclosures = new[] { bundle.DisclosureFor(0) },
            Binding = new PresentationBinding
            {
                Verifier = new DidId("did:tessera:v"),
                SessionNonce = new byte[16],
                AsOfRevocationEpoch = 0,
                Chain = "solana",
                HolderSignature = new byte[64], // placeholder, replaced below
                HolderPublicKey = holderPub,
                CreatedAt = DateTimeOffset.UtcNow,
            },
        };
        presentation = presentation with
        {
            Binding = presentation.Binding with { HolderSignature = SignChallenge(holderPriv, presentation) },
        };

        // Wrong root: zeroed
        var bogusRoot = new byte[32];
        var verifier = new PresentationVerifier(attestationVerifier, holderVerifier);
        var result = await verifier.VerifyAsync(presentation, bogusRoot);
        Assert.False(result.Valid);
        Assert.Equal("root_not_anchored", result.Reason);
    }

    [Fact]
    public async Task Presentation_SubjectMismatch_Fails()
    {
        var (_, issuer, attestationVerifier, _) = BuildPair();
        var subjectA = new DidId("did:tessera:A");
        // subjectB is the presenter: a real keypair-derived DID so the holder-signature check passes
        // and verification reaches the subject_mismatch check inside the disclosure loop.
        var (holderPriv, holderPub, subjectB, holderVerifier) = BuildHolder();
        var att = issuer.Issue("human_verified", subjectA, new AttestationPayload { Method = "x" });
        var bundle = new AttestationBundle(new[] { att });

        var presentation = new Presentation
        {
            Holder = subjectB, // mismatch with the attestation subject (subjectA)
            Disclosures = new[] { bundle.DisclosureFor(0) },
            Binding = new PresentationBinding
            {
                Verifier = new DidId("did:tessera:v"),
                SessionNonce = new byte[16],
                AsOfRevocationEpoch = 0,
                Chain = "solana",
                HolderSignature = new byte[64], // placeholder, replaced below
                HolderPublicKey = holderPub,
                CreatedAt = DateTimeOffset.UtcNow,
            },
        };
        presentation = presentation with
        {
            Binding = presentation.Binding with { HolderSignature = SignChallenge(holderPriv, presentation) },
        };
        var verifier = new PresentationVerifier(attestationVerifier, holderVerifier);
        var result = await verifier.VerifyAsync(presentation, bundle.Root);
        Assert.False(result.Valid);
        Assert.Equal("subject_mismatch", result.Reason);
    }
}
