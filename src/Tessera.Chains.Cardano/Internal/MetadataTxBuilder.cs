using Tessera.Chains.Cardano.Providers;

namespace Tessera.Chains.Cardano.Internal;

/// <summary>
/// Builds the Metadata-mode transaction: a plain self-payment whose auxiliary data records
/// <c>{ did, root, epoch }</c> under the configured label. No script is involved, so a verifier
/// trusts the controller key that signed the tx, not the chain.
/// </summary>
internal sealed class MetadataTxBuilder
{
    private const ulong FeeBuffer = 50_000;
    private const ulong MinChange = 1_200_000;

    private readonly ICardanoProvider _provider;
    private readonly ControllerKey _key;
    private readonly CardanoNetwork _network;
    private readonly ulong _label;
    private readonly byte[] _changeAddressBytes;

    public MetadataTxBuilder(ICardanoProvider provider, ControllerKey key, CardanoNetwork network, ulong label)
    {
        _provider = provider;
        _key = key;
        _network = network;
        _label = label;
        _changeAddressBytes = ScriptAddress.EnterpriseKeyAddressBytes(key.KeyHash, network);
    }

    public async Task<BuiltTx> BuildAsync(byte[] didHash, byte[] attestationRoot, ulong epoch, CancellationToken ct)
    {
        var pp = await _provider.GetProtocolParametersAsync(ct).ConfigureAwait(false);
        var tip = await _provider.GetTipAsync(ct).ConfigureAwait(false);
        var ttl = tip.Slot + 7200;

        // Authenticate the payload: the controller signs (did_hash‖root‖epoch) and we publish the
        // public key alongside it, so a reader can verify the metadata was authored by the
        // controller and not by some other address squatting the shared metadata label.
        var signature = MetadataAttestation.Sign(_key, didHash, attestationRoot, epoch);
        var (aux, auxHash) = CborTx.BuildMetadataAuxData(
            _label,
            Convert.ToHexString(didHash).ToLowerInvariant(),
            Convert.ToHexString(attestationRoot).ToLowerInvariant(),
            epoch,
            Convert.ToHexString(_key.PublicKey.Key).ToLowerInvariant(),
            Convert.ToHexString(signature).ToLowerInvariant());

        var wallet = await _provider.GetUtxosAsync(_key.Address, ct).ConfigureAwait(false);
        if (wallet.Count == 0)
            throw new InvalidOperationException(
                $"Controller wallet {_key.Address} has no UTxOs — fund it with preprod test ADA (faucet) before anchoring.");

        var funding = SelectFunding(wallet);
        var inputs = funding
            .Select(u => new InputRef(Convert.FromHexString(u.TxHash), (ulong)u.OutputIndex))
            .OrderBy(i => i.TxHash, ByteArrayComparer.Instance).ThenBy(i => i.Index)
            .ToList();
        var inputsTotal = (ulong)funding.Sum(u => (decimal)u.Lovelace);

        // Two-pass fee: build once to measure size, then finalise.
        var draft = Build(inputs, inputsTotal, fee: 200_000, auxHash, aux, signed: true);
        var fee = pp.MinFeeA * (ulong)draft.Cbor.Length + pp.MinFeeB + FeeBuffer;
        return Build(inputs, inputsTotal, fee, auxHash, aux, signed: true);
    }

    private BuiltTx Build(IReadOnlyList<InputRef> inputs, ulong inputsTotal, ulong fee, byte[] auxHash, byte[] aux, bool signed)
    {
        var change = checked(inputsTotal - fee);
        var changeOutput = new OutputSpec(_changeAddressBytes, change, Array.Empty<AssetAmount>(), null);
        var body = CborTx.BuildBody(
            inputs: inputs,
            outputs: new[] { changeOutput },
            fee: fee,
            ttl: 0,
            networkId: CardanoNetworkInfo.NetworkId(_network),
            auxiliaryDataHash: auxHash);

        var bodyHash = PlutusCbor.TransactionBodyHash(body);
        var witnesses = signed
            ? new[] { (_key.PublicKey.Key, _key.Sign(bodyHash)) }
            : Array.Empty<(byte[], byte[])>();
        var witnessSet = PlutusCbor.VKeyWitnessSet(witnesses);
        var tx = PlutusCbor.Transaction(body, witnessSet, aux);
        return new BuiltTx(tx, Convert.ToHexString(bodyHash).ToLowerInvariant());
    }

    private static List<CardanoUtxo> SelectFunding(IReadOnlyList<CardanoUtxo> wallet)
    {
        // Prefer pure-ADA UTxOs; gather enough to cover the change floor + fee.
        var picked = new List<CardanoUtxo>();
        ulong sum = 0;
        foreach (var u in wallet.Where(u => u.IsPureAda).OrderByDescending(u => u.Lovelace))
        {
            picked.Add(u);
            sum += u.Lovelace;
            if (sum >= MinChange + 1_000_000) break;
        }
        if (picked.Count == 0)
            throw new InvalidOperationException("No pure-ADA UTxO available — fund the controller wallet with test ADA.");
        return picked;
    }
}
