using CardanoSharp.Wallet.Utilities;
using Tessera.Chains.Cardano.Providers;

namespace Tessera.Chains.Cardano.Internal;

/// <summary>A built, signed transaction ready to submit.</summary>
internal sealed record BuiltTx(byte[] Cbor, string TxHash);

/// <summary>
/// Builds and signs the Plutus V3 anchor transactions (register via mint; update/bump via spend)
/// against the <c>identity_anchor</c> validator. Uses the provider to fetch parameters/UTxOs and
/// to evaluate execution units, then assembles the Conway CBOR (body + witness) by hand.
/// </summary>
internal sealed class CardanoTxBuilder
{
    // Safety margins applied to evaluated execution units and the size-based fee.
    private const double ExUnitsMargin = 1.15;
    private const ulong FeeBuffer = 60_000;
    private const ulong MinAdaFloor = 1_200_000;
    private const int MinUtxoOverheadBytes = 160;

    private readonly ICardanoProvider _provider;
    private readonly ControllerKey _key;
    private readonly CardanoNetwork _network;
    private readonly byte[] _script;
    private readonly byte[] _policyId;
    private readonly byte[] _scriptAddressBytes;
    private readonly byte[] _changeAddressBytes;

    public CardanoTxBuilder(ICardanoProvider provider, ControllerKey key, CardanoNetwork network, byte[] script)
    {
        _provider = provider;
        _key = key;
        _network = network;
        _script = script;
        _policyId = ScriptAddress.PolicyId(script);
        _scriptAddressBytes = ScriptAddress.EnterpriseScriptAddressBytes(_policyId, network);
        _changeAddressBytes = ScriptAddress.EnterpriseKeyAddressBytes(key.KeyHash, network);
    }

    public byte[] PolicyId => _policyId;

    /// <summary>register_did: mint the thread token and create the anchor UTxO.</summary>
    public Task<BuiltTx> BuildRegisterAsync(byte[] didHash, byte[] attestationRoot, CancellationToken ct)
    {
        var datum = DatumCodec.EncodeAnchorDatum(new DidAnchorDatumValue(didHash, attestationRoot, 0, _key.KeyHash));
        return BuildMintRegisterAsync(didHash, datum, DatumCodec.RegisterDidRedeemer(), ct);
    }

    /// <summary>
    /// Generic mint-and-lock registration: mint a unique beacon named <paramref name="assetName"/>
    /// and create the UTxO with <paramref name="datumCbor"/>. Used for both DID anchors and issuer records.
    /// </summary>
    public Task<BuiltTx> BuildMintRegisterAsync(byte[] assetName, byte[] datumCbor, byte[] redeemerData, CancellationToken ct)
        => BuildPlutusTxAsync(
            scriptInput: null,
            mint: new[] { new AssetAmount(_policyId, assetName, 1) },
            redeemerTag: RedeemerEntry.MintTag,
            redeemerData: redeemerData,
            anchorDatumCbor: datumCbor,
            anchorAsset: new AssetAmount(_policyId, assetName, 1),
            ct);

    /// <summary>update_root / bump_revocation: spend the anchor UTxO and recreate it with new state.</summary>
    public async Task<BuiltTx> BuildSpendAsync(
        CardanoUtxo anchorUtxo,
        byte[] redeemerData,
        DidAnchorDatumValue newState,
        byte[] didHash,
        CancellationToken ct)
    {
        var datum = DatumCodec.EncodeAnchorDatum(newState);
        return await BuildPlutusTxAsync(
            scriptInput: anchorUtxo,
            mint: null,
            redeemerTag: RedeemerEntry.SpendTag,
            redeemerData: redeemerData,
            anchorDatumCbor: datum,
            anchorAsset: new AssetAmount(_policyId, didHash, 1),
            ct).ConfigureAwait(false);
    }

    private async Task<BuiltTx> BuildPlutusTxAsync(
        CardanoUtxo? scriptInput,
        IReadOnlyList<AssetAmount>? mint,
        int redeemerTag,
        byte[] redeemerData,
        byte[] anchorDatumCbor,
        AssetAmount anchorAsset,
        CancellationToken ct)
    {
        var pp = await _provider.GetProtocolParametersAsync(ct).ConfigureAwait(false);
        var tip = await _provider.GetTipAsync(ct).ConfigureAwait(false);
        var ttl = tip.Slot + 7200; // ~2h validity window
        var languageViews = PlutusCbor.LanguageViews(pp.PlutusV3CostModel);

        var wallet = await _provider.GetUtxosAsync(_key.Address, ct).ConfigureAwait(false);
        if (wallet.Count == 0)
            throw new InvalidOperationException(
                $"Controller wallet {_key.Address} has no UTxOs — fund it with preprod test ADA (faucet) before anchoring.");

        var collateral = SelectCollateral(wallet);
        var anchorOutput = BuildAnchorOutput(anchorAsset, anchorDatumCbor, pp);

        // Spend inputs: the script UTxO (if any) plus wallet UTxOs to cover output + fee + min-change.
        var funding = SelectFunding(wallet, collateral, anchorOutput.Coin, scriptInput);
        var spendInputs = BuildSortedInputs(scriptInput, funding, out var scriptInputIndex);

        // Pass 1 — draft with placeholder ex-units, evaluate to learn the real budget.
        var draftRedeemers = new[]
        {
            new RedeemerEntry(redeemerTag, redeemerTag == RedeemerEntry.SpendTag ? scriptInputIndex : 0u, redeemerData, 2_000_000, 700_000_000),
        };
        var inputsTotal = SumLovelace(scriptInput, funding);
        var draft = AssembleUnsigned(spendInputs, anchorOutput, mint, draftRedeemers, languageViews, collateral, ttl, fee: 1_000_000, inputsTotal, signed: false);
        var evaluated = await EvaluateBudgetAsync(draft.Cbor, draftRedeemers, ct).ConfigureAwait(false);

        // Pass 2 — final fee from size + ex-units, then sign.
        var feeEstimate = ComputeFee(pp, draft.Cbor.Length, evaluated);
        var final = AssembleUnsigned(spendInputs, anchorOutput, mint, evaluated, languageViews, collateral, ttl, feeEstimate, inputsTotal, signed: false);
        var fee = ComputeFee(pp, final.Cbor.Length + 200 /* vkey witness */, evaluated);

        return Sign(spendInputs, anchorOutput, mint, evaluated, languageViews, collateral, ttl, fee, inputsTotal);
    }

    // ── assembly ───────────────────────────────────────────────────────────────

    private (byte[] Cbor, byte[] BodyHash) AssembleUnsigned(
        IReadOnlyList<InputRef> inputs, OutputSpec anchorOutput, IReadOnlyList<AssetAmount>? mint,
        IReadOnlyList<RedeemerEntry> redeemers, byte[] languageViews, CardanoUtxo collateral,
        ulong ttl, ulong fee, ulong inputsTotal, bool signed)
    {
        var change = checked(inputsTotal - anchorOutput.Coin - fee);
        var changeOutput = new OutputSpec(_changeAddressBytes, change, Array.Empty<AssetAmount>(), null);

        var redeemersCbor = PlutusCbor.Redeemers(redeemers);
        var scriptDataHash = PlutusCbor.ScriptDataHash(redeemersCbor, languageViews);

        var totalCollateral = (ulong)Math.Ceiling(fee * 1.5);
        var collateralReturn = new OutputSpec(_changeAddressBytes, collateral.Lovelace - totalCollateral, Array.Empty<AssetAmount>(), null);

        var body = CborTx.BuildBody(
            inputs: inputs,
            outputs: new[] { anchorOutput, changeOutput },
            fee: fee,
            ttl: ttl,
            networkId: CardanoNetworkInfo.NetworkId(_network),
            mint: mint,
            scriptDataHash: scriptDataHash,
            collateral: new[] { new InputRef(Convert.FromHexString(collateral.TxHash), (ulong)collateral.OutputIndex) },
            requiredSigners: new[] { _key.KeyHash },
            collateralReturn: collateralReturn,
            totalCollateral: totalCollateral);

        var bodyHash = PlutusCbor.TransactionBodyHash(body);
        var witnesses = signed
            ? new[] { (_key.PublicKey.Key, _key.Sign(bodyHash)) }
            : Array.Empty<(byte[], byte[])>();
        var witnessSet = PlutusCbor.WitnessSet(witnesses, redeemersCbor, _script);
        return (PlutusCbor.Transaction(body, witnessSet, null), bodyHash);
    }

    private BuiltTx Sign(
        IReadOnlyList<InputRef> inputs, OutputSpec anchorOutput, IReadOnlyList<AssetAmount>? mint,
        IReadOnlyList<RedeemerEntry> redeemers, byte[] languageViews, CardanoUtxo collateral,
        ulong ttl, ulong fee, ulong inputsTotal)
    {
        var (cbor, bodyHash) = AssembleUnsigned(inputs, anchorOutput, mint, redeemers, languageViews, collateral, ttl, fee, inputsTotal, signed: true);
        return new BuiltTx(cbor, Convert.ToHexString(bodyHash).ToLowerInvariant());
    }

    private async Task<RedeemerEntry[]> EvaluateBudgetAsync(byte[] draftCbor, RedeemerEntry[] draft, CancellationToken ct)
    {
        IReadOnlyList<RedeemerEvaluation> evals;
        try
        {
            evals = await _provider.EvaluateAsync(draftCbor, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Evaluation unavailable → fall back to the (generous) draft budget so the flow still proceeds.
            return draft;
        }

        if (evals.Count == 0) return draft;
        return draft.Select(d =>
        {
            var match = evals.FirstOrDefault(e => e.Index == d.Index) ?? evals[0];
            return d with
            {
                Mem = (ulong)(match.Mem * ExUnitsMargin),
                Steps = (ulong)(match.Steps * ExUnitsMargin),
            };
        }).ToArray();
    }

    // ── selection + sizing ───────────────────────────────────────────────────────

    private OutputSpec BuildAnchorOutput(AssetAmount anchorAsset, byte[] datumCbor, ProtocolParameters pp)
    {
        var assets = new[] { anchorAsset };
        var probe = new OutputSpec(_scriptAddressBytes, 2_000_000, assets, datumCbor);
        var size = CborTx.BuildBody(new[] { new InputRef(new byte[32], 0) }, new[] { probe }, 0, 0, 0).Length;
        var minAda = Math.Max(MinAdaFloor, (ulong)(size + MinUtxoOverheadBytes) * pp.CoinsPerUtxoByte);
        return new OutputSpec(_scriptAddressBytes, minAda, assets, datumCbor);
    }

    private static CardanoUtxo SelectCollateral(IReadOnlyList<CardanoUtxo> wallet)
        => wallet.Where(u => u.IsPureAda && u.Lovelace >= 5_000_000).OrderBy(u => u.Lovelace).FirstOrDefault()
           ?? wallet.Where(u => u.IsPureAda).OrderByDescending(u => u.Lovelace).FirstOrDefault()
           ?? throw new InvalidOperationException("No pure-ADA UTxO available for Plutus collateral — fund the controller wallet with a few test ADA.");

    private static List<CardanoUtxo> SelectFunding(IReadOnlyList<CardanoUtxo> wallet, CardanoUtxo collateral, ulong needed, CardanoUtxo? scriptInput)
    {
        var target = needed + 2_000_000; // output + headroom for fee/change
        var picked = new List<CardanoUtxo>();
        ulong sum = scriptInput?.Lovelace ?? 0;
        foreach (var u in wallet.Where(u => !SameUtxo(u, collateral) && (scriptInput is null || !SameUtxo(u, scriptInput)))
                                 .OrderByDescending(u => u.Lovelace))
        {
            if (sum >= target) break;
            picked.Add(u);
            sum += u.Lovelace;
        }
        if (sum < target)
            throw new InvalidOperationException($"Insufficient funds in the controller wallet: have {sum}, need ~{target} lovelace.");
        return picked;
    }

    private static IReadOnlyList<InputRef> BuildSortedInputs(CardanoUtxo? scriptInput, IEnumerable<CardanoUtxo> funding, out uint scriptInputIndex)
    {
        var all = new List<CardanoUtxo>();
        if (scriptInput is not null) all.Add(scriptInput);
        all.AddRange(funding);

        var sorted = all
            .Select(u => new InputRef(Convert.FromHexString(u.TxHash), (ulong)u.OutputIndex))
            .OrderBy(i => i.TxHash, ByteArrayComparer.Instance)
            .ThenBy(i => i.Index)
            .ToList();

        scriptInputIndex = 0;
        if (scriptInput is not null)
        {
            var key = (TxHash: Convert.FromHexString(scriptInput.TxHash), Index: (ulong)scriptInput.OutputIndex);
            scriptInputIndex = (uint)sorted.FindIndex(i => ByteArrayComparer.Instance.Equals(i.TxHash, key.TxHash) && i.Index == key.Index);
        }
        return sorted;
    }

    private static ulong ComputeFee(ProtocolParameters pp, int txSize, IReadOnlyList<RedeemerEntry> redeemers)
    {
        var sizeFee = pp.MinFeeA * (ulong)txSize + pp.MinFeeB;
        double exFee = 0;
        foreach (var r in redeemers)
            exFee += r.Mem * pp.PriceMem + r.Steps * pp.PriceStep;
        return sizeFee + (ulong)Math.Ceiling(exFee) + FeeBuffer;
    }

    private static ulong SumLovelace(CardanoUtxo? scriptInput, IEnumerable<CardanoUtxo> funding)
        => (scriptInput?.Lovelace ?? 0) + (ulong)funding.Sum(u => (decimal)u.Lovelace);

    private static bool SameUtxo(CardanoUtxo a, CardanoUtxo b) => a.TxHash == b.TxHash && a.OutputIndex == b.OutputIndex;
}
