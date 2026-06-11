//// Shared on-chain checks for the identity-registry validators.

use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/address.{Script}
use cardano/assets.{AssetName, quantity_of}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference}
use identity_registry/types.{DidAnchorDatum, IssuerDatum}

/// True iff `vkh` is one of the transaction's required signers.
pub fn signed_by(
  signatories: List<VerificationKeyHash>,
  vkh: VerificationKeyHash,
) -> Bool {
  list.has(signatories, vkh)
}

/// The input being spent, located by its output reference. Fails if absent.
pub fn own_input(inputs: List<Input>, own_ref: OutputReference) -> Input {
  expect Some(input) =
    list.find(inputs, fn(input) { input.output_reference == own_ref })
  input
}

/// The single output that returns thread token `(own_hash, asset_name)` of
/// quantity 1 to this script's own address. Requiring EXACTLY one such output
/// is the double-satisfaction guard: distinct anchors carry distinct asset
/// names, so no single output can ever satisfy two spends at once.
pub fn single_continuing_output(
  outputs: List<Output>,
  own_hash: ByteArray,
  asset_name: AssetName,
) -> Output {
  expect [only] =
    list.filter(
      outputs,
      fn(output) {
        and {
          output.address.payment_credential == Script(own_hash),
          quantity_of(output.value, own_hash, asset_name) == 1,
        }
      },
    )
  only
}

/// Decode the inline `DidAnchorDatum` from a continuing output.
pub fn output_anchor_datum(output: Output) -> DidAnchorDatum {
  expect InlineDatum(data) = output.datum
  expect datum: DidAnchorDatum = data
  datum
}

/// Decode the inline `IssuerDatum` from a continuing output.
pub fn output_issuer_datum(output: Output) -> IssuerDatum {
  expect InlineDatum(data) = output.datum
  expect datum: IssuerDatum = data
  datum
}
