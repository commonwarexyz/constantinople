//! Golden wire-format fixtures shared with the explorer.
//!
//! The explorer hand-maintains a TypeScript copy of the transaction codec
//! (`explorer/src/codec.ts`); nothing else ties the two implementations
//! together, so drift used to fail at runtime in a browser. This test makes
//! the Rust codec the source of truth: it deterministically signs one
//! transaction per operation kind and asserts the checked-in fixture file
//! (`explorer/tests/fixtures/wire.json`) matches. The explorer's test suite
//! decodes and re-encodes the same file, so either side drifting fails CI.
//!
//! After an intentional wire-format change, regenerate with:
//!
//! ```text
//! UPDATE_WIRE_FIXTURES=1 cargo test -p constantinople-primitives --test wire_fixtures
//! ```

use commonware_codec::{Encode, EncodeSize as _};
use commonware_cryptography::{Signer as _, ed25519, sha256};
use commonware_formatting::hex;
use constantinople_primitives::{
    AccountKey, Operation, SignedTransaction, TRANSACTION_NAMESPACE, Transaction,
    TransactionPublicKey, Voucher, channel_address,
};
use core::num::NonZeroU64;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    comment: String,
    max_mint_amount: String,
    /// The batch wrapping of every transaction below, as submitted to the
    /// relayer (varint count followed by the encoded transactions).
    batch_hex: String,
    transactions: Vec<TransactionFixture>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransactionFixture {
    kind: &'static str,
    /// The full signed transaction as it appears on the wire.
    signed_hex: String,
    /// Where the signed body (the digest preimage) ends and the sender's
    /// scheme-tagged transaction signature begins.
    body_length: usize,
    /// The transaction's message digest (SHA-256 of the body).
    digest_hex: String,
    sender_public_key_hex: String,
    nonce: String,
    /// Operation-specific fields, stringly-typed so the TS side can consume
    /// them without u64 precision loss.
    #[serde(skip_serializing_if = "Option::is_none")]
    to_account_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

fn sign(signer: &ed25519::PrivateKey, tx: Transaction<sha256::Digest>) -> Tx {
    tx.seal_and_sign(
        signer,
        TRANSACTION_NAMESPACE,
        &mut sha256::Sha256::default(),
    )
}

type Tx = SignedTransaction<sha256::Sha256>;

fn fixture_entry(kind: &'static str, tx: &Tx) -> TransactionFixture {
    TransactionFixture {
        kind,
        signed_hex: hex(&tx.encode()),
        body_length: tx.value().encode_size(),
        digest_hex: hex(tx.message_digest().as_ref()),
        sender_public_key_hex: hex(&tx.value().sender.get().expect("sender decodes").encode()),
        nonce: tx.value().nonce.to_string(),
        to_account_key_hex: None,
        value: None,
    }
}

fn build_fixture() -> Fixture {
    let payer = ed25519::PrivateKey::from_seed(1);
    let receiver = ed25519::PrivateKey::from_seed(2);
    let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
    let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
    let payer_account = AccountKey::from_public_key(&payer_pk);
    let receiver_account = AccountKey::from_public_key(&receiver_pk);
    let nz = |value: u64| NonZeroU64::new(value).expect("fixture values are non-zero");

    let transfer_value = 7;
    let transfer = sign(
        &payer,
        Transaction::transfer(payer_pk.clone(), receiver_pk.clone(), nz(transfer_value), 0),
    );

    // The fixture channel is payee-run (operator == receiver), the demo's
    // default topology.
    let open_nonce = 1;
    let open = sign(
        &payer,
        Transaction::open_channel(
            payer_pk.clone(),
            receiver_account,
            receiver_account,
            nz(50),
            424_242,
            open_nonce,
        ),
    );

    let channel = channel_address(
        &payer_account,
        &receiver_account,
        &receiver_account,
        open_nonce,
    );
    let voucher = Voucher::sign(&payer, channel, 35);
    let close = sign(
        &receiver,
        Transaction::close_channel(
            receiver_pk,
            payer_pk.clone(),
            receiver_account,
            open_nonce,
            voucher.cumulative,
            voucher.signature,
            0,
        ),
    );

    let timeout = sign(
        &payer,
        Transaction::timeout_channel(
            payer_pk.clone(),
            receiver_account,
            receiver_account,
            open_nonce,
            2,
        ),
    );

    // Mint exactly the cap, so a cap change shows up as fixture drift.
    let mint = sign(
        &payer,
        Transaction::mint(payer_pk, nz(Operation::MAX_MINT_AMOUNT), 3),
    );

    let mut transfer_entry = fixture_entry("transfer", &transfer);
    transfer_entry.to_account_key_hex = Some(hex(receiver_account.as_ref()));
    transfer_entry.value = Some(transfer_value.to_string());
    let mut mint_entry = fixture_entry("mint", &mint);
    mint_entry.value = Some(Operation::MAX_MINT_AMOUNT.to_string());
    let transactions = vec![
        transfer_entry,
        fixture_entry("open_channel", &open),
        fixture_entry("close_channel", &close),
        fixture_entry("timeout_channel", &timeout),
        mint_entry,
    ];

    let batch = vec![transfer, open, close, timeout, mint];

    Fixture {
        comment: "Generated by crates/primitives/tests/wire_fixtures.rs — do not edit by hand. \
                  Regenerate with UPDATE_WIRE_FIXTURES=1 after an intentional codec change."
            .to_string(),
        max_mint_amount: Operation::MAX_MINT_AMOUNT.to_string(),
        batch_hex: hex(&batch.encode()),
        transactions,
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../explorer/tests/fixtures/wire.json")
}

#[test]
fn wire_fixtures_match_the_checked_in_file() {
    let generated = serde_json::to_value(build_fixture()).expect("fixture serializes");
    let path = fixture_path();

    if std::env::var("UPDATE_WIRE_FIXTURES").is_ok() {
        let pretty = serde_json::to_string_pretty(&generated).expect("fixture pretty-prints");
        std::fs::write(&path, pretty + "\n").expect("fixture file writes");
        return;
    }

    let checked_in: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "missing wire fixture at {path:?} ({error}); generate it with \
                 UPDATE_WIRE_FIXTURES=1 cargo test -p constantinople-primitives --test wire_fixtures"
            )
        }),
    )
    .expect("fixture file parses");

    assert_eq!(
        checked_in, generated,
        "the Rust wire format no longer matches explorer/tests/fixtures/wire.json; if the \
         change is intentional, regenerate with UPDATE_WIRE_FIXTURES=1 and update the \
         explorer codec to match"
    );
}
