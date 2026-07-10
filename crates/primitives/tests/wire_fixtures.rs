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
    TransactionPublicKey, VOUCHER_NAMESPACE, Voucher, channel_address,
    operator_api::{
        RegisterRequest, STREAM_CHUNK_EVENT, STREAM_END_EVENT, STREAM_PAYMENT_REQUIRED_EVENT,
        SettleRequest, StreamChunk, StreamEnd, StreamEndReason, VoucherRequest,
    },
    voucher_message,
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
    /// Everything the explorer's paid-stream client must reproduce
    /// byte-exactly: the channel address derivation and the voucher signing
    /// path (ed25519 is deterministic, so the TS test re-signs with the
    /// fixture key and compares signatures).
    channel: ChannelFixture,
    /// The `GET /stream` SSE contract: event names and serialized payload
    /// samples, so a Rust-side rename cannot silently strand the TS client.
    stream: StreamFixture,
    /// The operator request bodies the explorer builds (`POST /channels`,
    /// `/vouchers`, `/settle`), serialized from the channel fixture above:
    /// the request half of the contract, pinned like `stream` pins the
    /// response half.
    requests: RequestFixture,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestFixture {
    register_sample: String,
    voucher_sample: String,
    settle_sample: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StreamFixture {
    chunk_event: String,
    payment_required_event: String,
    end_event: String,
    /// Every [`StreamEndReason`] as it crosses the wire.
    end_reasons: Vec<String>,
    /// A serialized [`StreamChunk`] / [`StreamEnd`], pinning field names.
    chunk_sample: String,
    end_sample: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChannelFixture {
    /// The payer's raw 32-byte ed25519 private key. Lets the TS suite
    /// re-sign the open transaction and the voucher from scratch and assert
    /// byte-identity with the fixtures.
    payer_private_key_hex: String,
    payer_account_hex: String,
    receiver_account_hex: String,
    operator_account_hex: String,
    open_nonce: String,
    /// `channel_address(payer, receiver, operator, open_nonce)`.
    address_hex: String,
    /// The namespaces the two ed25519 signing paths must prefix (via the
    /// commonware `union_unique` framing) to what they sign.
    transaction_namespace: String,
    voucher_namespace: String,
    voucher_cumulative: String,
    /// `voucher_message(address, cumulative)`: the pre-namespace preimage.
    voucher_message_hex: String,
    voucher_signature_hex: String,
}

#[derive(Serialize, Default)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    receiver_account_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operator_account_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deposit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiry: Option<String>,
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
        ..Default::default()
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
    let channel_fixture = ChannelFixture {
        payer_private_key_hex: hex(&payer.encode()),
        payer_account_hex: hex(payer_account.as_ref()),
        receiver_account_hex: hex(receiver_account.as_ref()),
        operator_account_hex: hex(receiver_account.as_ref()),
        open_nonce: open_nonce.to_string(),
        address_hex: hex(channel.as_ref()),
        transaction_namespace: String::from_utf8(TRANSACTION_NAMESPACE.to_vec())
            .expect("namespace is ASCII"),
        voucher_namespace: String::from_utf8(VOUCHER_NAMESPACE.to_vec())
            .expect("namespace is ASCII"),
        voucher_cumulative: voucher.cumulative.to_string(),
        voucher_message_hex: hex(&voucher_message(&channel, voucher.cumulative)),
        voucher_signature_hex: hex(&voucher.signature.encode()),
    };
    let request_fixture = RequestFixture {
        register_sample: serde_json::to_string(&RegisterRequest::new(
            &channel,
            &payer_pk,
            open_nonce,
            open.message_digest(),
        ))
        .expect("register request serializes"),
        voucher_sample: serde_json::to_string(&VoucherRequest::new(&voucher))
            .expect("voucher request serializes"),
        settle_sample: serde_json::to_string(&SettleRequest::new(&channel))
            .expect("settle request serializes"),
    };
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
    let mut open_entry = fixture_entry("open_channel", &open);
    open_entry.receiver_account_key_hex = Some(hex(receiver_account.as_ref()));
    open_entry.operator_account_key_hex = Some(hex(receiver_account.as_ref()));
    open_entry.deposit = Some(50.to_string());
    open_entry.expiry = Some(424_242.to_string());
    let mut mint_entry = fixture_entry("mint", &mint);
    mint_entry.value = Some(Operation::MAX_MINT_AMOUNT.to_string());
    let transactions = vec![
        transfer_entry,
        open_entry,
        fixture_entry("close_channel", &close),
        fixture_entry("timeout_channel", &timeout),
        mint_entry,
    ];

    let end_reasons = [
        StreamEndReason::Complete,
        StreamEndReason::PaymentTimeout,
        StreamEndReason::DepositExhausted,
        StreamEndReason::ChannelClosed,
    ]
    .iter()
    .map(|reason| {
        serde_json::to_value(reason)
            .expect("reason serializes")
            .as_str()
            .expect("reason is a string")
            .to_string()
    })
    .collect();
    let stream_fixture = StreamFixture {
        chunk_event: STREAM_CHUNK_EVENT.to_string(),
        payment_required_event: STREAM_PAYMENT_REQUIRED_EVENT.to_string(),
        end_event: STREAM_END_EVENT.to_string(),
        end_reasons,
        chunk_sample: serde_json::to_string(&StreamChunk {
            text: "hello ".into(),
            served: 1,
            paid: 0,
        })
        .expect("chunk serializes"),
        end_sample: serde_json::to_string(&StreamEnd {
            reason: StreamEndReason::PaymentTimeout,
            served: 32,
            paid: 7,
        })
        .expect("end serializes"),
    };

    let batch = vec![transfer, open, close, timeout, mint];

    Fixture {
        comment: "Generated by crates/primitives/tests/wire_fixtures.rs — do not edit by hand. \
                  Regenerate with UPDATE_WIRE_FIXTURES=1 after an intentional codec change."
            .to_string(),
        max_mint_amount: Operation::MAX_MINT_AMOUNT.to_string(),
        batch_hex: hex(&batch.encode()),
        transactions,
        channel: channel_fixture,
        stream: stream_fixture,
        requests: request_fixture,
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
