#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod sealed;
pub use sealed::{Sealable, Sealed};

mod signed;
pub use signed::{
    LazySignedTransaction, Signable, Signed, materialize_transaction_chunks,
    preload_transaction_chunks, preload_transaction_slice, verify_transaction_batch,
    verify_transaction_chunks,
};

mod account;
pub use account::{Account, AccountKey, NONCE_BITMAP_CAPACITY, Nonce};

mod auth;
pub use auth::{TransactionBatchVerifier, TransactionPublicKey, TransactionSignature};

mod cache;
pub use cache::{DecompressedPublicKey, PublicKeyCache};

mod block;
pub use block::{Block, BlockCfg, Header, SealedBlock};

mod transaction;
pub use transaction::{
    CHANNEL_NEVER_EXPIRES, Operation, SignedTransaction, Transaction, VerifiedTransaction,
};

pub mod operator_api;

mod channel;
pub use channel::{VOUCHER_NAMESPACE, Voucher, channel_address, verify_voucher, voucher_message};

mod url;
pub use url::resolve_named_http_url;

/// Signing namespace for transaction signatures.
pub const TRANSACTION_NAMESPACE: &[u8] = b"constantinople-tx";
