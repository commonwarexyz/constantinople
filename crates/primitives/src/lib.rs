#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod sealed;
pub use sealed::{Sealable, Sealed};

mod signed;
pub use signed::{
    Signable, Signed, materialize_transaction_chunks, preload_transaction_chunks,
    verify_transaction_batch, verify_transaction_chunks,
};

mod account;
pub use account::{Account, DEFAULT_ACCOUNT_BALANCE};

mod block;
pub use block::{Block, BlockCfg, Header, SealedBlock};

mod transaction;
pub use transaction::{SignedTransaction, Transaction, VerifiedTransaction};

/// Signing namespace for transaction signatures.
pub const TRANSACTION_NAMESPACE: &[u8] = b"constantinople-tx";
