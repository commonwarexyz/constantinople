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
pub use account::{Account, AccountKey, DEFAULT_ACCOUNT_BALANCE, NONCE_BITMAP_CAPACITY, Nonce};

mod auth;
pub use auth::{TransactionBatchVerifier, TransactionPublicKey, TransactionSignature};

mod cache;
pub use cache::{DecompressedPublicKey, PublicKeyCache};

mod block;
pub use block::{Block, BlockCfg, Header, SealedBlock};

mod transaction;
pub use transaction::{SignedTransaction, Transaction, VerifiedTransaction};

/// Signing namespace for transaction signatures.
pub const TRANSACTION_NAMESPACE: &[u8] = b"constantinople-tx";

// Finalization consumes the hasher and returns it reset for the next caller.
fn finalize_in_place<H: commonware_cryptography::Hasher>(hasher: &mut H) -> H::Digest {
    let (next, digest) = core::mem::take(hasher).finalize();
    *hasher = next;
    digest
}
