#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod sealed;
pub use sealed::{Sealable, Sealed};

mod signed;
pub use signed::{Signable, Signed, Verified};

mod account;
pub use account::{Account, Address};

mod block;
pub use block::{
    Block, BlockCfg, Header, SignedBlock, SignedTransaction, VerifiedBlock, VerifiedTransaction,
};

mod transaction;
pub use transaction::Transaction;
