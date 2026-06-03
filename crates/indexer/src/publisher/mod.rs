//! Publisher components for finalized index uploads.
//!
//! The production validator path uses [`Publisher`] on the single owning
//! secondary. It stages finalized-block data into one combined upload path:
//!
//! | Path             | Families / tables                                            |
//! | ---------------- | ------------------------------------------------------------ |
//! | `raw` (KV)       | `BLOCK`, `BLOCK_BY_H`, `TX`, `TX_BY_H`            |
//! | `sql` (metadata) | `block_meta`                                                 |
//! | `qmdb` (state)   | Account-state operation log                                  |
//! | `qmdb` (tx hash) | Transaction-hash operation log                                |
//!
//! Simplex certificates are uploaded separately through [`CertificateReporter`]
//! using `exoware-simplex` indexes in the same Store. Those proof artifacts are
//! not the canonical block or transaction storage path.
//!
//! [`StoreClient`]: exoware_sdk::StoreClient

pub(crate) mod block;
pub mod certificate;
pub mod qmdb;
pub mod sql;

pub use certificate::CertificateReporter;
pub use qmdb::Publisher;
pub use sql::SqlRow;
