//! Store-backed Simplex upload client.
//!
//! `exoware-simplex` stores Commonware Simplex artifacts in the Exoware Store
//! using a stable logical key layout. It is intentionally a client library, not
//! a consensus participant: callers still build and verify Commonware blocks and
//! certificates, then use this crate to persist the encoded artifacts.

mod client;
mod error;
pub mod keys;
mod resolver;
mod types;

pub use client::{PreparedEntry, PreparedUpload, SimplexClient};
pub use error::SimplexError;
pub use resolver::init_marshal_resolver;
pub use types::{encode_block_data, BlockData, Finalized, Notarized, UploadReceipt, UploadSummary};
