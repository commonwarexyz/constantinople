//! Mempool webserver actor.
//!
//! Accepts signed transactions over HTTP, verifies them, and serves
//! batches to the consensus layer via [`TransactionSource`](crate::TransactionSource).
//!
//! # Architecture
//!
//! - **HTTP handlers** (axum) run on tokio worker threads, decoding and
//!   verifying transactions in parallel.
//! - **Actor** owns a byte-bounded FIFO pool and processes submit,
//!   propose, and report messages from a single channel.
//! - **Mailbox** is the cloneable handle that implements
//!   [`TransactionSource`](crate::TransactionSource) and
//!   [`Reporter`](commonware_consensus::Reporter).

mod actor;
pub use actor::{Actor, Config, TxStatus};

mod mailbox;
pub use mailbox::Mailbox;

mod http;
