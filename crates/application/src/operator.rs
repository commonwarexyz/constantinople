//! Off-chain payment-channel operator.
//!
//! This is the off-chain half of a payment channel: the service that accepts
//! streaming micropayments. For each request it receives a voucher — the
//! payer's signature over a monotonically increasing cumulative amount — and
//! verifies it locally, with no on-chain transaction per payment. Periodically
//! (here, once at the end) it submits the latest voucher on-chain to settle.
//!
//! The verification the operator performs (see
//! `service::RegisteredChannel::serve`) uses the exact same
//! [`constantinople_primitives::verify_voucher`] predicate the chain applies at
//! settlement, plus the off-chain-only monotonicity check.
//! This is the guarantee that matters: the operator never accepts a voucher the
//! chain would later reject (which would leave it unpaid). See
//! [`constantinople_primitives::Voucher`] for the shared voucher type.

pub mod service;

#[cfg(test)]
mod lifecycle;
