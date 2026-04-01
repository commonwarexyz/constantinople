//! In-memory transfer processing.
//!
//! The processor executes simple transfers over an account-only state view.
//! Transactions declare no accesses. Instead, the scheduler infers that every
//! transaction writes the sender and recipient accounts.

pub mod executor;
pub mod state;

#[cfg(test)]
mod tests;
