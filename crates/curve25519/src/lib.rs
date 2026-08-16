//! SIMD-accelerated Ed25519 batch verification vendored from Commonware PR 4467.
//!
//! Constantinople carries this experiment locally so it can be evaluated without
//! changing the pinned Commonware revision. The X25519 API from the source PR is
//! intentionally omitted because validators use only the signing backend.
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod curve;
pub use curve::backend_name;
pub mod signing;
