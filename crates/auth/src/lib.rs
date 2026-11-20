#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod keys;
pub use keys::{ChannelKey, Mac, PrivateKey, PublicKey, SharedKey};

mod shared;
pub use shared::SharedKeys;

mod tag;
pub use tag::{SECURITY_BITS, TRANSACTIONS_LOG2, Tag, TagKey, Tags, tag_bits};

mod submission;
pub use submission::{Rejection, Submission};

mod report;
pub use report::{MAX_ENTRIES, Report, status};

mod scheme;
#[cfg(any(test, feature = "mocks"))]
pub use scheme::fixture;
pub use scheme::{Certificate, Reports, Scheme, Vote};

mod verdicts;
pub use commonware_storage::journal::contiguous::fixed::Config as VerdictsConfig;
pub use verdicts::Verdicts;
