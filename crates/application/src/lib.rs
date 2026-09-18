// Nested consensus futures exceed the default trait solver depth.
#![recursion_limit = "256"]
#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod consensus;
pub mod executor;
