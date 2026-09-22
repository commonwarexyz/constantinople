//! Sequence-log retention policy (the domain model behind
//! `log.retention.v1.SetRetention`).
//!
//! This module carries the wire-stable domain type plus its `commonware_codec` impls (so the
//! rule can be persisted next to the log) and its validation.

use anyhow::ensure;
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};

/// A sequence-log retention rule. Interpreted directly over sequence numbers;
/// the stream service tracks the live frontier and evicts continuously.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetentionPolicy {
    /// Keep the newest `count` batches, sliding the retained window forward as
    /// the frontier advances. `count` must be > 0.
    KeepLatest { count: u64 },
    /// Retain sequence numbers strictly greater than `threshold`.
    GreaterThan { threshold: u64 },
    /// Retain sequence numbers greater than or equal to `threshold`.
    GreaterThanOrEqual { threshold: u64 },
    /// Retain nothing: evict up to the live frontier, continuously.
    DropAll,
}

impl Write for RetentionPolicy {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            RetentionPolicy::KeepLatest { count } => {
                0u8.write(buf);
                count.write(buf);
            }
            RetentionPolicy::GreaterThan { threshold } => {
                1u8.write(buf);
                threshold.write(buf);
            }
            RetentionPolicy::GreaterThanOrEqual { threshold } => {
                2u8.write(buf);
                threshold.write(buf);
            }
            RetentionPolicy::DropAll => {
                3u8.write(buf);
            }
        }
    }
}

impl EncodeSize for RetentionPolicy {
    fn encode_size(&self) -> usize {
        1 + match self {
            RetentionPolicy::KeepLatest { .. }
            | RetentionPolicy::GreaterThan { .. }
            | RetentionPolicy::GreaterThanOrEqual { .. } => u64::SIZE,
            RetentionPolicy::DropAll => 0,
        }
    }
}

impl Read for RetentionPolicy {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(RetentionPolicy::KeepLatest {
                count: u64::read(buf)?,
            }),
            1 => Ok(RetentionPolicy::GreaterThan {
                threshold: u64::read(buf)?,
            }),
            2 => Ok(RetentionPolicy::GreaterThanOrEqual {
                threshold: u64::read(buf)?,
            }),
            3 => Ok(RetentionPolicy::DropAll),
            v => Err(CodecError::InvalidEnum(v)),
        }
    }
}

/// Reject rules that cannot be enforced. `keep_latest` must keep at least one
/// batch; the threshold and drop-all rules accept any value.
pub fn validate_retention_policy(policy: &RetentionPolicy) -> anyhow::Result<()> {
    if let RetentionPolicy::KeepLatest { count } = policy {
        ensure!(*count > 0, "keep_latest count must be > 0");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_retention_policy, RetentionPolicy};
    use commonware_codec::{DecodeExt, Encode};

    fn round_trip(policy: &RetentionPolicy) {
        let encoded = policy.encode();
        let decoded = RetentionPolicy::decode(encoded).expect("decode");
        assert_eq!(&decoded, policy);
    }

    #[test]
    fn codec_round_trip() {
        round_trip(&RetentionPolicy::KeepLatest { count: 5 });
        round_trip(&RetentionPolicy::GreaterThan { threshold: 42 });
        round_trip(&RetentionPolicy::GreaterThanOrEqual { threshold: 7 });
        round_trip(&RetentionPolicy::DropAll);
    }

    #[test]
    fn keep_latest_requires_positive_count() {
        let err = validate_retention_policy(&RetentionPolicy::KeepLatest { count: 0 })
            .expect_err("count 0 rejected");
        assert!(err.to_string().contains("keep_latest count must be > 0"));

        validate_retention_policy(&RetentionPolicy::KeepLatest { count: 1 }).expect("count 1 ok");
    }

    #[test]
    fn other_rules_validate() {
        validate_retention_policy(&RetentionPolicy::GreaterThan { threshold: 0 }).expect("gt ok");
        validate_retention_policy(&RetentionPolicy::GreaterThanOrEqual { threshold: 0 })
            .expect("gte ok");
        validate_retention_policy(&RetentionPolicy::DropAll).expect("drop_all ok");
    }
}
