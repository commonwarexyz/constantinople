use anyhow::{ensure, Context};
use bytes::BufMut;
use commonware_codec::{
    Buf, Copying, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt,
    Write,
};
use std::collections::HashSet;

use crate::keys::Prefix;
use crate::kv_codec::Utf8;
use crate::selector::{compile_payload_regex, Selector};

pub const PRUNE_POLICY_CONTROL_KEY: &str = "manifest/control/compaction-prune-policies";
/// Wire version of the persisted prune-policy document. A prune document
/// carries only key scopes; sequence-log retention is configured separately via
/// `log.retention.v1.SetRetention`.
pub const PRUNE_POLICY_DOCUMENT_VERSION: u32 = 2;

/// One prune rule. `scope` selects which keys to consider; `retain` decides
/// what survives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrunePolicy {
    pub scope: KeysScope,
    pub retain: RetainPolicy,
}

/// User-key-space scope: filter a key-prefix family by `selector`, partition
/// matched keys into `group_by` groups, order within each group by `order_by`,
/// then apply `retain` to decide which keys to delete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeysScope {
    pub selector: Selector,
    pub group_by: GroupBy,
    pub order_by: Option<OrderBy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct GroupBy {
    pub capture_groups: Vec<Utf8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderBy {
    pub capture_group: Utf8,
    pub encoding: OrderEncoding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderEncoding {
    BytesAsc,
    U64Be,
    I64Be,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetainPolicy {
    KeepLatest { count: usize },
    GreaterThan { threshold: u64 },
    GreaterThanOrEqual { threshold: u64 },
    DropAll,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrunePolicyDocument {
    pub version: u32,
    pub policies: Vec<PrunePolicy>,
}

impl Write for OrderEncoding {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            OrderEncoding::BytesAsc => 0u8.write(buf),
            OrderEncoding::U64Be => 1u8.write(buf),
            OrderEncoding::I64Be => 2u8.write(buf),
        }
    }
}

impl FixedSize for OrderEncoding {
    const SIZE: usize = 1;
}

impl Read for OrderEncoding {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(OrderEncoding::BytesAsc),
            1 => Ok(OrderEncoding::U64Be),
            2 => Ok(OrderEncoding::I64Be),
            v => Err(CodecError::InvalidEnum(v)),
        }
    }
}

impl Write for RetainPolicy {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            RetainPolicy::KeepLatest { count } => {
                0u8.write(buf);
                (*count as u64).write(buf);
            }
            RetainPolicy::GreaterThan { threshold } => {
                1u8.write(buf);
                threshold.write(buf);
            }
            RetainPolicy::GreaterThanOrEqual { threshold } => {
                2u8.write(buf);
                threshold.write(buf);
            }
            RetainPolicy::DropAll => {
                3u8.write(buf);
            }
        }
    }
}

impl EncodeSize for RetainPolicy {
    fn encode_size(&self) -> usize {
        1 + match self {
            RetainPolicy::KeepLatest { .. }
            | RetainPolicy::GreaterThan { .. }
            | RetainPolicy::GreaterThanOrEqual { .. } => u64::SIZE,
            RetainPolicy::DropAll => 0,
        }
    }
}

impl Read for RetainPolicy {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(RetainPolicy::KeepLatest {
                count: u64::read(buf)? as usize,
            }),
            1 => Ok(RetainPolicy::GreaterThan {
                threshold: u64::read(buf)?,
            }),
            2 => Ok(RetainPolicy::GreaterThanOrEqual {
                threshold: u64::read(buf)?,
            }),
            3 => Ok(RetainPolicy::DropAll),
            v => Err(CodecError::InvalidEnum(v)),
        }
    }
}

impl Write for GroupBy {
    fn write(&self, buf: &mut impl BufMut) {
        self.capture_groups.as_slice().write(buf);
    }
}

impl EncodeSize for GroupBy {
    fn encode_size(&self) -> usize {
        self.capture_groups.as_slice().encode_size()
    }
}

impl Read for GroupBy {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let range: RangeCfg<usize> = (..).into();
        let capture_groups = Vec::<Utf8>::read_cfg(buf, &(range, ()))?;
        Ok(GroupBy { capture_groups })
    }
}

impl Write for OrderBy {
    fn write(&self, buf: &mut impl BufMut) {
        self.capture_group.write(buf);
        self.encoding.write(buf);
    }
}

impl EncodeSize for OrderBy {
    fn encode_size(&self) -> usize {
        self.capture_group.encode_size() + OrderEncoding::SIZE
    }
}

impl Read for OrderBy {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(OrderBy {
            capture_group: Utf8::read(buf)?,
            encoding: OrderEncoding::read(buf)?,
        })
    }
}

impl Write for KeysScope {
    fn write(&self, buf: &mut impl BufMut) {
        self.selector.write(buf);
        self.group_by.write(buf);
        self.order_by.write(buf);
    }
}

impl EncodeSize for KeysScope {
    fn encode_size(&self) -> usize {
        self.selector.encode_size() + self.group_by.encode_size() + self.order_by.encode_size()
    }
}

impl Read for KeysScope {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(KeysScope {
            selector: Selector::read(buf)?,
            group_by: GroupBy::read(buf)?,
            order_by: Option::<OrderBy>::read(buf)?,
        })
    }
}

impl Write for PrunePolicy {
    fn write(&self, buf: &mut impl BufMut) {
        self.scope.write(buf);
        self.retain.write(buf);
    }
}

impl EncodeSize for PrunePolicy {
    fn encode_size(&self) -> usize {
        self.scope.encode_size() + self.retain.encode_size()
    }
}

impl Read for PrunePolicy {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(PrunePolicy {
            scope: KeysScope::read(buf)?,
            retain: RetainPolicy::read(buf)?,
        })
    }
}

impl Write for PrunePolicyDocument {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.policies.as_slice().write(buf);
    }
}

impl EncodeSize for PrunePolicyDocument {
    fn encode_size(&self) -> usize {
        u32::SIZE + self.policies.as_slice().encode_size()
    }
}

impl Read for PrunePolicyDocument {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let version = u32::read(buf)?;
        let range: RangeCfg<usize> = (..).into();
        let policies = Vec::<PrunePolicy>::read_cfg(buf, &(range, ()))?;
        Ok(PrunePolicyDocument { version, policies })
    }
}

pub fn validate_policy(policy: &PrunePolicy) -> anyhow::Result<()> {
    validate_user_keys_scope(&policy.scope)?;
    validate_retain_for_scope(policy)?;
    Ok(())
}

fn validate_user_keys_scope(scope: &KeysScope) -> anyhow::Result<()> {
    Prefix::new(scope.selector.prefix.clone()).context("invalid selector prefix")?;
    let regex = compile_payload_regex(&scope.selector.payload_regex)?;
    validate_capture_groups(
        &regex,
        &scope.group_by.capture_groups,
        "group_by capture_groups",
    )?;
    ensure!(
        capture_groups_are_unique(&scope.group_by.capture_groups),
        "group_by capture_groups must not contain duplicates"
    );
    if let Some(order_by) = &scope.order_by {
        validate_capture_groups(
            &regex,
            std::slice::from_ref(&order_by.capture_group),
            "order_by capture_group",
        )?;
    }
    Ok(())
}

fn validate_retain_for_scope(policy: &PrunePolicy) -> anyhow::Result<()> {
    let scope = &policy.scope;
    match policy.retain {
        RetainPolicy::KeepLatest { count } => {
            ensure!(count > 0, "keep_latest count must be > 0");
            ensure!(
                scope.order_by.is_some(),
                "keep_latest requires order_by to be configured"
            );
        }
        RetainPolicy::GreaterThan { .. } | RetainPolicy::GreaterThanOrEqual { .. } => {
            let order_by = scope
                .order_by
                .as_ref()
                .context("threshold retention requires order_by to be configured")?;
            ensure!(
                matches!(order_by.encoding, OrderEncoding::U64Be),
                "threshold retention currently requires order_by.encoding = u64_be"
            );
        }
        RetainPolicy::DropAll => {}
    }
    Ok(())
}

pub fn ensure_unique_policy_families(policies: &[PrunePolicy]) -> anyhow::Result<()> {
    let mut user_prefixes: Vec<&[u8]> = Vec::new();
    for policy in policies {
        let scope = &policy.scope;
        // Nested prefixes select overlapping physical key ranges, so two
        // policies could disagree about the same rows. Reject any pair where
        // one prefix extends the other (equality included).
        let prefix: &[u8] = &scope.selector.prefix;
        for seen in &user_prefixes {
            ensure!(
                !seen.starts_with(prefix) && !prefix.starts_with(seen),
                "overlapping compaction prune policies for key prefixes {seen:?} and {prefix:?}"
            );
        }
        user_prefixes.push(prefix);
    }
    Ok(())
}

pub fn validate_policy_document(document: &PrunePolicyDocument) -> anyhow::Result<()> {
    ensure!(
        document.version == PRUNE_POLICY_DOCUMENT_VERSION,
        "unsupported prune policy document version {} (expected {})",
        document.version,
        PRUNE_POLICY_DOCUMENT_VERSION
    );
    for policy in &document.policies {
        validate_policy(policy)?;
    }
    ensure_unique_policy_families(&document.policies)?;
    Ok(())
}

pub fn decode_policy_document(raw: &[u8]) -> anyhow::Result<PrunePolicyDocument> {
    if raw.is_empty() {
        return Ok(PrunePolicyDocument {
            version: PRUNE_POLICY_DOCUMENT_VERSION,
            policies: Vec::new(),
        });
    }
    let document = PrunePolicyDocument::read_cfg(&mut Copying(raw), &())
        .context("failed to decode prune policy document")?;
    validate_policy_document(&document)?;
    Ok(document)
}

pub fn encode_policy_document(document: &PrunePolicyDocument) -> anyhow::Result<Vec<u8>> {
    validate_policy_document(document)?;
    Ok(document.encode().to_vec())
}

fn validate_capture_groups(
    regex: &regex::bytes::Regex,
    groups: &[Utf8],
    label: &str,
) -> anyhow::Result<()> {
    let known: HashSet<&str> = regex.capture_names().flatten().collect();
    for group in groups {
        ensure!(
            known.contains(&**group),
            "{label} references unknown capture group {group:?}"
        );
    }
    Ok(())
}

fn capture_groups_are_unique(groups: &[Utf8]) -> bool {
    let mut seen = HashSet::new();
    groups.iter().all(|group| seen.insert(group))
}

#[cfg(test)]
mod tests {
    use super::{
        decode_policy_document, encode_policy_document, GroupBy, KeysScope, OrderBy, OrderEncoding,
        PrunePolicy, PrunePolicyDocument, RetainPolicy, Selector, PRUNE_POLICY_CONTROL_KEY,
        PRUNE_POLICY_DOCUMENT_VERSION,
    };
    use crate::kv_codec::Utf8;
    use bytes::Bytes;

    fn sample_policy() -> PrunePolicy {
        PrunePolicy {
            scope: KeysScope {
                selector: Selector {
                    prefix: Bytes::copy_from_slice(&[1]),
                    payload_regex: Utf8::from(
                        "(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$",
                    ),
                },
                group_by: GroupBy {
                    capture_groups: vec![Utf8::from("logical")],
                },
                order_by: Some(OrderBy {
                    capture_group: Utf8::from("version"),
                    encoding: OrderEncoding::U64Be,
                }),
            },
            retain: RetainPolicy::KeepLatest { count: 10 },
        }
    }

    fn sample_document() -> PrunePolicyDocument {
        PrunePolicyDocument {
            version: PRUNE_POLICY_DOCUMENT_VERSION,
            policies: vec![sample_policy()],
        }
    }

    #[test]
    fn nested_selector_prefixes_rejected() {
        let mut nested = sample_policy();
        nested.scope.selector.prefix = Bytes::copy_from_slice(&[1, 2]);
        let err = super::ensure_unique_policy_families(&[sample_policy(), nested])
            .expect_err("nested prefixes overlap");
        assert!(err.to_string().contains("overlapping compaction"));

        let disjoint = sample_policy();
        let mut other = sample_policy();
        other.scope.selector.prefix = Bytes::copy_from_slice(&[2]);
        super::ensure_unique_policy_families(&[disjoint, other]).expect("disjoint prefixes");
    }

    #[test]
    fn codec_round_trip() {
        let encoded = encode_policy_document(&sample_document()).expect("encode");
        let decoded = decode_policy_document(&encoded).expect("decode");
        assert_eq!(decoded, sample_document());
    }

    #[test]
    fn empty_bytes_means_no_policies() {
        let decoded = decode_policy_document(b"").expect("empty ok");
        assert_eq!(decoded.version, PRUNE_POLICY_DOCUMENT_VERSION);
        assert!(decoded.policies.is_empty());
        assert_eq!(
            PRUNE_POLICY_CONTROL_KEY,
            "manifest/control/compaction-prune-policies"
        );
    }

    #[test]
    fn keep_latest_requires_order_by() {
        let doc = PrunePolicyDocument {
            version: PRUNE_POLICY_DOCUMENT_VERSION,
            policies: vec![PrunePolicy {
                scope: KeysScope {
                    selector: Selector {
                        prefix: Bytes::copy_from_slice(&[1]),
                        payload_regex: Utf8::from(
                            "(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$",
                        ),
                    },
                    group_by: GroupBy {
                        capture_groups: vec![Utf8::from("logical")],
                    },
                    order_by: None,
                },
                retain: RetainPolicy::KeepLatest { count: 1 },
            }],
        };
        let encoded = encode_policy_document(&doc);
        assert!(encoded.is_err());
        assert!(encoded
            .unwrap_err()
            .to_string()
            .contains("keep_latest requires order_by"));
    }

    #[test]
    fn capture_groups_must_exist() {
        let doc = PrunePolicyDocument {
            version: PRUNE_POLICY_DOCUMENT_VERSION,
            policies: vec![PrunePolicy {
                scope: KeysScope {
                    selector: Selector {
                        prefix: Bytes::copy_from_slice(&[1]),
                        payload_regex: Utf8::from("(?s)^(?P<logical>.+)$"),
                    },
                    group_by: GroupBy {
                        capture_groups: vec![Utf8::from("missing")],
                    },
                    order_by: Some(OrderBy {
                        capture_group: Utf8::from("logical"),
                        encoding: OrderEncoding::BytesAsc,
                    }),
                },
                retain: RetainPolicy::KeepLatest { count: 1 },
            }],
        };
        let encoded = encode_policy_document(&doc);
        assert!(encoded.is_err());
        assert!(encoded
            .unwrap_err()
            .to_string()
            .contains("unknown capture group"));
    }

    #[test]
    fn oversized_selector_prefix_returns_error() {
        let doc = PrunePolicyDocument {
            version: PRUNE_POLICY_DOCUMENT_VERSION,
            policies: vec![PrunePolicy {
                scope: KeysScope {
                    selector: Selector {
                        prefix: Bytes::from(vec![0u8; crate::keys::MAX_KEY_LEN + 1]),
                        payload_regex: Utf8::from("(?s)^(?P<logical>.+)$"),
                    },
                    group_by: GroupBy::default(),
                    order_by: None,
                },
                retain: RetainPolicy::DropAll,
            }],
        };
        let err = encode_policy_document(&doc).expect_err("oversized prefix");
        assert!(err.to_string().contains("invalid selector prefix"));
    }
}
