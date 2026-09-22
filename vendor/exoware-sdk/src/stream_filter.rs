//! Validated filter for `log.stream.v1.Subscribe`.
//!
//! The filter is a list of `Selector`s with OR semantics: a row is delivered
//! if any selector's byte prefix selects its family AND its payload_regex
//! matches the key's payload bytes. The list is capped at 16 to
//! keep server-side regex compile cost predictable. When `value_filters` is
//! non-empty, rows that pass the key filter must also satisfy any one
//! `Filter` in the value list (OR within the value list; AND between key
//! and value filters).

use std::collections::BTreeSet;

use anyhow::ensure;
use bytes::Bytes;
use regex::bytes::Regex;

use crate::keys::Prefix;
use crate::selector::Selector;

pub const MAX_SELECTORS_PER_FILTER: usize = 16;
pub const MAX_VALUE_FILTERS_PER_FILTER: usize = 16;

/// Matches a row's raw value bytes by exact match, prefix, or regex. Wire
/// shape mirrors `common.kv.v1.Filter`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    Exact(Bytes),
    Prefix(Bytes),
    Regex(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamFilter {
    pub selectors: Vec<Selector>,
    pub value_filters: Vec<Filter>,
}

/// A compiled bundle of `Filter`s ready to evaluate against a byte
/// slice. OR semantics: `matches` returns true when any contained filter
/// matches the input. An empty bundle matches nothing; callers should model
/// "no filter configured" as `Option::None` and skip the match.
#[derive(Clone, Debug)]
pub struct CompiledFilters {
    exacts: BTreeSet<Bytes>,
    prefixes: Vec<Bytes>,
    regexes: Vec<Regex>,
}

impl CompiledFilters {
    /// Compile filters from the domain `Filter` representation. Returns
    /// `Ok(None)` when the input is empty (caller should skip matching).
    pub fn compile(filters: &[Filter]) -> Result<Option<Self>, String> {
        if filters.is_empty() {
            return Ok(None);
        }
        let mut exacts = BTreeSet::<Bytes>::new();
        let mut prefixes = Vec::new();
        let mut regexes = Vec::new();
        for filter in filters {
            match filter {
                Filter::Exact(bytes) => {
                    exacts.insert(bytes.clone());
                }
                Filter::Prefix(bytes) => prefixes.push(bytes.clone()),
                Filter::Regex(pattern) => {
                    if pattern.trim().is_empty() {
                        return Err("regex filter must not be empty".to_string());
                    }
                    regexes.push(
                        Regex::new(pattern)
                            .map_err(|e| format!("invalid regex `{pattern}`: {e}"))?,
                    );
                }
            }
        }
        Ok(Some(Self {
            exacts,
            prefixes,
            regexes,
        }))
    }

    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.exacts.iter().any(|exact| exact.as_ref() == bytes)
            || self.prefixes.iter().any(|p| bytes.starts_with(p))
            || self.regexes.iter().any(|r| r.is_match(bytes))
    }
}

/// Shape-only validation: bounds, family validity, non-empty regex string.
/// Does NOT compile the regex — the server compiles once per subscribe.
pub fn validate_filter(filter: &StreamFilter) -> anyhow::Result<()> {
    ensure!(
        !filter.selectors.is_empty(),
        "stream filter must contain at least one selector"
    );
    ensure!(
        filter.selectors.len() <= MAX_SELECTORS_PER_FILTER,
        "stream filter capped at {MAX_SELECTORS_PER_FILTER} selectors"
    );
    ensure!(
        filter.value_filters.len() <= MAX_VALUE_FILTERS_PER_FILTER,
        "stream filter capped at {MAX_VALUE_FILTERS_PER_FILTER} value_filters"
    );
    for selector in &filter.selectors {
        Prefix::new(selector.prefix.clone())
            .map_err(|e| anyhow::anyhow!("invalid selector prefix: {e}"))?;
        ensure!(
            !selector.payload_regex.trim().is_empty(),
            "selector payload_regex must not be empty"
        );
    }
    for vf in &filter.value_filters {
        match vf {
            Filter::Regex(r) => {
                ensure!(!r.trim().is_empty(), "value_filter regex must not be empty")
            }
            Filter::Exact(_) | Filter::Prefix(_) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv_codec::Utf8;

    fn selector(prefix: u8) -> Selector {
        Selector {
            prefix: Bytes::copy_from_slice(&[prefix]),
            payload_regex: Utf8::from("(?s).*"),
        }
    }

    #[test]
    fn accepts_one_selector() {
        let f = StreamFilter {
            selectors: vec![selector(1)],
            value_filters: vec![],
        };
        validate_filter(&f).unwrap();
    }

    #[test]
    fn rejects_empty() {
        let f = StreamFilter {
            selectors: vec![],
            value_filters: vec![],
        };
        assert!(validate_filter(&f).is_err());
    }

    #[test]
    fn rejects_too_many() {
        let f = StreamFilter {
            selectors: (0..(MAX_SELECTORS_PER_FILTER as u8 + 1))
                .map(selector)
                .collect(),
            value_filters: vec![],
        };
        assert!(validate_filter(&f).is_err());
    }

    #[test]
    fn rejects_empty_regex() {
        let f = StreamFilter {
            selectors: vec![Selector {
                prefix: Bytes::copy_from_slice(&[1]),
                payload_regex: Utf8::from(""),
            }],
            value_filters: vec![],
        };
        assert!(validate_filter(&f).is_err());
    }
}
