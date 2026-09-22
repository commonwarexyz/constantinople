use exoware_sdk::kv_codec::Utf8;
use exoware_sdk::prune_policy::{
    GroupBy, KeysScope, OrderBy, OrderEncoding, PrunePolicy, RetainPolicy,
};
use exoware_sdk::selector::Selector;

use crate::codec::UPDATE_PREFIX;

fn base_keys_scope() -> KeysScope {
    KeysScope {
        selector: Selector {
            prefix: UPDATE_PREFIX.as_bytes().clone(),
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
    }
}

/// Build a prune policy that keeps the latest `count` update rows per logical raw
/// key in the standard qmdb update family.
pub fn keep_latest_updates(count: usize) -> PrunePolicy {
    PrunePolicy {
        scope: base_keys_scope(),
        retain: RetainPolicy::KeepLatest { count },
    }
}

/// Build a prune policy that keeps only update rows whose uploaded location is
/// greater than or equal to `min_location`.
pub fn keep_positions_gte(min_location: u64) -> PrunePolicy {
    PrunePolicy {
        scope: base_keys_scope(),
        retain: RetainPolicy::GreaterThanOrEqual {
            threshold: min_location,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{keep_latest_updates, keep_positions_gte};
    use crate::codec::{
        encode_ordered_key_bytes, encode_update_key, ORDERED_KEY_TERMINATOR_LEN, UPDATE_FAMILY,
        UPDATE_PREFIX,
    };
    use commonware_storage::merkle::{mmr, Location};
    use exoware_sdk::kv_codec::Utf8;
    use exoware_sdk::prune_policy::{validate_policy, OrderEncoding, RetainPolicy};
    use exoware_sdk::selector::compile_payload_regex;

    fn compiled_update_regex() -> regex::bytes::Regex {
        let policy = keep_latest_updates(1);
        let scope = &policy.scope;
        validate_policy(&policy).expect("policy should validate");
        compile_payload_regex(&scope.selector.payload_regex).expect("regex")
    }

    #[test]
    fn test_keep_latest_updates_matches_update_key_layout() {
        let policy = keep_latest_updates(3);
        let scope = &policy.scope;
        assert_eq!(scope.selector.prefix.as_ref(), &[UPDATE_FAMILY]);
        assert_eq!(
            &*scope.selector.payload_regex,
            "(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$"
        );
        assert_eq!(scope.group_by.capture_groups, vec![Utf8::from("logical")]);
        let order_by = scope.order_by.as_ref().expect("order_by");
        assert_eq!(&*order_by.capture_group, "version");
        assert_eq!(order_by.encoding, OrderEncoding::U64Be);
        assert_eq!(policy.retain, RetainPolicy::KeepLatest { count: 3 });
    }

    // The prune regex re-states the encode_update_key layout, and enforcement
    // silently retains any row the regex fails to match, so pin the two
    // together: every payload the codec can produce must match, with the
    // grouping capture equal to the escaped key and the order capture equal to
    // the big-endian location.
    #[test]
    fn test_update_regex_matches_encode_update_key_payloads() {
        let regex = compiled_update_regex();

        // Raw keys exercising the escape grammar: empty, embedded zeros at
        // every position, bytes that mimic the escape pair and the terminator,
        // and the longest zero-free key that still fits.
        let max_key = vec![0xAB_u8; 243];
        let keys: Vec<&[u8]> = vec![
            b"",
            b"a",
            b"k-00000001",
            b"\x00",
            b"\x00\x00",
            b"a\x00",
            b"\x00a",
            b"a\x00b",
            b"\x00\xFF",
            b"\xFF\x00",
            b"\xFF\xFF",
            &max_key,
        ];
        let locations = [0u64, 1, 0xFF, 0x0000_FF00_00FF_0000, u64::MAX];

        let mut logical_captures = HashSet::new();
        for &raw_key in &keys {
            let mut per_key = HashSet::new();
            for location in locations {
                let key = encode_update_key::<mmr::Family>(raw_key, Location::new(location))
                    .expect("encode update key");
                let payload = UPDATE_PREFIX.strip(&key).expect("payload");
                let captures = regex.captures(&payload).unwrap_or_else(|| {
                    panic!("regex must match key {raw_key:02X?} at location {location}")
                });
                assert_eq!(
                    captures.get(0).expect("full match").as_bytes(),
                    payload.as_ref()
                );
                let escaped = encode_ordered_key_bytes(raw_key);
                let logical = captures.name("logical").expect("logical").as_bytes();
                assert_eq!(
                    logical,
                    &escaped[..escaped.len() - ORDERED_KEY_TERMINATOR_LEN]
                );
                assert_eq!(
                    captures.name("version").expect("version").as_bytes(),
                    location.to_be_bytes().as_slice()
                );
                per_key.insert(logical.to_vec());
            }
            // Grouping correctness: every location of one raw key must land in
            // the same group, and no two raw keys may share a group.
            assert_eq!(per_key.len(), 1, "one group per raw key");
            assert!(
                logical_captures.insert(per_key.into_iter().next().unwrap()),
                "group for key {raw_key:02X?} must be distinct"
            );
        }
    }

    #[test]
    fn test_update_regex_rejects_malformed_payloads() {
        let regex = compiled_update_regex();

        // Shorter than a terminator plus a version.
        let truncated = vec![0x61_u8; 9];
        // No terminator where the fixed-width layout demands one.
        let unterminated = [b"ab".as_slice(), &[0x11; 8][..]].concat();
        // Escape byte followed by something other than the zero escape.
        let broken_escape = [&[0x00, 0x01, 0x00, 0x00][..], &[0x11; 8][..]].concat();
        for payload in [truncated, unterminated, broken_escape] {
            assert!(
                !regex.is_match(&payload),
                "regex must reject invalid payload {payload:02X?}"
            );
        }
    }

    #[test]
    fn test_keep_positions_gte_uses_threshold_retention() {
        let policy = keep_positions_gte(42);
        let scope = &policy.scope;
        assert_eq!(
            policy.retain,
            RetainPolicy::GreaterThanOrEqual { threshold: 42 }
        );
        assert_eq!(
            &*scope.order_by.as_ref().expect("order_by").capture_group,
            "version"
        );
    }
}
