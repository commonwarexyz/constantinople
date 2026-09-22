use std::sync::Arc;

use commonware_storage::merkle::{Family, Location};
use exoware_sdk::keys::Key;
use exoware_sdk::selector::Selector;
use exoware_sdk::stream_filter::StreamFilter;
use exoware_sdk::{PrefixedStoreClient, StreamSubscription};

use crate::codec::{
    decode_operation_location_key, decode_watermark_location, OPERATION_PREFIX, WATERMARK_PREFIX,
};
use crate::QmdbError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RowFamily {
    Op,
    Watermark,
}

#[derive(Clone)]
pub(crate) struct RowClassifier<F: Family> {
    classify: Arc<dyn Fn(&Key, &[u8]) -> Option<(RowFamily, Location<F>)> + Send + Sync + 'static>,
}

impl<F: Family> RowClassifier<F> {
    fn new(
        classify: impl Fn(&Key, &[u8]) -> Option<(RowFamily, Location<F>)> + Send + Sync + 'static,
    ) -> Self {
        Self {
            classify: Arc::new(classify),
        }
    }

    pub(crate) fn classify(&self, key: &Key, value: &[u8]) -> Option<(RowFamily, Location<F>)> {
        (self.classify)(key, value)
    }
}

pub(crate) async fn open_store_subscription(
    client: &PrefixedStoreClient,
    filter: StreamFilter,
    since: Option<u64>,
) -> Result<StreamSubscription, QmdbError> {
    client
        .stream()
        .subscribe(filter, since)
        .await
        .map_err(|err| QmdbError::Stream(err.to_string()))
}

/// Select operation and publication rows from a QMDB historical log.
pub(crate) fn classify_and_filter<F: Family>() -> (RowClassifier<F>, StreamFilter) {
    use exoware_sdk::keys::{Key as StoreKey, Prefix};
    use exoware_sdk::kv_codec::Utf8;

    struct RowRule<F: Family> {
        prefix: Prefix,
        family: RowFamily,
        decode: Arc<dyn Fn(&StoreKey) -> Option<Location<F>> + Send + Sync>,
    }

    let op_prefix = OPERATION_PREFIX.as_bytes().clone();
    let watermark_prefix = WATERMARK_PREFIX.as_bytes().clone();

    let compiled: [RowRule<F>; 2] = [
        RowRule {
            prefix: OPERATION_PREFIX,
            family: RowFamily::Op,
            decode: Arc::new(|key| decode_operation_location_key::<F>(key).ok()),
        },
        RowRule {
            prefix: WATERMARK_PREFIX,
            family: RowFamily::Watermark,
            decode: Arc::new(|key| decode_watermark_location::<F>(key).ok()),
        },
    ];
    let payload_regex = "(?s-u)^.{8}$".to_string();

    let classify = RowClassifier::new(move |key: &StoreKey, _value: &[u8]| {
        for rule in &compiled {
            if rule.prefix.matches(key) {
                return (rule.decode)(key).map(|location| (rule.family, location));
            }
        }
        None
    });

    let filter = StreamFilter {
        selectors: vec![
            Selector {
                prefix: op_prefix,
                payload_regex: Utf8::from(payload_regex.as_str()),
            },
            Selector {
                prefix: watermark_prefix,
                payload_regex: Utf8::from(payload_regex.as_str()),
            },
        ],
        value_filters: vec![],
    };
    (classify, filter)
}

#[cfg(test)]
mod tests {
    use commonware_storage::merkle::{mmr, Location};
    use exoware_sdk::keys::Key;
    use exoware_sdk::selector::compile_payload_regex;

    use super::{classify_and_filter, RowFamily};
    use crate::codec::{encode_operation_key, encode_watermark_key};

    const LOCATIONS: [u64; 4] = [0, 1, 0x0102_0304_0506_0708, u64::MAX];

    // The payload regexes re-state the codec's row layouts, and the server
    // drops any row a selector fails to match, so pin them together: every
    // operation and watermark key the codec can produce must match its
    // selector's regex in full and classify to the same family and location.
    #[test]
    fn test_backend_selectors_match_their_row_payloads() {
        let (classifier, filter) = classify_and_filter::<mmr::Family>();
        for location in LOCATIONS {
            let loc = Location::new(location);
            let rows: [(RowFamily, Key); 2] = [
                (RowFamily::Op, encode_operation_key(loc)),
                (RowFamily::Watermark, encode_watermark_key(loc)),
            ];
            for (family, key) in rows {
                let selector = filter
                    .selectors
                    .iter()
                    .find(|s| key.starts_with(&s.prefix))
                    .expect("row must carry a selector prefix");
                let regex = compile_payload_regex(&selector.payload_regex).expect("regex");
                let payload = &key[selector.prefix.len()..];
                let captures = regex.captures(payload).unwrap_or_else(|| {
                    panic!("regex must match {family:?} payload {payload:02X?}")
                });
                assert_eq!(captures.get(0).expect("full match").as_bytes(), payload);
                assert_eq!(classifier.classify(&key, &[]), Some((family, loc)));
            }
        }
    }
}
