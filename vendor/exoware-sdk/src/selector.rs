//! Shared key-filter shape: `(prefix, payload_regex)`.
//!
//! Used by both `prune_policy` (prune service) and `stream_filter` (stream
//! service) so one domain type round-trips through the `common.kv.v1.Selector`
//! proto message and one regex compiler handles validation everywhere.

use anyhow::{ensure, Context};
use bytes::{BufMut, Bytes};
use commonware_codec::{Buf, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use regex::bytes::Regex;

use crate::keys::MAX_KEY_LEN;
use crate::kv_codec::Utf8;

/// Identifies a subset of keys by a byte prefix + payload regex. Matches the
/// `common.kv.v1.Selector` wire shape (see `proto/common/v1/kv.proto`). A key
/// belongs to the selector's family iff it starts with `prefix`; the payload
/// (the key bytes after `prefix`) is matched against `payload_regex`. An empty
/// `prefix` matches all keys.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Selector {
    pub prefix: Bytes,
    pub payload_regex: Utf8,
}

impl Write for Selector {
    fn write(&self, buf: &mut impl BufMut) {
        self.prefix.as_ref().write(buf);
        self.payload_regex.write(buf);
    }
}

impl EncodeSize for Selector {
    fn encode_size(&self) -> usize {
        self.prefix.as_ref().encode_size() + self.payload_regex.encode_size()
    }
}

impl Read for Selector {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let range: RangeCfg<usize> = (..=MAX_KEY_LEN).into();
        let prefix = Vec::<u8>::read_cfg(buf, &(range, ()))?;
        Ok(Selector {
            prefix: Bytes::from(prefix),
            payload_regex: Utf8::read(buf)?,
        })
    }
}

/// Compile the payload regex, rejecting empty / blank strings. Bytes-regex
/// because keys carry arbitrary non-UTF8 payloads.
pub fn compile_payload_regex(raw: &str) -> anyhow::Result<Regex> {
    ensure!(
        !raw.trim().is_empty(),
        "selector payload_regex must not be empty"
    );
    Regex::new(raw).with_context(|| format!("invalid selector payload_regex {raw:?}"))
}
