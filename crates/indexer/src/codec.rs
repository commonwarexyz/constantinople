//! Thin codec helpers for indexer values.
//!
//! Values are encoded with [`commonware_codec`] using the same canonical
//! representation that consensus uses on the wire. Decoding back requires the
//! same `Cfg` that was used to encode (e.g. [`constantinople_primitives::BlockCfg`]).

use bytes::Bytes;
use commonware_codec::{Copying, Encode, Error as CodecError, Read};

/// Encode a value with the canonical `commonware-codec` representation.
pub fn to_bytes<T: Encode>(value: &T) -> Bytes {
    value.encode()
}

/// Decode a value using its required codec config.
pub fn from_bytes<T: Read>(bytes: &[u8], cfg: &T::Cfg) -> Result<T, CodecError> {
    let mut buf = Copying(bytes);
    T::read_cfg(&mut buf, cfg)
}
