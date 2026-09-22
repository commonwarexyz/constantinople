use std::cmp::Ordering;

use bytes::{BufMut, Bytes};
use commonware_codec::{
    Buf, Copying, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};

use crate::keys::{read_bit_be, read_bits_to_bytes, write_bit_be, Key};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Utf8(pub String);

impl std::ops::Deref for Utf8 {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for Utf8 {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Utf8 {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for Utf8 {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl std::fmt::Display for Utf8 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for Utf8 {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Utf8 {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<Utf8> for String {
    fn from(s: Utf8) -> Self {
        s.0
    }
}

impl Write for Utf8 {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.as_bytes().write(buf);
    }
}

impl EncodeSize for Utf8 {
    fn encode_size(&self) -> usize {
        self.0.as_bytes().encode_size()
    }
}

impl Read for Utf8 {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let range: RangeCfg<usize> = (..).into();
        let bytes = Vec::<u8>::read_cfg(buf, &(range, ()))?;
        let s =
            String::from_utf8(bytes).map_err(|_| CodecError::Invalid("Utf8", "invalid utf8"))?;
        Ok(Utf8(s))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KvFieldKind {
    Int64,
    UInt64,
    Float64,
    Boolean,
    Utf8,
    Date32,
    Date64,
    Timestamp,
    Decimal128,
    Decimal256,
    FixedSizeBinary(u8),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum KvFieldRef {
    Key {
        byte_offset: u16,
        kind: KvFieldKind,
    },
    ZOrderKey {
        bit_offset: u16,
        field_position: u8,
        field_widths: Vec<u8>,
        kind: KvFieldKind,
    },
    Value {
        index: u16,
        kind: KvFieldKind,
        nullable: bool,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum KvExpr {
    Field(KvFieldRef),
    Literal(KvReducedValue),
    Add(Box<KvExpr>, Box<KvExpr>),
    Sub(Box<KvExpr>, Box<KvExpr>),
    Mul(Box<KvExpr>, Box<KvExpr>),
    Div(Box<KvExpr>, Box<KvExpr>),
    Lower(Box<KvExpr>),
    DateTruncDay(Box<KvExpr>),
    CastFloat64(Box<KvExpr>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum KvPredicateConstraint {
    StringEq(String),
    BoolEq(bool),
    FixedSizeBinaryEq(Bytes),
    IntRange {
        min: Option<i64>,
        max: Option<i64>,
    },
    UInt64Range {
        min: Option<u64>,
        max: Option<u64>,
    },
    FloatRange {
        min: Option<(f64, bool)>,
        max: Option<(f64, bool)>,
    },
    Decimal128Range {
        min: Option<i128>,
        max: Option<i128>,
    },
    Decimal256Range {
        min: Option<[u8; 32]>,
        max: Option<[u8; 32]>,
    },
    IsNull,
    IsNotNull,
    StringIn(Vec<String>),
    IntIn(Vec<i64>),
    UInt64In(Vec<u64>),
    FixedSizeBinaryIn(Vec<Bytes>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct KvPredicateCheck {
    pub field: KvFieldRef,
    pub constraint: KvPredicateConstraint,
}

#[derive(Clone, Debug, PartialEq)]
pub struct KvPredicate {
    pub checks: Vec<KvPredicateCheck>,
    pub contradiction: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum KvReducedValue {
    Int64(i64),
    UInt64(u64),
    Float64(f64),
    Boolean(bool),
    Utf8(String),
    Date32(i32),
    Date64(i64),
    Timestamp(i64),
    Decimal128(i128),
    Decimal256([u8; 32]),
    FixedSizeBinary(Bytes),
}

#[derive(Debug, Clone)]
pub enum StoredValue {
    Int64(i64),
    UInt64(u64),
    Float64(f64),
    Boolean(bool),
    Utf8(String),
    Bytes(Vec<u8>),
    List(Vec<StoredValue>),
}

impl Write for StoredValue {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            StoredValue::Int64(v) => {
                0u8.write(buf);
                v.write(buf);
            }
            StoredValue::UInt64(v) => {
                1u8.write(buf);
                v.write(buf);
            }
            StoredValue::Float64(v) => {
                2u8.write(buf);
                v.write(buf);
            }
            StoredValue::Boolean(v) => {
                3u8.write(buf);
                v.write(buf);
            }
            StoredValue::Utf8(v) => {
                4u8.write(buf);
                v.as_bytes().write(buf);
            }
            StoredValue::Bytes(v) => {
                5u8.write(buf);
                v.as_slice().write(buf);
            }
            StoredValue::List(items) => {
                6u8.write(buf);
                items.as_slice().write(buf);
            }
        }
    }
}

impl EncodeSize for StoredValue {
    fn encode_size(&self) -> usize {
        1 + match self {
            StoredValue::Int64(_) => i64::SIZE,
            StoredValue::UInt64(_) => u64::SIZE,
            StoredValue::Float64(_) => f64::SIZE,
            StoredValue::Boolean(_) => bool::SIZE,
            StoredValue::Utf8(v) => v.as_bytes().encode_size(),
            StoredValue::Bytes(v) => v.as_slice().encode_size(),
            StoredValue::List(items) => items.as_slice().encode_size(),
        }
    }
}

impl Read for StoredValue {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let range: RangeCfg<usize> = (..).into();
        match u8::read(buf)? {
            0 => Ok(StoredValue::Int64(i64::read(buf)?)),
            1 => Ok(StoredValue::UInt64(u64::read(buf)?)),
            2 => Ok(StoredValue::Float64(f64::read(buf)?)),
            3 => Ok(StoredValue::Boolean(bool::read(buf)?)),
            4 => Ok(StoredValue::Utf8(Utf8::read(buf)?.0)),
            5 => {
                let bytes = Vec::<u8>::read_cfg(buf, &(range, ()))?;
                Ok(StoredValue::Bytes(bytes))
            }
            6 => {
                let items = Vec::<StoredValue>::read_cfg(buf, &(range, ()))?;
                Ok(StoredValue::List(items))
            }
            v => Err(CodecError::InvalidEnum(v)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoredRow {
    pub values: Vec<Option<StoredValue>>,
}

impl Write for StoredRow {
    fn write(&self, buf: &mut impl BufMut) {
        self.values.as_slice().write(buf);
    }
}

impl EncodeSize for StoredRow {
    fn encode_size(&self) -> usize {
        self.values.as_slice().encode_size()
    }
}

impl Read for StoredRow {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let range: RangeCfg<usize> = (..).into();
        let values = Vec::<Option<StoredValue>>::read_cfg(buf, &(range, ()))?;
        Ok(StoredRow { values })
    }
}

pub fn decode_stored_row(value: &[u8]) -> Result<StoredRow, CodecError> {
    StoredRow::read_cfg(&mut Copying(value), &())
}

/// Read a typed field. Key fields do not require a decoded stored row.
pub fn extract_field(
    key: &Key,
    archived: Option<&StoredRow>,
    field: &KvFieldRef,
) -> Result<Option<KvReducedValue>, String> {
    match field {
        KvFieldRef::Key { byte_offset, kind } => {
            extract_key_field(key, usize::from(*byte_offset), *kind)
                .map(Some)
                .ok_or_else(|| "invalid key field".to_string())
        }
        KvFieldRef::ZOrderKey {
            bit_offset,
            field_position,
            field_widths,
            kind,
        } => extract_zorder_key_field(
            key,
            usize::from(*bit_offset),
            usize::from(*field_position),
            field_widths,
            *kind,
        )
        .map(Some)
        .ok_or_else(|| "invalid z-order key field".to_string()),
        KvFieldRef::Value {
            index,
            kind,
            nullable,
        } => extract_stored_field(
            archived.ok_or_else(|| "value field requires stored row".to_string())?,
            usize::from(*index),
            *kind,
            *nullable,
        ),
    }
}

pub fn predicate_needs_value(predicate: &KvPredicate) -> bool {
    predicate
        .checks
        .iter()
        .any(|check| matches!(check.field, KvFieldRef::Value { .. }))
}

pub fn eval_predicate(
    key: &Key,
    archived: Option<&StoredRow>,
    predicate: &KvPredicate,
) -> Result<bool, String> {
    if predicate.contradiction {
        return Ok(false);
    }
    for check in &predicate.checks {
        let value = extract_field(key, archived, &check.field)?;
        if !matches_predicate_constraint(value.as_ref(), &check.constraint) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn interleave_ordered_key_fields(fields: &[Vec<u8>]) -> Vec<u8> {
    let total_bits = fields.iter().map(|field| field.len() * 8).sum::<usize>();
    let mut out = vec![0u8; total_bits.div_ceil(8)];
    let max_bits = fields
        .iter()
        .map(|field| field.len() * 8)
        .max()
        .unwrap_or(0);
    let mut out_bit = 0usize;
    for bit_idx in 0..max_bits {
        for field in fields {
            if bit_idx < field.len() * 8 {
                if read_bit_be(field, bit_idx) {
                    write_bit_be(&mut out, out_bit, true);
                }
                out_bit += 1;
            }
        }
    }
    out
}

pub fn deinterleave_ordered_key_fields(
    interleaved: &[u8],
    field_widths: &[u8],
) -> Option<Vec<Vec<u8>>> {
    let total_bits = field_widths
        .iter()
        .map(|width| usize::from(*width) * 8)
        .sum::<usize>();
    if interleaved.len() * 8 != total_bits {
        return None;
    }
    let max_bits = field_widths
        .iter()
        .map(|width| usize::from(*width) * 8)
        .max()
        .unwrap_or(0);
    let mut out = field_widths
        .iter()
        .map(|width| vec![0u8; usize::from(*width)])
        .collect::<Vec<_>>();
    let mut in_bit = 0usize;
    for bit_idx in 0..max_bits {
        for field in &mut out {
            if bit_idx < field.len() * 8 {
                let bit = read_bit_be(interleaved, in_bit);
                write_bit_be(field, bit_idx, bit);
                in_bit += 1;
            }
        }
    }
    Some(out)
}

pub fn extract_key_field(
    key: &Key,
    byte_offset: usize,
    kind: KvFieldKind,
) -> Option<KvReducedValue> {
    let width = key_field_width(kind);
    let end = byte_offset.checked_add(width)?;
    let bytes = key.get(byte_offset..end)?;
    decode_ordered_key_field_bytes(bytes, kind)
}

pub fn extract_zorder_key_field(
    key: &Key,
    bit_offset: usize,
    field_position: usize,
    field_widths: &[u8],
    kind: KvFieldKind,
) -> Option<KvReducedValue> {
    let total_width = field_widths
        .iter()
        .map(|width| usize::from(*width))
        .sum::<usize>();
    let interleaved = extract_key_bytes(key, bit_offset, total_width)?;
    let fields = deinterleave_ordered_key_fields(&interleaved, field_widths)?;
    let bytes = fields.get(field_position)?;
    decode_ordered_key_field_bytes(bytes, kind)
}

fn extract_key_bytes(key: &Key, bit_offset: usize, width: usize) -> Option<Vec<u8>> {
    let end_bit = bit_offset.checked_add(width.checked_mul(8)?)?;
    if end_bit > key.len() * 8 {
        return None;
    }
    if bit_offset.is_multiple_of(8) {
        let byte_offset = bit_offset / 8;
        return Some(key.get(byte_offset..byte_offset + width)?.to_vec());
    }
    let mut out = vec![0u8; width];
    read_bits_to_bytes(key, bit_offset, &mut out, width * 8);
    Some(out)
}

pub fn extract_stored_field(
    archived: &StoredRow,
    index: usize,
    kind: KvFieldKind,
    nullable: bool,
) -> Result<Option<KvReducedValue>, String> {
    let stored_opt = archived
        .values
        .get(index)
        .ok_or_else(|| "stored row index out of bounds".to_string())?
        .as_ref();
    let Some(stored) = stored_opt else {
        if nullable {
            return Ok(None);
        }
        return Err("non-nullable field stored as null".to_string());
    };

    let value = match (kind, stored) {
        (KvFieldKind::Int64, StoredValue::Int64(v)) => KvReducedValue::Int64(*v),
        (KvFieldKind::UInt64, StoredValue::UInt64(v)) => KvReducedValue::UInt64(*v),
        (KvFieldKind::Float64, StoredValue::Float64(v)) => KvReducedValue::Float64(*v),
        (KvFieldKind::Float64, StoredValue::Int64(v)) => KvReducedValue::Float64(*v as f64),
        (KvFieldKind::Boolean, StoredValue::Boolean(v)) => KvReducedValue::Boolean(*v),
        (KvFieldKind::Utf8, StoredValue::Utf8(v)) => KvReducedValue::Utf8(v.as_str().to_string()),
        (KvFieldKind::Date32, StoredValue::Int64(v)) => KvReducedValue::Date32(*v as i32),
        (KvFieldKind::Date64, StoredValue::Int64(v)) => KvReducedValue::Date64(*v),
        (KvFieldKind::Timestamp, StoredValue::Int64(v)) => KvReducedValue::Timestamp(*v),
        (KvFieldKind::Decimal128, StoredValue::Bytes(bytes)) => {
            let raw: [u8; 16] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "invalid Decimal128 byte width".to_string())?;
            KvReducedValue::Decimal128(i128::from_le_bytes(raw))
        }
        (KvFieldKind::Decimal256, StoredValue::Bytes(bytes)) => {
            let raw: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "invalid Decimal256 byte width".to_string())?;
            KvReducedValue::Decimal256(raw)
        }
        (KvFieldKind::FixedSizeBinary(width), StoredValue::Bytes(bytes)) => {
            if bytes.as_slice().len() != usize::from(width) {
                return Err("invalid FixedSizeBinary byte width".to_string());
            }
            KvReducedValue::FixedSizeBinary(Bytes::copy_from_slice(bytes))
        }
        _ => return Err("stored field type mismatch".to_string()),
    };
    Ok(Some(value))
}

fn key_field_width(kind: KvFieldKind) -> usize {
    match kind {
        KvFieldKind::Int64
        | KvFieldKind::UInt64
        | KvFieldKind::Float64
        | KvFieldKind::Date64
        | KvFieldKind::Timestamp => 8,
        KvFieldKind::Boolean => 1,
        KvFieldKind::Utf8 => 16,
        KvFieldKind::Date32 => 4,
        KvFieldKind::Decimal128 => 16,
        KvFieldKind::Decimal256 => 32,
        KvFieldKind::FixedSizeBinary(width) => usize::from(width),
    }
}

fn decode_ordered_key_field_bytes(bytes: &[u8], kind: KvFieldKind) -> Option<KvReducedValue> {
    Some(match kind {
        KvFieldKind::Int64 => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::Int64(decode_i64_ordered(raw))
        }
        KvFieldKind::UInt64 => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::UInt64(u64::from_be_bytes(raw))
        }
        KvFieldKind::Float64 => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::Float64(decode_f64_ordered(raw))
        }
        KvFieldKind::Boolean => KvReducedValue::Boolean(*bytes.first()? != 0),
        KvFieldKind::Utf8 => KvReducedValue::Utf8(decode_fixed_text(bytes)?),
        KvFieldKind::Date32 => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::Date32(decode_i32_ordered(raw))
        }
        KvFieldKind::Date64 => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::Date64(decode_i64_ordered(raw))
        }
        KvFieldKind::Timestamp => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::Timestamp(decode_i64_ordered(raw))
        }
        KvFieldKind::Decimal128 => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::Decimal128(decode_i128_ordered(raw))
        }
        KvFieldKind::Decimal256 => {
            let raw = bytes.try_into().ok()?;
            KvReducedValue::Decimal256(decode_i256_ordered(raw))
        }
        KvFieldKind::FixedSizeBinary(width) => {
            if bytes.len() != usize::from(width) {
                return None;
            }
            KvReducedValue::FixedSizeBinary(Bytes::copy_from_slice(bytes))
        }
    })
}

fn matches_predicate_constraint(
    value: Option<&KvReducedValue>,
    constraint: &KvPredicateConstraint,
) -> bool {
    match (value, constraint) {
        (None, KvPredicateConstraint::IsNull) => return true,
        (None, KvPredicateConstraint::IsNotNull) => return false,
        (Some(_), KvPredicateConstraint::IsNull) => return false,
        (Some(_), KvPredicateConstraint::IsNotNull) => return true,
        (None, _) => return false,
        _ => {}
    }
    let value = value.expect("checked above");
    match (value, constraint) {
        (KvReducedValue::Utf8(v), KvPredicateConstraint::StringEq(expected)) => v == expected,
        (KvReducedValue::Boolean(v), KvPredicateConstraint::BoolEq(expected)) => v == expected,
        (KvReducedValue::Int64(v), KvPredicateConstraint::IntRange { min, max }) => {
            in_i64_bounds(*v, *min, *max)
        }
        (KvReducedValue::Date32(v), KvPredicateConstraint::IntRange { min, max }) => {
            in_i64_bounds(*v as i64, *min, *max)
        }
        (KvReducedValue::Date64(v), KvPredicateConstraint::IntRange { min, max }) => {
            in_i64_bounds(*v, *min, *max)
        }
        (KvReducedValue::Timestamp(v), KvPredicateConstraint::IntRange { min, max }) => {
            in_i64_bounds(*v, *min, *max)
        }
        (KvReducedValue::Float64(v), KvPredicateConstraint::FloatRange { min, max }) => {
            in_f64_bounds(*v, min, max)
        }
        (KvReducedValue::Decimal128(v), KvPredicateConstraint::Decimal128Range { min, max }) => {
            in_i128_bounds(*v, *min, *max)
        }
        (KvReducedValue::Decimal256(v), KvPredicateConstraint::Decimal256Range { min, max }) => {
            in_i256_le_bounds(v, min.as_ref(), max.as_ref())
        }
        (KvReducedValue::Utf8(v), KvPredicateConstraint::StringIn(values)) => values.contains(v),
        (KvReducedValue::Int64(v), KvPredicateConstraint::IntIn(values)) => values.contains(v),
        (KvReducedValue::UInt64(v), KvPredicateConstraint::UInt64Range { min, max }) => {
            in_u64_bounds(*v, *min, *max)
        }
        (KvReducedValue::UInt64(v), KvPredicateConstraint::UInt64In(values)) => values.contains(v),
        (
            KvReducedValue::FixedSizeBinary(v),
            KvPredicateConstraint::FixedSizeBinaryEq(expected),
        ) => v == expected,
        (KvReducedValue::FixedSizeBinary(v), KvPredicateConstraint::FixedSizeBinaryIn(values)) => {
            values.contains(v)
        }
        _ => false,
    }
}

fn in_i64_bounds(value: i64, min: Option<i64>, max: Option<i64>) -> bool {
    min.is_none_or(|lower| value >= lower) && max.is_none_or(|upper| value <= upper)
}

fn in_u64_bounds(value: u64, min: Option<u64>, max: Option<u64>) -> bool {
    min.is_none_or(|lower| value >= lower) && max.is_none_or(|upper| value <= upper)
}

fn in_i128_bounds(value: i128, min: Option<i128>, max: Option<i128>) -> bool {
    min.is_none_or(|lower| value >= lower) && max.is_none_or(|upper| value <= upper)
}

fn in_f64_bounds(value: f64, min: &Option<(f64, bool)>, max: &Option<(f64, bool)>) -> bool {
    min.is_none_or(|(bound, inclusive)| {
        let order = value.total_cmp(&bound);
        order.is_gt() || (inclusive && order.is_eq())
    }) && max.is_none_or(|(bound, inclusive)| {
        let order = value.total_cmp(&bound);
        order.is_lt() || (inclusive && order.is_eq())
    })
}

fn decode_i64_ordered(bytes: [u8; 8]) -> i64 {
    (u64::from_be_bytes(bytes) ^ 0x8000_0000_0000_0000) as i64
}

fn decode_f64_ordered(bytes: [u8; 8]) -> f64 {
    let bits = u64::from_be_bytes(bytes);
    let decoded = if bits & 0x8000_0000_0000_0000 != 0 {
        bits ^ 0x8000_0000_0000_0000
    } else {
        !bits
    };
    f64::from_bits(decoded)
}

fn decode_i32_ordered(bytes: [u8; 4]) -> i32 {
    (u32::from_be_bytes(bytes) ^ 0x8000_0000) as i32
}

fn decode_i128_ordered(bytes: [u8; 16]) -> i128 {
    (u128::from_be_bytes(bytes) ^ (1u128 << 127)) as i128
}

fn decode_i256_ordered(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[0] ^= 0x80;
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = bytes[31 - i];
    }
    le
}

fn cmp_i256_le_bytes(a: &[u8; 32], b: &[u8; 32]) -> Ordering {
    let a_neg = a[31] & 0x80 != 0;
    let b_neg = b[31] & 0x80 != 0;
    match (a_neg, b_neg) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => {
            for i in (0..32).rev() {
                match a[i].cmp(&b[i]) {
                    Ordering::Equal => continue,
                    ord => return ord,
                }
            }
            Ordering::Equal
        }
    }
}

fn in_i256_le_bounds(value: &[u8; 32], min: Option<&[u8; 32]>, max: Option<&[u8; 32]>) -> bool {
    min.is_none_or(|lower| cmp_i256_le_bytes(value, lower) != Ordering::Less)
        && max.is_none_or(|upper| cmp_i256_le_bytes(value, upper) != Ordering::Greater)
}

fn decode_fixed_text(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end])
        .ok()
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MAX_KEY_LEN;
    use commonware_codec::Encode;

    #[test]
    fn float_bounds_follow_total_order() {
        for value in [
            f64::NEG_INFINITY,
            -0.0,
            0.0,
            f64::INFINITY,
            f64::NAN,
            -f64::NAN,
        ] {
            assert!(in_f64_bounds(value, &None, &None));
            for bound in [-0.0, 0.0, f64::NAN, -f64::NAN] {
                assert_eq!(
                    in_f64_bounds(value, &Some((bound, true)), &None),
                    value.total_cmp(&bound).is_ge()
                );
                assert_eq!(
                    in_f64_bounds(value, &None, &Some((bound, false))),
                    value.total_cmp(&bound).is_lt()
                );
            }
        }
    }

    #[test]
    fn fixed_utf8_key_round_trip() {
        let mut key = vec![0u8; MAX_KEY_LEN];
        key[4..8].copy_from_slice(b"west");
        let key = Key::from(key);
        let value = extract_key_field(&key, 4, KvFieldKind::Utf8).expect("utf8 field");
        assert_eq!(value, KvReducedValue::Utf8("west".to_string()));
    }

    #[test]
    fn int64_key_round_trip() {
        let mut key = vec![0u8; MAX_KEY_LEN];
        let encoded = ((-42i64 as u64) ^ 0x8000_0000_0000_0000).to_be_bytes();
        key[8..16].copy_from_slice(&encoded);
        let key = Key::from(key);
        let value = extract_key_field(&key, 8, KvFieldKind::Int64).expect("int64 field");
        assert_eq!(value, KvReducedValue::Int64(-42));
    }

    #[test]
    fn stored_decimal128_field_round_trip() {
        let row = StoredRow {
            values: vec![Some(StoredValue::Bytes(123i128.to_le_bytes().to_vec()))],
        };
        let bytes = row.encode();
        let decoded = decode_stored_row(&bytes).expect("decoded row");
        let value = extract_stored_field(&decoded, 0, KvFieldKind::Decimal128, false)
            .expect("valid field")
            .expect("present field");
        assert_eq!(value, KvReducedValue::Decimal128(123));
    }

    #[test]
    fn non_nullable_missing_field_is_invalid() {
        let row = StoredRow { values: vec![None] };
        let bytes = row.encode();
        let decoded = decode_stored_row(&bytes).expect("decoded row");
        let err = extract_stored_field(&decoded, 0, KvFieldKind::Int64, false)
            .expect_err("missing non-nullable field should fail");
        assert!(err.contains("non-nullable"));
    }

    #[test]
    fn zorder_interleave_round_trips_mixed_width_fields() {
        let fields = vec![vec![0x80, 0x01, 0x02, 0x03], vec![0xAA, 0xBB], vec![0xCC]];
        let interleaved = interleave_ordered_key_fields(&fields);
        let decoded =
            deinterleave_ordered_key_fields(&interleaved, &[4, 2, 1]).expect("deinterleave");
        assert_eq!(decoded, fields);
    }

    #[test]
    fn eval_predicate_supports_zorder_key_fields() {
        let mut key_buf = vec![0u8; 19];
        let x = ((2i64 as u64) ^ 0x8000_0000_0000_0000)
            .to_be_bytes()
            .to_vec();
        let y = ((1i64 as u64) ^ 0x8000_0000_0000_0000)
            .to_be_bytes()
            .to_vec();
        let interleaved = interleave_ordered_key_fields(&[x, y]);
        key_buf[3..3 + interleaved.len()].copy_from_slice(&interleaved);
        let key = Key::from(key_buf);

        let predicate = KvPredicate {
            checks: vec![
                KvPredicateCheck {
                    field: KvFieldRef::ZOrderKey {
                        bit_offset: 24,
                        field_position: 0,
                        field_widths: vec![8, 8],
                        kind: KvFieldKind::Int64,
                    },
                    constraint: KvPredicateConstraint::IntRange {
                        min: Some(1),
                        max: Some(2),
                    },
                },
                KvPredicateCheck {
                    field: KvFieldRef::ZOrderKey {
                        bit_offset: 24,
                        field_position: 1,
                        field_widths: vec![8, 8],
                        kind: KvFieldKind::Int64,
                    },
                    constraint: KvPredicateConstraint::IntRange {
                        min: Some(1),
                        max: Some(2),
                    },
                },
            ],
            contradiction: false,
        };

        assert!(eval_predicate(&key, None, &predicate).expect("predicate eval"));
    }
}
