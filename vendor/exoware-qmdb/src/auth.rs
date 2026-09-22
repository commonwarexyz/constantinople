use commonware_codec::Decode;
use commonware_cryptography::Hasher;
use commonware_storage::merkle::{hasher::Hasher as MerkleHasher, Family, Location, Position};
use exoware_sdk::keys::Key;
use exoware_sdk::{RangeMode, SerializableReadSession};

use crate::codec::{
    decode_digest, decode_operation_location_key, decode_watermark_location, encode_node_key,
    encode_operation_key, encode_update_key, encode_watermark_key, merkle_size_for_watermark,
    op_count_for_watermark, WATERMARK_PREFIX,
};
use crate::error::QmdbError;

pub(crate) async fn load_latest_auth_immutable_update_row<F: Family>(
    session: &SerializableReadSession,
    watermark: Location<F>,
    key: &[u8],
) -> Result<Option<(Key, Vec<u8>)>, QmdbError> {
    let start = encode_update_key(key, Location::<F>::new(0))?;
    let end = encode_update_key(key, watermark)?;
    let rows = session
        .range_with_mode(&start, &end, 1, RangeMode::Reverse)
        .await?;
    Ok(rows
        .into_iter()
        .next()
        .map(|(key, value)| (key, value.to_vec())))
}

pub(crate) async fn read_latest_auth_watermark<F: Family>(
    session: &SerializableReadSession,
) -> Result<Option<Location<F>>, QmdbError> {
    let (start, end) = WATERMARK_PREFIX.bounds();
    let rows = session
        .range_with_mode(&start, &end, 1, RangeMode::Reverse)
        .await?;
    match rows.into_iter().next() {
        Some((key, _)) => Ok(Some(decode_watermark_location(&key)?)),
        None => Ok(None),
    }
}

pub(crate) async fn require_published_auth_watermark<F: Family>(
    session: &SerializableReadSession,
    watermark: Location<F>,
) -> Result<(), QmdbError> {
    let available = read_latest_auth_watermark::<F>(session)
        .await?
        .unwrap_or(Location::new(0));
    let watermark_exists = session
        .get(&encode_watermark_key(watermark))
        .await?
        .is_some();
    if available < watermark
        || (!watermark_exists && available == Location::new(0) && watermark == Location::new(0))
    {
        return Err(QmdbError::WatermarkTooLow {
            requested: watermark.as_u64(),
            available: available.as_u64(),
        });
    }
    Ok(())
}

pub(crate) fn auth_inactive_peaks<F: Family>(
    watermark: Location<F>,
    inactivity_floor: Location<F>,
) -> Result<usize, QmdbError> {
    Ok(F::inactive_peaks(
        op_count_for_watermark(watermark)?,
        inactivity_floor,
    ))
}

pub(crate) async fn compute_auth_root<F: Family, H: Hasher>(
    session: &SerializableReadSession,
    watermark: Location<F>,
    inactive_peaks: usize,
) -> Result<H::Digest, QmdbError> {
    let size = merkle_size_for_watermark(watermark)?;
    let leaves = op_count_for_watermark(watermark)?;
    let peak_positions: Vec<(Position<F>, u32)> = F::peaks(size).collect();
    let fetched = if peak_positions.is_empty() {
        std::collections::HashMap::new()
    } else {
        let peak_keys: Vec<Key> = peak_positions
            .iter()
            .map(|(pos, _)| encode_node_key(*pos))
            .collect();
        let peak_key_refs: Vec<&Key> = peak_keys.iter().collect();
        session
            .get_many(&peak_key_refs, peak_key_refs.len() as u32)
            .await?
            .collect()
            .await?
    };
    let mut peaks = Vec::with_capacity(peak_positions.len());
    for (peak_pos, _) in &peak_positions {
        let key = encode_node_key(*peak_pos);
        let Some(bytes) = fetched.get(&key) else {
            return Err(QmdbError::CorruptData(format!(
                "missing authenticated Merkle peak node at position {peak_pos}"
            )));
        };
        peaks.push(decode_digest(
            bytes.as_ref(),
            format!("authenticated peak node at position {peak_pos}"),
        )?);
    }
    let hasher = commonware_storage::qmdb::hasher::<H>();
    hasher
        .root(leaves, inactive_peaks, peaks.iter())
        .map_err(|e| QmdbError::CommonwareMerkle(e.to_string()))
}

pub(crate) async fn load_auth_operation_at<F: Family, Op>(
    session: &SerializableReadSession,
    location: Location<F>,
    cfg: &Op::Cfg,
) -> Result<Op, QmdbError>
where
    Op: Decode,
{
    let Some(bytes) = session.get(&encode_operation_key(location)).await? else {
        return Err(QmdbError::CorruptData(format!(
            "missing authenticated operation row at location {location}"
        )));
    };
    Op::decode_cfg(commonware_codec::Copying(bytes.as_ref()), cfg).map_err(|e| {
        QmdbError::CorruptData(format!(
            "failed to decode authenticated operation at location {location}: {e}"
        ))
    })
}

pub(crate) async fn load_auth_operation_bytes_range<F: Family>(
    session: &SerializableReadSession,
    start_location: Location<F>,
    end_location_exclusive: Location<F>,
) -> Result<Vec<Vec<u8>>, QmdbError> {
    if start_location >= end_location_exclusive {
        return Ok(Vec::new());
    }
    let start = encode_operation_key(start_location);
    let end = encode_operation_key(end_location_exclusive - 1);
    let rows = session
        .range(
            &start,
            &end,
            (*end_location_exclusive - *start_location) as usize,
        )
        .await?;
    if rows.len() != (*end_location_exclusive - *start_location) as usize {
        return Err(QmdbError::CorruptData(format!(
            "expected {} authenticated operation rows in range [{start_location}, {end_location_exclusive}), found {}",
            *end_location_exclusive - *start_location,
            rows.len()
        )));
    }
    let mut operations = Vec::with_capacity(rows.len());
    for (offset, (key, value)) in rows.into_iter().enumerate() {
        let expected_location = start_location + offset as u64;
        let location = decode_operation_location_key::<F>(&key)?;
        if location != expected_location {
            return Err(QmdbError::CorruptData(format!(
                "authenticated operation row order mismatch: expected {expected_location}, got {location}"
            )));
        }
        operations.push(value.to_vec());
    }
    Ok(operations)
}
