use super::{VerifiedAccountLookup, verify_current_account_lookup as verify};
use commonware_codec::Encode;
use js_sys::{BigInt, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

/// Authenticate one fixed account inclusion, returning a hit and throwing on failure. Absence is
/// not authenticated: the server reports a missing account as not found.
#[wasm_bindgen]
pub fn verify_current_account_lookup(
    proof: &[u8],
    root: &[u8],
    key: &[u8],
    expected_tip: u64,
    encoded_operation: Option<Vec<u8>>,
    exclusion: bool,
) -> Result<JsValue, JsValue> {
    let verified = verify(proof, root, key, expected_tip, encoded_operation, exclusion)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let result = Object::new();
    let (kind, key) = match verified {
        VerifiedAccountLookup::Present {
            location,
            key,
            account,
        } => {
            Reflect::set(&result, &"location".into(), &BigInt::from(location).into())?;
            Reflect::set(
                &result,
                &"value".into(),
                &Uint8Array::from(account.encode().as_ref()).into(),
            )?;
            ("hit", key)
        }
    };
    Reflect::set(&result, &"type".into(), &kind.into())?;
    Reflect::set(
        &result,
        &"key".into(),
        &Uint8Array::from(key.as_ref()).into(),
    )?;
    Ok(result.into())
}
