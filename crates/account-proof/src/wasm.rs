use super::{VerifiedAccountLookup, verify_current_account_lookup as verify};
use commonware_codec::Encode;
use js_sys::{BigInt, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

/// Authenticate one fixed account update, returning `{location, key, value}` and throwing on
/// failure.
#[wasm_bindgen]
pub fn verify_current_account_lookup(
    proof: &[u8],
    root: &[u8],
    key: &[u8],
    expected_tip: u64,
    encoded_operation: &[u8],
) -> Result<JsValue, JsValue> {
    let VerifiedAccountLookup {
        location,
        key,
        account,
    } = verify(proof, root, key, expected_tip, encoded_operation)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let result = Object::new();
    Reflect::set(&result, &"location".into(), &BigInt::from(location).into())?;
    Reflect::set(
        &result,
        &"key".into(),
        &Uint8Array::from(key.as_ref()).into(),
    )?;
    Reflect::set(
        &result,
        &"value".into(),
        &Uint8Array::from(account.encode().as_ref()).into(),
    )?;
    Ok(result.into())
}
