//! HTTP wire types shared by the channel operator and its clients.
//!
//! The operator's API and the spammer's client used to hand-copy these
//! request/response shapes (and their hex conventions) and had already
//! drifted once; this module is the single definition both sides build
//! against. Every chain type crosses the wire hex-encoded via its codec
//! encoding, so the typed constructors and accessors here are the only
//! places that encode or parse fields.

use crate::{AccountKey, TransactionPublicKey, Voucher};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::ed25519;
use commonware_formatting::{from_hex, hex};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// A wire field that failed to parse back into its chain type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldError {
    /// Name of the offending field.
    pub field: &'static str,
}

impl core::fmt::Display for FieldError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "bad {}", self.field)
    }
}

impl core::error::Error for FieldError {}

/// Hex-encodes a codec value for the wire.
fn encode_field<T: Encode>(value: &T) -> String {
    hex(&value.encode())
}

/// Decodes a hex-encoded wire field into any codec type with no config.
fn decode_field<T: DecodeExt<()>>(field: &'static str, value: &str) -> Result<T, FieldError> {
    let bytes = from_hex(value).ok_or(FieldError { field })?;
    T::decode(bytes.as_slice()).map_err(|_| FieldError { field })
}

/// Response to `GET /public-key`: the operator's identity (the key that
/// settles channels; in a payee-run deployment it is also the receiver).
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    /// Hex-encoded operator transaction public key.
    pub public_key: String,
    /// Hex-encoded operator account key (derived from `public_key`; provided
    /// for display and tooling, not parsed by clients).
    pub account: String,
    /// Latest finalized height the operator has observed (0 until its first
    /// poll lands). Lets clients pick sane channel expiries.
    pub height: u64,
    /// Minimum blocks between registration and a channel's expiry; the
    /// operator refuses channels with less runway. Advertised so clients
    /// derive expiries from the operator's actual configuration instead of
    /// agreeing with it by convention.
    pub min_runway: u64,
    /// Blocks before expiry at which the operator stops serving vouchers and
    /// force-settles.
    pub settle_margin: u64,
    /// Chain units one streamed token on `GET /stream` costs.
    pub price_per_token: u64,
    /// Tokens the stream may run ahead of the channel's paid cumulative
    /// before it pauses for a voucher. Advertised (like the margins) so
    /// clients pace their payments from the operator's actual configuration.
    pub debt_limit: u64,
    /// Total tokens in the streamed content. Advertised so clients size a
    /// channel deposit that covers the whole stream instead of agreeing on
    /// the content's length by convention.
    pub stream_tokens: u64,
}

impl PublicKeyResponse {
    pub fn new(
        public_key: &TransactionPublicKey,
        height: u64,
        min_runway: u64,
        settle_margin: u64,
        price_per_token: u64,
        debt_limit: u64,
        stream_tokens: u64,
    ) -> Self {
        Self {
            public_key: encode_field(public_key),
            account: encode_field(&AccountKey::from_public_key(public_key)),
            height,
            min_runway,
            settle_margin,
            price_per_token,
            debt_limit,
            stream_tokens,
        }
    }

    /// Parses the operator transaction public key.
    pub fn public_key(&self) -> Result<TransactionPublicKey, FieldError> {
        decode_field("public_key", &self.public_key)
    }
}

/// Request to `POST /channels`: register a finalized channel open.
///
/// Deliberately minimal: the operator derives the payer, participants,
/// voucher key, and channel address from the verified open transaction, so
/// the request carries nothing the client could assert incorrectly. The
/// initial zero-value voucher (a signature over `(channel, 0)`) proves the
/// registrant holds the channel's voucher key and gives the operator a
/// starting voucher, making every registered channel closeable — including
/// one that never pays.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Hex-encoded digest of the finalized `OpenChannel` transaction.
    pub open_tx_digest: String,
    /// Hex-encoded voucher-key signature over `(channel, 0)` — the channel's
    /// initial zero-value voucher.
    pub zero_voucher: String,
}

impl RegisterRequest {
    pub fn new<D: Encode>(open_tx_digest: &D, zero_voucher: &ed25519::Signature) -> Self {
        Self {
            open_tx_digest: encode_field(open_tx_digest),
            zero_voucher: encode_field(zero_voucher),
        }
    }

    /// Parses the open transaction digest (generic: the wire does not fix the
    /// chain's hash function).
    pub fn open_tx_digest<D: DecodeExt<()>>(&self) -> Result<D, FieldError> {
        decode_field("open_tx_digest", &self.open_tx_digest)
    }

    /// Parses the initial zero-voucher signature.
    pub fn zero_voucher(&self) -> Result<ed25519::Signature, FieldError> {
        decode_field("zero_voucher", &self.zero_voucher)
    }
}

/// Response to `POST /channels`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// Whether this request newly registered the channel. `false` is still
    /// success: the channel was already registered with matching metadata (an
    /// idempotent replay, e.g. a retry after a lost response). Failures are
    /// HTTP errors, never `registered: false`.
    pub registered: bool,
    /// Opaque bearer capability authorizing this channel's stream and manual
    /// settlement endpoints. Channel addresses are public chain data, so
    /// clients must keep this value private and present it on those requests.
    /// An idempotent registration replay returns the original capability.
    pub capability: String,
}

/// Request to `POST /vouchers`: one off-chain payment step.
#[derive(Debug, Serialize, Deserialize)]
pub struct VoucherRequest {
    /// Hex-encoded channel account key.
    pub channel: String,
    /// Cumulative amount the voucher signs over.
    pub cumulative: u64,
    /// Hex-encoded voucher-key signature over `(channel, cumulative)`.
    pub signature: String,
}

impl VoucherRequest {
    pub fn new(voucher: &Voucher) -> Self {
        Self {
            channel: encode_field(&voucher.channel),
            cumulative: voucher.cumulative,
            signature: encode_field(&voucher.signature),
        }
    }

    /// Reassembles the voucher this request carries.
    pub fn voucher(&self) -> Result<Voucher, FieldError> {
        Ok(Voucher {
            channel: decode_field("channel", &self.channel)?,
            cumulative: self.cumulative,
            signature: decode_field::<ed25519::Signature>("signature", &self.signature)?,
        })
    }
}

/// Response to `POST /vouchers`. Failures surface as HTTP errors, so a `200`
/// body means the voucher was accepted.
#[derive(Debug, Serialize, Deserialize)]
pub struct VoucherResponse {
    /// Cumulative amount the channel has paid for after accepting this
    /// voucher (the voucher's own cumulative).
    pub cumulative: u64,
}

/// Parses the hex-encoded `channel` query parameter of `GET /stream`.
pub fn parse_channel(value: &str) -> Result<AccountKey, FieldError> {
    decode_field("channel", value)
}

/// SSE event name carrying a [`StreamChunk`].
pub const STREAM_CHUNK_EVENT: &str = "chunk";
/// SSE event name carrying a [`StreamMeter`] when the stream pauses.
pub const STREAM_PAYMENT_REQUIRED_EVENT: &str = "payment-required";
/// SSE event name carrying the terminal [`StreamEnd`].
pub const STREAM_END_EVENT: &str = "end";

/// One `chunk` event on `GET /stream`: the next priced slice of content plus
/// the channel's meter after paying for it.
///
/// The stream endpoint is the demo's metered service: content is delivered
/// token by token over SSE while the channel's debt (`served - paid`) stays
/// under the advertised [`PublicKeyResponse::debt_limit`]. A request without
/// a registered channel answers `402 Payment Required`.
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamChunk {
    /// The next slice of content. `Cow` lets a server with static content
    /// serialize each chunk without a per-token copy.
    pub text: Cow<'static, str>,
    /// Tokens the channel has consumed after this chunk.
    pub served: u64,
    /// Cumulative amount the channel's latest voucher has paid for.
    pub paid: u64,
}

/// The `payment-required` event on `GET /stream`: the meter is at the debt
/// limit; a fresher voucher within the grace window resumes the stream.
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamMeter {
    /// Tokens the channel has consumed.
    pub served: u64,
    /// Cumulative amount the channel's latest voucher has paid for.
    pub paid: u64,
}

/// Why a `GET /stream` session ended (the terminal `end` event).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamEndReason {
    /// The content ran out; everything served was paid for or within limit.
    Complete,
    /// The debt limit was hit and no voucher arrived within the grace window.
    PaymentTimeout,
    /// Serving another token would exceed the channel's escrowed deposit.
    DepositExhausted,
    /// The channel stopped being servable (settlement started or expiry is
    /// too close).
    ChannelClosed,
}

/// The terminal `end` event on `GET /stream`.
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamEnd {
    /// Why the stream ended.
    pub reason: StreamEndReason,
    /// Tokens the channel consumed over its lifetime.
    pub served: u64,
    /// Cumulative amount the channel's latest voucher has paid for.
    pub paid: u64,
}

/// Request to `POST /settle`: close the channel on-chain now.
#[derive(Debug, Serialize, Deserialize)]
pub struct SettleRequest {
    /// Hex-encoded channel account key.
    pub channel: String,
    /// Opaque capability returned by the channel's registration.
    pub capability: String,
}

impl SettleRequest {
    pub fn new(channel: &AccountKey, capability: impl Into<String>) -> Self {
        Self {
            channel: encode_field(channel),
            capability: capability.into(),
        }
    }

    pub fn channel(&self) -> Result<AccountKey, FieldError> {
        parse_channel(&self.channel)
    }
}

/// Response to `POST /settle`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SettleResponse {
    /// Whether the close finalized (false: abandoned, vouchers forfeited).
    pub settled: bool,
    /// The cumulative amount the settlement covered.
    pub cumulative: u64,
}

/// Response to `GET /stats`: the operator's lifetime counters. `vouchers` is
/// the off-chain payment count the chain never sees; alongside `settled` it
/// is the payments-per-settlement story in two numbers. Self-reported by the
/// operator (unlike chain data, not proof-verified).
#[derive(Debug, Serialize, Deserialize)]
pub struct StatsResponse {
    /// Channels registered (lifetime).
    pub channels: u64,
    /// Channels whose close finalized.
    pub settled: u64,
    /// Channels whose close was abandoned.
    pub abandoned: u64,
    /// Vouchers accepted off-chain.
    pub vouchers: u64,
    /// Streamed content served through `GET /stream` (lifetime), in chain
    /// units (a token count while the price per token is 1).
    pub streamed: u64,
    /// Latest finalized height the operator has observed.
    pub height: u64,
}

/// Error body every operator failure responds with.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Why an operator request failed, split by what a retry can fix.
///
/// This is the retry contract of the operator API: the HTTP surface maps
/// `Rejected` to `400` and `Unavailable` to `503`, and clients map those
/// statuses back, so both sides share one classification instead of
/// hand-synchronizing it across the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperatorError {
    /// The request itself is invalid; retrying it will keep failing.
    Rejected(String),
    /// A dependency (indexer, relayer) has not caught up or could not be
    /// reached; the same request may succeed shortly.
    Unavailable(String),
}

impl OperatorError {
    /// A permanent rejection of the request itself.
    pub fn rejected(message: impl Into<String>) -> Self {
        Self::Rejected(message.into())
    }

    /// A transient dependency failure worth retrying.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable(message.into())
    }
}

impl core::fmt::Display for OperatorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rejected(message) | Self::Unavailable(message) => f.write_str(message),
        }
    }
}

impl core::error::Error for OperatorError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel_address;
    use commonware_codec::FixedSize as _;
    use commonware_cryptography::Signer as _;

    #[test]
    fn register_request_roundtrips_typed_fields() {
        let voucher_key = ed25519::PrivateKey::from_seed(1);
        let digest = commonware_cryptography::sha256::Digest::from([3u8; 32]);
        let channel = AccountKey::from([7u8; AccountKey::SIZE]);
        let zero_voucher = Voucher::sign(&voucher_key, channel, 0);

        let request = RegisterRequest::new(&digest, &zero_voucher.signature);
        assert_eq!(
            request
                .open_tx_digest::<commonware_cryptography::sha256::Digest>()
                .expect("digest parses"),
            digest
        );
        assert_eq!(
            request.zero_voucher().expect("signature parses"),
            zero_voucher.signature
        );
    }

    #[test]
    fn voucher_request_roundtrips_the_voucher() {
        let voucher_key = ed25519::PrivateKey::from_seed(4);
        let payer_account = AccountKey::from([4u8; AccountKey::SIZE]);
        let receiver = AccountKey::from([5u8; AccountKey::SIZE]);
        let channel = channel_address(
            &payer_account,
            &receiver,
            &receiver,
            &voucher_key.public_key(),
            0,
        );
        let voucher = Voucher::sign(&voucher_key, channel, 25);

        let request = VoucherRequest::new(&voucher);
        assert_eq!(request.voucher().expect("voucher parses"), voucher);
    }

    /// An advertisement missing a knob must fail to parse rather than
    /// silently defaulting to zero margins.
    #[test]
    fn public_key_response_rejects_missing_advertised_knobs() {
        let payer_key = ed25519::PrivateKey::from_seed(6);
        let payer = TransactionPublicKey::ed25519(payer_key.public_key());
        let response = PublicKeyResponse::new(&payer, 42, 20, 10, 1, 32, 500);

        let partial_wire = format!(
            r#"{{"public_key":"{}","account":"{}"}}"#,
            response.public_key, response.account
        );
        serde_json::from_str::<PublicKeyResponse>(&partial_wire)
            .expect_err("advertisement without margins must not parse");
    }

    #[test]
    fn bad_hex_names_the_field() {
        let request = SettleRequest {
            channel: "zz".to_string(),
            capability: "capability".to_string(),
        };
        let error = request.channel().expect_err("bad hex must fail");
        assert_eq!(error.field, "channel");
        assert_eq!(error.to_string(), "bad channel");
    }

    #[test]
    fn authorized_settle_request_roundtrips() {
        let channel = AccountKey::from([8u8; AccountKey::SIZE]);
        let capability = "opaque-capability";

        let settle = SettleRequest::new(&channel, capability);
        assert_eq!(settle.channel().expect("channel parses"), channel);
        assert_eq!(settle.capability, capability);
    }
}
