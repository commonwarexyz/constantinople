//! The metered demo content: a fixed essay the operator streams token by
//! token through `GET /stream`.
//!
//! Deterministic on purpose — the demo (and any test hitting the endpoint)
//! must not depend on an external content source. The metering loop is
//! source-agnostic; swapping this for a proxied LLM stream would change
//! nothing about payment enforcement.

use std::sync::OnceLock;

/// The essay `GET /stream` serves, one token at a time.
const ESSAY: &str = "Every payment you are watching right now costs this chain nothing.

The words appearing on your screen are being sold one at a time. Each token \
has a price, and the payer's browser is signing a steady stream of vouchers \
to cover them — dozens of little payments that no block will ever contain. \
The chain saw one transaction when this channel opened, and it will see one \
more when it closes. Everything in between happens here, off-chain, at the \
speed of an HTTP round trip.

A payment channel is a simple bargain. The payer escrows a deposit on-chain \
and names three parties: itself, a receiver, and an operator whose key is \
allowed to settle. From then on, payment is just a signature. Each voucher \
signs a single number — the cumulative amount the payer owes — and hands it \
to the operator. A bigger number replaces a smaller one. Lose a voucher? It \
doesn't matter; the latest one carries the whole history. When the channel \
closes, the operator submits only that final voucher, the receiver is paid \
its cumulative in one transfer, and the payer reclaims the rest of the \
deposit.

The enforcement you are experiencing is the interesting part. This server \
streams content only while the debt — tokens served minus tokens paid for — \
stays under a small credit window. Stop paying and the stream pauses, waits \
politely for one more voucher, then hangs up. The operator risks at most the \
credit window; the payer risks at most the deposit. Neither needs to trust \
the other, because the voucher in the operator's hand is already an \
on-chain-enforceable claim, and the deposit backing it is already locked.

Why bother? Because fees and finality make tiny payments absurd on any \
chain, and yet tiny payments are the natural shape of metered services: \
tokens from a model, bytes from an archive, seconds of a stream. A channel \
amortizes two on-chain transactions across thousands of micropayments, \
which is how a feeless demo chain — or a fee-charging real one — can sell \
you this essay word by word without drowning in its own accounting.

When this stream ends, look at the channel's account in the explorer. You \
will find no trace of the payments you just watched — only an open, and \
eventually a close whose single number is the sum of all of them. That gap \
between what happened and what the chain needed to record is the whole \
point.
";

/// The essay split into priced tokens: each token is one word plus the
/// whitespace that follows it, so concatenating every token reproduces
/// [`ESSAY`] exactly and the client can render chunks verbatim.
pub fn tokens() -> &'static [&'static str] {
    static TOKENS: OnceLock<Vec<&'static str>> = OnceLock::new();
    TOKENS.get_or_init(|| {
        let mut tokens = Vec::new();
        let mut rest = ESSAY;
        while !rest.is_empty() {
            let word_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let token_end = rest[word_end..]
                .find(|c: char| !c.is_whitespace())
                .map_or(rest.len(), |ws| word_end + ws);
            tokens.push(&rest[..token_end]);
            rest = &rest[token_end..];
        }
        tokens
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_reassemble_the_essay() {
        assert_eq!(tokens().concat(), ESSAY);
        assert!(tokens().iter().all(|token| !token.trim().is_empty()));
        // The demo's pacing assumes a few hundred tokens, and the explorer
        // sizes its deposit at DEPOSIT_TOKENS = 600 (PaidStreamPage.tsx) so a
        // paying session ends with `complete`, not `deposit_exhausted` —
        // growing the essay past that silently breaks the demo's ending.
        assert!((300..600).contains(&tokens().len()));
    }
}
