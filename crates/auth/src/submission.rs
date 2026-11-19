//! Submissions: a transaction with its authenticator, sent to one validator.

use crate::{
    keys::{ChannelKey, Mac, SharedKey},
    tag::{Tags, tag_bits},
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_utils::Participant;

/// Why a validator does not admit a [`Submission`] to its pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The submission names another validator as its proposer.
    NotProposer,
    /// The authenticator does not hold one tag of the right length per validator.
    Authenticator,
    /// The submission did not come from the transaction's sender.
    Channel,
    /// The tag for this validator is not the sender's.
    Tag,
}

/// `(tr, a_1, ..., a_n)` as its sender submits it to validator `proposer`.
///
/// The tags depend on the proposer, so they are of no use to another validator. The MAC
/// realises the authenticated channel between the sender and the proposer: a validator
/// adds to its pool only submissions it received from the sender itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submission<T> {
    /// Index of the validator that is to propose the transaction.
    pub proposer: Participant,
    /// The transaction, without a signature.
    pub transaction: T,
    /// One tag per validator, in participant order.
    pub authenticator: Tags,
    /// Full-length MAC under the key the sender shares with the proposer.
    pub mac: Mac,
}

impl<T> Submission<T> {
    /// Builds the submission of `transaction` to `proposer`.
    ///
    /// `keys` holds the key the sender shares with each validator, in participant order,
    /// and `digest` is the transaction's digest.
    ///
    /// # Panics
    ///
    /// Panics if `proposer` is not the index of a validator.
    pub fn new(keys: &[SharedKey], proposer: Participant, transaction: T, digest: &[u8]) -> Self {
        let bits = tag_bits(participants(keys.len()));
        let mut authenticator = Tags::with_capacity(bits, keys.len());
        authenticator.extend(keys.iter().map(|key| key.tag.tag(proposer, digest, bits)));
        let mac = mac(
            &keys[usize::from(proposer)].channel,
            proposer,
            digest,
            &authenticator,
        );
        Self {
            proposer,
            transaction,
            authenticator,
            mac,
        }
    }

    /// The check validator `me` makes before it adds the submission to its pool.
    ///
    /// `key` is the key `me` shares with the transaction's sender, `digest` is the
    /// transaction's digest and `validators` is the size of the committee.
    pub fn admit(
        &self,
        me: Participant,
        key: &SharedKey,
        digest: &[u8],
        validators: usize,
    ) -> Result<(), Rejection> {
        if self.proposer != me {
            return Err(Rejection::NotProposer);
        }
        let bits = tag_bits(participants(validators));
        if self.authenticator.bits() != bits || self.authenticator.len() != validators {
            return Err(Rejection::Authenticator);
        }
        if mac(&key.channel, me, digest, &self.authenticator) != self.mac {
            return Err(Rejection::Channel);
        }

        // A sender that authenticates a wrong tag for its own proposer is faulty.
        // Proposing the transaction would only earn this validator's own "no".
        if self.authenticator.get(usize::from(me)) != Some(key.tag.tag(me, digest, bits)) {
            return Err(Rejection::Tag);
        }
        Ok(())
    }
}

fn participants(validators: usize) -> u32 {
    u32::try_from(validators).expect("committee size must fit in u32")
}

/// The MAC binds the proposer, the transaction and every tag. All three have a fixed
/// width for a given committee, so their concatenation is unambiguous.
fn mac(key: &ChannelKey, proposer: Participant, digest: &[u8], authenticator: &Tags) -> Mac {
    key.mac(&[
        &proposer.get().to_be_bytes(),
        digest,
        authenticator.as_bytes(),
    ])
}

impl<T: Write> Write for Submission<T> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proposer.write(buf);
        self.transaction.write(buf);
        self.authenticator.write(buf);
        self.mac.write(buf);
    }
}

impl<T: EncodeSize> EncodeSize for Submission<T> {
    fn encode_size(&self) -> usize {
        self.proposer.encode_size()
            + self.transaction.encode_size()
            + self.authenticator.encode_size()
            + Mac::SIZE
    }
}

impl<T: Read> Read for Submission<T> {
    /// The transaction's configuration and the size of the committee.
    type Cfg = (T::Cfg, usize);

    fn read_cfg(buf: &mut impl Buf, (transaction, validators): &Self::Cfg) -> Result<Self, Error> {
        let proposer = Participant::read(buf)?;
        if usize::from(proposer) >= *validators {
            return Err(Error::Invalid("Submission", "unknown proposer"));
        }
        let transaction = T::read_cfg(buf, transaction)?;
        let bits = tag_bits(participants(*validators));
        let authenticator = Tags::read_cfg(buf, &(bits, RangeCfg::new(*validators..=*validators)))?;
        let mac = Mac::read(buf)?;
        Ok(Self {
            proposer,
            transaction,
            authenticator,
            mac,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::PrivateKey;
    use commonware_codec::{Decode, Encode};
    use commonware_utils::test_rng;

    const NAMESPACE: &[u8] = b"chain";
    const DIGEST: &[u8] = &[7u8; 32];

    struct Fixture {
        /// The user's key with each validator.
        user: Vec<SharedKey>,
        /// Each validator's key with the user.
        validators: Vec<SharedKey>,
    }

    fn fixture(n: usize) -> Fixture {
        fixture_from(&mut test_rng(), n)
    }

    fn fixture_from(rng: &mut impl rand::CryptoRng, n: usize) -> Fixture {
        let user = PrivateKey::random(rng);
        let secrets: Vec<_> = (0..n).map(|_| PrivateKey::random(rng)).collect();
        Fixture {
            user: secrets
                .iter()
                .map(|v| user.with_validator(NAMESPACE, &v.public_key()).unwrap())
                .collect(),
            validators: secrets
                .iter()
                .map(|v| v.with_user(NAMESPACE, &user.public_key()).unwrap())
                .collect(),
        }
    }

    #[test]
    fn proposer_admits_a_correct_submission() {
        let f = fixture(6);
        let proposer = Participant::new(2);
        let submission = Submission::new(&f.user, proposer, 9u64, DIGEST);
        assert_eq!(submission.authenticator.len(), 6);
        assert_eq!(submission.authenticator.bits(), 86);
        assert_eq!(
            submission.admit(proposer, &f.validators[2], DIGEST, 6),
            Ok(())
        );
    }

    #[test]
    fn every_validator_finds_its_tag() {
        let f = fixture(6);
        let proposer = Participant::new(2);
        let submission = Submission::new(&f.user, proposer, 9u64, DIGEST);
        for (index, key) in f.validators.iter().enumerate() {
            assert_eq!(
                submission.authenticator.get(index),
                Some(key.tag.tag(proposer, DIGEST, 86))
            );
        }
    }

    #[test]
    fn only_the_named_proposer_admits() {
        let f = fixture(6);
        let submission = Submission::new(&f.user, Participant::new(2), 9u64, DIGEST);
        assert_eq!(
            submission.admit(Participant::new(3), &f.validators[3], DIGEST, 6),
            Err(Rejection::NotProposer)
        );

        // Renaming the proposer does not help: the MAC and the tags bind it.
        let mut renamed = submission;
        renamed.proposer = Participant::new(3);
        assert_eq!(
            renamed.admit(Participant::new(3), &f.validators[3], DIGEST, 6),
            Err(Rejection::Channel)
        );
    }

    #[test]
    fn a_submission_from_someone_else_is_rejected() {
        let f = fixture(6);
        let proposer = Participant::new(0);
        let submission = Submission::new(&f.user, proposer, 9u64, DIGEST);

        // Another transaction, or changed tags, under the same MAC.
        assert_eq!(
            submission.admit(proposer, &f.validators[0], &[8u8; 32], 6),
            Err(Rejection::Channel)
        );
        let mut changed = submission.clone();
        changed.authenticator = Submission::new(&f.user, proposer, 9u64, &[8u8; 32]).authenticator;
        assert_eq!(
            changed.admit(proposer, &f.validators[0], DIGEST, 6),
            Err(Rejection::Channel)
        );

        // A sender with other keys.
        let mut rng = test_rng();
        let _ = fixture_from(&mut rng, 6);
        let stranger = fixture_from(&mut rng, 6);
        assert_eq!(
            submission.admit(proposer, &stranger.validators[0], DIGEST, 6),
            Err(Rejection::Channel)
        );
    }

    #[test]
    fn a_wrong_tag_for_the_proposer_is_rejected() {
        let f = fixture(6);
        let proposer = Participant::new(1);

        // The sender authenticates tags for another transaction.
        let mut submission = Submission::new(&f.user, proposer, 9u64, DIGEST);
        submission.authenticator =
            Submission::new(&f.user, proposer, 9u64, &[8u8; 32]).authenticator;
        submission.mac = mac(
            &f.user[1].channel,
            proposer,
            DIGEST,
            &submission.authenticator,
        );
        assert_eq!(
            submission.admit(proposer, &f.validators[1], DIGEST, 6),
            Err(Rejection::Tag)
        );
    }

    #[test]
    fn an_authenticator_for_another_committee_is_rejected() {
        let f = fixture(6);
        let proposer = Participant::new(1);
        let submission = Submission::new(&f.user[..5], proposer, 9u64, DIGEST);
        assert_eq!(
            submission.admit(proposer, &f.validators[1], DIGEST, 6),
            Err(Rejection::Authenticator)
        );
    }

    #[test]
    fn submission_roundtrips() {
        let f = fixture(16);
        let submission = Submission::new(&f.user, Participant::new(15), 9u64, DIGEST);
        let encoded = submission.encode();
        assert_eq!(encoded.len(), submission.encode_size());
        // 16 tags of 45 bits.
        assert_eq!(submission.authenticator.encode_size(), 1 + 90);

        let decoded = Submission::<u64>::decode_cfg(encoded.clone(), &((), 16)).unwrap();
        assert_eq!(decoded, submission);

        // A committee of another size expects another authenticator.
        assert!(Submission::<u64>::decode_cfg(encoded.clone(), &((), 15)).is_err());
        assert!(Submission::<u64>::decode_cfg(encoded, &((), 17)).is_err());
    }
}
