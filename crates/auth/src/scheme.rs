//! The signing scheme of votes that carry reports.
//!
//! Validators sign with their ed25519 identity keys under the `n >= 5f + 1` fault model.
//! An attestation is a [`Vote`]: the voter's [`Report`] and its signature over the
//! subject and the report. A certificate keeps every vote, so the notarization of a
//! block holds the reports that determine the status of its MAC transactions.

use crate::report::Report;
use bytes::{BufMut, Bytes};
use commonware_codec::{Buf, EncodeSize, Error, Read, ReadExt, ReadRangeExt, Write};
use commonware_consensus::{
    simplex::{scheme::Namespace, types::Subject},
    types::Round,
};
use commonware_cryptography::{
    BatchEntry, BatchVerifier as _, Digest, Signer as _, Verifier as _,
    certificate::{
        self, AssemblyError, Attestation, Namespace as _, Signers, Subject as _, Verification,
    },
    ed25519::{PrivateKey, PublicKey, Signature},
};
use commonware_parallel::Strategy;
use commonware_utils::{
    N5f1, Participant,
    iter::NonEmpty,
    ordered::{Quorum, Set},
    sync::Mutex,
};
use rand::CryptoRng;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// A validator keeps its reports for this many of the latest rounds.
const RETAINED_ROUNDS: usize = 256;

/// The attestation of a vote: a report and a signature over the subject and the report.
///
/// A vote for a block (notarize) reports on the block's MAC transactions. Nullify and
/// finalize votes carry [`Report::empty`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Vote {
    /// The voter's report.
    pub report: Report,
    /// Signature over the subject's message followed by the encoded report.
    pub signature: Signature,
}

impl Write for Vote {
    fn write(&self, buf: &mut impl BufMut) {
        self.report.write(buf);
        self.signature.write(buf);
    }
}

impl EncodeSize for Vote {
    fn encode_size(&self) -> usize {
        self.report.encode_size() + self.signature.encode_size()
    }
}

impl Read for Vote {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            report: Report::read(buf)?,
            signature: Signature::read(buf)?,
        })
    }
}

/// The votes of a quorum for one subject.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate {
    /// The validators whose votes follow.
    pub signers: Signers,
    /// One vote per signer, in signer order.
    pub votes: Vec<Vote>,
}

impl Certificate {
    /// The reports of the votes, in signer order.
    pub fn reports(&self) -> impl Iterator<Item = &Report> {
        self.votes.iter().map(|vote| &vote.report)
    }
}

impl Write for Certificate {
    fn write(&self, buf: &mut impl BufMut) {
        self.signers.write(buf);
        self.votes.write(buf);
    }
}

impl EncodeSize for Certificate {
    fn encode_size(&self) -> usize {
        self.signers.encode_size() + self.votes.encode_size()
    }
}

impl Read for Certificate {
    /// The largest number of validators.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, validators: &Self::Cfg) -> Result<Self, Error> {
        let signers = Signers::read_cfg(buf, validators)?;
        if signers.count() == 0 {
            return Err(Error::Invalid("Certificate", "no signers"));
        }
        let votes = Vec::<Vote>::read_range(buf, ..=*validators)?;
        if signers.count() != votes.len() {
            return Err(Error::Invalid(
                "Certificate",
                "signers and votes counts differ",
            ));
        }
        Ok(Self { signers, votes })
    }
}

/// The reports a validator attaches to its votes for blocks.
///
/// The validator records its report on a block once it has compared the tags of the
/// block's column, before it tells consensus that the block may be voted for. The scheme
/// then signs a vote for that block with the report. Clones share the reports.
#[derive(Clone, Debug, Default)]
pub struct Reports(Arc<Mutex<BTreeMap<Round, Recorded>>>);

/// The report on the block a validator may vote for in one round.
#[derive(Debug)]
struct Recorded {
    payload: Vec<u8>,
    report: Report,
}

impl Reports {
    /// Records this validator's report on the block with commitment `payload`, proposed
    /// in `round`. A validator votes for at most one block of a round.
    pub fn insert(&self, round: Round, payload: &[u8], report: Report) {
        let mut reports = self.0.lock();
        let payload = payload.to_vec();
        reports.insert(round, Recorded { payload, report });
        while reports.len() > RETAINED_ROUNDS {
            reports.pop_first();
        }
    }

    fn get(&self, round: Round, payload: &[u8]) -> Option<Report> {
        self.0
            .lock()
            .get(&round)
            .filter(|recorded| recorded.payload == payload)
            .map(|recorded| recorded.report.clone())
    }
}

/// Signs and verifies votes with reports.
#[derive(Clone, Debug)]
pub struct Scheme {
    participants: Set<PublicKey>,
    signer: Option<(Participant, PrivateKey)>,
    namespace: Namespace,
    reports: Reports,
}

impl Scheme {
    /// Creates the scheme of a validator, which signs with `private_key`.
    ///
    /// Returns `None` if `private_key` is not the key of a participant.
    pub fn signer(
        namespace: &[u8],
        participants: Set<PublicKey>,
        private_key: PrivateKey,
        reports: Reports,
    ) -> Option<Self> {
        let index = participants.index(&private_key.public_key())?;
        Some(Self {
            participants,
            signer: Some((index, private_key)),
            namespace: Namespace::derive(namespace),
            reports,
        })
    }

    /// Creates a scheme that verifies votes and certificates but cannot sign.
    pub fn verifier(namespace: &[u8], participants: Set<PublicKey>) -> Self {
        Self {
            participants,
            signer: None,
            namespace: Namespace::derive(namespace),
            reports: Reports::default(),
        }
    }

    /// The reports this validator signs with its votes for blocks.
    pub const fn reports(&self) -> &Reports {
        &self.reports
    }

    /// Whether a vote for `subject` may carry `report`.
    const fn accepts<D: Digest>(subject: &Subject<'_, D>, report: &Report) -> bool {
        matches!(subject, Subject::Notarize { .. }) || report.is_empty()
    }

    /// Checks the structure of `certificate` and stages the signature of each vote.
    ///
    /// Returns `false` if the certificate is malformed for `subject`.
    fn stage<'a, D: Digest>(
        &'a self,
        subject: &Subject<'_, D>,
        certificate: &'a Certificate,
        entries: &mut Vec<(&'a [u8], Vec<u8>, &'a PublicKey, &'a Signature)>,
    ) -> bool {
        let quorum = self.participants.quorum::<N5f1>() as usize;
        if certificate.signers.len() != self.participants.len()
            || certificate.signers.count() != certificate.votes.len()
            || certificate.signers.count() < quorum
        {
            return false;
        }
        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();
        for (signer, vote) in certificate.signers.iter().zip(&certificate.votes) {
            let Some(public_key) = self.participants.key(signer) else {
                return false;
            };
            if !Self::accepts(subject, &vote.report) {
                return false;
            }
            entries.push((
                namespace,
                signed(&message, &vote.report),
                public_key,
                &vote.signature,
            ));
        }
        true
    }
}

/// What a voter signs: the subject's message, then its report.
///
/// The message of each kind of subject is self-delimiting, and each kind has its own
/// namespace.
fn signed(message: &Bytes, report: &Report) -> Vec<u8> {
    let mut signed = Vec::with_capacity(message.len() + report.encode_size());
    signed.extend_from_slice(message);
    report.write(&mut signed);
    signed
}

fn verify_staged(
    rng: &mut impl CryptoRng,
    entries: &[(&[u8], Vec<u8>, &PublicKey, &Signature)],
    strategy: &impl Strategy,
) -> bool {
    PublicKey::verify_batch(
        rng,
        entries,
        |_, (namespace, message, public_key, signature)| BatchEntry {
            namespace,
            message,
            public_key,
            signature,
        },
        strategy,
    )
}

impl certificate::Verifier for Scheme {
    type Subject<'a, D: Digest> = Subject<'a, D>;
    type Faults = N5f1;
    type PublicKey = PublicKey;
    type Certificate = Certificate;

    fn verify_certificate<R, D>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        certificate: &Self::Certificate,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
    {
        let mut entries = Vec::with_capacity(certificate.votes.len());
        self.stage(&subject, certificate, &mut entries) && verify_staged(rng, &entries, strategy)
    }

    fn verify_certificates<'a, R, D, I>(
        &self,
        rng: &mut R,
        certificates: NonEmpty<I>,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
        I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
    {
        let mut entries = Vec::new();
        for (subject, certificate) in certificates {
            if !self.stage(&subject, certificate, &mut entries) {
                return false;
            }
        }
        verify_staged(rng, &entries, strategy)
    }

    fn is_batchable() -> bool {
        true
    }

    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg {
        self.participants.len()
    }

    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg {
        u32::MAX as usize
    }
}

impl certificate::Scheme for Scheme {
    type Signature = Vote;

    fn me(&self) -> Option<Participant> {
        self.signer.as_ref().map(|(index, _)| *index)
    }

    fn participants(&self) -> &Set<Self::PublicKey> {
        &self.participants
    }

    /// Signs a vote.
    ///
    /// A vote for a block carries the report recorded for it in [`Reports`]. Without
    /// one there is nothing to sign: the validator has not compared the block's tags.
    fn sign<D: Digest>(&self, subject: Self::Subject<'_, D>) -> Option<Attestation<Self>> {
        let (index, private_key) = self.signer.as_ref()?;
        let report = match &subject {
            Subject::Notarize { proposal } => self
                .reports
                .get(proposal.round, proposal.payload.as_ref())?,
            Subject::Nullify { .. } | Subject::Finalize { .. } => Report::empty(),
        };
        let signature = private_key.sign(
            subject.namespace(&self.namespace),
            &signed(&subject.message(), &report),
        );
        Some(Attestation {
            signer: *index,
            signature: Vote { report, signature }.into(),
        })
    }

    fn verify_attestation<R, D>(
        &self,
        _rng: &mut R,
        subject: Self::Subject<'_, D>,
        attestation: &Attestation<Self>,
        _strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
    {
        let Some(public_key) = self.participants.key(attestation.signer) else {
            return false;
        };
        let Some(vote) = attestation.signature.get() else {
            return false;
        };
        Self::accepts(&subject, &vote.report)
            && public_key.verify(
                subject.namespace(&self.namespace),
                &signed(&subject.message(), &vote.report),
                &vote.signature,
            )
    }

    fn verify_attestations<R, D, I>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        attestations: I,
        strategy: &impl Strategy,
    ) -> Verification<Self>
    where
        R: CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
    {
        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();

        let mut invalid = BTreeSet::new();
        let mut candidates = Vec::new();
        for attestation in attestations {
            let staged = self.participants.key(attestation.signer).and_then(|key| {
                let vote = attestation.signature.get()?;
                Self::accepts(&subject, &vote.report).then(|| (key, signed(&message, &vote.report)))
            });
            match staged {
                Some((key, signed)) => candidates.push((attestation, key, signed)),
                None => {
                    invalid.insert(attestation.signer);
                }
            }
        }

        fn signature(attestation: &Attestation<Scheme>) -> &Signature {
            &attestation
                .signature
                .get()
                .expect("decoded above")
                .signature
        }
        if !candidates.is_empty()
            && !PublicKey::verify_batch(
                rng,
                &candidates,
                |_, (attestation, public_key, message)| BatchEntry {
                    namespace,
                    message,
                    public_key,
                    signature: signature(attestation),
                },
                strategy,
            )
        {
            // The batch failed: verify each vote to find the invalid ones.
            for (attestation, public_key, message) in &candidates {
                if !public_key.verify(namespace, message, signature(attestation)) {
                    invalid.insert(attestation.signer);
                }
            }
        }

        let verified = candidates
            .into_iter()
            .filter(|(attestation, _, _)| !invalid.contains(&attestation.signer))
            .map(|(attestation, _, _)| attestation)
            .collect();
        Verification::new(verified, invalid.into_iter().collect())
    }

    fn optimistic_assemble<'a, R, D, I, J>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        pending: I,
        verified: J,
        strategy: &impl Strategy,
    ) -> Result<Self::Certificate, Verification<Self>>
    where
        R: CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: ExactSizeIterator + Send,
        J: IntoIterator<Item = &'a Attestation<Self>>,
        J::IntoIter: Send,
    {
        // Every vote ends up in a block, where anyone can check it, so each one is
        // verified before it enters a certificate.
        certificate::verify_then_assemble::<Self, _, D, _, _>(
            self, rng, subject, pending, verified, strategy,
        )
    }

    fn assemble<I>(
        &self,
        attestations: NonEmpty<I>,
        _strategy: &impl Strategy,
    ) -> Result<Self::Certificate, AssemblyError>
    where
        I: Iterator<Item = Attestation<Self>> + Send,
    {
        let mut entries = Vec::new();
        for Attestation { signer, signature } in attestations {
            self.participants
                .key(signer)
                .ok_or(AssemblyError::UnknownSigner(signer))?;
            let vote = signature
                .get()
                .cloned()
                .ok_or(AssemblyError::MalformedSignature(signer))?;
            entries.push((signer, vote));
        }
        entries.sort_by_key(|(signer, _)| *signer);
        let (signers, votes): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
        let signers = Signers::try_from((&self.participants, signers))?;

        let required = self.participants.quorum::<N5f1>();
        let found = signers.count() as u32;
        if found < required {
            return Err(AssemblyError::InsufficientAttestations(required, found));
        }
        Ok(Certificate { signers, votes })
    }

    fn is_attributable() -> bool {
        true
    }
}

/// Generates validator identities with a scheme for each, and a verifier.
#[cfg(any(test, feature = "mocks"))]
pub fn fixture(
    rng: &mut impl CryptoRng,
    namespace: &[u8],
    n: u32,
) -> certificate::mocks::Fixture<Scheme> {
    commonware_cryptography::ed25519::certificate::mocks::fixture(
        rng,
        namespace,
        n,
        |namespace, participants, private_key| {
            Scheme::signer(namespace, participants, private_key, Reports::default())
        },
        Scheme::verifier,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::status;
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_consensus::{
        simplex::{
            scheme::Scheme as SimplexScheme,
            types::{Finalize, Notarization, Notarize, Nullify, Proposal},
        },
        types::{Epoch, View},
    };
    use commonware_cryptography::{
        certificate::{Scheme as _, Verifier as _, mocks::Fixture},
        sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{Faults, non_empty, test_rng};

    const NAMESPACE: &[u8] = b"test";

    fn assert_simplex_scheme<S: SimplexScheme<Sha256Digest>>() {}

    #[test]
    fn scheme_is_a_simplex_scheme_with_n5f1() {
        assert_simplex_scheme::<Scheme>();
        assert_eq!(N5f1::quorum(6u32), 5);
    }

    fn proposal(view: u64) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(Epoch::new(0), View::new(view)),
            View::new(view - 1),
            Sha256Digest::from([view as u8; 32]),
        )
    }

    /// Every validator records `verdicts[i]` as its report on `proposal` and votes.
    fn notarizes(
        fixture: &Fixture<Scheme>,
        proposal: &Proposal<Sha256Digest>,
        verdicts: &[Vec<bool>],
    ) -> Vec<Notarize<Scheme, Sha256Digest>> {
        fixture
            .schemes
            .iter()
            .zip(verdicts)
            .map(|(scheme, verdicts)| {
                scheme.reports().insert(
                    proposal.round,
                    proposal.payload.as_ref(),
                    Report::new(verdicts),
                );
                Notarize::sign(scheme, proposal.clone()).unwrap()
            })
            .collect()
    }

    #[test]
    fn vote_for_a_block_carries_the_recorded_report() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 6);
        let proposal = proposal(2);
        let verdicts: Vec<Vec<bool>> = (0..6).map(|i| vec![true, i % 2 == 0]).collect();
        let votes = notarizes(&fixture, &proposal, &verdicts);

        for (vote, verdicts) in votes.iter().zip(&verdicts) {
            let report = &vote.attestation.signature.get().unwrap().report;
            assert_eq!(report.verdicts(2).as_ref(), Some(verdicts));
            assert!(vote.verify(&mut rng, &fixture.verifier, &Sequential));
        }
    }

    #[test]
    fn no_vote_for_a_block_without_a_report() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 6);
        let proposal = proposal(2);
        let scheme = &fixture.schemes[0];
        assert!(Notarize::sign(scheme, proposal.clone()).is_none());

        // A report on another block of the round, or on the block in another round.
        scheme
            .reports()
            .insert(proposal.round, &[9u8; 32], Report::empty());
        assert!(Notarize::sign(scheme, proposal.clone()).is_none());
        scheme.reports().insert(
            Round::new(Epoch::new(0), View::new(3)),
            proposal.payload.as_ref(),
            Report::empty(),
        );
        assert!(Notarize::sign(scheme, proposal.clone()).is_none());

        scheme
            .reports()
            .insert(proposal.round, proposal.payload.as_ref(), Report::empty());
        assert!(Notarize::sign(scheme, proposal).is_some());

        // A verifier never signs.
        assert!(Nullify::sign::<Sha256Digest>(&fixture.verifier, proposal_round()).is_none());
    }

    fn proposal_round() -> Round {
        Round::new(Epoch::new(0), View::new(2))
    }

    #[test]
    fn reports_are_kept_for_the_latest_rounds() {
        let reports = Reports::default();
        for view in 0..RETAINED_ROUNDS as u64 + 10 {
            let round = Round::new(Epoch::new(0), View::new(view));
            reports.insert(round, b"payload", Report::empty());
        }
        let round = |view| Round::new(Epoch::new(0), View::new(view));
        assert!(reports.get(round(9), b"payload").is_none());
        assert!(reports.get(round(10), b"payload").is_some());
        assert_eq!(reports.0.lock().len(), RETAINED_ROUNDS);
    }

    #[test]
    fn nullify_and_finalize_carry_the_empty_report() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 6);
        let proposal = proposal(2);
        let scheme = &fixture.schemes[1];

        let nullify = Nullify::sign::<Sha256Digest>(scheme, proposal.round).unwrap();
        assert!(
            nullify
                .attestation
                .signature
                .get()
                .unwrap()
                .report
                .is_empty()
        );
        assert!(nullify.verify::<_, Sha256Digest>(&mut rng, &fixture.verifier, &Sequential));

        let finalize = Finalize::sign(scheme, proposal.clone()).unwrap();
        assert!(
            finalize
                .attestation
                .signature
                .get()
                .unwrap()
                .report
                .is_empty()
        );
        assert!(finalize.verify(&mut rng, &fixture.verifier, &Sequential));

        // A finalize vote that reports is not a finalize vote, however it is signed.
        let report = Report::new(&[false]);
        let subject = Subject::Finalize {
            proposal: &proposal,
        };
        let signature = fixture.private_keys[1].sign(
            subject.namespace(&scheme.namespace),
            &signed(&subject.message(), &report),
        );
        let attestation = Attestation::<Scheme> {
            signer: Participant::new(1),
            signature: Vote { report, signature }.into(),
        };
        assert!(!fixture.verifier.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            subject,
            &attestation,
            &Sequential
        ));
    }

    #[test]
    fn signature_binds_the_report_the_subject_and_the_signer() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 6);
        let proposal = proposal(2);
        let verdicts = vec![vec![true, false]; 6];
        let votes = notarizes(&fixture, &proposal, &verdicts);
        let verify = |rng: &mut _, vote: &Notarize<Scheme, Sha256Digest>| {
            vote.verify(rng, &fixture.verifier, &Sequential)
        };

        // Another report under the same signature.
        let mut changed = votes[0].clone();
        let signature = changed
            .attestation
            .signature
            .get()
            .unwrap()
            .signature
            .clone();
        changed.attestation.signature = Vote {
            report: Report::empty(),
            signature,
        }
        .into();
        assert!(!verify(&mut rng, &changed));

        // Another proposal.
        let mut changed = votes[0].clone();
        changed.proposal = self::proposal(3);
        assert!(!verify(&mut rng, &changed));

        // Another signer, known or not.
        let mut changed = votes[0].clone();
        changed.attestation.signer = Participant::new(1);
        assert!(!verify(&mut rng, &changed));
        changed.attestation.signer = Participant::new(6);
        assert!(!verify(&mut rng, &changed));

        // A notarize vote is not a finalize vote.
        let as_finalize = Finalize::<Scheme, _> {
            proposal: proposal.clone(),
            attestation: Notarize::sign(&fixture.schemes[0], proposal)
                .unwrap()
                .attestation,
        };
        assert!(!as_finalize.verify(&mut rng, &fixture.verifier, &Sequential));

        // Another chain.
        let other = Scheme::verifier(b"other", fixture.verifier.participants.clone());
        assert!(!votes[0].verify(&mut rng, &other, &Sequential));
    }

    #[test]
    fn notarization_needs_n_minus_f_votes_and_keeps_their_reports() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 6);
        let proposal = proposal(2);
        // Entry 0: all approve. Entry 1: validators 0..3 approve. Entry 2: 0..2 approve.
        let verdicts: Vec<Vec<bool>> = (0..6).map(|i| vec![true, i < 3, i < 2]).collect();
        let votes = notarizes(&fixture, &proposal, &verdicts);
        let scheme = &fixture.schemes[0];

        assert_eq!(
            Notarization::from_notarizes(scheme, non_empty![@votes.iter().take(4)], &Sequential)
                .unwrap_err(),
            AssemblyError::InsufficientAttestations(5, 4)
        );

        // Assembled out of order, from the five votes of validators 0, 1, 2, 4 and 5.
        let quorum = [&votes[5], &votes[2], &votes[0], &votes[4], &votes[1]];
        let notarization =
            Notarization::from_notarizes(scheme, non_empty![@quorum], &Sequential).unwrap();
        assert!(notarization.verify(&mut rng, &fixture.verifier, &Sequential));

        let certificate = &notarization.certificate;
        let signers: Vec<u32> = certificate.signers.iter().map(Participant::get).collect();
        assert_eq!(signers, vec![0, 1, 2, 4, 5]);
        for (signer, report) in signers.iter().zip(certificate.reports()) {
            assert_eq!(
                report.verdicts(3).as_ref(),
                Some(&verdicts[*signer as usize])
            );
        }
        assert_eq!(status(certificate.reports(), 6, 3), vec![true, true, false]);

        // A notarization with the other four of validators 1..=5 and validator 0 sees
        // the same block but fewer approvals of entry 1.
        let other =
            Notarization::from_notarizes(scheme, non_empty![@votes.iter().skip(1)], &Sequential)
                .unwrap();
        assert!(other.verify(&mut rng, &fixture.verifier, &Sequential));
        assert_eq!(
            status(other.certificate.reports(), 6, 3),
            vec![true, false, false]
        );
    }

    #[test]
    fn certificate_roundtrips_and_rejects_tampering() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 6);
        let proposal = proposal(2);
        let verdicts: Vec<Vec<bool>> = (0..6).map(|i| vec![i != 3; 40]).collect();
        let votes = notarizes(&fixture, &proposal, &verdicts);
        let scheme = &fixture.schemes[0];
        let certificate =
            Notarization::from_notarizes(scheme, non_empty![@votes.iter().take(5)], &Sequential)
                .unwrap()
                .certificate;
        let subject = Subject::Notarize {
            proposal: &proposal,
        };
        let verify = |rng: &mut _, certificate: &Certificate| {
            fixture
                .verifier
                .verify_certificate(rng, subject, certificate, &Sequential)
        };
        assert!(verify(&mut rng, &certificate));

        let encoded = certificate.encode();
        assert_eq!(encoded.len(), certificate.encode_size());
        let config = fixture.verifier.certificate_codec_config();
        assert_eq!(
            Certificate::decode_cfg(encoded.clone(), &config).unwrap(),
            certificate
        );
        // A committee of five has no sixth signer.
        assert!(Certificate::decode_cfg(encoded, &5).is_err());

        // A report changed after signing.
        let mut changed = certificate.clone();
        changed.votes[3].report = Report::empty();
        assert!(!verify(&mut rng, &changed));

        // Votes attributed to other signers.
        let mut changed = certificate.clone();
        changed.votes.swap(0, 1);
        assert!(!verify(&mut rng, &changed));

        // One vote short of a quorum.
        let mut changed = certificate.clone();
        changed.votes.pop();
        changed.signers = Signers::new(6, (0..4).map(Participant::new)).expect("valid signers");
        assert!(!verify(&mut rng, &changed));

        // A certificate for a block is not one for finalizing it.
        assert!(!fixture.verifier.verify_certificate(
            &mut rng,
            Subject::Finalize {
                proposal: &proposal
            },
            &certificate,
            &Sequential
        ));
    }

    #[test]
    fn invalid_votes_are_reported_and_left_out() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 6);
        let proposal = proposal(2);
        let votes = notarizes(&fixture, &proposal, &vec![vec![true]; 6]);
        let subject = Subject::Notarize {
            proposal: &proposal,
        };

        let mut attestations: Vec<_> = votes.iter().map(|v| v.attestation.clone()).collect();
        // Validator 2 presents validator 3's vote as its own.
        attestations[2].signature = attestations[3].signature.clone();
        // Validator 4's vote does not decode.
        let mut truncated = Bytes::from_static(&[0, 1, 2]);
        attestations[4] = Attestation {
            signer: Participant::new(4),
            signature: commonware_codec::types::lazy::Lazy::deferred(&mut truncated, ()),
        };

        let scheme = &fixture.schemes[0];
        let result = scheme.verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            subject,
            attestations.clone(),
            &Sequential,
        );
        assert_eq!(
            result.invalid,
            vec![Participant::new(2), Participant::new(4)]
        );
        assert_eq!(result.verified.len(), 4);

        // Four valid votes are not a quorum of six validators.
        let outcome = scheme.optimistic_assemble::<_, Sha256Digest, _, _>(
            &mut rng,
            subject,
            attestations,
            [],
            &Sequential,
        );
        assert_eq!(outcome.unwrap_err().invalid.len(), 2);
    }

    #[test]
    fn vote_decodes_from_the_network() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 6);
        let proposal = proposal(2);
        let verdicts: Vec<Vec<bool>> = (0..6).map(|i| vec![i % 2 == 0; 9]).collect();
        let votes = notarizes(&fixture, &proposal, &verdicts);
        for vote in votes {
            let decoded = Notarize::<Scheme, Sha256Digest>::decode(vote.encode()).unwrap();
            assert_eq!(decoded, vote);
            assert!(decoded.verify(&mut rng, &fixture.verifier, &Sequential));
        }
    }
}
