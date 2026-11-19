//! `Chk`: the verdicts of one validator on the tags it has compared.

use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::Digest;
use commonware_runtime::ReadOptions;
use commonware_storage::{
    Context,
    journal::{
        Error,
        contiguous::{
            Contiguous, Many,
            fixed::{Config, Journal},
        },
    },
};
use commonware_utils::Participant;
use futures::{StreamExt as _, pin_mut};
use std::{collections::HashSet, num::NonZeroUsize};

/// A pair `(k, tr)` this validator answered "no" for.
#[derive(Clone, PartialEq, Eq, Hash)]
struct Rejected<D: Digest> {
    proposer: Participant,
    transaction: D,
}

impl<D: Digest> Write for Rejected<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proposer.get().write(buf);
        self.transaction.write(buf);
    }
}

impl<D: Digest> FixedSize for Rejected<D> {
    const SIZE: usize = u32::SIZE + D::SIZE;
}

impl<D: Digest> Read for Rejected<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            proposer: Participant::new(u32::read(buf)?),
            transaction: D::read(buf)?,
        })
    }
}

/// The partial map `Chk` from pairs (proposer, transaction) to verdicts.
///
/// A validator compares the tag a proposer sends for a transaction with its own once,
/// and its verdict then stands: the proposer cannot try another tag. A forger therefore
/// has one guess per validator, which is what makes short tags safe.
///
/// Only "no" verdicts are stored, and they are durable before [`Verdicts::check`]
/// returns, so a restart does not hand out a second guess. A "yes" is not stored: it is
/// found again by comparing, which tells a proposer nothing it does not know, since the
/// tag it sent before was the right one.
pub struct Verdicts<E: Context, D: Digest> {
    /// Taken while an operation that consumes the journal is in flight.
    journal: Option<Journal<E, Rejected<D>>>,
    rejected: HashSet<Rejected<D>>,
}

impl<E: Context, D: Digest> Verdicts<E, D> {
    /// Opens the store and loads the "no" verdicts recorded so far.
    pub async fn init(context: E, config: Config) -> Result<Self, Error> {
        let replay_buffer = config.replay_buffer;
        let journal = Journal::init(context, config).await?;
        let (journal, reader) = journal.snapshot().await?;
        let rejected = load(&reader, replay_buffer).await?;
        Ok(Self {
            journal: Some(journal),
            rejected,
        })
    }

    /// Number of "no" verdicts.
    pub fn rejected(&self) -> usize {
        self.rejected.len()
    }

    /// Returns this validator's verdict on each transaction of a block by `proposer`.
    ///
    /// Each entry is a transaction's digest and whether the tag the proposer sent for it
    /// equals this validator's own. An entry is approved iff its tag matches and the
    /// pair was not rejected before. New rejections are durable when this returns.
    ///
    /// # Panics
    ///
    /// Panics if an earlier call returned an error or was cancelled: the store can no
    /// longer vouch for its verdicts.
    pub async fn check(
        &mut self,
        proposer: Participant,
        entries: impl IntoIterator<Item = (D, bool)>,
    ) -> Result<Vec<bool>, Error> {
        let mut verdicts = Vec::new();
        let mut rejections = Vec::new();
        for (transaction, matches) in entries {
            let pair = Rejected {
                proposer,
                transaction,
            };
            let approved = matches && !self.rejected.contains(&pair);
            if !approved && self.rejected.insert(pair.clone()) {
                rejections.push(pair);
            }
            verdicts.push(approved);
        }

        if !rejections.is_empty() {
            let journal = self.journal.take().expect("verdict store failed earlier");
            let (journal, _) = journal.append_many(Many::Flat(&rejections)).await?;
            self.journal = Some(journal.sync().await?);
        }
        Ok(verdicts)
    }
}

async fn load<D: Digest>(
    reader: &impl Contiguous<Item = Rejected<D>>,
    buffer: NonZeroUsize,
) -> Result<HashSet<Rejected<D>>, Error> {
    let mut rejected = HashSet::new();
    let batches = reader
        .replay(reader.bounds(), buffer, ReadOptions::default())
        .await?;
    pin_mut!(batches);
    while let Some(batch) = batches.next().await {
        rejected.extend(batch?.items);
    }
    Ok(rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_runtime::{
        BufferPooler, Metrics, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};

    fn config(context: &(impl BufferPooler + Metrics)) -> Config {
        Config {
            partition: "verdicts".into(),
            items_per_blob: NZU64!(4),
            page_cache: CacheRef::from_pooler(&context.child("cache"), NZU16!(64), NZUsize!(16)),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
        }
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from([byte; 32])
    }

    #[test]
    fn a_no_stands_and_a_yes_is_compared_again() {
        deterministic::Runner::default().start(|context| async move {
            let mut verdicts =
                Verdicts::<_, Sha256Digest>::init(context.child("store"), config(&context))
                    .await
                    .unwrap();
            let proposer = Participant::new(1);

            let first = verdicts
                .check(proposer, [(digest(1), true), (digest(2), false)])
                .await
                .unwrap();
            assert_eq!(first, vec![true, false]);
            assert_eq!(verdicts.rejected(), 1);

            // The proposer now sends the right tag for the second transaction and a
            // wrong one for the first.
            let second = verdicts
                .check(proposer, [(digest(1), false), (digest(2), true)])
                .await
                .unwrap();
            assert_eq!(second, vec![false, false]);
            assert_eq!(verdicts.rejected(), 2);
        });
    }

    #[test]
    fn verdicts_are_per_proposer() {
        deterministic::Runner::default().start(|context| async move {
            let mut verdicts =
                Verdicts::<_, Sha256Digest>::init(context.child("store"), config(&context))
                    .await
                    .unwrap();
            let rejected = verdicts
                .check(Participant::new(1), [(digest(1), false)])
                .await
                .unwrap();
            assert_eq!(rejected, vec![false]);

            // The same transaction submitted to another proposer has other tags.
            let other = verdicts
                .check(Participant::new(2), [(digest(1), true)])
                .await
                .unwrap();
            assert_eq!(other, vec![true]);
        });
    }

    #[test]
    fn a_transaction_listed_twice_gets_one_verdict() {
        deterministic::Runner::default().start(|context| async move {
            let mut verdicts =
                Verdicts::<_, Sha256Digest>::init(context.child("store"), config(&context))
                    .await
                    .unwrap();
            let result = verdicts
                .check(
                    Participant::new(0),
                    [(digest(1), false), (digest(1), true), (digest(1), false)],
                )
                .await
                .unwrap();
            assert_eq!(result, vec![false, false, false]);
            assert_eq!(verdicts.rejected(), 1);
        });
    }

    #[test]
    fn a_restart_keeps_the_no_verdicts() {
        deterministic::Runner::default().start(|context| async move {
            let proposer = Participant::new(3);
            {
                let mut verdicts =
                    Verdicts::<_, Sha256Digest>::init(context.child("first"), config(&context))
                        .await
                        .unwrap();
                // More rejections than one blob holds, over several calls.
                for chunk in 0..3u8 {
                    let entries = (0..3u8).map(|i| (digest(chunk * 3 + i), i == 0));
                    let result = verdicts.check(proposer, entries).await.unwrap();
                    assert_eq!(result, vec![true, false, false]);
                }
                assert_eq!(verdicts.rejected(), 6);
            }

            let mut verdicts =
                Verdicts::<_, Sha256Digest>::init(context.child("second"), config(&context))
                    .await
                    .unwrap();
            assert_eq!(verdicts.rejected(), 6);
            let entries = (0..9u8).map(|i| (digest(i), true));
            let result = verdicts.check(proposer, entries).await.unwrap();
            let expected: Vec<bool> = (0..9).map(|i| i % 3 == 0).collect();
            assert_eq!(result, expected);
            assert_eq!(verdicts.rejected(), 6);
        });
    }
}
