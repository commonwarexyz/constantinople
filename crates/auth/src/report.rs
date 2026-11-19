//! Reports and the status a notarization determines.

use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error, Read, Write, varint::UInt};
use commonware_utils::N5f1;

/// Largest number of MAC transactions of one block a report can cover.
///
/// A report is decoded without a configuration, so this bounds what a vote can make a
/// validator allocate. The block budget keeps blocks below it.
pub const MAX_ENTRIES: usize = 1 << 18;

/// A validator's verdict on each MAC transaction of a block: whether the tag it received
/// from the block's proposer was the sender's.
///
/// A report has two encodings, and a validator signs the one it sends: the positions it
/// rejects, which is short when it rejects few, or one bit per transaction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Report(Form);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Form {
    /// The rejected positions, in increasing order. Every other position is approved.
    Rejected(Vec<u32>),
    /// Bit `j` (most significant first) is set iff position `j` is approved. Unused bits
    /// of the last byte are zero.
    Bitmap { len: usize, bits: Vec<u8> },
}

impl Report {
    /// The report that rejects nothing. Votes that are not for a block carry it.
    pub const fn empty() -> Self {
        Self(Form::Rejected(Vec::new()))
    }

    /// Whether this is [`Report::empty`].
    pub const fn is_empty(&self) -> bool {
        matches!(&self.0, Form::Rejected(rejected) if rejected.is_empty())
    }

    /// The report with the given verdict (`true` to approve) for each position, in the
    /// shorter of its two encodings.
    ///
    /// # Panics
    ///
    /// Panics if there are more than [`MAX_ENTRIES`] verdicts.
    pub fn new(verdicts: &[bool]) -> Self {
        assert!(verdicts.len() <= MAX_ENTRIES, "too many entries");
        let rejected = Self(Form::Rejected(
            verdicts
                .iter()
                .enumerate()
                .filter(|(_, approved)| !**approved)
                .map(|(position, _)| position as u32)
                .collect(),
        ));
        let bitmap_size =
            UInt(((verdicts.len() as u64) << 1) | 1).encode_size() + verdicts.len().div_ceil(8);
        if rejected.encode_size() <= bitmap_size {
            return rejected;
        }

        let mut bits = vec![0u8; verdicts.len().div_ceil(8)];
        for (position, _) in verdicts
            .iter()
            .enumerate()
            .filter(|(_, approved)| **approved)
        {
            bits[position / 8] |= 0x80 >> (position % 8);
        }
        Self(Form::Bitmap {
            len: verdicts.len(),
            bits,
        })
    }

    /// The verdict for each of the `entries` MAC transactions of a block.
    ///
    /// Returns `None` if the report does not fit such a block: it has another number of
    /// bits, or rejects a position the block does not have. Such a report is malformed
    /// and counts as rejecting everything.
    pub fn verdicts(&self, entries: usize) -> Option<Vec<bool>> {
        match &self.0 {
            Form::Rejected(rejected) => {
                if rejected
                    .last()
                    .is_some_and(|last| *last as usize >= entries)
                {
                    return None;
                }
                let mut verdicts = vec![true; entries];
                for position in rejected {
                    verdicts[*position as usize] = false;
                }
                Some(verdicts)
            }
            Form::Bitmap { len, bits } => (*len == entries).then(|| {
                (0..entries)
                    .map(|position| bits[position / 8] & (0x80 >> (position % 8)) != 0)
                    .collect()
            }),
        }
    }
}

/// The status of each of the `entries` MAC transactions of a block, as determined by the
/// reports of a notarization of that block by `validators` validators.
///
/// Entry `j` is `true` (the transaction is authentic) iff at least `2f + 1` of the
/// reports approve it. Different notarizations of one block can determine different
/// statuses; the chain fixes one by carrying a notarization in the next block.
pub fn status<'a>(
    reports: impl IntoIterator<Item = &'a Report>,
    validators: u32,
    entries: usize,
) -> Vec<bool> {
    let threshold = N5f1::m_quorum(validators);
    let mut approvals = vec![0u32; entries];
    for report in reports {
        let Some(verdicts) = report.verdicts(entries) else {
            continue;
        };
        for (count, approved) in approvals.iter_mut().zip(verdicts) {
            *count += u32::from(approved);
        }
    }
    approvals
        .into_iter()
        .map(|count| count >= threshold)
        .collect()
}

impl Write for Report {
    fn write(&self, buf: &mut impl BufMut) {
        match &self.0 {
            Form::Rejected(rejected) => {
                UInt((rejected.len() as u64) << 1).write(buf);
                // Gaps: every sequence of them is an increasing list of positions.
                let mut next = 0u32;
                for position in rejected {
                    UInt(position - next).write(buf);
                    next = position + 1;
                }
            }
            Form::Bitmap { len, bits } => {
                UInt(((*len as u64) << 1) | 1).write(buf);
                buf.put_slice(bits);
            }
        }
    }
}

impl EncodeSize for Report {
    fn encode_size(&self) -> usize {
        match &self.0 {
            Form::Rejected(rejected) => {
                let mut size = UInt((rejected.len() as u64) << 1).encode_size();
                let mut next = 0u32;
                for position in rejected {
                    size += UInt(position - next).encode_size();
                    next = position + 1;
                }
                size
            }
            Form::Bitmap { len, bits } => UInt(((*len as u64) << 1) | 1).encode_size() + bits.len(),
        }
    }
}

impl Read for Report {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let header = UInt::<u64>::read_cfg(buf, &())?.0;
        let len = usize::try_from(header >> 1)
            .ok()
            .filter(|len| *len <= MAX_ENTRIES)
            .ok_or(Error::Invalid("Report", "too many entries"))?;
        if header & 1 == 0 {
            let mut rejected = Vec::with_capacity(len.min(buf.remaining()));
            let mut next = 0u64;
            for _ in 0..len {
                let gap = UInt::<u32>::read_cfg(buf, &())?.0;
                let position = next + u64::from(gap);
                if position >= MAX_ENTRIES as u64 {
                    return Err(Error::Invalid("Report", "position out of range"));
                }
                rejected.push(position as u32);
                next = position + 1;
            }
            return Ok(Self(Form::Rejected(rejected)));
        }

        let bytes = len.div_ceil(8);
        if buf.remaining() < bytes {
            return Err(Error::EndOfBuffer);
        }
        let mut bits = vec![0; bytes];
        buf.copy_to_slice(&mut bits);
        if len % 8 != 0 && bits[bytes - 1] & (0xff >> (len % 8)) != 0 {
            return Err(Error::Invalid("Report", "non-zero padding"));
        }
        Ok(Self(Form::Bitmap { len, bits }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    fn roundtrip(report: &Report) {
        let encoded = report.encode();
        assert_eq!(encoded.len(), report.encode_size());
        assert_eq!(&Report::decode(encoded).unwrap(), report);
    }

    #[test]
    fn empty_report_is_one_byte() {
        let report = Report::empty();
        assert!(report.is_empty());
        assert_eq!(report.encode().as_ref(), &[0]);
        assert_eq!(report.verdicts(0), Some(vec![]));
        assert_eq!(report.verdicts(3), Some(vec![true; 3]));
        roundtrip(&report);
    }

    #[test]
    fn approving_everything_is_the_empty_report() {
        assert_eq!(Report::new(&[true; 1000]), Report::empty());
        assert_eq!(Report::new(&[]), Report::empty());
    }

    #[test]
    fn few_rejections_use_the_list() {
        let mut verdicts = vec![true; 5000];
        for position in [0, 1, 300, 4999] {
            verdicts[position] = false;
        }
        let report = Report::new(&verdicts);
        assert!(matches!(&report.0, Form::Rejected(r) if r == &[0, 1, 300, 4999]));
        // Header, then the gaps 0, 0, 298 and 4698.
        assert_eq!(report.encode_size(), 1 + 1 + 1 + 2 + 2);
        assert_eq!(report.verdicts(5000), Some(verdicts));
        roundtrip(&report);
    }

    #[test]
    fn many_rejections_use_the_bitmap() {
        let verdicts: Vec<bool> = (0..1001).map(|position| position % 3 == 0).collect();
        let report = Report::new(&verdicts);
        assert!(matches!(&report.0, Form::Bitmap { len: 1001, .. }));
        assert_eq!(report.encode_size(), 2 + 126);
        assert_eq!(report.verdicts(1001), Some(verdicts));
        assert!(!report.is_empty());
        roundtrip(&report);

        let nothing = Report::new(&[false; 64]);
        assert!(matches!(&nothing.0, Form::Bitmap { len: 64, .. }));
        assert_eq!(nothing.verdicts(64), Some(vec![false; 64]));
        roundtrip(&nothing);
    }

    #[test]
    fn a_report_for_another_block_is_malformed() {
        let list = Report::new(&[true, true, false]);
        assert!(matches!(&list.0, Form::Rejected(_)));
        assert_eq!(list.verdicts(2), None);
        assert_eq!(list.verdicts(3), Some(vec![true, true, false]));
        // The list does not say how many entries it covers.
        assert_eq!(list.verdicts(4), Some(vec![true, true, false, true]));

        let bitmap = Report::new(&[false; 64]);
        assert_eq!(bitmap.verdicts(63), None);
        assert_eq!(bitmap.verdicts(65), None);
    }

    #[test]
    fn decode_rejects_malformed_encodings() {
        // Non-zero padding in a bitmap of three bits.
        assert!(Report::decode(vec![(3 << 1) | 1, 0b1110_0000]).is_ok());
        assert!(Report::decode(vec![(3 << 1) | 1, 0b1111_0000]).is_err());
        // Truncated bitmap and truncated list.
        assert!(Report::decode(vec![(9 << 1) | 1, 0xff]).is_err());
        assert!(Report::decode(vec![2 << 1, 0]).is_err());
        // Trailing bytes.
        assert!(Report::decode(vec![0, 0]).is_err());

        // Too many entries, in either form.
        let too_many = (MAX_ENTRIES as u64 + 1) << 1;
        assert!(Report::decode(UInt(too_many).encode()).is_err());
        assert!(Report::decode(UInt(too_many | 1).encode()).is_err());

        // A position past the largest block.
        let mut encoded = UInt(1u64 << 1).encode().to_vec();
        UInt(MAX_ENTRIES as u32).write(&mut encoded);
        assert!(Report::decode(encoded).is_err());
        let mut encoded = UInt(1u64 << 1).encode().to_vec();
        UInt(MAX_ENTRIES as u32 - 1).write(&mut encoded);
        assert!(Report::decode(encoded).is_ok());
    }

    #[test]
    fn largest_report_roundtrips() {
        let verdicts: Vec<bool> = (0..MAX_ENTRIES).map(|position| position % 2 == 0).collect();
        let report = Report::new(&verdicts);
        assert_eq!(report.encode_size(), 3 + MAX_ENTRIES / 8);
        roundtrip(&report);
    }

    /// `approving[j]` of `n` reports approve entry `j`; the others reject it.
    fn reports(n: usize, approving: &[usize]) -> Vec<Report> {
        (0..n)
            .map(|validator| {
                let verdicts: Vec<bool> =
                    approving.iter().map(|count| validator < *count).collect();
                Report::new(&verdicts)
            })
            .collect()
    }

    #[test]
    fn status_needs_2f_plus_1_approvals() {
        // n = 6, f = 1: a notarization holds five votes and three must approve.
        let reports = reports(5, &[5, 3, 2, 0]);
        assert_eq!(status(&reports, 6, 4), vec![true, true, false, false]);

        // n = 16, f = 3: thirteen votes and seven must approve.
        let reports = self::reports(13, &[7, 6]);
        assert_eq!(status(&reports, 16, 2), vec![true, false]);
    }

    #[test]
    fn status_counts_a_malformed_report_as_rejecting_everything() {
        let mut reports = reports(5, &[3, 3]);
        assert_eq!(status(&reports, 6, 2), vec![true, true]);

        // One approving report now covers three entries instead of two.
        reports[0] = Report::new(&[false, false, false, false, false, false, false, false, true]);
        assert!(matches!(&reports[0].0, Form::Bitmap { .. }));
        assert_eq!(status(&reports, 6, 2), vec![false, false]);

        // A list that rejects a position the block does not have.
        let mut reports = self::reports(5, &[3, 3]);
        reports[0] = Report(Form::Rejected(vec![2]));
        assert_eq!(status(&reports, 6, 2), vec![false, false]);
    }

    #[test]
    fn status_of_a_block_without_entries_is_empty() {
        let reports = vec![Report::empty(); 5];
        assert_eq!(status(&reports, 6, 0), Vec::<bool>::new());
    }

    #[test]
    fn no_report_approves_nothing() {
        assert_eq!(status(&[], 6, 2), vec![false, false]);
    }
}
