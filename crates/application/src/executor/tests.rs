//! Settlement rules exercised through `commonware_glue::transfers`, plus randomized comparisons
//! against a direct model of the rules.

use super::{PreparedTransfer, account_slots, starting_accounts};
use commonware_codec::FixedSize as _;
use commonware_glue::transfers::{Plan, Selection};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_storage::qmdb::any::batch::Slot;
use commonware_utils::TestRng;
use constantinople_primitives::{
    Account, AccountKey, DEFAULT_ACCOUNT_BALANCE, NONCE_BITMAP_CAPACITY, Nonce,
};
use rand::RngExt as _;
use std::{collections::BTreeMap, num::NonZeroUsize};

/// Block-start accounts by key. An absent key holds the default account.
type State = BTreeMap<AccountKey, Account>;

/// Settled slots by key, sorted by key.
type Settled = Vec<(AccountKey, Slot<Account>)>;

fn key(index: u8) -> AccountKey {
    AccountKey::from([index; AccountKey::SIZE])
}

const fn account(balance: u64, base: u64, tx_count: u64) -> Account {
    Account {
        balance,
        nonce: Nonce::new(base, 0),
        tx_count,
    }
}

const fn transfer(
    sender: AccountKey,
    recipient: AccountKey,
    value: u64,
    nonce: u64,
) -> PreparedTransfer {
    PreparedTransfer {
        sender,
        recipient,
        value,
        nonce,
    }
}

fn sorted(keys: &[AccountKey], slots: Vec<Slot<Account>>) -> Settled {
    let mut settled: Settled = keys.iter().copied().zip(slots).collect();
    settled.sort_unstable_by_key(|(key, _)| *key);
    settled
}

/// Settles `transfers` as one body, as a verifier does, with a plan keyed by `seed`.
fn verify(
    state: &State,
    transfers: &[PreparedTransfer],
    seed: u64,
    strategy: &impl Strategy,
) -> Option<Settled> {
    let plan = Plan::with_seed(transfers, seed, strategy).ok()?;
    let reads = plan
        .keys()
        .iter()
        .map(|key| state.get(key).copied())
        .collect();
    let slots = plan.settle(&starting_accounts(reads), strategy).ok()?;
    Some(sorted(plan.keys(), account_slots(slots)))
}

/// Selects from `rounds` in order, as a proposer does, returning each round's accepted flags and
/// the slot of every touched key.
fn select(state: &State, rounds: &[Vec<PreparedTransfer>], seed: u64) -> (Vec<Vec<bool>>, Settled) {
    let mut selection = Selection::with_seed(seed);
    let mut accepted = Vec::with_capacity(rounds.len());

    // Each round registers the starting accounts of its newly touched keys before it applies.
    for round in rounds {
        let touched = selection.touch(round);
        let reads = selection.keys()[touched]
            .iter()
            .map(|key| state.get(key).copied())
            .collect();
        selection.register(starting_accounts(reads));
        accepted.push(selection.apply(round));
    }

    // Settle every touched key and sort by key to compare with other routes.
    let keys = selection.keys().to_vec();
    let slots = account_slots(selection.settle(&Sequential));
    (accepted, sorted(&keys, slots))
}

/// The transfers of `rounds` that `accepted` marks, in block order.
fn survivors(rounds: &[Vec<PreparedTransfer>], accepted: &[Vec<bool>]) -> Vec<PreparedTransfer> {
    rounds
        .iter()
        .flatten()
        .zip(accepted.iter().flatten())
        .filter_map(|(transfer, accepted)| accepted.then_some(*transfer))
        .collect()
}

/// The slots that change state.
fn written(settled: &Settled) -> Settled {
    settled
        .iter()
        .filter(|(_, slot)| !matches!(slot, Slot::Keep))
        .cloned()
        .collect()
}

/// The slot settlement writes for a key that starts as `read` and ends as `settled`.
fn expected_slot(read: Option<Account>, settled: Account) -> Slot<Account> {
    if settled == read.unwrap_or_default() {
        Slot::Keep
    } else if settled == Account::default() {
        Slot::Delete
    } else {
        Slot::Put(settled)
    }
}

/// One key's progress through a body in the model.
#[derive(Clone, Copy)]
struct Entry {
    start: Account,
    nonce: Nonce,
    tx_count: u64,
    debits: u64,
    credits: u64,
}

impl Entry {
    fn settled(&self) -> Option<Account> {
        Some(Account {
            balance: self
                .start
                .balance
                .checked_sub(self.debits)?
                .checked_add(self.credits)?,
            nonce: self.nonce,
            tx_count: self.tx_count,
        })
    }
}

/// A direct model of the settlement rules, applying transfers one at a time.
struct Model<'a> {
    state: &'a State,
    entries: BTreeMap<AccountKey, Entry>,
}

impl<'a> Model<'a> {
    const fn new(state: &'a State) -> Self {
        Self {
            state,
            entries: BTreeMap::new(),
        }
    }

    fn entry(&self, key: &AccountKey) -> Entry {
        self.entries.get(key).copied().unwrap_or_else(|| {
            let start = self.state.get(key).copied().unwrap_or_default();
            Entry {
                start,
                nonce: start.nonce,
                tx_count: start.tx_count,
                debits: 0,
                credits: 0,
            }
        })
    }

    /// Applies `transfer`'s nonce and sums, returning the entries it leaves, or `None` if its
    /// nonce is refused or a sum overflows.
    fn step(&self, transfer: &PreparedTransfer) -> Option<Vec<(AccountKey, Entry)>> {
        // The sender consumes the nonce and takes the debit.
        let mut sender = self.entry(&transfer.sender);
        if !sender.nonce.consume(transfer.nonce) {
            return None;
        }
        sender.tx_count = sender.tx_count.checked_add(1)?;
        sender.debits = sender.debits.checked_add(transfer.value)?;

        // A self-transfer credits the same entry, and any other transfer credits its recipient.
        if transfer.sender == transfer.recipient {
            sender.credits = sender.credits.checked_add(transfer.value)?;
            return Some(vec![(transfer.sender, sender)]);
        }
        let mut recipient = self.entry(&transfer.recipient);
        recipient.tx_count = recipient.tx_count.checked_add(1)?;
        recipient.credits = recipient.credits.checked_add(transfer.value)?;
        Some(vec![
            (transfer.sender, sender),
            (transfer.recipient, recipient),
        ])
    }

    /// The slot of every key touched so far, or `None` if any cannot settle.
    fn settled(&self) -> Option<Settled> {
        self.entries
            .iter()
            .map(|(key, entry)| {
                let read = self.state.get(key).copied();
                Some((*key, expected_slot(read, entry.settled()?)))
            })
            .collect()
    }

    /// Settles `transfers` as one body: every transfer must apply, and every key must settle once
    /// all of them have.
    fn verify(state: &State, transfers: &[PreparedTransfer]) -> Option<Settled> {
        let mut model = Model::new(state);
        for transfer in transfers {
            let entries = model.step(transfer)?;
            model.entries.extend(entries);
        }
        model.settled()
    }

    /// Accepts each transfer that applies and leaves every key it touches able to settle.
    fn select(state: &State, rounds: &[Vec<PreparedTransfer>]) -> (Vec<Vec<bool>>, Settled) {
        let mut model = Model::new(state);
        let mut touched = Vec::new();
        let mut accepted = Vec::with_capacity(rounds.len());

        // Accept a transfer only if it applies and every key it changes can still settle. A
        // dropped transfer leaves no entry behind.
        for round in rounds {
            let mut flags = Vec::with_capacity(round.len());
            for transfer in round {
                touched.extend([transfer.sender, transfer.recipient]);
                let entries = model
                    .step(transfer)
                    .filter(|entries| entries.iter().all(|(_, entry)| entry.settled().is_some()));
                flags.push(entries.is_some());
                model.entries.extend(entries.into_iter().flatten());
            }
            accepted.push(flags);
        }

        // Every touched key gets a slot, and a key no accepted transfer changed keeps its account.
        let mut settled = model.settled().expect("accepted transfers must settle");
        for key in touched {
            if !model.entries.contains_key(&key) {
                settled.push((key, Slot::Keep));
            }
        }
        settled.sort_unstable_by_key(|(key, _)| *key);
        settled.dedup_by_key(|(key, _)| *key);
        (accepted, settled)
    }
}

#[test]
fn executes_run_ahead_nonces() {
    let [sender, recipient] = [key(1), key(2)];
    let state = State::from([(sender, account(10, 0, 0))]);

    // Nonces inside the run-ahead window apply in any order.
    let body = [
        transfer(sender, recipient, 3, 2),
        transfer(sender, recipient, 4, 0),
        transfer(sender, recipient, 2, 1),
    ];
    let settled = verify(&state, &body, 0, &Sequential).expect("valid body must settle");

    // The sender pays all three values and consumes nonces 0 through 2.
    assert_eq!(
        settled,
        [
            (sender, Slot::Put(account(1, 3, 3))),
            (
                recipient,
                Slot::Put(account(DEFAULT_ACCOUNT_BALANCE + 9, 0, 3))
            ),
        ]
    );
}

#[test]
fn count_overflow_drops_atomically_across_refills() {
    let [sender, exhausted, last] = [key(1), key(2), key(3)];
    let state = State::from([
        (exhausted, account(100, 0, u64::MAX)),
        (last, account(100, 0, u64::MAX - 1)),
    ]);
    let rounds = vec![
        vec![
            transfer(sender, exhausted, 1, 0),
            transfer(sender, last, 1, 0),
        ],
        vec![
            transfer(sender, last, 1, 1),
            transfer(sender, sender, 1, 1),
            transfer(exhausted, sender, 1, 0),
        ],
    ];
    let (accepted, settled) = select(&state, &rounds, 0);
    assert_eq!(accepted, [vec![false, true], vec![false, true, false]]);
    assert_eq!(
        settled,
        [
            (sender, Slot::Put(account(99, 2, 2))),
            (exhausted, Slot::Keep),
            (last, Slot::Put(account(101, 0, u64::MAX))),
        ]
    );
    assert_eq!(verify(&state, &rounds.concat(), 0, &Sequential), None);
    let body = survivors(&rounds, &accepted);
    assert_eq!(
        written(&verify(&state, &body, 1, &Sequential).unwrap()),
        written(&settled)
    );
}

#[test]
fn self_transfer_consumes_the_last_count_once() {
    let sender = key(1);
    let state = State::from([(sender, account(100, 0, u64::MAX - 1))]);
    let rounds = vec![vec![
        transfer(sender, sender, 1, 0),
        transfer(sender, sender, 1, 1),
    ]];
    let (accepted, settled) = select(&state, &rounds, 0);
    assert_eq!(accepted, [vec![true, false]]);
    assert_eq!(settled, [(sender, Slot::Put(account(100, 1, u64::MAX)))]);
}

#[test]
fn rejects_refused_nonces() {
    let [sender, recipient] = [key(1), key(2)];
    let state = State::from([(sender, account(10, 1, 0))]);

    // The sender has consumed nonce 0, and each body presents a nonce its account refuses.
    let far = NONCE_BITMAP_CAPACITY + 5;
    for body in [
        // Stale: consumed before the block.
        vec![transfer(sender, recipient, 1, 0)],
        // Repeated in the run-ahead window.
        vec![
            transfer(sender, recipient, 1, 3),
            transfer(sender, recipient, 1, 3),
        ],
        // Repeated beyond the window.
        vec![
            transfer(sender, recipient, 1, far),
            transfer(sender, recipient, 1, far),
        ],
        // A self-transfer consumes its nonce too.
        vec![
            transfer(sender, sender, 1, 1),
            transfer(sender, recipient, 1, 1),
        ],
    ] {
        assert_eq!(
            verify(&state, &body, 0, &Sequential),
            None,
            "{body:?} must not settle"
        );
    }
}

#[test]
fn spends_only_block_start_balances() {
    let [payer, middle, sink] = [key(1), key(2), key(3)];
    let state = State::from([(payer, account(10, 0, 0)), (middle, account(0, 1, 0))]);

    // Middle's credit cannot fund its spend in the same block.
    let body = [transfer(payer, middle, 10, 0), transfer(middle, sink, 1, 1)];
    assert_eq!(verify(&state, &body, 0, &Sequential), None);

    // Credits apply after debits, so a pair of accounts can swap value.
    let state = State::from([(payer, account(10, 0, 0)), (middle, account(10, 0, 0))]);
    let body = [transfer(payer, middle, 4, 0), transfer(middle, payer, 3, 0)];
    assert_eq!(
        verify(&state, &body, 0, &Sequential).expect("swap must settle"),
        [
            (payer, Slot::Put(account(9, 1, 2))),
            (middle, Slot::Put(account(11, 1, 2))),
        ]
    );
}

#[test]
fn self_transfers_debit_and_credit_their_sender() {
    let [sender, recipient] = [key(1), key(2)];
    let state = State::from([(sender, account(9, 3, 0))]);

    // Spending the whole balance on a self-transfer leaves it unchanged and consumes the nonce.
    let body = [transfer(sender, sender, 9, 3)];
    assert_eq!(
        verify(&state, &body, 0, &Sequential).expect("self-transfer must settle"),
        [(sender, Slot::Put(account(9, 4, 1)))]
    );

    // The self-transfer's debit and the send's together fit the starting balance.
    let body = [
        transfer(sender, sender, 4, 3),
        transfer(sender, recipient, 5, 4),
    ];
    assert_eq!(
        verify(&state, &body, 0, &Sequential).expect("body must settle"),
        [
            (sender, Slot::Put(account(4, 5, 2))),
            (
                recipient,
                Slot::Put(account(DEFAULT_ACCOUNT_BALANCE + 5, 0, 1))
            ),
        ]
    );

    // Debits past the starting balance are rejected, and a self-transfer's credit cannot fund them.
    for body in [
        vec![
            transfer(sender, sender, 5, 3),
            transfer(sender, recipient, 5, 4),
        ],
        vec![
            transfer(sender, sender, 9, 3),
            transfer(sender, recipient, 9, 4),
        ],
        vec![transfer(sender, sender, 10, 3)],
    ] {
        assert_eq!(
            verify(&state, &body, 0, &Sequential),
            None,
            "{body:?} must not settle"
        );
    }

    // Selection drops the send that the self-transfer's debit leaves unaffordable.
    let rounds = vec![vec![
        transfer(sender, sender, 5, 3),
        transfer(sender, recipient, 5, 4),
        transfer(sender, recipient, 4, 4),
    ]];
    let (accepted, settled) = select(&state, &rounds, 0);
    assert_eq!(accepted, [vec![true, false, true]]);
    assert_eq!(
        settled,
        [
            (sender, Slot::Put(account(5, 5, 2))),
            (
                recipient,
                Slot::Put(account(DEFAULT_ACCOUNT_BALANCE + 4, 0, 1))
            ),
        ]
    );
}

#[test]
fn rejects_unaffordable_and_overflowing_sums() {
    let [poor, rich, recipient] = [key(1), key(2), key(3)];
    let state = State::from([
        (poor, account(5, 0, 0)),
        (rich, account(u64::MAX, 0, 0)),
        (recipient, account(u64::MAX - 1, 0, 0)),
    ]);
    for body in [
        // A debit past the starting balance.
        vec![transfer(poor, recipient, 6, 0)],
        // Debits that together exceed the starting balance.
        vec![transfer(poor, rich, 3, 0), transfer(poor, rich, 3, 1)],
        // A credit that overflows the recipient.
        vec![transfer(rich, recipient, 2, 0)],
        // Debits that sum past u64::MAX.
        vec![
            transfer(rich, poor, u64::MAX, 0),
            transfer(rich, poor, u64::MAX, 1),
        ],
        // Credits that sum past u64::MAX.
        vec![
            transfer(rich, poor, u64::MAX, 0),
            transfer(recipient, poor, u64::MAX - 1, 0),
        ],
    ] {
        assert_eq!(
            verify(&state, &body, 0, &Sequential),
            None,
            "{body:?} must not settle"
        );
    }

    // A final balance at u64::MAX fits, though a credit arrives before the debit it nets with.
    let body = [transfer(poor, rich, 1, 0), transfer(rich, recipient, 1, 0)];
    assert_eq!(
        verify(&state, &body, 0, &Sequential).expect("body must settle"),
        [
            (poor, Slot::Put(account(4, 1, 1))),
            (rich, Slot::Put(account(u64::MAX, 1, 2))),
            (recipient, Slot::Put(account(u64::MAX, 0, 1))),
        ]
    );
}

#[test]
fn selection_drops_what_cannot_settle() {
    let [alice, bob, carol, rich] = [key(1), key(2), key(3), key(4)];
    let state = State::from([
        (alice, account(50, 1, 0)),
        (bob, account(30, 0, 0)),
        (rich, account(u64::MAX - 10, 0, 0)),
    ]);
    let rounds = vec![
        vec![
            // Stale nonce.
            transfer(alice, carol, 10, 0),
            // Spends most of Alice's balance.
            transfer(alice, bob, 40, 1),
            // Alice's credit cannot fund Bob.
            transfer(bob, carol, 40, 0),
            // Affordable from Bob's start.
            transfer(bob, carol, 30, 0),
            // Repeats Bob's nonce.
            transfer(bob, carol, 1, 0),
        ],
        vec![
            // A self-transfer above Alice's start.
            transfer(alice, alice, 60, 2),
            // A self-transfer Alice's start covers, but not with her accepted debit.
            transfer(alice, alice, 20, 2),
            // A self-transfer that fits the rest of Alice's start.
            transfer(alice, alice, 10, 2),
            // Would overflow Rich, who no accepted transfer touches.
            transfer(carol, rich, 20, 0),
            // Carol is read in a later round.
            transfer(carol, alice, 10, 0),
        ],
    ];

    // Selection keeps each transfer that settles with those accepted before it, and Rich, touched
    // only by a dropped transfer, keeps its account.
    let (accepted, settled) = select(&state, &rounds, 0);
    assert_eq!(
        accepted,
        [
            vec![false, true, false, true, false],
            vec![false, false, true, false, true],
        ]
    );
    assert_eq!(
        settled,
        [
            (alice, Slot::Put(account(20, 3, 3))),
            (bob, Slot::Put(account(40, 1, 2))),
            (
                carol,
                Slot::Put(account(DEFAULT_ACCOUNT_BALANCE + 20, 1, 2))
            ),
            (rich, Slot::Keep),
        ]
    );
}

/// Draws a block-start state over `keys`. A `reachable` state holds only accounts settlement can
/// write: one that has consumed no nonce holds at least the default balance.
fn random_state(rng: &mut TestRng, keys: &[AccountKey], reachable: bool) -> State {
    const BALANCES: [u64; 11] = [
        0,
        1,
        5,
        50,
        DEFAULT_ACCOUNT_BALANCE - 1,
        DEFAULT_ACCOUNT_BALANCE,
        DEFAULT_ACCOUNT_BALANCE + 1,
        1_000,
        u64::MAX / 2,
        u64::MAX - 5,
        u64::MAX,
    ];
    const BASES: [u64; 6] = [0, 0, 1, 2, 1_000, u64::MAX - 1];
    let mut state = State::new();
    for key in keys {
        // Leave about a quarter of the keys absent.
        if rng.random_range(0..4) == 0 {
            continue;
        }

        // Draw a balance and a nonce, with about half the nonces showing run-ahead consumption.
        let bitmap = if rng.random_bool(0.5) {
            0
        } else {
            rng.random::<u64>() & rng.random::<u64>()
        };
        let mut account = Account {
            balance: BALANCES[rng.random_range(0..BALANCES.len())],
            nonce: Nonce::new(BASES[rng.random_range(0..BASES.len())], bitmap),
            tx_count: if reachable {
                rng.random_range(1..=100)
            } else {
                [0, 1, u64::MAX - 1, u64::MAX][rng.random_range(0..4)]
            },
        };

        // A reachable account that has consumed no nonce holds at least the default balance.
        if reachable && account.nonce == Nonce::default() {
            account.balance = account.balance.max(DEFAULT_ACCOUNT_BALANCE);
        }
        state.insert(*key, account);
    }
    state
}

/// Draws a body from `senders` to `recipients`. Each transfer is adversarial with probability
/// `noise`: its nonce is stale, run ahead, past the window, a repeat, or unusable, and its value
/// may exhaust or overflow balances. The rest draw small values and each sender's next sequential
/// nonce. A fifth of the transfers are self-transfers.
fn random_body(
    rng: &mut TestRng,
    state: &State,
    senders: &[AccountKey],
    recipients: &[AccountKey],
    len: usize,
    noise: f64,
) -> Vec<PreparedTransfer> {
    const VALUES: [u64; 10] = [
        1,
        2,
        3,
        10,
        49,
        50,
        100,
        u64::MAX / 2,
        u64::MAX - 1,
        u64::MAX,
    ];

    // Track each sender's next sequential nonce and every nonce drawn, for repeats.
    let mut next: BTreeMap<AccountKey, u64> = BTreeMap::new();
    let mut used: Vec<(AccountKey, u64)> = Vec::new();
    (0..len)
        .map(|_| {
            let sender = senders[rng.random_range(0..senders.len())];
            let recipient = if rng.random_range(0..5) == 0 {
                sender
            } else {
                recipients[rng.random_range(0..recipients.len())]
            };

            // Adversarial transfers draw extreme values and one of six nonce kinds, and the rest
            // take small values and the sender's next sequential nonce.
            let base = state.get(&sender).copied().unwrap_or_default().nonce.base;
            let sequential = next.entry(sender).or_insert(base);
            let (value, nonce) = if rng.random_bool(noise) {
                let value = VALUES[rng.random_range(0..VALUES.len())];
                let nonce = match rng.random_range(0..6) {
                    0 => base.saturating_sub(1),
                    1 => base.saturating_add(rng.random_range(1..=NONCE_BITMAP_CAPACITY)),
                    2 => base.saturating_add(NONCE_BITMAP_CAPACITY + rng.random_range(1..=3)),
                    3 => used
                        .iter()
                        .rev()
                        .find(|(key, _)| *key == sender)
                        .map_or(base, |(_, nonce)| *nonce),
                    4 => u64::MAX,
                    _ => *sequential,
                };
                (value, nonce)
            } else {
                let nonce = *sequential;
                *sequential = sequential.saturating_add(1);
                (rng.random_range(1..=10), nonce)
            };
            used.push((sender, nonce));
            transfer(sender, recipient, value, nonce)
        })
        .collect()
}

/// Splits `body` into between one and four rounds of candidates.
fn random_rounds(rng: &mut TestRng, body: &[PreparedTransfer]) -> Vec<Vec<PreparedTransfer>> {
    let mut rounds = Vec::new();
    let mut rest = body;
    for _ in 0..rng.random_range(0..4) {
        let (round, tail) = rest.split_at(rng.random_range(0..=rest.len()));
        rounds.push(round.to_vec());
        rest = tail;
    }
    rounds.push(rest.to_vec());
    rounds
}

/// Draws a small key universe, so transfers contend for the same accounts.
fn random_keys(rng: &mut TestRng) -> Vec<AccountKey> {
    const UNIVERSES: [u8; 7] = [1, 2, 3, 4, 6, 8, 32];
    (1..=UNIVERSES[rng.random_range(0..UNIVERSES.len())])
        .map(key)
        .collect()
}

/// Adversarial fractions of the randomized bodies.
const NOISE: [f64; 4] = [0.0, 0.05, 0.25, 0.75];

/// One randomized small case: a state, whether it is reachable, and a body.
fn random_case(rng: &mut TestRng) -> (State, bool, Vec<PreparedTransfer>) {
    let keys = random_keys(rng);
    let reachable = rng.random_bool(0.75);
    let state = random_state(rng, &keys, reachable);
    let len = rng.random_range(0..=40);
    let noise = NOISE[rng.random_range(0..NOISE.len())];
    let body = random_body(rng, &state, &keys, &keys, len, noise);
    (state, reachable, body)
}

#[test]
fn verification_matches_model() {
    let mut rng = TestRng::new(7);
    let mut settled = 0;
    for case in 0..20_000u64 {
        // Verification must agree with the model under a differently keyed plan per case.
        let (state, reachable, body) = random_case(&mut rng);
        let expected = Model::verify(&state, &body);
        assert_eq!(
            verify(&state, &body, case, &Sequential),
            expected,
            "case {case}: verification must match the model"
        );

        // A body that settles over a reachable state writes every key it changes.
        if let Some(slots) = expected {
            settled += 1;
            if reachable {
                assert!(
                    slots.iter().all(|(_, slot)| matches!(slot, Slot::Put(_))),
                    "case {case}: a reachable body must write every key it changes"
                );
            }
        }
    }

    // Enough bodies settle for the comparison to cover accepted bodies.
    assert!(
        settled > 2_000,
        "more than 2,000 bodies must settle, got {settled}"
    );
}

#[test]
fn selection_matches_model_and_verifies() {
    let mut rng = TestRng::new(8);
    let mut dropped = 0;
    for case in 0..20_000u64 {
        // Selection must accept the same transfers and settle the same slots as the model.
        let (state, _, body) = random_case(&mut rng);
        let rounds = random_rounds(&mut rng, &body);
        let (accepted, settled) = select(&state, &rounds, case);
        assert_eq!(
            (accepted.clone(), settled.clone()),
            Model::select(&state, &rounds),
            "case {case}: selection must match the model"
        );

        // The accepted body settles to the same writes under verification.
        let survivors = survivors(&rounds, &accepted);
        dropped += body.len() - survivors.len();
        let verified =
            verify(&state, &survivors, case, &Sequential).expect("survivors must settle");
        assert_eq!(
            written(&verified),
            written(&settled),
            "case {case}: survivors must settle to the selected writes"
        );
    }

    // Enough candidates drop for the comparison to cover rejections.
    assert!(
        dropped > 20_000,
        "more than 20,000 candidates must drop, got {dropped}"
    );
}

/// Keys enough for plans and settlement to split among workers.
fn many_keys(count: u32) -> Vec<AccountKey> {
    (0..count)
        .map(|index| {
            let mut raw = [0u8; AccountKey::SIZE];
            raw[..4].copy_from_slice(&index.to_le_bytes());
            AccountKey::from(raw)
        })
        .collect()
}

/// A funded state over `keys` whose accounts have consumed varied nonces.
fn funded_state(rng: &mut TestRng, keys: &[AccountKey]) -> State {
    keys.iter()
        .map(|key| (*key, account(1_000_000, rng.random_range(0..3), 0)))
        .collect()
}

#[test]
fn parallel_settlement_matches_model() {
    let strategy = Rayon::new(NonZeroUsize::new(4).unwrap()).expect("rayon pool");
    let keys = many_keys(40_000);
    let mut rng = TestRng::new(9);
    for (case, noise) in [0.0, 0.0, 0.0001, 0.001].into_iter().enumerate() {
        // Senders are funded, and the remaining recipients start absent.
        let senders = &keys[..rng.random_range(2_000..30_000)];
        let state = funded_state(&mut rng, senders);
        let body = random_body(&mut rng, &state, senders, &keys, 50_000, noise);

        // Verification on the pool matches the model, and only noise-free bodies settle.
        let expected = Model::verify(&state, &body);
        assert_eq!(
            expected.is_some(),
            noise == 0.0,
            "case {case}: a body must settle exactly when it carries no noise"
        );
        assert_eq!(
            verify(&state, &body, case as u64, &strategy),
            expected,
            "case {case}: pool verification must match the model"
        );

        // Selection matches the model, and its survivors verify on the pool.
        let rounds = random_rounds(&mut rng, &body);
        let (accepted, settled) = select(&state, &rounds, case as u64);
        assert_eq!(
            (accepted.clone(), settled),
            Model::select(&state, &rounds),
            "case {case}: selection must match the model"
        );
        let survivors = survivors(&rounds, &accepted);
        let verified = verify(&state, &survivors, case as u64, &strategy);
        assert!(verified.is_some(), "case {case}: survivors must settle");
        assert_eq!(
            verified,
            Model::verify(&state, &survivors),
            "case {case}: survivor verification must match the model"
        );
    }
}
