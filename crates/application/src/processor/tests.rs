//! End-to-end processor tests for transfer-only execution.

use super::{
    executor::{ProposalOutput, execute, propose},
    state::State,
};
use commonware_cryptography::{Signer, ed25519, sha256};
use constantinople_primitives::{Account, AccountKey, Signable, Transaction, VerifiedTransaction};
use core::num::NonZeroU64;

const NAMESPACE: &[u8] = b"processor-test";

type TestHasher = sha256::Sha256;
type TestTransaction = VerifiedTransaction<ed25519::PublicKey, TestHasher>;
type TestProposal = ProposalOutput<ed25519::PublicKey, TestHasher>;

#[derive(Debug, Clone)]
struct TestSigner {
    key: ed25519::PrivateKey,
    public_key: ed25519::PublicKey,
}

impl TestSigner {
    fn from_seed(seed: u64) -> Self {
        let key = ed25519::PrivateKey::from_seed(seed);
        let public_key = key.public_key();
        Self { key, public_key }
    }

    fn sign(&self, to: ed25519::PublicKey, value: u64, nonce: u64) -> TestTransaction {
        Transaction::new(
            self.key.public_key(),
            to,
            NonZeroU64::new(value).expect("test values must be non-zero"),
            nonce,
        )
        .seal_and_sign(&self.key, NAMESPACE, &mut TestHasher::default())
    }
}

fn account(balance: u64, nonce: u64) -> Account {
    Account { balance, nonce }
}

fn account_key(public_key: &ed25519::PublicKey) -> AccountKey<ed25519::PublicKey> {
    AccountKey::from_public_key(public_key)
}

fn changeset_account(
    changeset: &[(AccountKey<ed25519::PublicKey>, Account)],
    public_key: ed25519::PublicKey,
) -> Option<Account> {
    let account_key = account_key(&public_key);
    changeset
        .iter()
        .find_map(|(candidate, account)| (candidate == &account_key).then_some(*account))
}

#[test]
fn validate_tracks_pending_nonce_and_balance() {
    let signer = TestSigner::from_seed(0);
    let recipient = TestSigner::from_seed(1);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(10, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    let transactions = vec![
        signer.sign(recipient.public_key.clone(), 4, 0),
        signer.sign(recipient.public_key.clone(), 7, 1),
        signer.sign(recipient.public_key, 6, 1),
    ];
    let proposal: TestProposal = propose(&accounts, transactions);

    assert_eq!(proposal.valid.len(), 2);
    assert_eq!(proposal.invalid.len(), 1);
    assert_eq!(proposal.valid[0].value().nonce, 0);
    assert_eq!(proposal.valid[1].value().nonce, 1);
    assert_eq!(proposal.invalid[0].value().value.get(), 7);
}

#[test]
fn propose_and_verify_match_for_transfer_batch() {
    let sender_a = TestSigner::from_seed(10);
    let sender_b = TestSigner::from_seed(11);
    let recipient = TestSigner::from_seed(12);

    let mut accounts = State::new();
    accounts.insert(account_key(&sender_a.public_key), account(11, 0));
    accounts.insert(account_key(&sender_b.public_key), account(13, 0));
    accounts.insert(account_key(&recipient.public_key), account(5, 0));

    let transactions = vec![
        sender_a.sign(recipient.public_key.clone(), 4, 0),
        sender_b.sign(recipient.public_key.clone(), 6, 0),
    ];

    let proposal = propose(&accounts, transactions);
    let changeset =
        execute(&accounts, &proposal.valid).expect("valid proposal transactions should execute");

    assert_eq!(proposal.changeset, changeset);
    assert_eq!(
        changeset_account(&changeset, sender_a.public_key),
        Some(account(7, 1))
    );
    assert_eq!(
        changeset_account(&changeset, sender_b.public_key),
        Some(account(7, 1))
    );
    assert_eq!(
        changeset_account(&changeset, recipient.public_key),
        Some(account(15, 0))
    );
}

#[test]
fn self_transfer_only_bumps_nonce() {
    let signer = TestSigner::from_seed(0);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(9, 3));

    let transactions = vec![signer.sign(signer.public_key.clone(), 4, 3)];
    let proposal = propose(&accounts, transactions);
    let changeset =
        execute(&accounts, &proposal.valid).expect("valid proposal transactions should execute");
    assert_eq!(
        changeset_account(&changeset, signer.public_key),
        Some(account(9, 4))
    );
}

#[test]
fn self_transfer_is_included_and_preserves_balance() {
    let signer = TestSigner::from_seed(0);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(12, 5));

    let transaction = signer.sign(signer.public_key.clone(), 7, 5);
    let transactions = vec![transaction];
    let proposal = propose(&accounts, transactions);

    assert_eq!(proposal.valid.len(), 1);
    assert!(proposal.invalid.is_empty());
    assert_eq!(
        changeset_account(&proposal.changeset, signer.public_key.clone()),
        Some(account(12, 6))
    );

    let changeset =
        execute(&accounts, &proposal.valid).expect("self-transfer should execute successfully");
    assert_eq!(
        changeset_account(&changeset, signer.public_key),
        Some(account(12, 6))
    );
    assert_eq!(proposal.changeset, changeset);
}

#[test]
fn missing_recipient_starts_with_default_balance() {
    let signer = TestSigner::from_seed(20);
    let recipient = TestSigner::from_seed(21);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(9, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    let transactions = vec![signer.sign(recipient.public_key.clone(), 4, 0)];
    let proposal = propose(&accounts, transactions);
    let changeset =
        execute(&accounts, &proposal.valid).expect("valid proposal transactions should execute");

    assert_eq!(
        changeset_account(&changeset, recipient.public_key),
        Some(Account {
            balance: Account::default().balance + 4,
            nonce: 0,
        })
    );
}

#[test]
fn invalid_transfer_does_not_mutate_overlay() {
    let signer = TestSigner::from_seed(30);
    let recipient = TestSigner::from_seed(31);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(5, 0));
    accounts.insert(account_key(&recipient.public_key), account(0, 0));

    let transactions = vec![
        signer.sign(recipient.public_key.clone(), 6, 0),
        signer.sign(recipient.public_key.clone(), 4, 0),
    ];
    let proposal = propose(&accounts, transactions);

    assert_eq!(proposal.invalid.len(), 1);
    assert_eq!(proposal.valid.len(), 1);
    assert_eq!(
        changeset_account(&proposal.changeset, signer.public_key),
        Some(account(1, 1))
    );
    assert_eq!(
        changeset_account(&proposal.changeset, recipient.public_key),
        Some(account(4, 0))
    );
}

#[test]
fn recipient_overflow_rejects_without_charging_sender() {
    let signer = TestSigner::from_seed(40);
    let recipient = TestSigner::from_seed(41);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(10, 0));
    accounts.insert(account_key(&recipient.public_key), account(u64::MAX, 0));

    let transactions = vec![signer.sign(recipient.public_key, 1, 0)];
    let proposal = propose(&accounts, transactions);

    assert!(proposal.valid.is_empty());
    assert_eq!(proposal.invalid.len(), 1);
    assert!(proposal.changeset.is_empty());
    assert!(execute(&accounts, &proposal.invalid).is_none());
}
