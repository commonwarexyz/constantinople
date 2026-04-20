//! End-to-end processor tests for transfer-only execution.

use super::executor::{ProposalOutput, execute, propose};
use commonware_cryptography::{Signer, ed25519, sha256};
use constantinople_primitives::{Account, Address, Transaction, VerifiedTransaction};
use core::num::NonZeroU64;
use std::collections::HashMap;

const NAMESPACE: &[u8] = b"processor-test";

type TestHasher = sha256::Sha256;
type TestTransaction = VerifiedTransaction<ed25519::PublicKey, TestHasher>;
type TestProposal = ProposalOutput<ed25519::PublicKey, TestHasher>;

#[derive(Debug, Clone)]
struct TestSigner {
    key: ed25519::PrivateKey,
    address: Address,
}

impl TestSigner {
    fn from_seed(seed: u64) -> Self {
        let key = ed25519::PrivateKey::from_seed(seed);
        let address = Address::from_public_key(&mut TestHasher::default(), &key.public_key());
        Self { key, address }
    }

    fn sign(&self, to: Address, value: u64, nonce: u64) -> TestTransaction {
        Transaction::new(
            self.key.public_key(),
            to,
            NonZeroU64::new(value).expect("test values must be non-zero"),
            nonce,
        )
        .seal_and_sign_verified(&self.key, NAMESPACE, &mut TestHasher::default())
    }
}

fn account(balance: u64, nonce: u64) -> Account {
    Account { balance, nonce }
}

fn changeset_account(changeset: &[(Address, Account)], address: Address) -> Option<Account> {
    changeset
        .iter()
        .find_map(|(candidate, account)| (*candidate == address).then_some(*account))
}

#[test]
fn validate_tracks_pending_nonce_and_balance() {
    let signer = TestSigner::from_seed(0);
    let recipient = TestSigner::from_seed(1);
    let mut accounts = HashMap::new();
    accounts.insert(signer.address, account(10, 0));
    accounts.insert(recipient.address, Account::default());

    let proposal: TestProposal = propose(
        &accounts,
        vec![
            signer.sign(recipient.address, 4, 0),
            signer.sign(recipient.address, 7, 1),
            signer.sign(recipient.address, 6, 1),
        ],
    );

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

    let mut accounts = HashMap::new();
    accounts.insert(sender_a.address, account(11, 0));
    accounts.insert(sender_b.address, account(13, 0));
    accounts.insert(recipient.address, account(5, 0));

    let transactions = vec![
        sender_a.sign(recipient.address, 4, 0),
        sender_b.sign(recipient.address, 6, 0),
    ];

    let proposal = propose(&accounts, transactions);
    let changeset =
        execute(&accounts, &proposal.valid).expect("valid proposal transactions should execute");

    assert_eq!(proposal.changeset, changeset);
    assert_eq!(
        changeset_account(&changeset, sender_a.address),
        Some(account(7, 1))
    );
    assert_eq!(
        changeset_account(&changeset, sender_b.address),
        Some(account(7, 1))
    );
    assert_eq!(
        changeset_account(&changeset, recipient.address),
        Some(account(15, 0))
    );
}

#[test]
fn self_transfer_only_bumps_nonce() {
    let signer = TestSigner::from_seed(0);
    let mut accounts = HashMap::new();
    accounts.insert(signer.address, account(9, 3));

    let proposal = propose(&accounts, vec![signer.sign(signer.address, 4, 3)]);
    let changeset =
        execute(&accounts, &proposal.valid).expect("valid proposal transactions should execute");
    assert_eq!(
        changeset_account(&changeset, signer.address),
        Some(account(9, 4))
    );
}

#[test]
fn self_transfer_is_included_and_preserves_balance() {
    let signer = TestSigner::from_seed(0);
    let mut accounts = HashMap::new();
    accounts.insert(signer.address, account(12, 5));

    let transaction = signer.sign(signer.address, 7, 5);
    let proposal = propose(&accounts, vec![transaction]);

    assert_eq!(proposal.valid.len(), 1);
    assert!(proposal.invalid.is_empty());
    assert_eq!(
        changeset_account(&proposal.changeset, signer.address),
        Some(account(12, 6))
    );

    let changeset =
        execute(&accounts, &proposal.valid).expect("self-transfer should execute successfully");
    assert_eq!(
        changeset_account(&changeset, signer.address),
        Some(account(12, 6))
    );
    assert_eq!(proposal.changeset, changeset);
}

#[test]
fn missing_recipient_starts_with_default_balance() {
    let signer = TestSigner::from_seed(20);
    let recipient = TestSigner::from_seed(21);
    let mut accounts = HashMap::new();
    accounts.insert(signer.address, account(9, 0));
    accounts.insert(recipient.address, Account::default());

    let proposal = propose(&accounts, vec![signer.sign(recipient.address, 4, 0)]);
    let changeset =
        execute(&accounts, &proposal.valid).expect("valid proposal transactions should execute");

    assert_eq!(
        changeset_account(&changeset, recipient.address),
        Some(Account {
            balance: Account::default().balance + 4,
            nonce: 0,
        })
    );
}
