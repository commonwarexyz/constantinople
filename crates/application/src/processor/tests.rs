//! End-to-end processor tests for transfer-only execution.

use super::{
    executor::{Processor, ProposalOutput},
    state::State,
};
use commonware_cryptography::{Signer, blake3, ed25519};
use commonware_math::algebra::Random;
use constantinople_primitives::{Account, Address, Transaction, VerifiedTransaction};
use core::{marker::PhantomData, num::NonZeroU64};
use rand::rngs::OsRng;
use std::collections::HashMap;

const NAMESPACE: &[u8] = b"processor-test";

type TestHasher = blake3::Blake3;
type TestTransaction = VerifiedTransaction<ed25519::PublicKey, TestHasher>;
type TestProposal = ProposalOutput<ed25519::PublicKey, TestHasher>;

#[derive(Debug, Clone)]
struct TestSigner {
    key: ed25519::PrivateKey,
    address: Address,
}

impl TestSigner {
    fn new() -> Self {
        let key = ed25519::PrivateKey::random(&mut OsRng);
        let address = Address::from_public_key(&mut TestHasher::default(), &key.public_key());
        Self { key, address }
    }

    fn sign(&self, to: Address, value: u64, nonce: u64) -> TestTransaction {
        Transaction {
            sender: self.key.public_key(),
            to,
            value: NonZeroU64::new(value).expect("test values must be non-zero"),
            nonce,
            _digest: PhantomData,
        }
        .seal_and_sign_verified(&self.key, NAMESPACE, &mut TestHasher::default())
    }
}

fn processor() -> Processor {
    Processor::new()
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
    let signer = TestSigner::new();
    let recipient = TestSigner::new();
    let mut accounts = HashMap::new();
    accounts.insert(signer.address, account(10, 0));
    accounts.insert(recipient.address, Account::default());

    let proposal: TestProposal = processor().propose(
        State::new(accounts),
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
    let sender_a = TestSigner::new();
    let sender_b = TestSigner::new();
    let recipient = TestSigner::new();

    let mut accounts = HashMap::new();
    accounts.insert(sender_a.address, account(11, 0));
    accounts.insert(sender_b.address, account(13, 0));
    accounts.insert(recipient.address, account(5, 0));

    let transactions = vec![
        sender_a.sign(recipient.address, 4, 0),
        sender_b.sign(recipient.address, 6, 0),
    ];

    let processor = Processor::new();
    let proposal = processor.propose(State::new(accounts.clone()), transactions.clone());
    let verification = processor
        .execute(State::new(accounts), &proposal.valid)
        .expect("valid proposal transactions should execute");

    assert_eq!(proposal.changeset, verification.changeset);
    assert_eq!(
        changeset_account(&verification.changeset, sender_a.address),
        Some(account(7, 1))
    );
    assert_eq!(
        changeset_account(&verification.changeset, sender_b.address),
        Some(account(7, 1))
    );
    assert_eq!(
        changeset_account(&verification.changeset, recipient.address),
        Some(account(15, 0))
    );
}

#[test]
fn self_transfer_only_bumps_nonce() {
    let signer = TestSigner::new();
    let mut accounts = HashMap::new();
    accounts.insert(signer.address, account(9, 3));

    let processor = processor();
    let proposal = processor.propose(
        State::new(accounts.clone()),
        vec![signer.sign(signer.address, 4, 3)],
    );
    let output = processor
        .execute(State::new(accounts), &proposal.valid)
        .expect("valid proposal transactions should execute");
    assert_eq!(
        changeset_account(&output.changeset, signer.address),
        Some(account(9, 4))
    );
}
