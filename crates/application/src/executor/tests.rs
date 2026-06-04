use super::{ProposalOutput, State, execute, execute_unique, prepare_transfer, propose};
use commonware_cryptography::{Signer, ed25519, sha256};
use constantinople_primitives::{
    Account, AccountKey, DEFAULT_ACCOUNT_BALANCE, NONCE_BITMAP_CAPACITY, Nonce, Transaction,
    TransactionPublicKey, VerifiedTransaction,
};
use core::num::NonZeroU64;

const NAMESPACE: &[u8] = b"executor-test";

type TestHasher = sha256::Sha256;
type TestTransaction = VerifiedTransaction<TestHasher>;
type TestProposal = ProposalOutput<TestHasher>;

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
            TransactionPublicKey::ed25519(self.key.public_key()),
            TransactionPublicKey::ed25519(to),
            NonZeroU64::new(value).expect("test values must be non-zero"),
            nonce,
        )
        .seal_and_sign(&self.key, NAMESPACE, &mut TestHasher::default())
    }
}

fn account(balance: u64, nonce: u64) -> Account {
    Account {
        balance,
        nonce: Nonce::new(nonce, 0),
    }
}

fn account_key(public_key: &ed25519::PublicKey) -> AccountKey {
    AccountKey::from_public_key(&TransactionPublicKey::ed25519(public_key.clone()))
}

fn changeset_account(
    changeset: &[(AccountKey, Account)],
    public_key: ed25519::PublicKey,
) -> Option<Account> {
    let account_key = account_key(&public_key);
    changeset
        .iter()
        .find_map(|(candidate, account)| (candidate == &account_key).then_some(*account))
}

#[test]
fn proposal_tracks_pending_nonce_and_balance() {
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
fn proposal_accepts_nonce_inside_run_ahead_window() {
    let signer = TestSigner::from_seed(2);
    let recipient = TestSigner::from_seed(3);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(10, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    let transactions = vec![
        signer.sign(recipient.public_key.clone(), 3, 2),
        signer.sign(recipient.public_key.clone(), 4, 0),
        signer.sign(recipient.public_key.clone(), 2, 1),
    ];
    let proposal = propose(&accounts, transactions);
    let sender = changeset_account(&proposal.changeset, signer.public_key)
        .expect("sender should be updated");
    let recipient = changeset_account(&proposal.changeset, recipient.public_key)
        .expect("recipient should be updated");

    assert_eq!(proposal.valid.len(), 3);
    assert!(proposal.invalid.is_empty());
    assert_eq!(sender.balance, 1);
    assert_eq!(sender.nonce.base, 3);
    assert_eq!(recipient.balance, DEFAULT_ACCOUNT_BALANCE + 9);
}

#[test]
fn proposal_rejects_duplicate_run_ahead_nonce() {
    let signer = TestSigner::from_seed(4);
    let recipient = TestSigner::from_seed(5);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(10, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    let transactions = vec![
        signer.sign(recipient.public_key.clone(), 3, 2),
        signer.sign(recipient.public_key, 4, 2),
    ];
    let proposal = propose(&accounts, transactions);
    let sender = changeset_account(&proposal.changeset, signer.public_key)
        .expect("sender should be updated");

    assert_eq!(proposal.valid.len(), 1);
    assert_eq!(proposal.invalid.len(), 1);
    assert_eq!(sender.balance, 7);
    assert_eq!(sender.nonce.base, 0);
}

#[test]
fn proposal_accepts_far_ahead_nonce_and_rejects_duplicate() {
    let signer = TestSigner::from_seed(6);
    let recipient = TestSigner::from_seed(7);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(10, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    let nonce = NONCE_BITMAP_CAPACITY + 1;
    let transactions = vec![
        signer.sign(recipient.public_key.clone(), 3, nonce),
        signer.sign(recipient.public_key, 4, nonce),
    ];
    let proposal = propose(&accounts, transactions);
    let sender = changeset_account(&proposal.changeset, signer.public_key)
        .expect("sender should be updated");

    assert_eq!(proposal.valid.len(), 1);
    assert_eq!(proposal.invalid.len(), 1);
    assert_eq!(sender.balance, 7);
    assert_eq!(sender.nonce.base, NONCE_BITMAP_CAPACITY + 2);
}

#[test]
fn proposal_and_replay_match_for_transfer_batch() {
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
    let changeset = execute_prepared(&accounts, &proposal.valid)
        .expect("valid proposal transactions should execute");

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
fn unique_loaded_execution_matches_overlay_execution() {
    let sender_a = TestSigner::from_seed(20);
    let sender_b = TestSigner::from_seed(21);
    let recipient_a = TestSigner::from_seed(22);
    let recipient_b = TestSigner::from_seed(23);

    let mut accounts = State::new();
    accounts.insert(account_key(&sender_a.public_key), account(11, 0));
    accounts.insert(account_key(&sender_b.public_key), account(13, 0));
    accounts.insert(account_key(&recipient_a.public_key), account(5, 0));
    accounts.insert(account_key(&recipient_b.public_key), account(7, 0));

    let transactions = [
        sender_a.sign(recipient_a.public_key, 4, 0),
        sender_b.sign(recipient_b.public_key, 6, 0),
    ];
    let transfers = transactions
        .iter()
        .map(prepare_transfer)
        .collect::<Option<Vec<_>>>()
        .expect("test transactions should prepare");
    let loaded = transfers
        .iter()
        .flat_map(|transfer| [accounts[&transfer.sender], accounts[&transfer.recipient]])
        .collect::<Vec<_>>();

    assert_eq!(
        execute_unique(&transfers, &loaded),
        execute(&accounts, &transfers)
    );
}

#[test]
fn self_transfer_only_bumps_nonce() {
    let signer = TestSigner::from_seed(0);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(9, 3));

    let transactions = vec![signer.sign(signer.public_key.clone(), 4, 3)];
    let proposal = propose(&accounts, transactions);
    let changeset = execute_prepared(&accounts, &proposal.valid)
        .expect("valid proposal transactions should execute");

    assert_eq!(
        changeset_account(&changeset, signer.public_key),
        Some(account(9, 4))
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
    assert!(execute_prepared(&accounts, &proposal.invalid).is_none());
}

fn execute_prepared(
    accounts: &State,
    transactions: &[TestTransaction],
) -> Option<super::Changeset> {
    let transfers = transactions
        .iter()
        .map(prepare_transfer)
        .collect::<Option<Vec<_>>>()?;
    execute(accounts, &transfers)
}
