use super::{Changeset, State, compute, prepare_transfer};
use commonware_cryptography::{Signer, ed25519, sha256};
use constantinople_primitives::{
    Account, AccountKey, DEFAULT_ACCOUNT_BALANCE, NONCE_BITMAP_CAPACITY, Nonce, Transaction,
    TransactionPublicKey, VerifiedTransaction,
};
use core::num::NonZeroU64;
use std::collections::HashSet;

const NAMESPACE: &[u8] = b"executor-test";

type TestHasher = sha256::Sha256;
type TestTransaction = VerifiedTransaction<TestHasher>;

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
) -> Account {
    let account_key = account_key(&public_key);
    changeset
        .iter()
        .find_map(|(candidate, account)| (candidate == &account_key).then_some(*account))
        .expect("account should be in changeset")
}

fn run(accounts: &State, transactions: &[TestTransaction]) -> Option<Changeset> {
    let transfers = transactions
        .iter()
        .map(prepare_transfer)
        .collect::<Option<Vec<_>>>()?;
    compute(accounts, &transfers)
}

#[test]
fn executes_run_ahead_nonces() {
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
    let changeset = run(&accounts, &transactions).expect("valid batch should execute");

    let sender = changeset_account(&changeset, signer.public_key);
    let recipient = changeset_account(&changeset, recipient.public_key);
    assert_eq!(sender.balance, 1);
    assert_eq!(sender.nonce.base, 3);
    assert_eq!(recipient.balance, DEFAULT_ACCOUNT_BALANCE + 9);
}

#[test]
fn rejects_insufficient_balance() {
    let signer = TestSigner::from_seed(0);
    let recipient = TestSigner::from_seed(1);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(5, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    let transactions = vec![signer.sign(recipient.public_key, 6, 0)];
    assert!(run(&accounts, &transactions).is_none());
}

#[test]
fn rejects_duplicate_run_ahead_nonce() {
    let signer = TestSigner::from_seed(4);
    let recipient = TestSigner::from_seed(5);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(10, 0));
    accounts.insert(account_key(&recipient.public_key), Account::default());

    let transactions = vec![
        signer.sign(recipient.public_key.clone(), 3, 2),
        signer.sign(recipient.public_key, 4, 2),
    ];
    assert!(run(&accounts, &transactions).is_none());
}

#[test]
fn rejects_far_ahead_duplicate_nonce() {
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
    assert!(run(&accounts, &transactions).is_none());
}

#[test]
fn executes_multi_sender_batch() {
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
    let changeset = run(&accounts, &transactions).expect("valid batch should execute");

    assert_eq!(
        changeset_account(&changeset, sender_a.public_key),
        account(7, 1)
    );
    assert_eq!(
        changeset_account(&changeset, sender_b.public_key),
        account(7, 1)
    );
    assert_eq!(
        changeset_account(&changeset, recipient.public_key),
        account(15, 0)
    );
}

#[test]
fn credits_apply_to_post_debit_sender_state() {
    let sender_a = TestSigner::from_seed(50);
    let sender_b = TestSigner::from_seed(51);

    let mut accounts = State::new();
    accounts.insert(account_key(&sender_a.public_key), account(10, 0));
    accounts.insert(account_key(&sender_b.public_key), account(10, 0));

    let transactions = vec![
        sender_a.sign(sender_b.public_key.clone(), 4, 0),
        sender_b.sign(sender_a.public_key.clone(), 3, 0),
    ];
    let changeset = run(&accounts, &transactions).expect("valid batch should execute");

    assert_eq!(
        changeset_account(&changeset, sender_a.public_key),
        account(9, 1)
    );
    assert_eq!(
        changeset_account(&changeset, sender_b.public_key),
        account(11, 1)
    );
}

#[test]
fn rejects_spend_funded_by_in_block_credit() {
    let payer = TestSigner::from_seed(52);
    let middle = TestSigner::from_seed(53);
    let sink = TestSigner::from_seed(54);

    let mut accounts = State::new();
    accounts.insert(account_key(&payer.public_key), account(10, 0));
    accounts.insert(account_key(&middle.public_key), account(0, 0));
    accounts.insert(account_key(&sink.public_key), account(0, 0));

    let transactions = vec![
        payer.sign(middle.public_key.clone(), 10, 0),
        middle.sign(sink.public_key, 1, 0),
    ];
    let transfers = prepared(&transactions);

    assert!(compute(&accounts, &transfers).is_none());
}

#[test]
fn self_transfer_only_bumps_nonce() {
    let signer = TestSigner::from_seed(0);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(9, 3));

    let transactions = vec![signer.sign(signer.public_key.clone(), 4, 3)];
    let changeset = run(&accounts, &transactions).expect("self-transfer should execute");

    assert_eq!(
        changeset_account(&changeset, signer.public_key),
        account(9, 4)
    );
}

#[test]
fn rejects_unfunded_self_transfer() {
    let signer = TestSigner::from_seed(42);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(0, 0));

    let transactions = vec![signer.sign(signer.public_key.clone(), 1, 0)];
    let transfers = prepared(&transactions);

    assert!(compute(&accounts, &transfers).is_none());
}

#[test]
fn rejects_recipient_overflow() {
    let signer = TestSigner::from_seed(40);
    let recipient = TestSigner::from_seed(41);
    let mut accounts = State::new();
    accounts.insert(account_key(&signer.public_key), account(10, 0));
    accounts.insert(account_key(&recipient.public_key), account(u64::MAX, 0));

    let transactions = vec![signer.sign(recipient.public_key, 1, 0)];
    assert!(run(&accounts, &transactions).is_none());
}

fn contended_accounts(account_count: usize) -> (State, Vec<TestSigner>) {
    let signers: Vec<TestSigner> = (0..account_count as u64)
        .map(TestSigner::from_seed)
        .collect();
    let mut accounts = State::new();
    for signer in &signers {
        accounts.insert(account_key(&signer.public_key), account(1_000, 0));
    }
    (accounts, signers)
}

fn prepared(transactions: &[TestTransaction]) -> Vec<super::PreparedTransfer> {
    transactions
        .iter()
        .map(prepare_transfer)
        .collect::<Option<Vec<_>>>()
        .expect("transactions should prepare")
}

#[test]
fn contended_general_account_load_keys_are_deduplicated() {
    let sender = TestSigner::from_seed(80);
    let recipient = TestSigner::from_seed(81);
    let transactions = (0..4)
        .map(|nonce| sender.sign(recipient.public_key.clone(), 1, nonce))
        .collect::<Vec<_>>();
    let transfers = prepared(&transactions);
    let plan = super::execution_plan(&transfers).expect("execution plan");
    let keys = plan.general.account_keys();
    let unique = keys.iter().copied().collect::<HashSet<_>>();

    assert!(plan.discrete.transfers.is_empty());
    assert_eq!(keys.len(), unique.len());
    assert_eq!(keys.len(), 2);
    assert!(unique.contains(&account_key(&sender.public_key)));
    assert!(unique.contains(&account_key(&recipient.public_key)));
}

#[test]
fn execution_plan_keeps_unique_transfers_discrete_in_mixed_batches() {
    let key = |seed| account_key(&TestSigner::from_seed(seed).public_key);
    let transfer = |sender, recipient, nonce| super::PreparedTransfer {
        sender,
        recipient,
        sender_prefix: sender.prefix(),
        recipient_prefix: recipient.prefix(),
        value: 1,
        nonce,
    };

    let repeated = key(90);
    let transfers = vec![
        transfer(key(80), key(81), 0),
        transfer(repeated, key(82), 0),
        transfer(repeated, key(83), 1),
        transfer(key(84), key(85), 0),
    ];
    let plan = super::execution_plan(&transfers).expect("execution plan");

    assert_eq!(plan.discrete.transfers.len(), 2);
    assert_eq!(plan.discrete.sender_keys.len(), 2);
    assert_eq!(plan.discrete.recipient_keys.len(), 2);
    assert_eq!(plan.general.account_keys().len(), 3);
}

#[test]
fn mixed_discrete_and_general_execution_writes_each_account_once() {
    let discrete_sender = TestSigner::from_seed(100);
    let discrete_recipient = TestSigner::from_seed(101);
    let repeated_sender = TestSigner::from_seed(102);
    let general_recipient = TestSigner::from_seed(103);

    let mut accounts = State::new();
    accounts.insert(account_key(&discrete_sender.public_key), account(10, 0));
    accounts.insert(account_key(&discrete_recipient.public_key), account(5, 0));
    accounts.insert(account_key(&repeated_sender.public_key), account(10, 0));
    accounts.insert(account_key(&general_recipient.public_key), account(7, 0));

    let transactions = vec![
        discrete_sender.sign(discrete_recipient.public_key.clone(), 3, 0),
        repeated_sender.sign(general_recipient.public_key.clone(), 2, 0),
        repeated_sender.sign(general_recipient.public_key.clone(), 2, 1),
    ];
    let changeset = run(&accounts, &transactions).expect("valid mixed batch should execute");
    let unique = changeset.iter().map(|(key, _)| key).collect::<HashSet<_>>();

    assert_eq!(changeset.len(), unique.len());
    assert_eq!(
        changeset_account(&changeset, discrete_sender.public_key),
        account(7, 1)
    );
    assert_eq!(
        changeset_account(&changeset, discrete_recipient.public_key),
        account(8, 0)
    );
    assert_eq!(
        changeset_account(&changeset, repeated_sender.public_key),
        account(6, 2)
    );
    assert_eq!(
        changeset_account(&changeset, general_recipient.public_key),
        account(11, 0)
    );
}

#[test]
fn executes_large_contended_batch() {
    // Contended accounts: senders overlap recipients, each signs several
    // transactions in out-of-order (run-ahead) nonces, and round 2 is a
    // self-transfer for every account. Every transaction is valid.
    let account_count = 600usize;
    let (accounts, signers) = contended_accounts(account_count);

    let mut transactions = Vec::new();
    for round in 0..4u64 {
        for (index, signer) in signers.iter().enumerate() {
            let recipient = if round == 2 {
                signer.public_key.clone()
            } else {
                signers[(index * 7 + 1) % account_count].public_key.clone()
            };
            transactions.push(signer.sign(recipient, 1, round));
        }
    }
    let transfers = prepared(&transactions);

    assert!(compute(&accounts, &transfers).is_some());
}

#[test]
fn rejects_large_duplicate_nonce_batch() {
    // A duplicate nonce makes the batch invalid.
    let account_count = 600usize;
    let (accounts, signers) = contended_accounts(account_count);

    let mut transactions = Vec::new();
    for (index, signer) in signers.iter().enumerate() {
        let recipient = signers[(index + 1) % account_count].public_key.clone();
        transactions.push(signer.sign(recipient.clone(), 1, 0));
        transactions.push(signer.sign(recipient.clone(), 2, 0)); // duplicate nonce
        transactions.push(signer.sign(recipient, 1, 1));
    }
    let transfers = prepared(&transactions);

    assert!(compute(&accounts, &transfers).is_none());
}

#[test]
fn failed_debit_rejects_batch() {
    // A failed debit rejects the whole batch, even when its recipient is near
    // overflow.
    let broke = TestSigner::from_seed(1);
    let funded = TestSigner::from_seed(2);
    let recipient = TestSigner::from_seed(3);

    let mut accounts = State::new();
    accounts.insert(account_key(&broke.public_key), account(0, 0)); // cannot pay
    accounts.insert(account_key(&funded.public_key), account(100, 0));
    accounts.insert(
        account_key(&recipient.public_key),
        Account {
            balance: u64::MAX - 1,
            nonce: Nonce::new(0, 0),
        },
    );

    let transactions = [
        broke.sign(recipient.public_key.clone(), 1, 0), // debit fails
        funded.sign(recipient.public_key, 1, 0),
    ];
    let transfers = prepared(&transactions);

    assert!(compute(&accounts, &transfers).is_none());
}
