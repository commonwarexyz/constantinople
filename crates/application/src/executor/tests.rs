use super::{Changeset, State, execute, execute_with_shards, prepare_transfer};
use commonware_cryptography::{Signer, ed25519, sha256};
use commonware_parallel::Sequential;
use constantinople_primitives::{
    Account, AccountKey, DEFAULT_ACCOUNT_BALANCE, NONCE_BITMAP_CAPACITY, Nonce, Transaction,
    TransactionPublicKey, VerifiedTransaction,
};
use core::num::NonZeroU64;

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
    execute(&Sequential, accounts, &transfers)
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

fn prepared(transactions: &[TestTransaction]) -> Vec<super::PreparedTransfer<TestHasher>> {
    transactions
        .iter()
        .map(prepare_transfer)
        .collect::<Option<Vec<_>>>()
        .expect("transactions should prepare")
}

const SHARD_COUNTS: &[usize] = &[1, 2, 3, 5, 8, 16];

#[test]
fn execution_is_independent_of_shard_count() {
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

    let expected = execute_with_shards(&accounts, &transfers, 1).expect("valid batch executes");
    for &shards in SHARD_COUNTS {
        assert_eq!(
            execute_with_shards(&accounts, &transfers, shards),
            Some(expected.clone()),
            "shards={shards}"
        );
    }
}

#[test]
fn invalid_batch_rejected_for_all_shard_counts() {
    // A duplicate nonce makes the batch invalid; every shard count must reject it.
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

    for &shards in SHARD_COUNTS {
        assert!(
            execute_with_shards(&accounts, &transfers, shards).is_none(),
            "shards={shards}"
        );
    }
}

#[test]
fn failed_debit_rejects_for_all_shard_counts() {
    // A failed debit (insufficient balance) rejects the whole batch on every
    // shard count, even when its recipient is near overflow (no phantom credit
    // can ever spuriously overflow the valid transfer).
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

    for &shards in SHARD_COUNTS {
        assert!(
            execute_with_shards(&accounts, &transfers, shards).is_none(),
            "shards={shards}"
        );
    }
}
