//! End-to-end processor test harness.
//!
//! This module builds a small in-memory harness around the processor so tests
//! can:
//!
//! - seed initial account and storage state
//! - define scripted precompile behavior
//! - verify declared block access lists against proposal-time discovery
//! - assert receipts and persistent changesets
//! - compare sequential and parallel verifier execution

use super::{
    Precompiles,
    access::AccessListBuilder,
    executor::{ExecutionOutput, Processor, ProposalOutput, ValidationResult, VerificationError},
    frame::{Frame, FrameError},
    keys::{account_key, storage_key},
    state::{DiscoveryState, State, StateReader},
};
use bytes::Bytes;
use commonware_codec::{DecodeExt, FixedSize};
use commonware_cryptography::{Signer, blake3, ed25519};
use commonware_parallel::{Rayon, Sequential, Strategy};
use constantinople_primitives::{
    Access, AccessList, AccessMode, Account, Address, BlockAccessList, Receipt, ReceiptStatus,
    Slot, StateValue, Transaction, VerifiedTransaction,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rstest::rstest;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    marker::PhantomData,
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

const NAMESPACE: &[u8] = b"processor-test";

type TestDigest = blake3::Digest;
type TestHasher = blake3::Blake3;
type TestTransaction = VerifiedTransaction<ed25519::PublicKey, TestHasher>;
type TestValidation = ValidationResult<ed25519::PublicKey, TestHasher>;

#[derive(Debug, Clone)]
struct TestSigner {
    seed: u64,
    address: Address,
}

impl TestSigner {
    fn new(seed: u64) -> Self {
        let key = ed25519::PrivateKey::from_seed(seed);
        let address = Address::from_public_key(&mut TestHasher::default(), &key.public_key());
        Self { seed, address }
    }

    fn sign(&self, to: Address, value: u64, nonce: u64, input: Bytes) -> TestTransaction {
        let key = ed25519::PrivateKey::from_seed(self.seed);
        Transaction {
            sender: key.public_key(),
            to,
            input,
            value,
            nonce,
            _digest: PhantomData,
        }
        .seal_and_sign_verified(&key, NAMESPACE, &mut TestHasher::default())
    }
}

#[derive(Debug, Clone)]
enum DeclaredAccesses {
    Discover,
    Fixed(AccessList),
}

#[derive(Debug, Clone)]
struct TransactionSpec {
    signer: TestSigner,
    to: Address,
    value: u64,
    nonce: u64,
    input: Bytes,
    declared_accesses: DeclaredAccesses,
}

impl TransactionSpec {
    fn transfer(signer: TestSigner, to: Address, value: u64, nonce: u64) -> Self {
        Self {
            signer,
            to,
            value,
            nonce,
            input: Bytes::new(),
            declared_accesses: DeclaredAccesses::Discover,
        }
    }

    fn call(signer: TestSigner, to: Address, value: u64, nonce: u64, input: Bytes) -> Self {
        Self {
            signer,
            to,
            value,
            nonce,
            input,
            declared_accesses: DeclaredAccesses::Discover,
        }
    }

    fn with_access_list(mut self, access_list: AccessList) -> Self {
        self.declared_accesses = DeclaredAccesses::Fixed(access_list);
        self
    }

    fn sign(&self) -> TestTransaction {
        self.signer
            .sign(self.to, self.value, self.nonce, self.input.clone())
    }

    fn declared_accesses(&self, discovered: &[Access]) -> AccessList {
        match &self.declared_accesses {
            DeclaredAccesses::Discover => discovered.to_vec(),
            DeclaredAccesses::Fixed(access_list) => access_list.clone(),
        }
    }

    fn expected_access_list(&self, precompiles: &TestPrecompiles) -> AccessList {
        declared_accesses(
            self.signer.address,
            self.to,
            self.value,
            precompiles.simulation_access_list(self.to),
        )
    }
}

#[derive(Debug, Clone)]
enum PrecompileStep {
    InspectAccount(Address),
    InspectStorage(Address, Slot),
    AssertAccountBalance(Address, u64),
    AssertStorage(Address, Slot, Slot),
    ReadStorage(Slot),
    AssertReadStorage(Slot, Slot),
    WriteStorage(Slot, Slot),
    Transfer(Address, u64),
    Call(Address, u64, Bytes),
    AssertCallReturns(Address, u64, Bytes, Bytes),
    AssertCallReverts(Address, u64, Bytes, Bytes),
    Count(Arc<AtomicUsize>),
    Panic,
    Return(Bytes),
    Revert(Bytes),
}

#[derive(Debug, Clone, Default)]
struct TestPrecompiles {
    programs: BTreeMap<Address, Vec<PrecompileStep>>,
    panic_on_lookup: Option<Address>,
}

impl TestPrecompiles {
    fn insert(&mut self, address: Address, program: Vec<PrecompileStep>) {
        self.programs.insert(address, program);
    }

    fn set_panic_on_lookup(&mut self, address: Address) {
        self.panic_on_lookup = Some(address);
    }

    fn simulation_access_list(&self, address: Address) -> AccessList {
        let mut builder = AccessListBuilder::default();
        let mut visited = HashSet::new();
        self.record_simulation_accesses(address, &mut builder, &mut visited);
        builder.into_access_list()
    }

    fn record_simulation_accesses(
        &self,
        address: Address,
        builder: &mut AccessListBuilder,
        visited: &mut HashSet<Address>,
    ) {
        if !visited.insert(address) {
            return;
        }

        let Some(program) = self.programs.get(&address) else {
            return;
        };

        for step in program {
            match step {
                PrecompileStep::InspectAccount(address) => {
                    builder.record_account(*address, AccessMode::Read);
                }
                PrecompileStep::InspectStorage(address, slot) => {
                    builder.record_storage(*address, *slot, AccessMode::Read);
                }
                PrecompileStep::AssertAccountBalance(address, _) => {
                    builder.record_account(*address, AccessMode::Read);
                }
                PrecompileStep::AssertStorage(address, slot, _) => {
                    builder.record_storage(*address, *slot, AccessMode::Read);
                }
                PrecompileStep::ReadStorage(slot) => {
                    builder.record_storage(address, *slot, AccessMode::Read);
                }
                PrecompileStep::AssertReadStorage(slot, _) => {
                    builder.record_storage(address, *slot, AccessMode::Read);
                }
                PrecompileStep::WriteStorage(slot, _) => {
                    builder.record_storage(address, *slot, AccessMode::Write);
                }
                PrecompileStep::Transfer(recipient, _) => {
                    builder.record_account(address, AccessMode::Write);
                    builder.record_account(*recipient, AccessMode::Write);
                }
                PrecompileStep::Call(callee, value, _)
                | PrecompileStep::AssertCallReturns(callee, value, _, _)
                | PrecompileStep::AssertCallReverts(callee, value, _, _) => {
                    if *value > 0 {
                        builder.record_account(address, AccessMode::Write);
                        builder.record_account(*callee, AccessMode::Write);
                    } else {
                        builder.record_account(address, AccessMode::Read);
                        builder.record_account(*callee, AccessMode::Read);
                    }

                    self.record_simulation_accesses(*callee, builder, visited);
                }
                PrecompileStep::Count(_)
                | PrecompileStep::Panic
                | PrecompileStep::Return(_)
                | PrecompileStep::Revert(_) => {}
            }
        }
    }
}

impl Precompiles for TestPrecompiles {
    fn is_precompile(&self, address: Address) -> bool {
        if self.panic_on_lookup == Some(address) {
            panic!("precompile lookup panicked");
        }

        self.programs.contains_key(&address)
    }

    fn execute<S, R>(
        &self,
        address: Address,
        frame: &mut Frame<'_, R>,
        processor: &Processor<'_, S, Self>,
    ) -> Result<Bytes, FrameError>
    where
        S: Strategy,
        R: StateReader,
        Self: Sized,
    {
        let program = self
            .programs
            .get(&address)
            .expect("precompile must exist")
            .clone();

        for step in program {
            match step {
                PrecompileStep::InspectAccount(address) => {
                    let _ = frame.inspect_account(address)?;
                }
                PrecompileStep::InspectStorage(address, slot) => {
                    let _ = frame.inspect_storage(address, slot)?;
                }
                PrecompileStep::AssertAccountBalance(address, expected_balance) => {
                    let account = frame.inspect_account(address)?;
                    assert_eq!(
                        account.balance, expected_balance,
                        "unexpected account balance"
                    );
                }
                PrecompileStep::AssertStorage(address, slot, expected) => {
                    let value = frame.inspect_storage(address, slot)?;
                    assert_eq!(value, expected, "unexpected storage value");
                }
                PrecompileStep::ReadStorage(slot) => {
                    let _ = frame.read_self_storage(slot)?;
                }
                PrecompileStep::AssertReadStorage(slot, expected) => {
                    let value = frame.read_self_storage(slot)?;
                    assert_eq!(value, expected, "unexpected owner storage value");
                }
                PrecompileStep::WriteStorage(slot, value) => {
                    frame.write_storage(slot, value)?;
                }
                PrecompileStep::Transfer(address, value) => {
                    frame.transfer(address, value)?;
                }
                PrecompileStep::Call(address, value, input) => {
                    let _ = frame.call(processor, address, value, input)?;
                }
                PrecompileStep::AssertCallReturns(address, value, input, expected) => {
                    let result = frame.call(processor, address, value, input)?;
                    assert_eq!(result, expected, "unexpected child return value");
                }
                PrecompileStep::AssertCallReverts(address, value, input, expected) => {
                    let result = frame.call(processor, address, value, input);
                    assert_eq!(
                        result,
                        Err(FrameError::Revert(expected)),
                        "unexpected child revert result"
                    );
                }
                PrecompileStep::Count(counter) => {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                PrecompileStep::Panic => panic!("scripted precompile panic"),
                PrecompileStep::Return(data) => return Ok(data),
                PrecompileStep::Revert(data) => return Err(FrameError::Revert(data)),
            }
        }

        Ok(Bytes::new())
    }
}

#[derive(Debug)]
struct ProposalRun {
    valid: Vec<TestTransaction>,
    invalid: Vec<TestTransaction>,
    output: ProposalOutput<TestDigest>,
}

impl ProposalRun {
    fn access_list(&self, index: usize) -> &[Access] {
        self.output.access_list.accesses_for_transaction(index)
    }
}

#[derive(Debug)]
struct ProcessorRun {
    transactions: Vec<TestTransaction>,
    proposed: ProposalOutput<TestDigest>,
    declared_access_list: BlockAccessList,
    output: ExecutionOutput<TestDigest>,
}

impl ProcessorRun {
    fn receipt(&self, index: usize) -> &Receipt<TestDigest> {
        &self.output.receipts[index]
    }

    fn proposed_access_list(&self, index: usize) -> &[Access] {
        self.proposed.access_list.accesses_for_transaction(index)
    }

    fn declared_access_list(&self, index: usize) -> &[Access] {
        self.declared_access_list.accesses_for_transaction(index)
    }

    fn account_change(&self, address: Address) -> Option<Account> {
        match self.output.changeset.get(&account_key(address)) {
            Some(StateValue::Account(account)) => Some(*account),
            Some(StateValue::Storage(_)) => panic!("account key stored a storage value"),
            None => None,
        }
    }

    fn storage_change(&self, address: Address, slot: Slot) -> Option<Slot> {
        let mut hasher = TestHasher::default();
        let key = storage_key(&mut hasher, address, slot);
        match self.output.changeset.get(&key) {
            Some(StateValue::Storage(value)) => Some(*value),
            Some(StateValue::Account(_)) => panic!("storage key stored an account value"),
            None => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ProcessorHarness {
    accounts: HashMap<Address, Account>,
    storage: HashMap<(Address, Slot), Slot>,
    precompiles: TestPrecompiles,
}

impl ProcessorHarness {
    fn signer(&self, seed: u64) -> TestSigner {
        TestSigner::new(seed)
    }

    fn set_panic_on_lookup(&mut self, address: Address) {
        self.precompiles.set_panic_on_lookup(address);
    }

    fn insert_precompile(&mut self, address: Address, program: Vec<PrecompileStep>) {
        self.precompiles.insert(address, program);
    }

    fn set_account(&mut self, address: Address, account: Account) {
        self.accounts.insert(address, account);
    }

    fn set_storage(&mut self, address: Address, slot: Slot, value: Slot) {
        self.storage.insert((address, slot), value);
    }

    fn state(&self) -> State {
        State::new(self.accounts.clone(), self.storage.clone())
    }

    fn transactions(&self, specs: &[TransactionSpec]) -> Vec<TestTransaction> {
        specs.iter().map(TransactionSpec::sign).collect()
    }

    fn validate(&self, transactions: Vec<TestTransaction>) -> TestValidation {
        let processor = Processor::new(&Sequential, &self.precompiles);
        processor.validate(&self.state(), transactions)
    }

    fn validate_specs(&self, specs: &[TransactionSpec]) -> TestValidation {
        self.validate(self.transactions(specs))
    }

    fn propose_transactions(&self, transactions: Vec<TestTransaction>) -> ProposalRun {
        let processor = Processor::new(&Sequential, &self.precompiles);
        let mut discovery_state = DiscoveryState::new(self.state());
        let validation = processor.validate(&discovery_state, transactions);
        let valid = validation.valid;
        let invalid = validation.invalid;
        let output = processor.propose(&mut discovery_state, &valid);

        ProposalRun {
            valid,
            invalid,
            output,
        }
    }

    fn propose_specs(&self, specs: &[TransactionSpec]) -> ProposalRun {
        self.propose_transactions(self.transactions(specs))
    }

    fn propose_unchecked(&self, transactions: &[TestTransaction]) -> ProposalOutput<TestDigest> {
        let processor = Processor::new(&Sequential, &self.precompiles);
        let mut discovery_state = DiscoveryState::new(self.state());
        processor.propose(&mut discovery_state, transactions)
    }

    fn declared_access_list(
        &self,
        specs: &[TransactionSpec],
        proposal: &ProposalRun,
    ) -> BlockAccessList {
        assert_eq!(
            specs.len(),
            proposal.valid.len(),
            "execute_specs only supports fully valid transaction batches",
        );

        let transaction_accesses = specs
            .iter()
            .enumerate()
            .map(|(index, spec)| spec.declared_accesses(proposal.access_list(index)))
            .collect::<Vec<_>>();

        BlockAccessList::from_transactions(
            transaction_accesses,
            proposal.output.access_list.account_writes.clone(),
            proposal.output.access_list.storage_writes.clone(),
        )
    }

    fn verify_with_strategy<S>(
        &self,
        transactions: &[TestTransaction],
        access_list: &BlockAccessList,
        strategy: &S,
    ) -> Result<ExecutionOutput<TestDigest>, VerificationError>
    where
        S: Strategy,
    {
        let processor = Processor::new(strategy, &self.precompiles);
        processor.verify(self.state(), transactions, access_list)
    }

    fn execute_specs(&self, specs: &[TransactionSpec]) -> Result<ProcessorRun, VerificationError> {
        self.execute_specs_with_strategy(specs, &Sequential)
    }

    fn execute_specs_with_strategy<S>(
        &self,
        specs: &[TransactionSpec],
        strategy: &S,
    ) -> Result<ProcessorRun, VerificationError>
    where
        S: Strategy,
    {
        let proposal = self.propose_specs(specs);
        assert!(
            proposal.invalid.is_empty(),
            "transaction should validate before execute_specs",
        );
        let declared_access_list = self.declared_access_list(specs, &proposal);
        let output = self.verify_with_strategy(&proposal.valid, &declared_access_list, strategy)?;

        assert_eq!(output.receipts, proposal.output.receipts);
        assert_eq!(output.changeset, proposal.output.changeset);

        Ok(ProcessorRun {
            transactions: proposal.valid,
            proposed: proposal.output,
            declared_access_list,
            output,
        })
    }
}

fn address(byte: u8) -> Address {
    Address::decode(&[byte; Address::SIZE][..]).expect("address bytes should decode")
}

fn address_from_seed(seed: u64) -> Address {
    let mut bytes = [0u8; Address::SIZE];
    bytes[..u64::BITS as usize / 8].copy_from_slice(&seed.to_be_bytes());
    Address::decode(&bytes[..]).expect("seed bytes should decode into an address")
}

fn slot(byte: u8) -> Slot {
    Slot::from([byte; Slot::SIZE])
}

fn slot_from_seed(seed: u64) -> Slot {
    let mut bytes = [0u8; Slot::SIZE];
    bytes[..u64::BITS as usize / 8].copy_from_slice(&seed.to_be_bytes());
    Slot::from(bytes)
}

fn account(balance: u64, nonce: u64) -> Account {
    Account { balance, nonce }
}

fn canonical_access_list(accesses: impl IntoIterator<Item = Access>) -> AccessList {
    let mut builder = AccessListBuilder::default();
    for access in accesses {
        match access {
            Access::Account(address, mode) => builder.record_account(address, mode),
            Access::Storage(address, slot, mode) => builder.record_storage(address, slot, mode),
        }
    }
    builder.into_access_list()
}

fn declared_accesses(
    sender: Address,
    to: Address,
    value: u64,
    extras: impl IntoIterator<Item = Access>,
) -> AccessList {
    let recipient_mode = if value > 0 {
        AccessMode::Write
    } else {
        AccessMode::Read
    };

    canonical_access_list(
        [
            Access::Account(sender, AccessMode::Write),
            Access::Account(to, recipient_mode),
        ]
        .into_iter()
        .chain(extras),
    )
}

fn empty_block_access_list(transaction_count: usize) -> BlockAccessList {
    BlockAccessList::from_transactions(
        (0..transaction_count).map(|_| AccessList::new()),
        Vec::new(),
        Vec::new(),
    )
}

fn random_bytes(rng: &mut StdRng, max_len: usize) -> Bytes {
    let len = rng.gen_range(0..=max_len);
    let mut bytes = vec![0u8; len];
    rng.fill(bytes.as_mut_slice());
    Bytes::from(bytes)
}

fn payload(seed: u64, tag: u8) -> Bytes {
    let mut bytes = seed.to_le_bytes().to_vec();
    bytes.push(tag);
    Bytes::from(bytes)
}

fn parallel_strategy() -> Rayon {
    Rayon::new(NonZeroUsize::new(4).expect("thread count must be non-zero"))
        .expect("rayon strategy should build")
}

fn assert_receipt(run: &ProcessorRun, index: usize, status: ReceiptStatus, return_data: Bytes) {
    assert_eq!(run.receipt(index).status, status);
    assert_eq!(run.receipt(index).return_data, return_data);
}

fn assert_access_mismatch<T: core::fmt::Debug>(result: Result<T, VerificationError>, index: usize) {
    assert_eq!(
        result.expect_err("declared BAL should fail verification"),
        VerificationError::AccessListMismatch {
            transaction_index: index,
        }
    );
}

#[derive(Debug, Clone, Copy)]
enum BuilderCase {
    UpgradesReadToWrite,
    DeduplicatesRepeatedAccesses,
    RecordsCrossAccountReads,
}

#[derive(Debug)]
struct RandomBatch {
    harness: ProcessorHarness,
    specs: Vec<TransactionSpec>,
}

fn random_round_trip_batch(seed: u64) -> RandomBatch {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut harness = ProcessorHarness::default();

    let signer_count = rng.gen_range(1..=3);
    let mut signers = Vec::with_capacity(signer_count);
    for index in 0..signer_count {
        let signer = harness.signer(seed.wrapping_mul(17).wrapping_add(index as u64 + 1));
        harness.set_account(signer.address, account(50, 0));
        signers.push(signer);
    }

    let mut external_accounts = Vec::with_capacity(3);
    for index in 0..3 {
        let address = address_from_seed(seed.wrapping_mul(100).wrapping_add(index as u64 + 1_000));
        let storage_slot =
            slot_from_seed(seed.wrapping_mul(200).wrapping_add(index as u64 + 2_000));
        let storage_value =
            slot_from_seed(seed.wrapping_mul(300).wrapping_add(index as u64 + 3_000));
        harness.set_account(address, account(index as u64 + 1, 0));
        harness.set_storage(address, storage_slot, storage_value);
        external_accounts.push((address, storage_slot, storage_value));
    }

    let precompile_count = rng.gen_range(1..=3);
    let mut precompiles = Vec::with_capacity(precompile_count);
    for index in 0..precompile_count {
        let address = address_from_seed(seed.wrapping_mul(400).wrapping_add(index as u64 + 4_000));
        let owner_slot = slot_from_seed(seed.wrapping_mul(500).wrapping_add(index as u64 + 5_000));
        let owner_value = slot_from_seed(seed.wrapping_mul(600).wrapping_add(index as u64 + 6_000));
        let (other, other_slot, _) = external_accounts[rng.gen_range(0..external_accounts.len())];

        harness.set_storage(address, owner_slot, owner_value);

        let program = match rng.gen_range(0..5) {
            0 => vec![
                PrecompileStep::ReadStorage(owner_slot),
                PrecompileStep::WriteStorage(
                    owner_slot,
                    slot_from_seed(seed.wrapping_mul(700).wrapping_add(index as u64 + 7_000)),
                ),
                PrecompileStep::Return(payload(seed, index as u8)),
            ],
            1 => vec![
                PrecompileStep::InspectAccount(other),
                PrecompileStep::Return(payload(seed, index as u8)),
            ],
            2 => vec![
                PrecompileStep::InspectStorage(other, other_slot),
                PrecompileStep::Return(payload(seed, index as u8)),
            ],
            3 if !precompiles.is_empty() => {
                let callee = precompiles[rng.gen_range(0..precompiles.len())];
                vec![
                    PrecompileStep::Call(callee, 0, random_bytes(&mut rng, 4)),
                    PrecompileStep::Return(payload(seed, index as u8)),
                ]
            }
            _ => vec![PrecompileStep::Return(payload(seed, index as u8))],
        };

        harness.insert_precompile(address, program);
        precompiles.push(address);
    }

    let transaction_count = rng.gen_range(1..=6);
    let mut next_nonces = vec![0u64; signers.len()];
    let mut specs = Vec::with_capacity(transaction_count);
    for _ in 0..transaction_count {
        let signer_index = rng.gen_range(0..signers.len());
        let signer = signers[signer_index].clone();
        let nonce = next_nonces[signer_index];
        next_nonces[signer_index] += 1;

        if rng.gen_bool(0.7) {
            let to = precompiles[rng.gen_range(0..precompiles.len())];
            specs.push(TransactionSpec::call(
                signer,
                to,
                0,
                nonce,
                random_bytes(&mut rng, 4),
            ));
        } else {
            let (to, _, _) = external_accounts[rng.gen_range(0..external_accounts.len())];
            specs.push(TransactionSpec::transfer(
                signer,
                to,
                rng.gen_range(0..=3),
                nonce,
            ));
        }
    }

    RandomBatch { harness, specs }
}

fn random_user_transactions(seed: u64) -> (ProcessorHarness, Vec<TestTransaction>) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut harness = ProcessorHarness::default();

    let panic_address = address_from_seed(seed.wrapping_add(9_000));
    let safe_precompile = address_from_seed(seed.wrapping_add(9_001));
    harness.set_panic_on_lookup(panic_address);
    harness.insert_precompile(safe_precompile, vec![PrecompileStep::Return(Bytes::new())]);

    let signer_count = rng.gen_range(1..=3);
    let mut signers = Vec::with_capacity(signer_count);
    for index in 0..signer_count {
        let signer = harness.signer(seed.wrapping_mul(19).wrapping_add(index as u64 + 1));
        harness.set_account(
            signer.address,
            account(rng.gen_range(0..=12), rng.gen_range(0..=2)),
        );
        signers.push(signer);
    }

    let mut transactions = Vec::new();
    let transaction_count = rng.gen_range(1..=8);
    for _ in 0..transaction_count {
        let signer = signers[rng.gen_range(0..signers.len())].clone();
        let target = match rng.gen_range(0..3) {
            0 => panic_address,
            1 => safe_precompile,
            _ => address_from_seed(rng.gen_range(10_000..20_000)),
        };
        let nonce = match rng.gen_range(0..4) {
            0 => 0,
            1 => 1,
            2 => rng.gen_range(2..=8),
            _ => u64::MAX,
        };

        transactions.push(signer.sign(
            target,
            rng.gen_range(0..=20),
            nonce,
            random_bytes(&mut rng, 4),
        ));
    }

    (harness, transactions)
}

#[test]
fn propose_builds_block_access_list_and_final_writes() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(7);
    let precompile = address(0x44);
    let storage_slot = slot(0x11);
    let new_value = slot(0x99);

    harness.set_account(sender.address, account(1, 0));
    harness.set_storage(precompile, storage_slot, slot(0x01));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::ReadStorage(storage_slot),
            PrecompileStep::WriteStorage(storage_slot, new_value),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let proposal = harness.propose_specs(&[TransactionSpec::call(
        sender.clone(),
        precompile,
        0,
        0,
        Bytes::new(),
    )]);

    assert!(proposal.invalid.is_empty());
    assert_eq!(proposal.output.receipts.len(), 1);
    assert_eq!(proposal.output.receipts[0].status, ReceiptStatus::Success);
    assert_eq!(proposal.output.access_list.tx_offsets, vec![0, 3]);
    assert!(
        proposal
            .output
            .access_list
            .tx_accesses
            .contains(&Access::Account(sender.address, AccessMode::Write))
    );
    assert!(
        proposal
            .output
            .access_list
            .tx_accesses
            .contains(&Access::Account(precompile, AccessMode::Read))
    );
    assert!(
        proposal
            .output
            .access_list
            .tx_accesses
            .contains(&Access::Storage(
                precompile,
                storage_slot,
                AccessMode::Write
            ))
    );
    assert_eq!(proposal.output.access_list.account_writes.len(), 1);
    assert_eq!(
        proposal.output.access_list.account_writes[0].address,
        sender.address
    );
    assert_eq!(
        proposal.output.access_list.account_writes[0].account.nonce,
        1
    );
    assert_eq!(proposal.output.access_list.storage_writes.len(), 1);
    assert_eq!(
        proposal.output.access_list.storage_writes[0].address,
        precompile
    );
    assert_eq!(
        proposal.output.access_list.storage_writes[0].slot,
        storage_slot
    );
    assert_eq!(
        proposal.output.access_list.storage_writes[0].value,
        new_value
    );

    let mut hasher = TestHasher::default();
    let storage_key = storage_key(&mut hasher, precompile, storage_slot);
    assert_eq!(
        proposal.output.changeset.get(&account_key(sender.address)),
        Some(&StateValue::Account(account(1, 1)))
    );
    assert_eq!(
        proposal.output.changeset.get(&storage_key),
        Some(&StateValue::Storage(new_value))
    );
}

#[test]
fn verify_accepts_proposed_block_access_list() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(8);
    let precompile = address(0x45);
    let storage_slot = slot(0x12);
    let new_value = slot(0xaa);

    harness.set_account(sender.address, account(1, 0));
    harness.set_storage(precompile, storage_slot, slot(0x02));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::ReadStorage(storage_slot),
            PrecompileStep::WriteStorage(storage_slot, new_value),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender,
            precompile,
            0,
            0,
            Bytes::new(),
        )])
        .expect("BAL should verify");

    assert_eq!(run.output.receipts, run.proposed.receipts);
    assert_eq!(run.output.changeset, run.proposed.changeset);
}

#[test]
fn verify_rejects_malformed_block_access_list() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(58);
    let precompile = address(0x46);
    let counter = Arc::new(AtomicUsize::new(0));

    harness.set_account(sender.address, account(1, 0));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::Count(counter.clone()),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let proposal = harness.propose_specs(&[TransactionSpec::call(
        sender,
        precompile,
        0,
        0,
        Bytes::new(),
    )]);
    let mut access_list = proposal.output.access_list.clone();
    access_list.tx_offsets = vec![1, 1];

    counter.store(0, Ordering::SeqCst);
    let result = harness.verify_with_strategy(&proposal.valid, &access_list, &Sequential);
    assert_eq!(
        result.expect_err("malformed BAL should be rejected before execution"),
        VerificationError::MalformedBlockAccessList,
    );
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[test]
fn write_access_allows_reads() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(1);
    let precompile = address(0x31);
    let owner_slot = slot(0x41);

    harness.set_account(sender.address, account(10, 0));
    harness.set_storage(precompile, owner_slot, slot(0x10));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::AssertReadStorage(owner_slot, slot(0x10)),
            PrecompileStep::WriteStorage(owner_slot, slot(0x20)),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let run = harness
        .execute_specs(&[
            TransactionSpec::call(sender.clone(), precompile, 0, 0, Bytes::new()).with_access_list(
                declared_accesses(
                    sender.address,
                    precompile,
                    0,
                    [Access::Storage(precompile, owner_slot, AccessMode::Write)],
                ),
            ),
        ])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
    assert_eq!(run.storage_change(precompile, owner_slot), Some(slot(0x20)));
}

#[test]
fn undeclared_account_read_rejects_declared_bal() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(2);
    let precompile = address(0x32);
    let other = address(0x42);

    harness.set_account(sender.address, account(10, 0));
    harness.set_account(other, account(7, 3));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::InspectAccount(other),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let result = harness.execute_specs(&[TransactionSpec::call(
        sender.clone(),
        precompile,
        0,
        0,
        Bytes::new(),
    )
    .with_access_list(declared_accesses(sender.address, precompile, 0, []))]);

    assert_access_mismatch(result, 0);
}

#[test]
fn declared_account_read_succeeds() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(3);
    let precompile = address(0x33);
    let other = address(0x43);

    harness.set_account(sender.address, account(10, 0));
    harness.set_account(other, account(7, 3));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::AssertAccountBalance(other, 7),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let run = harness
        .execute_specs(&[
            TransactionSpec::call(sender.clone(), precompile, 0, 0, Bytes::new()).with_access_list(
                declared_accesses(
                    sender.address,
                    precompile,
                    0,
                    [Access::Account(other, AccessMode::Read)],
                ),
            ),
        ])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
}

#[test]
fn undeclared_storage_read_rejects_declared_bal() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(4);
    let precompile = address(0x34);
    let other = address(0x44);
    let other_slot = slot(0x54);

    harness.set_account(sender.address, account(10, 0));
    harness.set_storage(other, other_slot, slot(0x11));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::InspectStorage(other, other_slot),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let result = harness.execute_specs(&[TransactionSpec::call(
        sender.clone(),
        precompile,
        0,
        0,
        Bytes::new(),
    )
    .with_access_list(declared_accesses(sender.address, precompile, 0, []))]);

    assert_access_mismatch(result, 0);
}

#[test]
fn read_only_storage_write_rejects_declared_bal() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(5);
    let precompile = address(0x35);
    let owner_slot = slot(0x55);

    harness.set_account(sender.address, account(10, 0));
    harness.set_storage(precompile, owner_slot, slot(0x01));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::WriteStorage(owner_slot, slot(0x02)),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let result = harness.execute_specs(&[TransactionSpec::call(
        sender.clone(),
        precompile,
        0,
        0,
        Bytes::new(),
    )
    .with_access_list(declared_accesses(
        sender.address,
        precompile,
        0,
        [Access::Storage(precompile, owner_slot, AccessMode::Read)],
    ))]);

    assert_access_mismatch(result, 0);
}

#[test]
fn precompile_can_read_any_declared_storage() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(6);
    let precompile = address(0x36);
    let other = address(0x46);
    let other_slot = slot(0x56);

    harness.set_account(sender.address, account(10, 0));
    harness.set_storage(other, other_slot, slot(0x12));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::AssertStorage(other, other_slot, slot(0x12)),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let run = harness
        .execute_specs(&[
            TransactionSpec::call(sender.clone(), precompile, 0, 0, Bytes::new()).with_access_list(
                declared_accesses(
                    sender.address,
                    precompile,
                    0,
                    [Access::Storage(other, other_slot, AccessMode::Read)],
                ),
            ),
        ])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
}

#[test]
fn precompile_cannot_write_other_account_storage() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(7);
    let precompile = address(0x37);
    let other = address(0x47);
    let shared_slot = slot(0x57);

    harness.set_account(sender.address, account(10, 0));
    harness.set_storage(precompile, shared_slot, slot(0x01));
    harness.set_storage(other, shared_slot, slot(0x02));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::AssertStorage(other, shared_slot, slot(0x02)),
            PrecompileStep::WriteStorage(shared_slot, slot(0x03)),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender,
            precompile,
            0,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
    assert_eq!(
        run.storage_change(precompile, shared_slot),
        Some(slot(0x03))
    );
    assert_eq!(run.storage_change(other, shared_slot), None);
}

#[test]
fn transfer_requires_declared_recipient_access() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(8);
    let precompile = address(0x38);
    let beneficiary = address(0x48);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::Transfer(beneficiary, 1),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let result = harness.execute_specs(&[TransactionSpec::call(
        sender.clone(),
        precompile,
        1,
        0,
        Bytes::new(),
    )
    .with_access_list(declared_accesses(sender.address, precompile, 1, []))]);

    assert_access_mismatch(result, 0);
}

#[test]
fn precompile_transfer_updates_balances() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(9);
    let precompile = address(0x39);
    let beneficiary = address(0x49);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::Transfer(beneficiary, 3),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender.clone(),
            precompile,
            4,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
    assert_eq!(run.account_change(sender.address), Some(account(6, 1)));
    assert_eq!(run.account_change(precompile), Some(account(1, 0)));
    assert_eq!(run.account_change(beneficiary), Some(account(3, 0)));
}

#[test]
fn precompile_transfer_underflow_reverts() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(10);
    let precompile = address(0x3A);
    let beneficiary = address(0x4A);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::Transfer(beneficiary, 1),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender.clone(),
            precompile,
            0,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
    assert_eq!(run.account_change(sender.address), Some(account(10, 1)));
    assert_eq!(run.account_change(precompile), None);
    assert_eq!(run.account_change(beneficiary), None);
}

#[test]
fn root_transfer_overflow_reverts() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(59);
    let recipient = address(0x4B);

    harness.set_account(sender.address, account(10, 0));
    harness.set_account(recipient, account(u64::MAX, 0));

    let run = harness
        .execute_specs(&[TransactionSpec::transfer(sender.clone(), recipient, 1, 0)])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
    assert_eq!(run.account_change(sender.address), Some(account(10, 1)));
    assert_eq!(run.account_change(recipient), None);
    assert!(
        run.proposed_access_list(0)
            .contains(&Access::Account(recipient, AccessMode::Write))
    );
}

#[test]
fn precompile_transfer_overflow_reverts() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(60);
    let precompile = address(0x3B);
    let beneficiary = address(0x4C);

    harness.set_account(sender.address, account(10, 0));
    harness.set_account(beneficiary, account(u64::MAX, 0));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::Transfer(beneficiary, 1),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender.clone(),
            precompile,
            1,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
    assert_eq!(run.account_change(sender.address), Some(account(10, 1)));
    assert_eq!(run.account_change(precompile), None);
    assert_eq!(run.account_change(beneficiary), None);
    assert!(
        run.proposed_access_list(0)
            .contains(&Access::Account(beneficiary, AccessMode::Write))
    );
}

#[test]
fn root_transfer_zero_value_is_noop() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(11);
    let recipient = address(0x4B);

    harness.set_account(sender.address, account(10, 0));

    let run = harness
        .execute_specs(&[TransactionSpec::transfer(sender.clone(), recipient, 0, 0)])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::new());
    assert_eq!(run.account_change(sender.address), Some(account(10, 1)));
    assert_eq!(run.account_change(recipient), None);
}

#[test]
fn root_self_transfer_keeps_balance() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(12);

    harness.set_account(sender.address, account(10, 0));

    let run = harness
        .execute_specs(&[TransactionSpec::transfer(
            sender.clone(),
            sender.address,
            10,
            0,
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::new());
    assert_eq!(run.account_change(sender.address), Some(account(10, 1)));
}

#[test]
fn precompile_zero_value_call_can_still_mutate_own_storage() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(13);
    let precompile = address(0x3C);
    let owner_slot = slot(0x5C);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::WriteStorage(owner_slot, slot(0x21)),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender,
            precompile,
            0,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
    assert_eq!(run.storage_change(precompile, owner_slot), Some(slot(0x21)));
}

#[test]
fn child_success_merges_into_parent() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(14);
    let precompile = address(0x3D);
    let owner_slot = slot(0x5D);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::WriteStorage(owner_slot, slot(0x30)),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender.clone(),
            precompile,
            2,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
    assert_eq!(run.account_change(sender.address), Some(account(8, 1)));
    assert_eq!(run.account_change(precompile), Some(account(2, 0)));
    assert_eq!(run.storage_change(precompile, owner_slot), Some(slot(0x30)));
}

#[test]
fn child_revert_discards_child_diff() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(15);
    let precompile = address(0x3E);
    let owner_slot = slot(0x5E);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::WriteStorage(owner_slot, slot(0x31)),
            PrecompileStep::Revert(Bytes::from_static(b"stop")),
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender.clone(),
            precompile,
            2,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::from_static(b"stop"));
    assert_eq!(run.account_change(sender.address), Some(account(10, 1)));
    assert_eq!(run.account_change(precompile), None);
    assert_eq!(run.storage_change(precompile, owner_slot), None);
}

#[test]
fn recursive_precompile_call_merges_nested_diff() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(16);
    let parent = address(0x63);
    let child = address(0x64);
    let child_slot = slot(0x73);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        child,
        vec![
            PrecompileStep::WriteStorage(child_slot, slot(0x33)),
            PrecompileStep::Return(Bytes::from_static(b"child")),
        ],
    );
    harness.insert_precompile(
        parent,
        vec![
            PrecompileStep::AssertCallReturns(
                child,
                3,
                Bytes::from_static(b"nested"),
                Bytes::from_static(b"child"),
            ),
            PrecompileStep::Return(Bytes::from_static(b"parent")),
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender.clone(),
            parent,
            5,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(
        &run,
        0,
        ReceiptStatus::Success,
        Bytes::from_static(b"parent"),
    );
    assert_eq!(run.account_change(sender.address), Some(account(5, 1)));
    assert_eq!(run.account_change(parent), Some(account(2, 0)));
    assert_eq!(run.account_change(child), Some(account(3, 0)));
    assert_eq!(run.storage_change(child, child_slot), Some(slot(0x33)));

    let access_list = run.proposed_access_list(0);
    assert!(access_list.contains(&Access::Account(parent, AccessMode::Write)));
    assert!(access_list.contains(&Access::Account(child, AccessMode::Write)));
    assert!(access_list.contains(&Access::Storage(child, child_slot, AccessMode::Write)));
}

#[test]
fn recursive_precompile_call_can_handle_child_revert() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(17);
    let parent = address(0x65);
    let child = address(0x66);
    let parent_slot = slot(0x74);
    let child_slot = slot(0x75);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        child,
        vec![
            PrecompileStep::WriteStorage(child_slot, slot(0x44)),
            PrecompileStep::Revert(Bytes::from_static(b"child-revert")),
        ],
    );
    harness.insert_precompile(
        parent,
        vec![
            PrecompileStep::AssertCallReverts(
                child,
                0,
                Bytes::new(),
                Bytes::from_static(b"child-revert"),
            ),
            PrecompileStep::WriteStorage(parent_slot, slot(0x45)),
            PrecompileStep::Return(Bytes::from_static(b"handled")),
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(sender, parent, 0, 0, Bytes::new())])
        .expect("processing should succeed");

    assert_receipt(
        &run,
        0,
        ReceiptStatus::Success,
        Bytes::from_static(b"handled"),
    );
    assert_eq!(run.storage_change(parent, parent_slot), Some(slot(0x45)));
    assert_eq!(run.storage_change(child, child_slot), None);
    assert_eq!(run.account_change(child), None);
}

#[test]
fn recursive_precompile_call_bubbles_child_revert() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(18);
    let parent = address(0x67);
    let child = address(0x68);
    let child_slot = slot(0x76);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        child,
        vec![
            PrecompileStep::WriteStorage(child_slot, slot(0x46)),
            PrecompileStep::Revert(Bytes::from_static(b"bubble")),
        ],
    );
    harness.insert_precompile(
        parent,
        vec![
            PrecompileStep::Call(child, 0, Bytes::new()),
            PrecompileStep::Return(Bytes::from_static(b"unreachable")),
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender.clone(),
            parent,
            0,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(
        &run,
        0,
        ReceiptStatus::Revert,
        Bytes::from_static(b"bubble"),
    );
    assert_eq!(run.account_change(sender.address), Some(account(10, 1)));
    assert_eq!(run.account_change(parent), None);
    assert_eq!(run.account_change(child), None);
    assert_eq!(run.storage_change(child, child_slot), None);
}

#[test]
fn recursive_precompile_call_halts_at_max_depth() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(19);
    let recursive = address(0x69);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        recursive,
        vec![PrecompileStep::Call(recursive, 0, Bytes::new())],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender.clone(),
            recursive,
            0,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
    assert_eq!(run.account_change(sender.address), Some(account(10, 1)));
    assert_eq!(run.account_change(recursive), None);
    assert!(
        run.proposed_access_list(0)
            .contains(&Access::Account(recursive, AccessMode::Read))
    );
}

#[rstest]
#[case("empty", 20, 0x60, Bytes::new())]
#[case("ascii", 21, 0x61, Bytes::from_static(b"revert"))]
#[case("binary", 22, 0x62, Bytes::from(vec![0, 1, 2, 3]))]
fn revert_payload_is_preserved(
    #[case] _suffix: &'static str,
    #[case] seed: u64,
    #[case] precompile_byte: u8,
    #[case] payload: Bytes,
) {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(seed);
    let precompile = address(precompile_byte);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(precompile, vec![PrecompileStep::Revert(payload.clone())]);

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender,
            precompile,
            0,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Revert, payload);
}

#[test]
fn restored_value_is_omitted_from_changeset() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(23);
    let precompile = address(0x3F);
    let owner_slot = slot(0x5F);

    harness.set_account(sender.address, account(10, 0));
    harness.set_storage(precompile, owner_slot, slot(0x40));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::WriteStorage(owner_slot, slot(0x41)),
            PrecompileStep::WriteStorage(owner_slot, slot(0x40)),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender.clone(),
            precompile,
            0,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
    assert_eq!(run.storage_change(precompile, owner_slot), None);
    assert_eq!(run.account_change(sender.address), Some(account(10, 1)));
}

#[test]
fn restored_account_balance_is_omitted_from_changeset() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(24);
    let first = address(0x40);
    let second = address(0x50);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        first,
        vec![
            PrecompileStep::Transfer(second, 5),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );
    harness.insert_precompile(
        second,
        vec![
            PrecompileStep::Transfer(sender.address, 5),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let run = harness
        .execute_specs(&[
            TransactionSpec::call(sender.clone(), first, 5, 0, Bytes::new()),
            TransactionSpec::call(sender.clone(), second, 0, 1, Bytes::new()),
        ])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::from_static(b"ok"));
    assert_receipt(&run, 1, ReceiptStatus::Success, Bytes::from_static(b"ok"));
    assert_eq!(run.account_change(sender.address), Some(account(10, 2)));
    assert_eq!(run.account_change(first), None);
    assert_eq!(run.account_change(second), None);
}

#[test]
fn later_transaction_sees_prior_transaction_state() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(25);
    let precompile = address(0x41);
    let owner_slot = slot(0x61);
    let reader = address(0x42);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::WriteStorage(owner_slot, slot(0x42)),
            PrecompileStep::Return(Bytes::from_static(b"written")),
        ],
    );
    harness.insert_precompile(
        reader,
        vec![
            PrecompileStep::AssertStorage(precompile, owner_slot, slot(0x42)),
            PrecompileStep::Return(Bytes::from_static(b"read")),
        ],
    );

    let run = harness
        .execute_specs(&[
            TransactionSpec::call(sender.clone(), precompile, 0, 0, Bytes::new()),
            TransactionSpec::call(sender, reader, 0, 1, Bytes::new()),
        ])
        .expect("processing should succeed");

    assert_receipt(
        &run,
        0,
        ReceiptStatus::Success,
        Bytes::from_static(b"written"),
    );
    assert_receipt(&run, 1, ReceiptStatus::Success, Bytes::from_static(b"read"));
    assert_eq!(run.storage_change(precompile, owner_slot), Some(slot(0x42)));
}

#[test]
fn reverted_transaction_does_not_affect_later_transactions() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(26);
    let writer = address(0x43);
    let reader = address(0x44);
    let owner_slot = slot(0x62);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        writer,
        vec![
            PrecompileStep::WriteStorage(owner_slot, slot(0x51)),
            PrecompileStep::Revert(Bytes::from_static(b"nope")),
        ],
    );
    harness.insert_precompile(
        reader,
        vec![
            PrecompileStep::AssertStorage(writer, owner_slot, Slot::default()),
            PrecompileStep::Return(Bytes::from_static(b"clear")),
        ],
    );

    let run = harness
        .execute_specs(&[
            TransactionSpec::call(sender.clone(), writer, 0, 0, Bytes::new()),
            TransactionSpec::call(sender.clone(), reader, 0, 1, Bytes::new()),
        ])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::from_static(b"nope"));
    assert_receipt(
        &run,
        1,
        ReceiptStatus::Success,
        Bytes::from_static(b"clear"),
    );
    assert_eq!(run.storage_change(writer, owner_slot), None);
    assert_eq!(run.account_change(sender.address), Some(account(10, 2)));
}

#[test]
fn nonce_advances_across_slice() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(27);
    let first = address(0x45);
    let second = address(0x46);

    harness.set_account(sender.address, account(10, 0));

    let run = harness
        .execute_specs(&[
            TransactionSpec::transfer(sender.clone(), first, 1, 0),
            TransactionSpec::transfer(sender.clone(), second, 2, 1),
        ])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Success, Bytes::new());
    assert_receipt(&run, 1, ReceiptStatus::Success, Bytes::new());
    assert_eq!(run.account_change(sender.address), Some(account(7, 2)));
    assert_eq!(run.account_change(first), Some(account(1, 0)));
    assert_eq!(run.account_change(second), Some(account(2, 0)));
}

#[test]
fn reverted_tx_still_consumes_nonce_for_next_tx() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(28);
    let precompile = address(0x47);
    let recipient = address(0x57);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        precompile,
        vec![PrecompileStep::Revert(Bytes::from_static(b"nope"))],
    );

    let run = harness
        .execute_specs(&[
            TransactionSpec::call(sender.clone(), precompile, 0, 0, Bytes::new()),
            TransactionSpec::transfer(sender.clone(), recipient, 1, 1),
        ])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::from_static(b"nope"));
    assert_receipt(&run, 1, ReceiptStatus::Success, Bytes::new());
    assert_eq!(run.account_change(sender.address), Some(account(9, 2)));
    assert_eq!(run.account_change(recipient), Some(account(1, 0)));
}

#[test]
fn validate_filters_duplicate_nonce_from_batch() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(29);

    harness.set_account(sender.address, account(10, 0));

    let result = harness.validate_specs(&[
        TransactionSpec::transfer(sender.clone(), address(0x58), 1, 0),
        TransactionSpec::transfer(sender.clone(), address(0x59), 1, 0),
        TransactionSpec::transfer(sender, address(0x5A), 1, 1),
    ]);

    assert_eq!(result.valid.len(), 2);
    assert_eq!(result.valid[0].value().nonce, 0);
    assert_eq!(result.valid[1].value().nonce, 1);
    assert_eq!(result.invalid.len(), 1);
    assert_eq!(result.invalid[0].value().nonce, 0);
}

#[test]
fn validate_drops_static_invalid_transactions() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(30);
    let recipient = address(0x93);

    harness.set_account(sender.address, account(10, 0));

    let result = harness.validate_specs(&[
        TransactionSpec::transfer(sender.clone(), recipient, 1, 1),
        TransactionSpec::transfer(sender, recipient, 1, 0),
    ]);

    assert_eq!(result.valid.len(), 1);
    assert_eq!(result.valid[0].value().nonce, 0);
    assert_eq!(result.invalid.len(), 1);
    assert_eq!(result.invalid[0].value().nonce, 1);
}

#[test]
fn validate_rejects_duplicate_nonce() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(31);
    let recipient = address(0x94);

    harness.set_account(sender.address, account(10, 0));

    let result = harness.validate_specs(&[
        TransactionSpec::transfer(sender.clone(), recipient, 1, 0),
        TransactionSpec::transfer(sender, recipient, 1, 0),
    ]);

    assert_eq!(result.valid.len(), 1);
    assert_eq!(result.invalid.len(), 1);
}

#[test]
fn validate_rejects_non_precompile_with_input() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(32);
    let recipient = address(0x95);

    harness.set_account(sender.address, account(10, 0));

    let result = harness.validate_specs(&[TransactionSpec::call(
        sender,
        recipient,
        0,
        0,
        Bytes::from_static(b"payload"),
    )]);

    assert!(result.valid.is_empty());
    assert_eq!(result.invalid.len(), 1);
}

#[test]
fn validate_rejects_insufficient_balance() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(33);
    let recipient = address(0x96);

    harness.set_account(sender.address, account(1, 0));

    let result = harness.validate_specs(&[TransactionSpec::transfer(sender, recipient, 2, 0)]);

    assert!(result.valid.is_empty());
    assert_eq!(result.invalid.len(), 1);
}

#[test]
fn validate_rejects_max_nonce_transaction() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(34);
    let recipient = address(0x91);

    harness.set_account(sender.address, account(10, u64::MAX));

    let result =
        harness.validate_specs(&[TransactionSpec::transfer(sender, recipient, 0, u64::MAX)]);

    assert!(result.valid.is_empty());
    assert_eq!(result.invalid.len(), 1);
}

#[test]
fn max_nonce_transaction_reverts_if_validation_is_bypassed() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(35);
    let recipient = address(0x97);
    let transaction = sender.sign(recipient, 0, u64::MAX, Bytes::new());

    harness.set_account(sender.address, account(10, u64::MAX));

    let output = harness.propose_unchecked(&[transaction]);

    assert_eq!(output.receipts.len(), 1);
    assert_eq!(output.receipts[0].status, ReceiptStatus::Revert);
    assert!(output.changeset.is_empty());
}

#[test]
fn precompile_panic_reverts_instead_of_panicking() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(36);
    let precompile = address(0x92);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(precompile, vec![PrecompileStep::Panic]);

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender,
            precompile,
            0,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
}

#[test]
fn precompile_panic_after_mutation_discards_diff_but_keeps_accesses() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(61);
    let precompile = address(0x93);
    let owner_slot = slot(0x12);

    harness.set_account(sender.address, account(10, 0));
    harness.set_storage(precompile, owner_slot, slot(0x01));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::WriteStorage(owner_slot, slot(0x02)),
            PrecompileStep::Panic,
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender.clone(),
            precompile,
            0,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
    assert_eq!(run.account_change(sender.address), Some(account(10, 1)));
    assert_eq!(run.account_change(precompile), None);
    assert_eq!(run.storage_change(precompile, owner_slot), None);
    assert!(run.proposed_access_list(0).contains(&Access::Storage(
        precompile,
        owner_slot,
        AccessMode::Write
    )));
}

#[test]
fn validate_rejects_transaction_when_precompile_lookup_panics() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(37);
    let panic_address = address(0x98);

    harness.set_account(sender.address, account(10, 0));
    harness.set_panic_on_lookup(panic_address);

    let result = harness.validate_specs(&[TransactionSpec::call(
        sender,
        panic_address,
        0,
        0,
        Bytes::from_static(b"payload"),
    )]);

    assert!(result.valid.is_empty());
    assert_eq!(result.invalid.len(), 1);
}

#[test]
fn propose_reverts_transaction_when_precompile_lookup_panics() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(38);
    let panic_address = address(0x99);
    let transaction = sender.sign(panic_address, 0, 0, Bytes::from_static(b"payload"));

    harness.set_account(sender.address, account(10, 0));
    harness.set_panic_on_lookup(panic_address);

    let output = harness.propose_unchecked(&[transaction]);

    assert_eq!(output.receipts.len(), 1);
    assert_eq!(output.receipts[0].status, ReceiptStatus::Revert);
    assert!(output.receipts[0].return_data.is_empty());
}

#[test]
fn verify_reverts_transaction_when_precompile_lookup_panics_if_validation_is_bypassed() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(39);
    let panic_address = address(0x9A);
    let transaction = sender.sign(panic_address, 0, 0, Bytes::from_static(b"payload"));

    harness.set_account(sender.address, account(10, 0));
    harness.set_panic_on_lookup(panic_address);

    let proposal = harness.propose_unchecked(std::slice::from_ref(&transaction));
    let output = harness
        .verify_with_strategy(&[transaction], &proposal.access_list, &Sequential)
        .expect("lookup panic should revert, not invalidate the block");

    assert_eq!(output.receipts.len(), 1);
    assert_eq!(output.receipts[0].status, ReceiptStatus::Revert);
    assert!(output.receipts[0].return_data.is_empty());
}

#[test]
fn nested_call_to_non_precompile_target_reverts() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(62);
    let parent = address(0x9B);
    let child = address(0x9C);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(parent, vec![PrecompileStep::Call(child, 0, Bytes::new())]);

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender.clone(),
            parent,
            0,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::new());
    assert_eq!(run.account_change(sender.address), Some(account(10, 1)));
    assert_eq!(run.account_change(parent), None);
    assert_eq!(run.account_change(child), None);
    assert!(
        !run.proposed_access_list(0)
            .contains(&Access::Account(child, AccessMode::Read))
    );
    assert!(
        !run.proposed_access_list(0)
            .contains(&Access::Account(child, AccessMode::Write))
    );
}

#[test]
fn successful_tx_returns_built_access_list() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(40);
    let precompile = address(0x49);
    let other = address(0x5A);
    let other_slot = slot(0x6A);
    let owner_slot = slot(0x6B);

    harness.set_account(sender.address, account(10, 0));
    harness.set_account(other, account(7, 0));
    harness.set_storage(other, other_slot, slot(0x22));
    harness.set_storage(precompile, owner_slot, slot(0x23));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::AssertAccountBalance(other, 7),
            PrecompileStep::AssertStorage(other, other_slot, slot(0x22)),
            PrecompileStep::AssertReadStorage(owner_slot, slot(0x23)),
            PrecompileStep::WriteStorage(owner_slot, slot(0x24)),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender.clone(),
            precompile,
            0,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    let access_list = run.proposed_access_list(0);
    assert_eq!(run.declared_access_list(0), access_list);
    assert_eq!(
        access_list,
        TransactionSpec::call(sender, precompile, 0, 0, Bytes::new())
            .expected_access_list(&harness.precompiles)
            .as_slice()
    );
    assert_eq!(access_list.len(), 5);
}

#[test]
fn reverted_tx_still_returns_observed_access_list() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(41);
    let precompile = address(0x4A);
    let storage_slot = slot(0x16);

    harness.set_account(sender.address, account(10, 0));
    harness.set_storage(precompile, storage_slot, slot(0x06));
    harness.insert_precompile(
        precompile,
        vec![PrecompileStep::Revert(Bytes::from_static(b"stop"))],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender.clone(),
            precompile,
            0,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    assert_receipt(&run, 0, ReceiptStatus::Revert, Bytes::from_static(b"stop"));
    assert!(
        run.proposed_access_list(0)
            .contains(&Access::Account(sender.address, AccessMode::Write))
    );
    assert!(
        run.proposed_access_list(0)
            .contains(&Access::Account(precompile, AccessMode::Read))
    );
}

#[rstest]
#[case(
    "builder-upgrades-read-write",
    42,
    0x4B,
    BuilderCase::UpgradesReadToWrite
)]
#[case(
    "builder-deduplicates",
    43,
    0x4C,
    BuilderCase::DeduplicatesRepeatedAccesses
)]
#[case(
    "builder-cross-account-reads",
    44,
    0x4D,
    BuilderCase::RecordsCrossAccountReads
)]
fn builder_access_patterns(
    #[case] _suffix: &'static str,
    #[case] seed: u64,
    #[case] precompile_byte: u8,
    #[case] case: BuilderCase,
) {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(seed);
    let precompile = address(precompile_byte);
    let other = address(0x5C);
    let other_slot = slot(0x6D);
    let owner_slot = slot(0x6E);

    harness.set_account(sender.address, account(10, 0));

    let (program, expected_accesses, expected_len) = match case {
        BuilderCase::UpgradesReadToWrite => (
            vec![
                PrecompileStep::ReadStorage(owner_slot),
                PrecompileStep::WriteStorage(owner_slot, slot(0x30)),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
            declared_accesses(
                sender.address,
                precompile,
                0,
                [Access::Storage(precompile, owner_slot, AccessMode::Write)],
            ),
            3,
        ),
        BuilderCase::DeduplicatesRepeatedAccesses => (
            vec![
                PrecompileStep::InspectAccount(other),
                PrecompileStep::InspectAccount(other),
                PrecompileStep::InspectStorage(other, other_slot),
                PrecompileStep::InspectStorage(other, other_slot),
                PrecompileStep::ReadStorage(owner_slot),
                PrecompileStep::ReadStorage(owner_slot),
                PrecompileStep::WriteStorage(owner_slot, slot(0x31)),
                PrecompileStep::WriteStorage(owner_slot, slot(0x31)),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
            declared_accesses(
                sender.address,
                precompile,
                0,
                [
                    Access::Account(other, AccessMode::Read),
                    Access::Storage(other, other_slot, AccessMode::Read),
                    Access::Storage(precompile, owner_slot, AccessMode::Write),
                ],
            ),
            5,
        ),
        BuilderCase::RecordsCrossAccountReads => (
            vec![
                PrecompileStep::InspectAccount(other),
                PrecompileStep::InspectStorage(other, other_slot),
                PrecompileStep::Return(Bytes::from_static(b"ok")),
            ],
            declared_accesses(
                sender.address,
                precompile,
                0,
                [
                    Access::Account(other, AccessMode::Read),
                    Access::Storage(other, other_slot, AccessMode::Read),
                ],
            ),
            4,
        ),
    };

    harness.insert_precompile(precompile, program);

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender,
            precompile,
            0,
            0,
            Bytes::new(),
        )])
        .expect("processing should succeed");

    let access_list = run.proposed_access_list(0);
    assert_eq!(access_list.len(), expected_len);
    assert_eq!(access_list, expected_accesses.as_slice());

    if matches!(case, BuilderCase::UpgradesReadToWrite) {
        assert!(!access_list.contains(&Access::Storage(precompile, owner_slot, AccessMode::Read,)));
    }
}

#[test]
fn verify_rejects_missing_declared_access() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(45);
    let precompile = address(0x46);
    let storage_slot = slot(0x13);

    harness.set_account(sender.address, account(1, 0));
    harness.set_storage(precompile, storage_slot, slot(0x03));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::ReadStorage(storage_slot),
            PrecompileStep::WriteStorage(storage_slot, slot(0xbb)),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let proposal = harness.propose_specs(&[TransactionSpec::call(
        sender,
        precompile,
        0,
        0,
        Bytes::new(),
    )]);
    let mut access_list = proposal.output.access_list.clone();
    access_list
        .tx_accesses
        .retain(|access| !matches!(access, Access::Storage(_, _, _)));
    access_list.tx_offsets = vec![0, 2];

    let result = harness.verify_with_strategy(&proposal.valid, &access_list, &Sequential);
    assert_access_mismatch(result, 0);
}

#[test]
fn verify_rejects_unused_declared_access() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(46);
    let precompile = address(0x47);
    let storage_slot = slot(0x14);
    let extra_account = address(0x99);

    harness.set_account(sender.address, account(1, 0));
    harness.set_storage(precompile, storage_slot, slot(0x04));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::ReadStorage(storage_slot),
            PrecompileStep::WriteStorage(storage_slot, slot(0xcc)),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let proposal = harness.propose_specs(&[TransactionSpec::call(
        sender,
        precompile,
        0,
        0,
        Bytes::new(),
    )]);
    let mut access_list = proposal.output.access_list.clone();
    access_list
        .tx_accesses
        .push(Access::Account(extra_account, AccessMode::Read));
    access_list.tx_offsets = vec![0, 4];

    let result = harness.verify_with_strategy(&proposal.valid, &access_list, &Sequential);
    assert_access_mismatch(result, 0);
}

#[test]
fn verify_rejects_redundant_declared_access() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(47);
    let precompile = address(0x4A);
    let storage_slot = slot(0x17);

    harness.set_account(sender.address, account(1, 0));
    harness.set_storage(precompile, storage_slot, slot(0x07));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::ReadStorage(storage_slot),
            PrecompileStep::WriteStorage(storage_slot, slot(0xde)),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let proposal = harness.propose_specs(&[TransactionSpec::call(
        sender.clone(),
        precompile,
        0,
        0,
        Bytes::new(),
    )]);
    let mut access_list = proposal.output.access_list.clone();
    access_list
        .tx_accesses
        .push(Access::Account(sender.address, AccessMode::Write));
    access_list.tx_offsets = vec![0, 4];

    let result = harness.verify_with_strategy(&proposal.valid, &access_list, &Sequential);
    assert_access_mismatch(result, 0);
}

#[test]
fn verify_stops_after_first_access_mismatch() {
    let mut harness = ProcessorHarness::default();
    let sender_a = harness.signer(48);
    let sender_b = harness.signer(49);
    let invalid_precompile = address(0x4B);
    let counting_precompile = address(0x4C);
    let storage_slot = slot(0x18);
    let counter = Arc::new(AtomicUsize::new(0));

    harness.set_account(sender_a.address, account(1, 0));
    harness.set_account(sender_b.address, account(1, 0));
    harness.set_storage(invalid_precompile, storage_slot, slot(0x08));
    harness.insert_precompile(
        invalid_precompile,
        vec![
            PrecompileStep::ReadStorage(storage_slot),
            PrecompileStep::WriteStorage(storage_slot, slot(0xef)),
            PrecompileStep::Return(Bytes::from_static(b"bad")),
        ],
    );
    harness.insert_precompile(
        counting_precompile,
        vec![
            PrecompileStep::Count(counter.clone()),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let proposal = harness.propose_specs(&[
        TransactionSpec::call(sender_a, invalid_precompile, 0, 0, Bytes::new()),
        TransactionSpec::call(sender_b, counting_precompile, 0, 0, Bytes::new()),
    ]);
    let first_transaction_accesses = proposal
        .output
        .access_list
        .accesses_for_transaction(0)
        .iter()
        .copied()
        .filter(|access| !matches!(access, Access::Storage(_, _, _)))
        .collect::<Vec<_>>();
    let second_transaction_accesses = proposal
        .output
        .access_list
        .accesses_for_transaction(1)
        .to_vec();
    let first_transaction_end =
        u32::try_from(first_transaction_accesses.len()).expect("test BAL must fit in u32");
    let block_end =
        u32::try_from(first_transaction_accesses.len() + second_transaction_accesses.len())
            .expect("test BAL must fit in u32");

    let mut access_list = proposal.output.access_list.clone();
    access_list.tx_accesses = first_transaction_accesses;
    access_list.tx_accesses.extend(second_transaction_accesses);
    access_list.tx_offsets = vec![0, first_transaction_end, block_end];

    counter.store(0, Ordering::SeqCst);
    let result = harness.verify_with_strategy(&proposal.valid, &access_list, &Sequential);
    assert_access_mismatch(result, 0);
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[test]
fn verify_rejects_wrong_final_state() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(50);
    let precompile = address(0x48);
    let storage_slot = slot(0x15);

    harness.set_account(sender.address, account(1, 0));
    harness.set_storage(precompile, storage_slot, slot(0x05));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::ReadStorage(storage_slot),
            PrecompileStep::WriteStorage(storage_slot, slot(0xdd)),
            PrecompileStep::Return(Bytes::from_static(b"ok")),
        ],
    );

    let proposal = harness.propose_specs(&[TransactionSpec::call(
        sender,
        precompile,
        0,
        0,
        Bytes::new(),
    )]);
    let mut access_list = proposal.output.access_list.clone();
    access_list.storage_writes[0].value = slot(0xee);

    let result = harness.verify_with_strategy(&proposal.valid, &access_list, &Sequential);
    assert_eq!(
        result.expect_err("wrong final writes must be rejected"),
        VerificationError::FinalStateMismatch,
    );
}

#[test]
fn reverted_transaction_still_requires_exact_declared_accesses() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(51);
    let precompile = address(0x49);
    let storage_slot = slot(0x16);

    harness.set_account(sender.address, account(1, 0));
    harness.set_storage(precompile, storage_slot, slot(0x06));
    harness.insert_precompile(
        precompile,
        vec![
            PrecompileStep::ReadStorage(storage_slot),
            PrecompileStep::Revert(Bytes::from_static(b"nope")),
        ],
    );

    let run = harness
        .execute_specs(&[TransactionSpec::call(
            sender,
            precompile,
            0,
            0,
            Bytes::new(),
        )])
        .expect("reverted tx should still verify with matching BAL");

    assert_eq!(run.output.receipts.len(), 1);
    assert_eq!(run.output.receipts[0].status, ReceiptStatus::Revert);
    assert!(run.proposed_access_list(0).contains(&Access::Storage(
        precompile,
        storage_slot,
        AccessMode::Read
    )));
}

#[test]
fn parallel_execution_matches_sequential_output() {
    let mut sequential_harness = ProcessorHarness::default();
    let mut parallel_harness = ProcessorHarness::default();
    let sender_a = sequential_harness.signer(52);
    let sender_b = sequential_harness.signer(53);
    let sender_c = sequential_harness.signer(54);
    let precompile_x = address(0x60);
    let precompile_y = address(0x61);
    let slot_x = slot(0x71);
    let slot_y = slot(0x72);

    for harness in [&mut sequential_harness, &mut parallel_harness] {
        harness.set_account(sender_a.address, account(10, 0));
        harness.set_account(sender_b.address, account(10, 0));
        harness.set_account(sender_c.address, account(10, 0));
        harness.insert_precompile(
            precompile_x,
            vec![
                PrecompileStep::ReadStorage(slot_x),
                PrecompileStep::WriteStorage(slot_x, slot(0x81)),
                PrecompileStep::Return(Bytes::from_static(b"x")),
            ],
        );
        harness.insert_precompile(
            precompile_y,
            vec![
                PrecompileStep::ReadStorage(slot_y),
                PrecompileStep::WriteStorage(slot_y, slot(0x82)),
                PrecompileStep::Return(Bytes::from_static(b"y")),
            ],
        );
    }

    let specs = vec![
        TransactionSpec::call(sender_a, precompile_x, 0, 0, Bytes::new()),
        TransactionSpec::call(sender_b, precompile_x, 0, 0, Bytes::new()),
        TransactionSpec::call(sender_c, precompile_y, 0, 0, Bytes::new()),
    ];

    let sequential = sequential_harness
        .execute_specs(&specs)
        .expect("sequential processing should succeed");
    let strategy = parallel_strategy();
    let parallel = parallel_harness
        .execute_specs_with_strategy(&specs, &strategy)
        .expect("parallel processing should succeed");

    assert_eq!(parallel.output, sequential.output);
    assert_eq!(
        parallel.declared_access_list,
        sequential.declared_access_list
    );
}

#[test]
fn parallel_execution_reports_receipts_in_transaction_order() {
    let mut harness = ProcessorHarness::default();
    let sender_a = harness.signer(55);
    let sender_b = harness.signer(56);
    let sender_c = harness.signer(57);
    let precompile_x = address(0x62);
    let precompile_y = address(0x63);
    let slot_x = slot(0x73);
    let slot_y = slot(0x74);

    harness.set_account(sender_a.address, account(10, 0));
    harness.set_account(sender_b.address, account(10, 0));
    harness.set_account(sender_c.address, account(10, 0));
    harness.insert_precompile(
        precompile_x,
        vec![
            PrecompileStep::WriteStorage(slot_x, slot(0x91)),
            PrecompileStep::Return(Bytes::from_static(b"first")),
        ],
    );
    harness.insert_precompile(
        precompile_y,
        vec![
            PrecompileStep::WriteStorage(slot_y, slot(0x92)),
            PrecompileStep::Return(Bytes::from_static(b"second")),
        ],
    );

    let strategy = parallel_strategy();
    let run = harness
        .execute_specs_with_strategy(
            &[
                TransactionSpec::call(sender_a, precompile_x, 0, 0, Bytes::new()),
                TransactionSpec::call(sender_b, precompile_x, 0, 0, Bytes::new()),
                TransactionSpec::call(sender_c, precompile_y, 0, 0, Bytes::new()),
            ],
            &strategy,
        )
        .expect("parallel processing should succeed");

    for (index, transaction) in run.transactions.iter().enumerate() {
        assert_eq!(
            run.output.receipts[index].transaction_hash,
            *transaction.message_digest(),
        );
    }

    assert_eq!(
        run.output.receipts[0].return_data,
        Bytes::from_static(b"first")
    );
    assert_eq!(
        run.output.receipts[1].return_data,
        Bytes::from_static(b"first")
    );
    assert_eq!(
        run.output.receipts[2].return_data,
        Bytes::from_static(b"second")
    );
}

#[test]
fn nested_call_to_undeclared_account_rejects_declared_bal() {
    let mut harness = ProcessorHarness::default();
    let sender = harness.signer(58);
    let parent = address(0xA0);
    let child = address(0xA1);
    let child_slot = slot(0xB0);

    harness.set_account(sender.address, account(10, 0));
    harness.insert_precompile(
        child,
        vec![
            PrecompileStep::WriteStorage(child_slot, slot(0x01)),
            PrecompileStep::Return(Bytes::new()),
        ],
    );
    harness.insert_precompile(parent, vec![PrecompileStep::Call(child, 0, Bytes::new())]);

    let result =
        harness.execute_specs(&[
            TransactionSpec::call(sender.clone(), parent, 0, 0, Bytes::new()).with_access_list(
                declared_accesses(
                    sender.address,
                    parent,
                    0,
                    [Access::Storage(child, child_slot, AccessMode::Write)],
                ),
            ),
        ]);

    assert_access_mismatch(result, 0);
}

#[test]
fn property_random_batches_round_trip_through_verification() {
    let strategy = parallel_strategy();

    for seed in 0..16 {
        let batch = random_round_trip_batch(seed);

        let sequential = batch
            .harness
            .execute_specs(&batch.specs)
            .expect("random batch should verify sequentially");
        let parallel = batch
            .harness
            .execute_specs_with_strategy(&batch.specs, &strategy)
            .expect("random batch should verify in parallel");

        assert_eq!(parallel.output, sequential.output, "seed {seed} diverged");
        assert_eq!(
            parallel.declared_access_list, sequential.declared_access_list,
            "seed {seed} produced different BALs",
        );

        for (index, spec) in batch.specs.iter().enumerate() {
            let expected = spec.expected_access_list(&batch.harness.precompiles);
            assert_eq!(
                sequential.proposed_access_list(index),
                expected.as_slice(),
                "seed {seed} produced a non-canonical access list for tx {index}",
            );
        }
    }
}

#[test]
fn property_random_user_transactions_never_panic_processor() {
    for seed in 0..32 {
        let (harness, transactions) = random_user_transactions(seed);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let processor = Processor::new(&Sequential, &harness.precompiles);
            let state = harness.state();
            let _ = processor.validate(&state, transactions.clone());
            let mut discovery_state = DiscoveryState::new(state.clone());
            let _ = processor.propose(&mut discovery_state, &transactions);
            let access_list = empty_block_access_list(transactions.len());
            let _ = processor.verify(state, &transactions, &access_list);
        }));

        assert!(result.is_ok(), "seed {seed} panicked");
    }
}
