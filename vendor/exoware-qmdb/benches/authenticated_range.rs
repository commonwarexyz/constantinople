use std::{num::NonZeroUsize, time::Duration};

use commonware_codec::{Encode, RangeCfg};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_storage::{
    merkle::{mem::Mem, mmr, Family as _, Location, Proof},
    qmdb::keyless::variable::Operation,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use exoware_qmdb::{prepare_authenticated_range, AuthenticatedOperationRange};

type Family = mmr::Family;
type BatchOperation = Operation<Family, Vec<u8>>;

const PREFIX_OPERATIONS: usize = 1_024;
const VALUE_SIZE: usize = 64;

struct AuthenticatedRangeFixture {
    root: Digest,
    proof: Proof<Family, Digest>,
    pinned_nodes: Vec<Digest>,
    encoded_operations: Vec<Vec<u8>>,
}

impl AuthenticatedRangeFixture {
    fn view(&self) -> AuthenticatedOperationRange<'_, Digest, Family> {
        AuthenticatedOperationRange {
            start_location: Location::new(PREFIX_OPERATIONS as u64),
            proof: &self.proof,
            pinned_nodes: &self.pinned_nodes,
            encoded_operations: &self.encoded_operations,
        }
    }
}

fn operations(count: usize, floor: Location<Family>) -> Vec<BatchOperation> {
    assert!(count > 0);
    let mut operations = Vec::with_capacity(count);
    for index in 0..count - 1 {
        let mut value = vec![0; VALUE_SIZE];
        value[..8].copy_from_slice(&(index as u64).to_be_bytes());
        operations.push(BatchOperation::Append(value));
    }
    operations.push(BatchOperation::Commit(None, floor));
    operations
}

fn authenticated_range_fixture(count: usize) -> AuthenticatedRangeFixture {
    let start = Location::new(PREFIX_OPERATIONS as u64);
    let end = start + count as u64;
    let suffix = operations(count, start)
        .iter()
        .map(|operation| operation.encode().to_vec())
        .collect::<Vec<_>>();
    let mut prefix = vec![BatchOperation::Commit(None, Location::new(0))];
    prefix.extend(operations(PREFIX_OPERATIONS - 1, Location::new(0)));
    let prefix = prefix
        .iter()
        .map(|operation| operation.encode().to_vec())
        .collect::<Vec<_>>();

    // Build the originating history and proof independently of the adapter outside the timed loop
    let hasher = commonware_storage::qmdb::hasher::<Sha256>();
    let mut memory = Mem::<Family, Digest>::new();
    let mut batch = memory.new_batch();
    for operation in prefix.iter().chain(&suffix) {
        batch = batch.add(&hasher, operation);
    }
    let batch = batch.merkleize(&memory, &hasher);
    memory.apply_batch(&batch).expect("apply source operations");
    let inactive_peaks = Family::inactive_peaks(end, start);
    AuthenticatedRangeFixture {
        root: memory.root(&hasher, inactive_peaks).expect("source root"),
        proof: memory
            .range_proof(&hasher, start..end, inactive_peaks)
            .expect("source continuation proof"),
        pinned_nodes: Family::nodes_to_pin(start)
            .map(|position| memory.get_node(position).expect("source pinned node"))
            .collect(),
        encoded_operations: suffix,
    }
}

fn bench_strategy<S: Strategy>(
    bencher: &mut criterion::Bencher<'_>,
    source: &AuthenticatedRangeFixture,
    strategy: &S,
) {
    let authenticated = source.view();
    let operation_cfg = (RangeCfg::from(..=VALUE_SIZE), ());
    bencher.iter(|| {
        prepare_authenticated_range::<Family, Sha256, BatchOperation, S>(
            &authenticated,
            &source.root,
            &operation_cfg,
            strategy,
        )
        .expect("prepare authenticated continuation")
    });
}

fn authenticated_range(criterion: &mut Criterion) {
    let available = std::thread::available_parallelism()
        .map(NonZeroUsize::get)
        .unwrap_or(1);
    let mut worker_counts = vec![1, 2, 4, 8, available];
    worker_counts.retain(|workers| *workers <= available);
    worker_counts.sort_unstable();
    worker_counts.dedup();

    let mut group = criterion.benchmark_group(format!("{}::prepare", module_path!()));
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(20));

    for count in [100_000usize, 196_000, 256_000] {
        let source = authenticated_range_fixture(count);
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!(
                "variant=keyless_variable_variable_values family=mmr strategy=sequential operations={count} value_size={VALUE_SIZE}"
            )),
            &source,
            |bencher, source| bench_strategy(bencher, source, &Sequential),
        );
        for workers in &worker_counts {
            let strategy = Rayon::new(NonZeroUsize::new(*workers).expect("nonzero workers"))
                .expect("construct adaptive Rayon strategy");
            group.bench_with_input(
                BenchmarkId::from_parameter(format!(
                    "variant=keyless_variable_variable_values family=mmr strategy=rayon workers={workers} operations={count} value_size={VALUE_SIZE}"
                )),
                &source,
                |bencher, source| bench_strategy(bencher, source, &strategy),
            );
        }
    }
    group.finish();
}

criterion_group!(benches, authenticated_range);
criterion_main!(benches);
