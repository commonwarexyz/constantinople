//! HTTP state-reader adapters backed by validator state and runtime metadata.

use commonware_codec::Encode;
use commonware_consensus::types::Epoch;
use commonware_cryptography::Hasher;
use commonware_formatting::hex;
use commonware_p2p::{Address, Ingress};
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use commonware_utils::{
    ordered::{Map, Set},
    sequence::U64,
};
use constantinople_application::consensus::committee_for_epoch;
use constantinople_engine::types::{CommitteeSyncDb, StateSyncDb};
use constantinople_mempool::webserver::{
    AccountReader, CommitteeReader, CommitteeSnapshot, EPOCH_LENGTH, EligiblePeer,
};
use constantinople_primitives::{Account, AccountKey, TransactionPublicKey};
use futures::future::{BoxFuture, FutureExt};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// Read-only callback returning the P2P router's current connected peers.
pub type ConnectedPeersReader =
    Arc<dyn Fn() -> Vec<commonware_cryptography::ed25519::PublicKey> + Send + Sync>;

/// Shared latest-finalized-height cursor for the HTTP state reader.
#[derive(Clone, Default)]
pub struct FinalizedHeight(Arc<AtomicU64>);

impl FinalizedHeight {
    /// Records a newly finalized height without allowing the cursor to move backwards.
    pub fn observe(&self, height: u64) {
        self.0.fetch_max(height, Ordering::Release);
    }

    fn get(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

type CommitteePublicKey = commonware_cryptography::ed25519::PublicKey;

#[derive(Clone)]
struct ConfiguredPeer {
    public_key: CommitteePublicKey,
    peer: String,
    address: String,
}

/// Forwards [`AccountReader::get`] to the attached state database.
pub struct StateDbReader<E, H, T>
where
    E: BufferPooler + Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
    T: Strategy,
{
    db: StateSyncDb<E, H, T>,
    committee: CommitteeSyncDb<E, H, T>,
    finalized_height: FinalizedHeight,
    eligible: Vec<ConfiguredPeer>,
    genesis_current: Set<CommitteePublicKey>,
    genesis_scheduled: Set<CommitteePublicKey>,
    connected_peers: ConnectedPeersReader,
}

impl<E, H, T> StateDbReader<E, H, T>
where
    E: BufferPooler + Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
    T: Strategy,
{
    pub fn new(
        db: StateSyncDb<E, H, T>,
        committee: CommitteeSyncDb<E, H, T>,
        finalized_height: FinalizedHeight,
        eligible: Map<CommitteePublicKey, Address>,
        genesis_current: Set<CommitteePublicKey>,
        genesis_scheduled: Set<CommitteePublicKey>,
        connected_peers: ConnectedPeersReader,
    ) -> Self {
        let eligible = eligible
            .iter_pairs()
            .map(|(public_key, address)| ConfiguredPeer {
                public_key: public_key.clone(),
                peer: hex(&public_key.encode()),
                address: format_address(address),
            })
            .collect();
        Self {
            db,
            committee,
            finalized_height,
            eligible,
            genesis_current,
            genesis_scheduled,
            connected_peers,
        }
    }
}

impl<E, H, T> AccountReader for StateDbReader<E, H, T>
where
    E: BufferPooler + Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
    T: Strategy,
{
    fn get<'a>(&'a self, public_key: TransactionPublicKey) -> BoxFuture<'a, Option<Account>> {
        async move {
            let db = self.db.read().await;
            db.get(&AccountKey::from_public_key(&public_key))
                .await
                .ok()
                .flatten()
        }
        .boxed()
    }
}

impl<E, H, T> CommitteeReader for StateDbReader<E, H, T>
where
    E: BufferPooler + Storage + Clock + Metrics + Send + Sync + 'static,
    H: Hasher,
    T: Strategy,
{
    fn get<'a>(&'a self) -> BoxFuture<'a, CommitteeSnapshot> {
        async move {
            let height = self.finalized_height.get();
            let epoch = Epoch::new(height / EPOCH_LENGTH);
            let target_epoch = Epoch::new(
                epoch
                    .get()
                    .checked_add(2)
                    .expect("committee target epoch must not overflow"),
            );
            let committee = self.committee.read().await;
            let row_zero = committee
                .get(&U64::new(0))
                .await
                .expect("epoch-zero committee state read must succeed");
            let row_one = committee
                .get(&U64::new(1))
                .await
                .expect("epoch-one committee state read must succeed");
            drop(committee);
            let initialized = row_zero.is_some() && row_one.is_some();
            let (current, scheduled) = if initialized {
                let (current, scheduled) = futures::join!(
                    committee_for_epoch(&self.committee, epoch),
                    committee_for_epoch(&self.committee, target_epoch),
                );
                (current.into_members(), scheduled.into_members())
            } else {
                (self.genesis_current.clone(), self.genesis_scheduled.clone())
            };
            let current = format_committee(current);
            let scheduled = format_committee(scheduled);
            committee_snapshot(
                height,
                &current,
                &scheduled,
                &self.eligible,
                (self.connected_peers)(),
            )
        }
        .boxed()
    }
}

fn committee_snapshot(
    height: u64,
    current: &[String],
    scheduled: &[String],
    eligible: &[ConfiguredPeer],
    connected_peers: Vec<CommitteePublicKey>,
) -> CommitteeSnapshot {
    let connected = Set::from_iter_dedup(connected_peers);
    CommitteeSnapshot {
        height,
        current: current.to_vec(),
        scheduled: scheduled.to_vec(),
        available: eligible
            .iter()
            .map(|peer| EligiblePeer {
                peer: peer.peer.clone(),
                address: peer.address.clone(),
                connected: connected.position(&peer.public_key).is_some(),
            })
            .collect(),
    }
}

fn format_committee(members: Set<CommitteePublicKey>) -> Vec<String> {
    members
        .iter()
        .map(|public_key| hex(&public_key.encode()))
        .collect()
}

fn format_address(address: &Address) -> String {
    match address.ingress() {
        Ingress::Socket(address) => address.to_string(),
        Ingress::Dns { host, port } => format!("{host}:{port}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfiguredPeer, FinalizedHeight, committee_snapshot, format_address};
    use commonware_codec::Encode;
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_formatting::hex;
    use commonware_p2p::Address;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn committee_snapshot_retains_disconnected_eligible_peers() {
        let first = ed25519::PrivateKey::from_seed(1).public_key();
        let second = ed25519::PrivateKey::from_seed(2).public_key();
        let first_hex = hex(&first.encode());
        let second_hex = hex(&second.encode());
        let current = vec![first_hex.clone()];
        let scheduled = vec![first_hex.clone(), second_hex.clone()];
        let eligible = vec![
            ConfiguredPeer {
                public_key: first.clone(),
                peer: first_hex.clone(),
                address: "127.0.0.1:9000".into(),
            },
            ConfiguredPeer {
                public_key: second,
                peer: second_hex.clone(),
                address: "127.0.0.1:9001".into(),
            },
        ];

        let snapshot = committee_snapshot(17_890, &current, &scheduled, &eligible, vec![first]);

        assert_eq!(snapshot.height, 17_890);
        assert_eq!(snapshot.current, vec![first_hex.clone()]);
        assert_eq!(snapshot.scheduled, vec![first_hex, second_hex.clone()]);
        assert_eq!(snapshot.available.len(), 2);
        assert!(snapshot.available[0].connected);
        assert!(!snapshot.available[1].connected);
        assert_eq!(snapshot.available[1].peer, second_hex);
    }

    #[test]
    fn finalized_height_is_monotonic() {
        let height = FinalizedHeight::default();
        height.observe(12);
        height.observe(9);

        assert_eq!(height.get(), 12);
    }

    #[test]
    fn socket_address_uses_the_dialable_ingress_form() {
        let address = Address::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000));

        assert_eq!(format_address(&address), "127.0.0.1:9000");
    }
}
