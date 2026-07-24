//! Naive local-filesystem storage for private DKG material.
//!
//! [`FileSecretStore`] stores codec-encoded shares, dealer seeds, and private
//! dealings directly on disk. The bytes are **not encrypted**: Unix file and
//! directory permissions are the only confidentiality measure. This is a
//! convenient validator-local implementation, not a production-grade secret
//! manager. Operators needing protection from a compromised host, encrypted
//! backups, key rotation, or hardware isolation should provide a different
//! [`SecretStore`] implementation.
//!
//! Each put writes a temporary file in the destination directory, flushes the
//! file, atomically renames it over the destination, and flushes the directory
//! before returning. Files are created with mode `0600` and store-owned
//! directories with mode `0700` on Unix.

use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    PublicKey,
    bls12381::{dkg::feldman_desmedt::DealerPrivMsg, primitives::group::Share},
    transcript::Summary,
};
use commonware_glue::dkg::SecretStore;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind, Write as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const SHARES: &str = "shares";
const SEEDS: &str = "seeds";
const DEALINGS: &str = "dealings";
const INITIAL_SHARE_MARKER: &str = "initial-share-seeded";
const HEX: &[u8; 16] = b"0123456789abcdef";
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// A naive, plaintext, validator-local implementation of DKG [`SecretStore`].
///
/// `root` is owned by this store and contains one codec-encoded file per
/// secret. Clones may safely replace distinct records, though independently
/// opened stores are not coordinated across processes.
///
/// This type deliberately does not encrypt secret material and is **not
/// production-grade secret storage**. Its `0600`/`0700` Unix permissions only
/// protect against other unprivileged local users.
#[derive(Clone, Debug)]
pub struct FileSecretStore {
    root: PathBuf,
}

impl FileSecretStore {
    /// Opens the store rooted at `root`, creating its private directory layout
    /// if it does not exist.
    pub fn load(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        if root.file_name().is_none() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "secret store root must name a dedicated directory",
            ));
        }
        ensure_private_dir(&root)?;
        ensure_private_dir(&root.join(SHARES))?;
        ensure_private_dir(&root.join(SEEDS))?;
        ensure_private_dir(&root.join(DEALINGS))?;

        sync_directory(&root)?;
        sync_directory(parent_or_current(&root))?;

        Ok(Self { root })
    }

    /// Durably seeds the store with a trusted-setup share for `epoch` once.
    ///
    /// A durable marker prevents a later restart from resurrecting the
    /// trusted-setup share after normal DKG pruning has removed it.
    pub fn put_initial_share(&self, epoch: Epoch, share: Share) -> io::Result<()> {
        let marker = self.root.join(INITIAL_SHARE_MARKER);
        if let Some(seed_epoch) = read_optional(&marker)? {
            let seed_epoch = Epoch::decode(seed_epoch.as_slice()).map_err(|error| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid initial-share marker: {error}"),
                )
            })?;
            if seed_epoch != epoch {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "secret store was seeded for a different initial epoch",
                ));
            }
            return Ok(());
        }

        atomic_write(&self.share_path(epoch), &share.encode())?;
        atomic_write(&marker, &epoch.encode())
    }

    fn share_path(&self, epoch: Epoch) -> PathBuf {
        self.root.join(SHARES).join(epoch.get().to_string())
    }

    fn seed_path(&self, epoch: Epoch) -> PathBuf {
        self.root.join(SEEDS).join(epoch.get().to_string())
    }

    fn dealing_epoch_path(&self, epoch: Epoch) -> PathBuf {
        self.root.join(DEALINGS).join(epoch.get().to_string())
    }

    fn dealing_path<P: PublicKey>(&self, epoch: Epoch, dealer: &P) -> PathBuf {
        self.dealing_epoch_path(epoch)
            .join(hex_encode(&dealer.encode()))
    }
}

impl SecretStore for FileSecretStore {
    async fn put_share(&mut self, epoch: Epoch, share: Share) {
        atomic_write(&self.share_path(epoch), &share.encode())
            .expect("failed to durably store DKG share");
    }

    async fn get_share(&mut self, epoch: Epoch) -> Option<Share> {
        let bytes = read_optional(&self.share_path(epoch)).expect("failed to read DKG share")?;
        Some(Share::decode(bytes.as_slice()).unwrap_or_else(|error| {
            panic!(
                "corrupt persisted DKG share for epoch {}: {error}",
                epoch.get()
            )
        }))
    }

    async fn put_seed(&mut self, epoch: Epoch, seed: Summary) {
        atomic_write(&self.seed_path(epoch), &seed.encode())
            .expect("failed to durably store DKG dealer seed");
    }

    async fn get_seed(&mut self, epoch: Epoch) -> Option<Summary> {
        let bytes =
            read_optional(&self.seed_path(epoch)).expect("failed to read DKG dealer seed")?;
        Some(Summary::decode(bytes.as_slice()).unwrap_or_else(|error| {
            panic!(
                "corrupt persisted DKG dealer seed for epoch {}: {error}",
                epoch.get()
            )
        }))
    }

    async fn put_dealing<P: PublicKey>(&mut self, epoch: Epoch, dealer: P, private: DealerPrivMsg) {
        let epoch_path = self.dealing_epoch_path(epoch);
        ensure_private_dir(&epoch_path).expect("failed to create DKG dealing directory");
        sync_directory(self.root.join(DEALINGS).as_path())
            .expect("failed to flush DKG dealing directory");
        atomic_write(&self.dealing_path(epoch, &dealer), &private.encode())
            .expect("failed to durably store private DKG dealing");
    }

    async fn get_dealing<P: PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: &P,
    ) -> Option<DealerPrivMsg> {
        let bytes = read_optional(&self.dealing_path(epoch, dealer))
            .expect("failed to read private DKG dealing")?;
        Some(
            DealerPrivMsg::decode(bytes.as_slice()).unwrap_or_else(|error| {
                panic!(
                    "corrupt persisted private DKG dealing for epoch {}: {error}",
                    epoch.get()
                )
            }),
        )
    }

    async fn prune(&mut self, min: Epoch) {
        prune_epoch_files(&self.root.join(SHARES), min).expect("failed to prune old DKG shares");
        prune_epoch_files(&self.root.join(SEEDS), min)
            .expect("failed to prune old DKG dealer seeds");
        prune_epoch_directories(&self.root.join(DEALINGS), min)
            .expect("failed to prune old private DKG dealings");
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn read_optional(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = parent_or_current(path);
    ensure_private_dir(parent)?;

    let (temporary, mut file) = create_temporary(path)?;
    let result = (|| {
        set_private_file_permissions(&file)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn create_temporary(path: &Path) -> io::Result<(PathBuf, File)> {
    let parent = parent_or_current(path);
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "secret path has no file name"))?;

    for _ in 0..16 {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".{}.{}.tmp", std::process::id(), id));
        let temporary = parent.join(temporary_name);

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);

        match options.open(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        ErrorKind::AlreadyExists,
        "could not allocate a temporary secret file",
    ))
}

fn ensure_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path)?;

    Ok(())
}

fn set_private_file_permissions(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    Ok(())
}

fn parent_or_current(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn prune_epoch_files(path: &Path, min: Epoch) -> io::Result<()> {
    let mut changed = false;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(epoch) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u64>().ok())
        else {
            continue;
        };
        if epoch < min.get() {
            fs::remove_file(entry.path())?;
            changed = true;
        }
    }
    if changed {
        sync_directory(path)?;
    }
    Ok(())
}

fn prune_epoch_directories(path: &Path, min: Epoch) -> io::Result<()> {
    let mut changed = false;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(epoch) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u64>().ok())
        else {
            continue;
        };
        if epoch < min.get() {
            fs::remove_dir_all(entry.path())?;
            changed = true;
        }
    }
    if changed {
        sync_directory(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        Signer as _,
        bls12381::primitives::group::{Private, Scalar},
        ed25519,
    };
    use commonware_math::algebra::Random as _;
    use commonware_utils::{Participant, TestRng};
    use futures::executor::block_on;
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "constantinople-dkg-secrets-{}-{id}",
                std::process::id()
            )))
        }

        fn store_path(&self) -> PathBuf {
            self.0.join("store")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn materials(seed: u64) -> (Share, Summary, ed25519::PublicKey, DealerPrivMsg) {
        let mut rng = TestRng::new(seed);
        let share = Share::new(Participant::new(3), Private::random(&mut rng));
        let dealer_seed = Summary::random(&mut rng);
        let dealer = ed25519::PrivateKey::random(&mut rng).public_key();
        let dealing = DealerPrivMsg::new(Scalar::random(&mut rng));
        (share, dealer_seed, dealer, dealing)
    }

    fn assert_corruption_panic(result: std::thread::Result<()>, expected_message: &str) {
        let panic = result.expect_err("malformed persisted secret must panic");
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .expect("corruption panic should contain a string message");
        assert!(
            message.contains(expected_message),
            "unexpected corruption panic: {message}"
        );
    }

    #[test]
    fn round_trips_share_seed_and_dealing() {
        let directory = TestDirectory::new();
        let mut store = FileSecretStore::load(directory.store_path()).unwrap();
        let epoch = Epoch::new(7);
        let (share, seed, dealer, dealing) = materials(1);

        block_on(async {
            store.put_share(epoch, share.clone()).await;
            store.put_seed(epoch, seed).await;
            store
                .put_dealing(epoch, dealer.clone(), dealing.clone())
                .await;

            assert_eq!(store.get_share(epoch).await, Some(share));
            assert_eq!(store.get_seed(epoch).await, Some(seed));
            assert_eq!(store.get_dealing(epoch, &dealer).await, Some(dealing));
        });
    }

    #[test]
    fn recovers_all_material_after_restart() {
        let directory = TestDirectory::new();
        let path = directory.store_path();
        let epoch = Epoch::new(9);
        let (share, seed, dealer, dealing) = materials(2);

        {
            let mut store = FileSecretStore::load(&path).unwrap();
            block_on(async {
                store.put_share(epoch, share.clone()).await;
                store.put_seed(epoch, seed).await;
                store
                    .put_dealing(epoch, dealer.clone(), dealing.clone())
                    .await;
            });
        }

        let mut restarted = FileSecretStore::load(path).unwrap();
        block_on(async {
            assert_eq!(restarted.get_share(epoch).await, Some(share));
            assert_eq!(restarted.get_seed(epoch).await, Some(seed));
            assert_eq!(restarted.get_dealing(epoch, &dealer).await, Some(dealing));
        });
    }

    #[test]
    fn malformed_persisted_material_panics_instead_of_appearing_absent() {
        let directory = TestDirectory::new();
        let mut store = FileSecretStore::load(directory.store_path()).unwrap();
        let epoch = Epoch::new(10);
        let (share, seed, dealer, dealing) = materials(8);

        block_on(async {
            store.put_share(epoch, share).await;
            store.put_seed(epoch, seed).await;
            store.put_dealing(epoch, dealer.clone(), dealing).await;
        });

        fs::write(store.share_path(epoch), [0xff]).unwrap();
        assert_corruption_panic(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = block_on(store.get_share(epoch));
            })),
            "corrupt persisted DKG share for epoch 10",
        );

        fs::write(store.seed_path(epoch), [0xff]).unwrap();
        assert_corruption_panic(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = block_on(store.get_seed(epoch));
            })),
            "corrupt persisted DKG dealer seed for epoch 10",
        );

        fs::write(store.dealing_path(epoch, &dealer), [0xff]).unwrap();
        assert_corruption_panic(
            catch_unwind(AssertUnwindSafe(|| {
                let _ = block_on(store.get_dealing(epoch, &dealer));
            })),
            "corrupt persisted private DKG dealing for epoch 10",
        );
    }

    #[test]
    fn prune_removes_only_older_epochs_durably() {
        let directory = TestDirectory::new();
        let path = directory.store_path();
        let old_epoch = Epoch::new(3);
        let kept_epoch = Epoch::new(4);
        let (old_share, old_seed, old_dealer, old_dealing) = materials(3);
        let (kept_share, kept_seed, kept_dealer, kept_dealing) = materials(4);
        let mut store = FileSecretStore::load(&path).unwrap();

        block_on(async {
            store.put_share(old_epoch, old_share).await;
            store.put_seed(old_epoch, old_seed).await;
            store
                .put_dealing(old_epoch, old_dealer.clone(), old_dealing)
                .await;
            store.put_share(kept_epoch, kept_share.clone()).await;
            store.put_seed(kept_epoch, kept_seed).await;
            store
                .put_dealing(kept_epoch, kept_dealer.clone(), kept_dealing.clone())
                .await;
            store.prune(kept_epoch).await;
        });
        drop(store);

        let mut restarted = FileSecretStore::load(path).unwrap();
        block_on(async {
            assert_eq!(restarted.get_share(old_epoch).await, None);
            assert_eq!(restarted.get_seed(old_epoch).await, None);
            assert_eq!(restarted.get_dealing(old_epoch, &old_dealer).await, None);
            assert_eq!(restarted.get_share(kept_epoch).await, Some(kept_share));
            assert_eq!(restarted.get_seed(kept_epoch).await, Some(kept_seed));
            assert_eq!(
                restarted.get_dealing(kept_epoch, &kept_dealer).await,
                Some(kept_dealing)
            );
        });
    }

    #[test]
    fn initial_share_is_not_resurrected_after_pruning() {
        let directory = TestDirectory::new();
        let path = directory.store_path();
        let epoch = Epoch::zero();
        let (share, _, _, _) = materials(7);
        let mut store = FileSecretStore::load(&path).unwrap();

        store.put_initial_share(epoch, share.clone()).unwrap();
        block_on(store.prune(Epoch::new(1)));
        assert_eq!(block_on(store.get_share(epoch)), None);
        drop(store);

        let mut restarted = FileSecretStore::load(path).unwrap();
        restarted.put_initial_share(epoch, share).unwrap();
        assert_eq!(block_on(restarted.get_share(epoch)), None);
    }

    #[cfg(unix)]
    #[test]
    fn put_is_visible_and_private_before_it_resolves() {
        let directory = TestDirectory::new();
        let path = directory.store_path();
        let epoch = Epoch::new(11);
        let (_, seed, _, _) = materials(5);
        let mut store = FileSecretStore::load(&path).unwrap();

        block_on(store.put_seed(epoch, seed));

        let mode = fs::metadata(store.seed_path(epoch))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let mut independently_opened = FileSecretStore::load(path).unwrap();
        assert_eq!(block_on(independently_opened.get_seed(epoch)), Some(seed));
    }

    #[test]
    fn put_panics_instead_of_resolving_when_commit_fails() {
        let directory = TestDirectory::new();
        let path = directory.store_path();
        let mut store = FileSecretStore::load(&path).unwrap();
        fs::create_dir(path.join(SEEDS).join("13")).unwrap();
        let (_, seed, _, _) = materials(6);

        let result = catch_unwind(AssertUnwindSafe(|| {
            block_on(store.put_seed(Epoch::new(13), seed));
        }));

        assert!(result.is_err());
        let leftovers = fs::read_dir(path.join(SEEDS))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with('.'))
            .count();
        assert_eq!(leftovers, 0);
    }
}
