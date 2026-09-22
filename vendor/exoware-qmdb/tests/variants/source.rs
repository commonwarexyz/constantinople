//! Source aliases and configuration shared by ordered and unordered cases

macro_rules! source_type {
    (any, $ordering:ident, $encoding:ident, $family:ty, $key:ty, $value:ty) => {
        commonware_storage::qmdb::any::$ordering::$encoding::Db<
            $family, commonware_runtime::tokio::Context, $key, $value,
            commonware_cryptography::Sha256, commonware_storage::translator::TwoCap,
            commonware_parallel::Sequential,
        >
    };
    (current, $ordering:ident, $encoding:ident, $family:ty, $key:ty, $value:ty) => {
        commonware_storage::qmdb::current::$ordering::$encoding::Db<
            $family, commonware_runtime::tokio::Context, $key, $value,
            commonware_cryptography::Sha256, commonware_storage::translator::TwoCap, N,
            commonware_parallel::Sequential,
        >
    };
}

macro_rules! journal_config {
    (variable, $prefix:expr, $cache:expr, $cfg:expr) => {
        crate::common::variable_journal_config($prefix, $cache, $cfg, commonware_utils::NZU64!(8))
    };
    (fixed, $prefix:expr, $cache:expr, $cfg:expr) => {
        commonware_storage::journal::contiguous::fixed::Config {
            partition: format!("{}-log", $prefix),
            items_per_blob: commonware_utils::NZU64!(8),
            page_cache: $cache,
            write_buffer: commonware_utils::NZUsize!(1024),
            replay_buffer: commonware_utils::NZUsize!(1024),
        }
    };
}

macro_rules! source_config {
    (any, $encoding:ident, $prefix:expr, $cache:expr, $cfg:expr) => {
        commonware_storage::qmdb::any::Config {
            merkle_config: crate::common::merkle_config($prefix, $cache.clone()),
            journal_config: journal_config!($encoding, $prefix, $cache, $cfg),
            translator: commonware_storage::translator::TwoCap,
            init_cache_size: None,
            init_buffer: commonware_utils::NZUsize!(1 << 21),
            init_concurrency: (),
        }
    };
    (current, $encoding:ident, $prefix:expr, $cache:expr, $cfg:expr) => {
        commonware_storage::qmdb::current::Config {
            merkle_config: crate::common::merkle_config($prefix, $cache.clone()),
            journal_config: journal_config!($encoding, $prefix, $cache, $cfg),
            grafted_metadata_partition: format!("{}-grafted-metadata", $prefix),
            translator: commonware_storage::translator::TwoCap,
            init_cache_size: None,
            init_buffer: commonware_utils::NZUsize!(1 << 21),
            init_concurrency: (),
        }
    };
}
