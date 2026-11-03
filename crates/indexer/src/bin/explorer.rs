//! Store-backed explorer queries and fixed-relayer transaction submission.

use axum::Router;
use commonware_allocator::mimalloc::{Config, MiMalloc, Purge, Reserve};
use constantinople_indexer::{
    adapter::{self, BoxError, Profile},
    explorer,
};
use exoware_sdk::StoreClient;
use std::time::Duration;

#[global_allocator]
static ALLOC: MiMalloc = MiMalloc::new(Config {
    purge: Purge::After(Duration::from_secs(10)),
    reserve: Some(Reserve::pinned(2 << 30)),
    ..Config::DEFAULT
});

const PROFILE: Profile = Profile {
    name: "explorer-indexer",
    about: "Verified explorer API and transaction submission",
    default_port: 8092,
};

fn build_routes(client: &StoreClient, relayer_url: Option<&str>) -> Result<Router, BoxError> {
    explorer::router(client, relayer_url)
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    adapter::main(PROFILE, build_routes).await
}
