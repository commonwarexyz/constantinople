//! `EXOWARE_API_KEY` reaching the constructors.
//!
//! The unit tests cover which key wins and what each one resolves to. Only the lookup itself is
//! left, and it needs a process whose environment holds the variable. Setting one in-process
//! would be read by every other test building a client, so each case runs in a child instead.

use std::process::{Command, Output};

use exoware_sdk::{ClientBuildError, StoreClient, API_KEY_ENV};

/// Re-runs this binary for a single `#[ignore]`d case, with `EXOWARE_API_KEY` set to `key`.
fn run_in_child(case: &str, key: Option<&str>) -> Output {
    let mut command = Command::new(std::env::current_exe().expect("test binary path"));
    command.args([case, "--exact", "--ignored", "--nocapture"]);
    match key {
        Some(key) => command.env(API_KEY_ENV, key),
        None => command.env_remove(API_KEY_ENV),
    };
    command.output().expect("child test process should run")
}

fn assert_case_passes(case: &str, key: Option<&str>) {
    let output = run_in_child(case, key);
    assert!(
        output.status.success(),
        "{case} failed in a child process\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A byte no base64url token contains, so the variable is broken config rather than a credential
/// that might still work.
const UNUSABLE: &str = "has\nnewline";

#[test]
fn build_reads_the_variable() {
    assert_case_passes("child_build_reads_the_variable", Some("token-abc"));
}

#[test]
fn build_rejects_an_unusable_variable() {
    assert_case_passes("child_build_rejects_an_unusable_variable", Some(UNUSABLE));
}

#[test]
fn an_unusable_variable_does_not_panic_the_infallible_constructors() {
    assert_case_passes("child_new_tolerates_an_unusable_variable", Some(UNUSABLE));
}

#[test]
fn an_absent_variable_builds() {
    assert_case_passes("child_build_without_the_variable", None);
}

#[test]
#[ignore = "run by build_reads_the_variable in a child process"]
fn child_build_reads_the_variable() {
    StoreClient::builder()
        .url("https://example.test")
        .build()
        .expect("a usable variable should build");
}

#[test]
#[ignore = "run by build_rejects_an_unusable_variable in a child process"]
fn child_build_rejects_an_unusable_variable() {
    let err = StoreClient::builder()
        .url("https://example.test")
        .build()
        .expect_err("an unusable variable should fail a fallible build");

    assert!(matches!(err, ClientBuildError::InvalidApiKeyEnv), "{err:?}");
    assert!(err.to_string().contains(API_KEY_ENV), "{err}");
}

#[test]
#[ignore = "run by an_unusable_variable_does_not_panic_the_infallible_constructors in a child process"]
fn child_new_tolerates_an_unusable_variable() {
    StoreClient::new("https://example.test");
}

#[test]
#[ignore = "run by an_absent_variable_builds in a child process"]
fn child_build_without_the_variable() {
    StoreClient::builder()
        .url("https://example.test")
        .build()
        .expect("no variable should build");
}
