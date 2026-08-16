#[path = "../benches/cadence_acceptance.rs"]
#[allow(dead_code)]
mod acceptance;

use acceptance::{parse_env_flag, parse_env_value};

#[test]
fn malformed_acceptance_values_fail_closed() {
    let numeric = std::panic::catch_unwind(|| parse_env_value::<usize>("LIMIT", "not-a-number"));
    assert!(numeric.is_err());
    let flag = std::panic::catch_unwind(|| parse_env_flag("FLAG", "sometimes"));
    assert!(flag.is_err());
}
