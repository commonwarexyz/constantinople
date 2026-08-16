use std::{
    env::{self, VarError},
    fmt::Display,
    str::FromStr,
};

pub fn parse_env_value<T>(name: &str, value: &str) -> T
where
    T: FromStr,
    T::Err: Display,
{
    value
        .parse()
        .unwrap_or_else(|error| panic!("invalid {name} value {value:?}: {error}"))
}

pub fn parse_env_flag(name: &str, value: &str) -> bool {
    match value {
        "1" | "true" | "yes" => true,
        "0" | "false" | "no" => false,
        _ => panic!("invalid {name} flag {value:?}"),
    }
}

pub fn env_or<T>(name: &str, default: T) -> T
where
    T: FromStr,
    T::Err: Display,
{
    match env::var(name) {
        Ok(value) => parse_env_value(name, &value),
        Err(VarError::NotPresent) => default,
        Err(VarError::NotUnicode(_)) => panic!("{name} must be valid UTF-8"),
    }
}

pub fn env_optional<T>(name: &str) -> Option<T>
where
    T: FromStr,
    T::Err: Display,
{
    match env::var(name) {
        Ok(value) => Some(parse_env_value(name, &value)),
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(_)) => panic!("{name} must be valid UTF-8"),
    }
}

pub fn env_flag(name: &str) -> bool {
    match env::var(name) {
        Ok(value) => parse_env_flag(name, &value),
        Err(VarError::NotPresent) => false,
        Err(VarError::NotUnicode(_)) => panic!("{name} must be valid UTF-8"),
    }
}
