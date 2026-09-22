//! The API key a client presents, and what a rejection tells the caller to do about it.
//!
//! A client cannot tell from its configuration whether the endpoint requires a credential, since
//! a deployment behind a load balancer authenticates every RPC and one without authenticates
//! none. It sends whatever it has and explains itself when a call is rejected.

use std::fmt;

use crate::{ClientBuildError, ClientError, ConnectError, ErrorCode};

/// Environment variable read for the API key when none is set on the builder.
pub const API_KEY_ENV: &str = "EXOWARE_API_KEY";

/// The API key, wrapped so a `Debug` of the builder cannot leak it into a log.
#[derive(Clone, Default)]
pub(crate) struct ApiKey(pub(crate) String);

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// How a constructor handles an `EXOWARE_API_KEY` that cannot be an HTTP header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnusableEnvKey {
    /// Fail the build.
    Reject,
    /// Build without a credential, leaving a rejected request to name the variable. The only
    /// option for the infallible constructors, which would otherwise have to panic.
    Tolerate,
}

/// Whether this client sends a credential with every request.
///
/// Threaded to every site that can raise an RPC error, because an endpoint reports the same code
/// whether a credential was missing or refused, and only the client knows which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Credential {
    Sent,
    Absent,
    /// Configured through the environment, but not sendable as an HTTP header value.
    Unusable,
}

/// A resolved credential, ready to configure a client with.
#[derive(Debug)]
pub(crate) struct Resolved {
    pub(crate) header: Option<http::HeaderValue>,
    pub(crate) credential: Credential,
}

/// Chooses between an explicitly configured key and one found in the environment.
///
/// Takes the environment lookup as an argument rather than reading it, so that every case is
/// reachable without touching a process-wide variable.
pub(crate) fn resolve(
    explicit: Option<String>,
    from_environment: Option<String>,
    unusable_env_key: UnusableEnvKey,
) -> Result<Resolved, ClientBuildError> {
    let (key, is_from_environment) = match explicit {
        Some(key) => (Some(key), false),
        None => (from_environment, true),
    };

    // Surrounding whitespace is trimmed rather than rejected. A key routinely arrives as
    // EXOWARE_API_KEY=$(cat token), which carries a trailing newline that is no part of it.
    let key = key
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty());
    let Some(key) = key else {
        return Ok(Resolved {
            header: None,
            credential: Credential::Absent,
        });
    };

    match bearer_header(&key) {
        Some(header) => Ok(Resolved {
            header: Some(header),
            credential: Credential::Sent,
        }),
        None if !is_from_environment => Err(ClientBuildError::InvalidApiKey),
        None => match unusable_env_key {
            UnusableEnvKey::Reject => Err(ClientBuildError::InvalidApiKeyEnv),
            UnusableEnvKey::Tolerate => Ok(Resolved {
                header: None,
                credential: Credential::Unusable,
            }),
        },
    }
}

/// Builds the Authorization header for a key, or `None` if the key cannot be one.
///
/// Marked sensitive so the credential cannot reach a log or a Debug of the client.
fn bearer_header(key: &str) -> Option<http::HeaderValue> {
    let mut value = http::HeaderValue::from_str(&format!("Bearer {key}")).ok()?;
    value.set_sensitive(true);
    Some(value)
}

impl Credential {
    /// Advice for an unauthenticated rejection.
    ///
    /// The reader may be running a binary they did not build, so no case names a Rust API. The
    /// environment variable is the one thing they can always act on.
    const fn remedy(self) -> &'static str {
        match self {
            Self::Absent => concat!(
                "This endpoint requires a credential and none was sent. The EXOWARE_API_KEY ",
                "environment variable supplies one"
            ),
            Self::Sent => concat!(
                "The credential sent with this request was refused. It may have expired, or ",
                "been issued for a different deployment, or lack the scope this call needs"
            ),
            Self::Unusable => concat!(
                "The EXOWARE_API_KEY environment variable is set to a value that cannot be an ",
                "HTTP header, so no credential was sent. Remove any control or non-ASCII ",
                "characters from it"
            ),
        }
    }
}

/// Presents an RPC error to the caller, dropping any page a proxy answered with and telling a
/// rejected caller what to do about their credential.
pub(crate) fn client_error_from_connect(
    mut err: ConnectError,
    credential: Credential,
) -> ClientError {
    err.message = err.message.take().and_then(without_html_body);
    if err.code == ErrorCode::Unauthenticated {
        let remedy = credential.remedy();
        err.message = Some(match err.message.take() {
            Some(message) => format!("{message}. {remedy}"),
            None => remedy.to_string(),
        });
    }
    ClientError::Rpc(Box::new(err))
}

/// Drops an HTML error page from a message, keeping whatever preceded it.
///
/// A proxy that rejects a request before it reaches a service answers with a page rather than a
/// ConnectRPC error, and the whole page arrives in the message. Returns `None` when nothing but
/// markup was there.
fn without_html_body(message: String) -> Option<String> {
    let lowercase = message.to_ascii_lowercase();
    let Some(start) = ["<html", "<!doctype"]
        .iter()
        .filter_map(|marker| lowercase.find(marker))
        .min()
    else {
        return Some(message);
    };

    let kept = message[..start].trim_end().trim_end_matches(':').trim_end();
    (!kept.is_empty()).then(|| kept.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 401 body an ALB serves when it rejects a token, verbatim.
    const PROXY_REJECTION: &str = "HTTP error 401: <html>\r\n<head><title>401 Authorization Required</title></head>\r\n<body>\r\n<center><h1>401 Authorization Required</h1></center>\r\n</body>\r\n</html>\r\n";

    /// An unusable key, being a byte no base64url token contains.
    const UNUSABLE: &str = "has\nnewline";

    fn rejection(credential: Credential) -> String {
        client_error_from_connect(
            ConnectError::new(ErrorCode::Unauthenticated, PROXY_REJECTION),
            credential,
        )
        .to_string()
    }

    fn from_env(key: &str, unusable_env_key: UnusableEnvKey) -> Result<Resolved, ClientBuildError> {
        resolve(None, Some(key.to_string()), unusable_env_key)
    }

    #[test]
    fn proxy_rejection_keeps_the_status_and_drops_the_page() {
        let err = client_error_from_connect(
            ConnectError::new(ErrorCode::Unauthenticated, PROXY_REJECTION),
            Credential::Sent,
        );
        let rendered = err.to_string();
        assert_eq!(err.rpc_code(), Some(ErrorCode::Unauthenticated));
        assert!(!rendered.contains('<'), "kept markup: {rendered}");
        assert!(rendered.contains("HTTP error 401"), "{rendered}");
    }

    #[test]
    fn a_missing_credential_is_told_how_to_supply_one() {
        let rendered = rejection(Credential::Absent);
        assert!(rendered.contains("none was sent"), "{rendered}");
        assert!(rendered.contains(API_KEY_ENV), "{rendered}");
    }

    /// The reader may not control the binary, so no rejection may point at a Rust API.
    #[test]
    fn no_remedy_names_an_api() {
        for credential in [Credential::Sent, Credential::Absent, Credential::Unusable] {
            let rendered = rejection(credential);
            assert!(!rendered.contains("StoreClient"), "{rendered}");
            assert!(!rendered.contains("::"), "{rendered}");
        }
    }

    /// A client that sent a credential needs to hear why one it already has failed, so it must
    /// not be told to set the variable it already set.
    #[test]
    fn a_refused_credential_is_told_why_rather_than_how_to_set_one() {
        let rendered = rejection(Credential::Sent);
        assert!(rendered.contains("refused"), "{rendered}");
        assert!(rendered.contains("expired"), "{rendered}");
        assert!(!rendered.contains(API_KEY_ENV), "{rendered}");
    }

    #[test]
    fn other_codes_carry_no_credential_remedy() {
        let err = client_error_from_connect(
            ConnectError::new(ErrorCode::NotFound, "no such key"),
            Credential::Absent,
        );
        assert_eq!(err.to_string(), "RPC error (not_found: no such key)");
    }

    #[test]
    fn html_body_recognized_with_a_doctype_and_when_it_is_the_whole_message() {
        assert_eq!(
            without_html_body("HTTP error 502: <!DOCTYPE html><html></html>".to_string()),
            Some("HTTP error 502".to_string())
        );
        assert_eq!(without_html_body("<html>bare</html>".to_string()), None);
    }

    #[test]
    fn a_service_message_survives_untouched() {
        // Service errors are the common case, and nothing about them should be trimmed.
        let message = "key not found: a < b";
        assert_eq!(
            without_html_body(message.to_string()),
            Some(message.to_string())
        );
    }

    #[test]
    fn a_key_becomes_a_sensitive_bearer_header() {
        let resolved = from_env("token-abc", UnusableEnvKey::Reject).unwrap();
        let header = resolved.header.unwrap();

        assert_eq!(resolved.credential, Credential::Sent);
        assert_eq!(header, "Bearer token-abc");
        // set_sensitive is what keeps the credential out of any log that debugs the transport.
        assert!(!format!("{header:?}").contains("token-abc"));
    }

    #[test]
    fn an_explicit_key_wins_over_the_environment() {
        let resolved = resolve(
            Some("explicit".to_string()),
            Some("from-env".to_string()),
            UnusableEnvKey::Reject,
        )
        .unwrap();

        assert_eq!(resolved.header.unwrap(), "Bearer explicit");
    }

    #[test]
    fn no_key_anywhere_sends_no_header() {
        // A deployment with no load balancer in front of it authenticates nothing, so this has to
        // keep working rather than demand a credential.
        let resolved = resolve(None, None, UnusableEnvKey::Reject).unwrap();

        assert!(resolved.header.is_none());
        assert_eq!(resolved.credential, Credential::Absent);
    }

    /// A key reaching the environment through `$(cat token)` carries a trailing newline, which
    /// would otherwise make it unusable.
    #[test]
    fn surrounding_whitespace_is_trimmed_rather_than_rejected() {
        let resolved = from_env("  padded-token\n", UnusableEnvKey::Reject).unwrap();

        assert_eq!(resolved.header.unwrap(), "Bearer padded-token");
        assert_eq!(resolved.credential, Credential::Sent);
    }

    #[test]
    fn a_variable_holding_only_whitespace_is_an_unset_one() {
        let resolved = from_env("   \n", UnusableEnvKey::Reject).unwrap();

        assert!(resolved.header.is_none());
        assert_eq!(resolved.credential, Credential::Absent);
    }

    #[test]
    fn an_explicit_unusable_key_always_fails() {
        // The caller passed it in code and called a fallible build, so the policy never applies.
        for unusable_env_key in [UnusableEnvKey::Reject, UnusableEnvKey::Tolerate] {
            assert!(matches!(
                resolve(Some(UNUSABLE.to_string()), None, unusable_env_key),
                Err(ClientBuildError::InvalidApiKey)
            ));
        }
    }

    #[test]
    fn an_unusable_environment_key_follows_the_policy() {
        assert!(matches!(
            from_env(UNUSABLE, UnusableEnvKey::Reject),
            Err(ClientBuildError::InvalidApiKeyEnv)
        ));

        let tolerated = from_env(UNUSABLE, UnusableEnvKey::Tolerate).unwrap();
        assert!(tolerated.header.is_none());
        assert_eq!(tolerated.credential, Credential::Unusable);
    }

    /// Whoever set the variable may not have written the binary, so the message names the
    /// variable and not the builder.
    #[test]
    fn rejecting_an_environment_key_names_the_variable() {
        let rendered = from_env(UNUSABLE, UnusableEnvKey::Reject)
            .unwrap_err()
            .to_string();

        assert!(rendered.contains(API_KEY_ENV), "{rendered}");
        assert!(!rendered.contains("StoreClient"), "{rendered}");
    }
}
