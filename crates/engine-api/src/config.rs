//! Startup configuration: every secret and setting the API binary reads, validated
//! together so a misconfigured deployment gets one error that lists all problems.
//!
//! Secrets come from `NAME` or `NAME_FILE` ([`crate::secrets`]). No message built here
//! contains a secret value, or any part of one.
use crate::{
    retention::RetentionConfig,
    secrets::{self, Lookup, Secret},
    AuthConfig,
};
use sqlx::postgres::PgConnectOptions;
use std::str::FromStr;

/// Everything `main` needs before it touches the database.
pub struct StartupConfig {
    pub auth: AuthConfig,
    /// The runtime login's connection URL (holds its password).
    pub database_url: Secret,
    pub retention: RetentionConfig,
    /// `IDENTITY_SECRETS_KEY` (or `_FILE`): the key of stored identity secrets, apart from the
    /// server key ([`crate::identity_secrets`]). Optional; must differ from `PASETO_LOCAL_KEY`.
    pub identity_key: Option<[u8; 32]>,
    /// Login lifetimes ([`crate::auth::SessionPolicy`]).
    pub session: crate::auth::SessionPolicy,
    /// `SCIM_RATE_PER_MINUTE` (default 600, 10 to 100000).
    pub scim_rate_per_minute: i32,
    /// `DYNODOC_EVENT_FANOUT`: `local` (default), `postgres` or `poll` ([`crate::fanout`]).
    pub fanout: crate::fanout::Mode,
    /// The request pool (`DB_POOL_MAX`, `DB_ACQUIRE_TIMEOUT_MS`, `DB_STATEMENT_TIMEOUT_MS`).
    pub pool: PoolConfig,
    /// `SHUTDOWN_DRAIN_SECONDS` (default 25, 0 to 300): how long in-flight requests and live
    /// streams may run after SIGTERM before the process exits.
    pub shutdown_drain_seconds: u64,
    /// `DYNODOC_OBJECT_STORE` and its settings ([`crate::object_store`]).
    pub objects: crate::object_store::ObjectStore,
    /// `REAUTH_MAX_AGE_SECONDS` (default 600, 60 to 86400, or 0 for none): how old a login may
    /// be for a sensitive action (`crate::auth::sessions::require_recent_login`).
    pub reauth_seconds: i64,
}

/// Request pool settings; the defaults are the values used before they were settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolConfig {
    pub max_connections: u32,
    pub acquire_timeout_ms: u64,
    pub statement_timeout_ms: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 8,
            acquire_timeout_ms: 5_000,
            statement_timeout_ms: 15_000,
        }
    }
}

impl StartupConfig {
    /// Load from the process environment.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::load(&|name| std::env::var_os(name))
    }

    /// Load from any environment. Fails with every problem found, one per line.
    pub fn load(lookup: Lookup) -> anyhow::Result<Self> {
        let mut problems = Vec::new();
        let paseto_key = match secret(lookup, "PASETO_LOCAL_KEY", &mut problems) {
            Ok(Some(value)) => parse_paseto_key(&value)
                .map_err(|problem| problems.push(problem))
                .ok(),
            Ok(None) => {
                problems.push(
                    "PASETO_LOCAL_KEY is not set (32 bytes, hex-encoded; or set PASETO_LOCAL_KEY_FILE)"
                        .into(),
                );
                None
            }
            Err(()) => None,
        };
        let service_key = match secret(lookup, "WEB_SERVICE_KEY", &mut problems) {
            Ok(Some(value)) if value.expose().len() >= 32 && !value.expose().trim().is_empty() => {
                Some(value)
            }
            Ok(_) => {
                problems.push(
                    "WEB_SERVICE_KEY of at least 32 characters is required in every environment"
                        .into(),
                );
                None
            }
            Err(()) => None,
        };
        // The API must never hold owner credentials, in either form.
        if lookup("MIGRATION_DATABASE_URL").is_some()
            || lookup("MIGRATION_DATABASE_URL_FILE").is_some()
        {
            problems.push(
                "MIGRATION_DATABASE_URL must not be present in the API environment (nor MIGRATION_DATABASE_URL_FILE)"
                    .into(),
            );
        }
        let database_url = match secret(lookup, "DATABASE_URL", &mut problems) {
            Ok(Some(url)) if PgConnectOptions::from_str(url.expose()).is_ok() => Some(url),
            Ok(Some(_)) => {
                problems.push("DATABASE_URL is not a valid PostgreSQL connection URL".into());
                None
            }
            Ok(None) => {
                problems.push(
                    "DATABASE_URL is not set (see .env / SETUP.md; or set DATABASE_URL_FILE)"
                        .into(),
                );
                None
            }
            Err(()) => None,
        };
        let retention = RetentionConfig::load(lookup, &mut problems);
        let identity_key = match secret(lookup, "IDENTITY_SECRETS_KEY", &mut problems) {
            Ok(Some(value)) => match parse_paseto_key(&value) {
                Ok(key) if Some(key) == paseto_key => {
                    problems.push(
                        "IDENTITY_SECRETS_KEY must differ from PASETO_LOCAL_KEY (it outlives a rotation of that key)"
                            .into(),
                    );
                    None
                }
                Ok(key) => Some(key),
                Err(problem) => {
                    problems.push(problem.replace("PASETO_LOCAL_KEY", "IDENTITY_SECRETS_KEY"));
                    None
                }
            },
            _ => None,
        };
        let day = 86_400;
        let session = crate::auth::SessionPolicy {
            refresh_ttl_seconds: seconds(
                lookup,
                "REFRESH_TTL_SECONDS",
                crate::auth::REFRESH_TTL_SECONDS,
                300..=90 * day,
                false,
                &mut problems,
            ),
            idle_timeout_seconds: seconds(
                lookup,
                "SESSION_IDLE_TIMEOUT_SECONDS",
                0,
                300..=30 * day,
                true,
                &mut problems,
            ),
            absolute_timeout_seconds: seconds(
                lookup,
                "SESSION_ABSOLUTE_TIMEOUT_SECONDS",
                0,
                900..=365 * day,
                true,
                &mut problems,
            ),
        };
        let scim_rate_per_minute = seconds(
            lookup,
            "SCIM_RATE_PER_MINUTE",
            600,
            10..=100_000,
            false,
            &mut problems,
        ) as i32;
        let fanout = match lookup("DYNODOC_EVENT_FANOUT").map(|v| v.into_string()) {
            None => crate::fanout::Mode::Local,
            Some(Ok(v)) if crate::fanout::Mode::parse(&v).is_some() => {
                crate::fanout::Mode::parse(&v).unwrap_or_default()
            }
            Some(_) => {
                problems.push("DYNODOC_EVENT_FANOUT must be local, postgres or poll".into());
                crate::fanout::Mode::Local
            }
        };
        let pool = PoolConfig {
            max_connections: seconds(lookup, "DB_POOL_MAX", 8, 1..=200, false, &mut problems)
                as u32,
            acquire_timeout_ms: seconds(
                lookup,
                "DB_ACQUIRE_TIMEOUT_MS",
                5_000,
                100..=120_000,
                false,
                &mut problems,
            ) as u64,
            statement_timeout_ms: seconds(
                lookup,
                "DB_STATEMENT_TIMEOUT_MS",
                15_000,
                100..=600_000,
                false,
                &mut problems,
            ) as u64,
        };
        let shutdown_drain_seconds = seconds(
            lookup,
            "SHUTDOWN_DRAIN_SECONDS",
            25,
            1..=300,
            true,
            &mut problems,
        ) as u64;
        let objects = crate::object_store::ObjectStore::load(lookup, &mut problems);
        let reauth_seconds = seconds(
            lookup,
            "REAUTH_MAX_AGE_SECONDS",
            600,
            60..=86_400,
            true,
            &mut problems,
        );

        let text = |name: &str| lookup(name).and_then(|v| v.into_string().ok());
        match (paseto_key, service_key, database_url) {
            (Some(paseto_key), Some(service_key), Some(database_url)) if problems.is_empty() => {
                Ok(Self {
                    auth: AuthConfig {
                        paseto_key,
                        service_key: Some(service_key.expose().to_string()),
                        token_ttl_seconds: text("TOKEN_TTL_SECONDS")
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(86_400),
                        public_base_url: text("PUBLIC_API_BASE_URL")
                            .unwrap_or_else(|| "http://127.0.0.1:8080".to_string()),
                    },
                    database_url,
                    retention,
                    identity_key,
                    session,
                    scim_rate_per_minute,
                    fanout,
                    pool,
                    shutdown_drain_seconds,
                    objects,
                    reauth_seconds,
                })
            }
            _ => anyhow::bail!(
                "invalid configuration ({} problem{}):\n  - {}",
                problems.len(),
                if problems.len() == 1 { "" } else { "s" },
                problems.join("\n  - ")
            ),
        }
    }
}

/// A whole number setting within `range` (or `0` when `zero` allows "none"); a problem is recorded
/// and the default returned.
fn seconds(
    lookup: Lookup,
    name: &str,
    default: i64,
    range: std::ops::RangeInclusive<i64>,
    zero: bool,
    problems: &mut Vec<String>,
) -> i64 {
    let Some(raw) = lookup(name) else {
        return default;
    };
    match raw.to_str().and_then(|v| v.trim().parse::<i64>().ok()) {
        Some(0) if zero => 0,
        Some(v) if range.contains(&v) => v,
        _ => {
            problems.push(format!(
                "{name} must be a whole number from {} to {}{}",
                range.start(),
                range.end(),
                if zero { ", or 0 for none" } else { "" }
            ));
            default
        }
    }
}

/// Read a secret. A read problem is recorded here and reported as `Err(())`.
fn secret(lookup: Lookup, name: &str, problems: &mut Vec<String>) -> Result<Option<Secret>, ()> {
    secrets::read(lookup, name).map_err(|error| problems.push(error.to_string()))
}

/// 32 random bytes as 64 hex characters (surrounding whitespace is ignored).
fn parse_paseto_key(secret: &Secret) -> Result<[u8; 32], String> {
    let bytes = hex::decode(secret.expose().trim())
        .map_err(|_| "PASETO_LOCAL_KEY must be hex-encoded".to_string())?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "PASETO_LOCAL_KEY must be 32 bytes (64 hex chars)".to_string())?;
    if key == [0u8; 32] {
        return Err("A random PASETO_LOCAL_KEY is required in every environment".into());
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, ffi::OsString};

    const KEY: &str = "0707070707070707070707070707070707070707070707070707070707070707";
    const SERVICE: &str = "isolated-configuration-test-service-key";
    const URL: &str = "postgres://runtime:p4ssw0rd-do-not-leak@127.0.0.1:5432/dynodoc";

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), OsString::from(v)))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn valid<'a>() -> Vec<(&'a str, &'a str)> {
        vec![
            ("PASETO_LOCAL_KEY", KEY),
            ("WEB_SERVICE_KEY", SERVICE),
            ("DATABASE_URL", URL),
        ]
    }

    fn error_of(pairs: &[(&str, &str)]) -> String {
        match StartupConfig::load(&env(pairs)) {
            Ok(_) => panic!("configuration was accepted"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn plain_variables_load_with_documented_defaults() {
        let config = StartupConfig::load(&env(&valid())).unwrap();
        assert_eq!(config.auth.paseto_key, [7u8; 32]);
        assert_eq!(config.auth.service_key.as_deref(), Some(SERVICE));
        assert_eq!(config.auth.token_ttl_seconds, 86_400);
        assert_eq!(config.auth.public_base_url, "http://127.0.0.1:8080");
        assert_eq!(config.database_url.expose(), URL);
        assert_eq!(config.retention, RetentionConfig::default());
    }

    #[test]
    fn plain_values_are_used_without_trimming_except_the_hex_key() {
        let padded_key = format!(" {KEY}\n");
        let padded_service = format!(" {SERVICE}\n");
        let mut pairs = valid();
        pairs[0].1 = &padded_key;
        pairs[1].1 = &padded_service;
        pairs.push(("TOKEN_TTL_SECONDS", "3600"));
        pairs.push(("PUBLIC_API_BASE_URL", "https://dynodoc.example.test"));
        let config = StartupConfig::load(&env(&pairs)).unwrap();
        assert_eq!(config.auth.paseto_key, [7u8; 32]);
        assert_eq!(
            config.auth.service_key.as_deref(),
            Some(padded_service.as_str())
        );
        assert_eq!(config.auth.token_ttl_seconds, 3600);
        assert_eq!(config.auth.public_base_url, "https://dynodoc.example.test");
    }

    #[test]
    fn identity_key_and_session_lifetimes_are_validated() {
        let mut pairs = valid();
        pairs.push(("IDENTITY_SECRETS_KEY", KEY));
        assert!(error_of(&pairs).contains("IDENTITY_SECRETS_KEY must differ"));
        let other = "0909090909090909090909090909090909090909090909090909090909090909";
        let mut pairs = valid();
        pairs.push(("IDENTITY_SECRETS_KEY", other));
        pairs.push(("SESSION_IDLE_TIMEOUT_SECONDS", "28800"));
        pairs.push(("SESSION_ABSOLUTE_TIMEOUT_SECONDS", "0"));
        let config = StartupConfig::load(&env(&pairs)).unwrap();
        assert_eq!(config.identity_key, Some([9u8; 32]));
        assert_eq!(config.session.idle_timeout_seconds, 28_800);
        assert_eq!(config.session.absolute_timeout_seconds, 0);
        let mut pairs = valid();
        pairs.push(("REFRESH_TTL_SECONDS", "0"));
        pairs.push(("SESSION_IDLE_TIMEOUT_SECONDS", "5"));
        let message = error_of(&pairs);
        assert!(message.contains("REFRESH_TTL_SECONDS must be"), "{message}");
        assert!(
            message.contains("SESSION_IDLE_TIMEOUT_SECONDS must be"),
            "{message}"
        );
        assert!(!message.contains(other));
    }

    #[test]
    fn pool_fanout_and_drain_settings_are_validated() {
        let config = StartupConfig::load(&env(&valid())).unwrap();
        assert_eq!(config.pool, PoolConfig::default());
        assert_eq!(config.fanout, crate::fanout::Mode::Local);
        assert_eq!(config.shutdown_drain_seconds, 25);
        assert!(config.objects.in_database());
        let mut pairs = valid();
        pairs.extend([
            ("DB_POOL_MAX", "32"),
            ("DB_ACQUIRE_TIMEOUT_MS", "2000"),
            ("DB_STATEMENT_TIMEOUT_MS", "30000"),
            ("DYNODOC_EVENT_FANOUT", "postgres"),
            ("SHUTDOWN_DRAIN_SECONDS", "0"),
        ]);
        let config = StartupConfig::load(&env(&pairs)).unwrap();
        assert_eq!(
            config.pool,
            PoolConfig {
                max_connections: 32,
                acquire_timeout_ms: 2000,
                statement_timeout_ms: 30000
            }
        );
        assert_eq!(config.fanout, crate::fanout::Mode::Postgres);
        assert_eq!(config.shutdown_drain_seconds, 0);
        let mut pairs = valid();
        pairs.extend([
            ("DB_POOL_MAX", "0"),
            ("DB_STATEMENT_TIMEOUT_MS", "soon"),
            ("DYNODOC_EVENT_FANOUT", "redis"),
            ("SHUTDOWN_DRAIN_SECONDS", "900"),
            ("DYNODOC_OBJECT_STORE", "filesystem"),
        ]);
        let message = error_of(&pairs);
        for name in [
            "DB_POOL_MAX",
            "DB_STATEMENT_TIMEOUT_MS",
            "DYNODOC_EVENT_FANOUT",
            "SHUTDOWN_DRAIN_SECONDS",
            "DYNODOC_OBJECT_DIR",
        ] {
            assert!(message.contains(name), "{name}: {message}");
        }
    }

    #[test]
    fn every_problem_is_listed_once_in_one_error() {
        let message = error_of(&[
            ("PASETO_LOCAL_KEY", "zz"),
            ("WEB_SERVICE_KEY", "short"),
            ("DATABASE_URL", "intentionally-invalid"),
            ("MIGRATION_DATABASE_URL", "never-use-this-owner-url"),
            ("RETENTION_AUTH_DAYS", "0"),
        ]);
        assert!(
            message.starts_with("invalid configuration (5 problems):"),
            "{message}"
        );
        for expected in [
            "PASETO_LOCAL_KEY must be hex-encoded",
            "WEB_SERVICE_KEY of at least 32 characters is required",
            "DATABASE_URL is not a valid PostgreSQL connection URL",
            "MIGRATION_DATABASE_URL must not be present",
            "RETENTION_AUTH_DAYS must be a whole number from 1 to 365",
        ] {
            assert_eq!(
                message.matches(expected).count(),
                1,
                "{expected}\n{message}"
            );
        }
        assert!(!message.contains("never-use-this-owner-url"), "{message}");
        assert!(!message.contains("short"), "{message}");
    }

    #[test]
    fn missing_secrets_are_each_named() {
        let message = error_of(&[]);
        for name in ["PASETO_LOCAL_KEY", "WEB_SERVICE_KEY", "DATABASE_URL"] {
            assert!(
                message.contains(&format!("{name} is not set"))
                    || message.contains(&format!("{name} of at least")),
                "{name}\n{message}"
            );
        }
    }

    #[test]
    fn key_shape_errors_keep_their_wording_and_never_echo_the_key() {
        let zero = "00".repeat(32);
        let short = "07".repeat(31);
        let odd = format!("{KEY}0");
        for (value, expected) in [
            (zero.as_str(), "A random PASETO_LOCAL_KEY is required"),
            (
                short.as_str(),
                "PASETO_LOCAL_KEY must be 32 bytes (64 hex chars)",
            ),
            (odd.as_str(), "PASETO_LOCAL_KEY must be hex-encoded"),
            (
                "not-hex-at-all-0123456789abcdef",
                "PASETO_LOCAL_KEY must be hex-encoded",
            ),
        ] {
            let mut pairs = valid();
            pairs[0].1 = value;
            let message = error_of(&pairs);
            assert!(message.contains(expected), "{message}");
            assert!(!message.contains(value), "{message}");
        }
        for value in ["", "short", "                                "] {
            let mut pairs = valid();
            pairs[1].1 = value;
            assert!(error_of(&pairs).contains("WEB_SERVICE_KEY of at least 32 characters"));
        }
    }

    #[test]
    fn migration_credentials_are_refused_in_both_forms() {
        for name in ["MIGRATION_DATABASE_URL", "MIGRATION_DATABASE_URL_FILE"] {
            let mut pairs = valid();
            pairs.push((name, ""));
            assert!(error_of(&pairs).contains("MIGRATION_DATABASE_URL must not be present"));
        }
    }

    #[test]
    fn file_variants_load_and_conflicts_are_errors() {
        let dir = std::env::temp_dir();
        let write = |text: &str| {
            let path = dir.join(format!("dynodoc-config-{}", uuid::Uuid::new_v4()));
            std::fs::write(&path, format!("{text}\n")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            path
        };
        let (key, service, url) = (write(KEY), write(SERVICE), write(URL));
        let pairs = [
            ("PASETO_LOCAL_KEY_FILE", key.to_str().unwrap()),
            ("WEB_SERVICE_KEY_FILE", service.to_str().unwrap()),
            ("DATABASE_URL_FILE", url.to_str().unwrap()),
        ];
        let config = StartupConfig::load(&env(&pairs)).unwrap();
        assert_eq!(config.auth.paseto_key, [7u8; 32]);
        assert_eq!(config.auth.service_key.as_deref(), Some(SERVICE));
        assert_eq!(config.database_url.expose(), URL);

        let mut both = pairs.to_vec();
        both.push(("WEB_SERVICE_KEY", SERVICE));
        let message = error_of(&both);
        assert!(
            message.contains("WEB_SERVICE_KEY and WEB_SERVICE_KEY_FILE are both set"),
            "{message}"
        );
        assert_eq!(
            message.matches("WEB_SERVICE_KEY of at least").count(),
            0,
            "{message}"
        );

        let missing = dir.join(format!("dynodoc-absent-{}", uuid::Uuid::new_v4()));
        let mut unreadable = pairs.to_vec();
        unreadable[2].1 = missing.to_str().unwrap();
        let message = error_of(&unreadable);
        assert!(message.contains("DATABASE_URL_FILE ("), "{message}");
        assert!(
            message.starts_with("invalid configuration (1 problem):"),
            "{message}"
        );
        for path in [key, service, url] {
            let _ = std::fs::remove_file(path);
        }
    }
}
