//! Secrets the identity features store: an organisation provider's client secret (migration 0077)
//! and the OpenID Connect ID token kept for RP-initiated logout (`login_session.id_token_hint`,
//! migration 0110). Each is a `DYNOENC` envelope ([`engine_core::at_rest`]) bound to the
//! installation, table, column and row.
//!
//! Two data keys, told apart by the envelope header's key id:
//!
//! - id 1, the legacy key: derived from the server key (`PASETO_LOCAL_KEY`). Rotating that key
//!   made every stored secret unreadable. It is still read, never written once id 2 is set.
//! - id 2, `IDENTITY_SECRETS_KEY` (or `_FILE`): 32 random bytes kept apart from the server key,
//!   so rotating `PASETO_LOCAL_KEY` only ends sessions (deployment guide 9.12).
//!
//! [`reseal_all`] rewrites every stored envelope under the current key (`engine-cli auth
//! reseal-identity-secrets`): after setting `IDENTITY_SECRETS_KEY` for the first time, and when
//! rotating it (the previous key is passed as an extra opening key).

use engine_core::at_rest::{self, Context, DataKey, Dek, Header};
use sqlx::PgPool;
use uuid::Uuid;

/// Key id of the data key derived from the server key.
pub const LEGACY_KEY_ID: u32 = 1;
/// Key id of `IDENTITY_SECRETS_KEY`.
pub const IDENTITY_KEY_ID: u32 = 2;

/// The legacy data key: HMAC-SHA-256 of a fixed label under the server key (the derivation of
/// migration 0077's first build, kept byte for byte so existing envelopes still open).
pub fn legacy_key(paseto_key: &[u8; 32]) -> DataKey {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, paseto_key);
    let tag = ring::hmac::sign(&key, b"dynodoc organisation sign-in provider secrets v1");
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(tag.as_ref());
    DataKey::new(LEGACY_KEY_ID, 1, Dek::from_bytes(bytes))
}

/// The data key of `IDENTITY_SECRETS_KEY`.
pub fn identity_key(bytes: &[u8; 32]) -> DataKey {
    DataKey::new(IDENTITY_KEY_ID, 1, Dek::from_bytes(*bytes))
}

/// The key new envelopes are written with: the identity key when configured, else the legacy one.
pub fn sealing_key(paseto_key: &[u8; 32], identity: Option<&[u8; 32]>) -> DataKey {
    identity.map_or_else(|| legacy_key(paseto_key), identity_key)
}

/// Seal `plaintext` for `(table, column, row)` of this installation.
pub fn seal(
    key: &DataKey,
    installation: Uuid,
    table: &str,
    column: &str,
    row: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, at_rest::Error> {
    at_rest::seal(
        key,
        &Context::new(installation, table, column, row)?,
        plaintext,
    )
}

/// Open an envelope with whichever of `keys` its header names; `None` when none does or the
/// envelope does not authenticate (wrong key, moved row, tampering).
pub fn open(
    keys: &[DataKey],
    installation: Uuid,
    table: &str,
    column: &str,
    row: &[u8],
    stored: &[u8],
) -> Option<Vec<u8>> {
    let id = Header::parse(stored).ok()?.dek_id;
    let ctx = Context::new(installation, table, column, row).ok()?;
    keys.iter()
        .filter(|k| k.id() == id)
        .find_map(|k| at_rest::open(k, &ctx, stored).ok())
}

/// What [`reseal_all`] did.
#[derive(Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ResealReport {
    /// Envelopes rewritten under the target key.
    pub resealed: u64,
    /// Envelopes already under the target key.
    pub current: u64,
    /// Envelopes no key opened (left unchanged; their secret must be entered again).
    pub unreadable: u64,
}

/// The stored envelopes: (table, column, row-id column).
const SEALED: &[(&str, &str, &str)] = &[
    ("organisation_sign_in_provider", "secret_sealed", "id"),
    ("login_session", "id_token_hint", "session_id"),
];

/// Rewrite every stored identity secret under `to`, opening each with `to` or one of `from`. One
/// transaction: either every readable envelope moves or none does.
pub async fn reseal_all(
    pool: &PgPool,
    from: &[DataKey],
    to: &DataKey,
) -> Result<ResealReport, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let installation: Uuid = sqlx::query_scalar("select id from device_authority where singleton")
        .fetch_one(&mut *tx)
        .await?;
    let mut report = ResealReport::default();
    for (table, column, id) in SEALED {
        let rows: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(&format!(
            "select {id},{column} from {table} where {column} is not null for update"
        ))
        .fetch_all(&mut *tx)
        .await?;
        for (row, stored) in rows {
            let ctx = Context::new(installation, table, column, row.as_bytes())
                .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
            if at_rest::open(to, &ctx, &stored).is_ok() {
                report.current += 1;
                continue;
            }
            let Some(plain) = from
                .iter()
                .find_map(|k| at_rest::open(k, &ctx, &stored).ok())
            else {
                report.unreadable += 1;
                continue;
            };
            let sealed = at_rest::seal(to, &ctx, &plain)
                .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
            sqlx::query(&format!("update {table} set {column}=$2 where {id}=$1"))
                .bind(row)
                .bind(sealed)
                .execute(&mut *tx)
                .await?;
            report.resealed += 1;
        }
    }
    tx.commit().await?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelopes_open_with_the_key_their_header_names_only() {
        let installation = Uuid::new_v4();
        let row = Uuid::new_v4();
        let legacy = legacy_key(&[7; 32]);
        let current = identity_key(&[9; 32]);
        let sealed = seal(&current, installation, "t", "c", row.as_bytes(), b"secret").unwrap();
        let both = [legacy_key(&[7; 32]), identity_key(&[9; 32])];
        assert_eq!(
            open(&both, installation, "t", "c", row.as_bytes(), &sealed).as_deref(),
            Some(&b"secret"[..])
        );
        // Another identity key with the same id does not open it, nor does the legacy key.
        assert!(open(
            &[identity_key(&[8; 32])],
            installation,
            "t",
            "c",
            row.as_bytes(),
            &sealed
        )
        .is_none());
        assert!(open(&[legacy], installation, "t", "c", row.as_bytes(), &sealed).is_none());
        // Moved to another row: refused.
        let other = Uuid::new_v4();
        assert!(open(&both, installation, "t", "c", other.as_bytes(), &sealed).is_none());
        // The legacy derivation never changes (existing envelopes depend on it).
        let old = seal(
            &legacy_key(&[7; 32]),
            installation,
            "t",
            "c",
            row.as_bytes(),
            b"x",
        )
        .unwrap();
        assert_eq!(Header::parse(&old).unwrap().dek_id, LEGACY_KEY_ID);
        assert_eq!(Header::parse(&sealed).unwrap().dek_id, IDENTITY_KEY_ID);
    }
}
