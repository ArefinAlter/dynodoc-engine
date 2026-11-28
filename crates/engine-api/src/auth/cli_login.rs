//! Browser-assisted CLI device login (RFC 8628-style with Ed25519 proof-of-possession).
//!
//! 1. `POST /auth/cli-login/start` (public, rate-limited) registers a pending request for
//!    an Ed25519 public key and returns a short-lived `device_code`, a human-readable
//!    `user_code` (`ABCD-EFGH`), a `challenge_nonce`, and the server's authority identity.
//! 2. The user visits `/cli-login?code=ABCD-EFGH` in their browser, signs in if needed,
//!    verifies the code & key fingerprint, and clicks Approve. The web server calls
//!    `GET /auth/cli-login/lookup` and `POST /auth/cli-login/approve` with the user's
//!    browser PASETO session (device/OAuth sessions are refused).
//! 3. `POST /auth/cli-login/poll` submits `device_code` and an Ed25519 signature over the
//!    `challenge_nonce` + `public_key`. Once approved, the server atomically consumes the
//!    request, verifies proof-of-possession, enrolls the `device_signing_key`, and returns
//!    the enrolled `key_id` and account summary.

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use engine_core::repository::device::validate_public_key;
use engine_core::repository::server_authority;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, Ed25519KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use super::{random_token, sha256, AuthContext};
use crate::devices::account_lock;
use crate::error::ApiError;
use crate::AppState;

/// A CLI login request expires after 5 minutes (database clock).
pub const REQUEST_TTL_SECONDS: i64 = 300;
/// Recommended client poll interval in seconds.
pub const POLL_INTERVAL_SECONDS: u64 = 3;
/// Maximum pending requests allowed per public key within the rate window.
const MAX_STARTS_PER_WINDOW: i32 = 20;
const DOMAIN: &[u8] = b"dynodoc.cli-login\0v1\0";
/// Ambiguity-free Crockford-style alphabet (excludes 0, 1, I, O).
const CODE_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/cli-login/start", post(start))
        .route("/auth/cli-login/lookup", get(lookup))
        .route("/auth/cli-login/approve", post(approve))
        .route("/auth/cli-login/poll", post(poll))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StartRequest {
    /// Lowercase 64-hex Ed25519 public key to enroll.
    pub public_key: String,
    /// Optional human-readable device label (1..=80 chars, no control characters).
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct StartResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_path: String,
    pub expires_in: i64,
    pub interval: u64,
    pub challenge: String,
    pub authority: Uuid,
    pub authority_public_key: Option<String>,
}

#[derive(Deserialize)]
pub struct LookupQuery {
    pub code: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct LookupResponse {
    pub user_code: String,
    pub label: String,
    pub public_key: String,
    pub fingerprint: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    pub user_code: String,
    /// `"approve"` or `"deny"`.
    pub decision: String,
    #[serde(default)]
    pub all_projects: bool,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PollRequest {
    pub device_code: String,
    /// Lowercase 128-hex Ed25519 signature over `canonical_message(challenge, public_key)`.
    pub signature: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct PollResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_access: Option<String>,
}

fn bad(reason: &str) -> ApiError {
    ApiError::BadRequest {
        reason: reason.into(),
    }
}

fn sanitize_label(raw: Option<&str>) -> Result<String, ApiError> {
    let trimmed = raw.map(str::trim).filter(|s| !s.is_empty());
    match trimmed {
        None => Ok("dynodoc-cli".to_owned()),
        Some(s) if s.chars().count() <= 80 && !s.chars().any(char::is_control) => Ok(s.to_owned()),
        Some(_) => Err(bad(
            "label must be 1 to 80 characters without control characters",
        )),
    }
}

pub fn normalize_user_code(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .trim()
        .to_ascii_uppercase()
        .chars()
        .filter(|c| *c != '-' && !c.is_whitespace())
        .map(|c| match c {
            '0' => 'O',
            '1' => 'I',
            other => other,
        })
        .collect();
    if cleaned.len() != 8 || !cleaned.bytes().all(|b| CODE_ALPHABET.contains(&b)) {
        return None;
    }
    Some(format!("{}-{}", &cleaned[..4], &cleaned[4..]))
}

fn generate_user_code() -> Result<String, ApiError> {
    let mut bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| ApiError::Internal("csprng failure".into()))?;
    let mut out = String::with_capacity(9);
    for (idx, b) in bytes.iter().enumerate() {
        if idx == 4 {
            out.push('-');
        }
        out.push(CODE_ALPHABET[(b & 31) as usize] as char);
    }
    Ok(out)
}

pub fn canonical_message(challenge: &str, public_key: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DOMAIN.len() + challenge.len() + 1 + public_key.len());
    msg.extend_from_slice(DOMAIN);
    msg.extend_from_slice(challenge.as_bytes());
    msg.push(0);
    msg.extend_from_slice(public_key.as_bytes());
    msg
}

pub fn verify_proof(public_key: &str, challenge: &str, signature_hex: &str) -> bool {
    let Ok(pk) = hex::decode(public_key) else {
        return false;
    };
    let Ok(sig) = hex::decode(signature_hex) else {
        return false;
    };
    if pk.len() != 32 || sig.len() != 64 {
        return false;
    }
    let msg = canonical_message(challenge, public_key);
    signature::UnparsedPublicKey::new(&signature::ED25519, &pk)
        .verify(&msg, &sig)
        .is_ok()
}

pub fn key_fingerprint(public_key: &str) -> String {
    let digest = sha256(public_key.as_bytes());
    let hex_digest = hex::encode(&digest[..8]);
    format!(
        "{}-{}-{}-{}",
        &hex_digest[0..4],
        &hex_digest[4..8],
        &hex_digest[8..12],
        &hex_digest[12..16]
    )
}

#[utoipa::path(
    operation_id = "cli_login_start",
    post,
    path = "/auth/cli-login/start",
    request_body = StartRequest,
    responses(
        (status = 200, description = "Pending CLI login request", body = StartResponse),
        (status = 400, description = "Invalid public key or label"),
        (status = 429, description = "Rate limit exceeded")
    ),
    tag = "auth"
)]
pub async fn start(
    State(state): State<AppState>,
    Json(req): Json<StartRequest>,
) -> Result<Json<StartResponse>, ApiError> {
    validate_public_key(&req.public_key)
        .map_err(|_| bad("Use a lowercase hexadecimal Ed25519 public key"))?;
    let label = sanitize_label(req.label.as_deref())?;

    let mut tx = state.pool.begin().await?;
    let window_key = sha256(format!("cli-login-start-v1:{}", req.public_key).as_bytes());
    let attempts: i32 = sqlx::query_scalar(
        "insert into auth_request_window(key_hash) values($1)
         on conflict(key_hash) do update set
           attempts = case when auth_request_window.started_at < now()-interval '15 minutes' then 1 else least(auth_request_window.attempts+1, 100) end,
           started_at = case when auth_request_window.started_at < now()-interval '15 minutes' then now() else auth_request_window.started_at end
         returning attempts",
    )
    .bind(window_key)
    .fetch_one(&mut *tx)
    .await?;
    if attempts > MAX_STARTS_PER_WINDOW {
        tx.commit().await?;
        return Err(ApiError::RateLimited { retry_after: 900 });
    }

    let already_enrolled: bool =
        sqlx::query_scalar("select exists(select 1 from device_signing_key where public_key=$1)")
            .bind(&req.public_key)
            .fetch_one(&mut *tx)
            .await?;
    if already_enrolled {
        return Err(ApiError::Conflict {
            reason: "This public key is already enrolled; generate a fresh device key".into(),
        });
    }

    let authority: Uuid = sqlx::query_scalar("select id from device_authority where singleton")
        .fetch_one(&mut *tx)
        .await?;
    let authority_public_key = server_authority::active(&mut tx)
        .await
        .ok()
        .map(|active| active.public_key);

    let (device_code, device_code_hash) = random_token()?;
    let (challenge, _) = random_token()?;
    let user_code = generate_user_code()?;
    let id = Uuid::new_v4();

    sqlx::query(
        "insert into cli_login_request(id, device_code_hash, user_code, public_key, label, challenge_nonce, status, expires_at)
         values($1, $2, $3, $4, $5, $6, 'pending', now() + make_interval(secs => $7))",
    )
    .bind(id)
    .bind(device_code_hash)
    .bind(&user_code)
    .bind(&req.public_key)
    .bind(&label)
    .bind(&challenge)
    .bind(REQUEST_TTL_SECONDS)
    .execute(&mut *tx)
    .await?;

    crate::product::audit(
        &mut tx,
        id,
        "auth.cli_login.started",
        id,
        json!({"label": label}),
    )
    .await
    .ok();

    tx.commit().await?;

    Ok(Json(StartResponse {
        device_code,
        verification_path: format!("/cli-login?code={user_code}"),
        user_code,
        expires_in: REQUEST_TTL_SECONDS,
        interval: POLL_INTERVAL_SECONDS,
        challenge,
        authority,
        authority_public_key,
    }))
}

#[utoipa::path(
    operation_id = "cli_login_lookup",
    get,
    path = "/auth/cli-login/lookup",
    security(("paseto" = [])),
    responses(
        (status = 200, description = "Pending CLI login details for confirmation", body = LookupResponse),
        (status = 400, description = "Malformed code"),
        (status = 403, description = "Browser session required"),
        (status = 404, description = "Code not found or expired")
    ),
    tag = "auth"
)]
pub async fn lookup(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(query): Query<LookupQuery>,
) -> Result<Json<LookupResponse>, ApiError> {
    if auth.device.is_some() {
        return Err(ApiError::Forbidden);
    }
    let Some(user_code) = normalize_user_code(&query.code) else {
        return Err(bad("Enter the 8-character code shown in your terminal"));
    };
    let row: Option<(String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "select label, public_key, expires_at from cli_login_request
         where user_code=$1 and status='pending' and expires_at > now()
         order by created_at desc limit 1",
    )
    .bind(&user_code)
    .fetch_optional(&state.pool)
    .await?;
    let Some((label, public_key, expires_at)) = row else {
        return Err(ApiError::NotFound);
    };
    let fingerprint = key_fingerprint(&public_key);
    Ok(Json(LookupResponse {
        user_code,
        label,
        public_key,
        fingerprint,
        expires_at,
    }))
}

#[utoipa::path(
    operation_id = "cli_login_approve",
    post,
    path = "/auth/cli-login/approve",
    request_body = ApproveRequest,
    security(("paseto" = [])),
    responses(
        (status = 200, description = "CLI login decision recorded", body = Value),
        (status = 400, description = "Invalid code or decision"),
        (status = 403, description = "Browser session required"),
        (status = 404, description = "Code not found or expired")
    ),
    tag = "auth"
)]
pub async fn approve(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<ApproveRequest>,
) -> Result<Json<Value>, ApiError> {
    if auth.device.is_some() {
        return Err(ApiError::Forbidden);
    }
    let Some(user_code) = normalize_user_code(&req.user_code) else {
        return Err(bad("Invalid CLI login code"));
    };
    let next_status = match req.decision.as_str() {
        "approve" => "approved",
        "deny" => "denied",
        _ => return Err(bad("decision must be approve or deny")),
    };

    let mut tx = state.pool.begin().await?;
    account_lock(&mut tx, &auth).await?;

    let row_id: Option<Uuid> = sqlx::query_scalar(
        "select id from cli_login_request
         where user_code=$1 and status='pending' and expires_at > now()
         order by created_at desc limit 1 for update",
    )
    .bind(&user_code)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row_id) = row_id else {
        return Err(ApiError::NotFound);
    };

    sqlx::query(
        "update cli_login_request
         set status=$2, identity_id=$3, session_generation=$4, grant_all_projects=$5, approved_at=now()
         where id=$1",
    )
    .bind(row_id)
    .bind(next_status)
    .bind(auth.identity_id)
    .bind(auth.session_generation)
    .bind(req.all_projects)
    .execute(&mut *tx)
    .await?;

    crate::product::audit(
        &mut tx,
        auth.identity_id,
        if next_status == "approved" {
            "auth.cli_login.approved"
        } else {
            "auth.cli_login.denied"
        },
        row_id,
        json!({"all_projects": req.all_projects}),
    )
    .await?;

    tx.commit().await?;
    Ok(Json(json!({ "status": next_status })))
}

#[utoipa::path(
    operation_id = "cli_login_poll",
    post,
    path = "/auth/cli-login/poll",
    request_body = PollRequest,
    responses(
        (status = 200, description = "Pending or approved with enrolled key", body = PollResponse),
        (status = 401, description = "Invalid proof-of-possession or expired"),
        (status = 403, description = "Denied by user"),
        (status = 409, description = "Device limit reached or key already enrolled")
    ),
    tag = "auth"
)]
pub async fn poll(
    State(state): State<AppState>,
    Json(req): Json<PollRequest>,
) -> Result<Json<PollResponse>, ApiError> {
    if req.device_code.len() != 64 || !req.device_code.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::Unauthorized);
    }
    let code_hash = sha256(req.device_code.as_bytes());
    let mut tx = state.pool.begin().await?;

    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        public_key: String,
        label: String,
        challenge_nonce: String,
        status: String,
        identity_id: Option<Uuid>,
        session_generation: Option<i32>,
        grant_all_projects: bool,
        expired: bool,
    }

    let row: Option<Row> = sqlx::query_as(
        "select id, public_key, label, challenge_nonce, status, identity_id, session_generation, grant_all_projects, (expires_at <= now()) as expired
         from cli_login_request where device_code_hash=$1 for update",
    )
    .bind(code_hash)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        return Err(ApiError::Unauthorized);
    };
    if row.expired || row.status == "consumed" {
        return Err(ApiError::Unauthorized);
    }
    if row.status == "denied" {
        return Err(ApiError::Forbidden);
    }
    if row.status == "pending" {
        tx.commit().await?;
        return Ok(Json(PollResponse {
            status: "pending".into(),
            key_id: None,
            identity_id: None,
            email: None,
            project_access: None,
        }));
    }

    if !verify_proof(&row.public_key, &row.challenge_nonce, &req.signature) {
        return Err(ApiError::Unauthorized);
    }
    let (Some(identity_id), Some(expected_gen)) = (row.identity_id, row.session_generation) else {
        return Err(ApiError::Unauthorized);
    };

    let active_email: Option<String> = sqlx::query_scalar(
        "select email from identity where id=$1 and disabled_at is null and erased_at is null and session_generation=$2 for update",
    )
    .bind(identity_id)
    .bind(expected_gen)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(email) = active_email else {
        return Err(ApiError::Unauthorized);
    };

    let (total, active): (i64, i64) = sqlx::query_as(
        "select count(*), count(*) filter(where not exists(select 1 from device_key_revocation r where r.key_id=k.id))
         from device_signing_key k where identity_id=$1",
    )
    .bind(identity_id)
    .fetch_one(&mut *tx)
    .await?;
    if total >= 128 || active >= 20 {
        return Err(ApiError::Conflict {
            reason: "Device limit reached".into(),
        });
    }

    let key_id = Uuid::new_v4();
    let proof_json = json!({
        "version": 1,
        "kind": "cli-login",
        "request_id": row.id,
        "public_key": row.public_key,
        "nonce": row.challenge_nonce,
        "signature": req.signature,
    });
    let inserted = sqlx::query(
        "insert into device_signing_key(id, identity_id, public_key, proof) values($1, $2, $3, $4) on conflict do nothing",
    )
    .bind(key_id)
    .bind(identity_id)
    .bind(&row.public_key)
    .bind(proof_json)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(ApiError::Conflict {
            reason: "Key cannot be enrolled; use a fresh key".into(),
        });
    }

    let mode = if row.grant_all_projects {
        "all"
    } else {
        "granted"
    };
    sqlx::query("insert into device_key_access(key_id, project_access) values($1, $2)")
        .bind(key_id)
        .bind(mode)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "insert into device_key_class(key_id, class, label, client_kind) values($1, 'person', $2, null)",
    )
    .bind(key_id)
    .bind(&row.label)
    .execute(&mut *tx)
    .await?;

    sqlx::query("update cli_login_request set status='consumed', consumed_at=now() where id=$1")
        .bind(row.id)
        .execute(&mut *tx)
        .await?;

    crate::product::audit(
        &mut tx,
        identity_id,
        "auth.cli_login.completed",
        key_id,
        json!({"public_key": row.public_key, "project_access": mode, "label": row.label}),
    )
    .await?;

    tx.commit().await?;

    Ok(Json(PollResponse {
        status: "approved".into(),
        key_id: Some(key_id),
        identity_id: Some(identity_id),
        email: Some(email),
        project_access: Some(mode.into()),
    }))
}

#[allow(dead_code)]
fn _check_key_sign_compat(kp: &Ed25519KeyPair, challenge: &str, public_key: &str) -> String {
    hex::encode(kp.sign(&canonical_message(challenge, public_key)).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    #[test]
    fn user_code_normalizes_and_formats() {
        assert_eq!(
            normalize_user_code("abcd-efgh"),
            Some("ABCD-EFGH".to_owned())
        );
        assert_eq!(
            normalize_user_code("  abcd efgh "),
            Some("ABCD-EFGH".to_owned())
        );
        assert_eq!(
            normalize_user_code("23456789"),
            Some("2345-6789".to_owned())
        );
        assert_eq!(normalize_user_code("short"), None);
        assert_eq!(normalize_user_code("ABCD-EFGH-9"), None);
    }

    #[test]
    fn generated_user_codes_are_valid() {
        for _ in 0..32 {
            let code = generate_user_code().unwrap();
            assert_eq!(code.len(), 9);
            assert_eq!(&code[4..5], "-");
            assert_eq!(normalize_user_code(&code), Some(code));
        }
    }

    #[test]
    fn proof_of_possession_verifies_and_rejects_tampering() {
        let kp = Ed25519KeyPair::from_seed_unchecked(&[9u8; 32]).unwrap();
        let pk_hex = hex::encode(kp.public_key().as_ref());
        let challenge = "ab".repeat(32);
        let sig_hex = hex::encode(kp.sign(&canonical_message(&challenge, &pk_hex)).as_ref());
        assert!(verify_proof(&pk_hex, &challenge, &sig_hex));
        assert!(!verify_proof(&pk_hex, &"cd".repeat(32), &sig_hex));
        let other = Ed25519KeyPair::from_seed_unchecked(&[8u8; 32]).unwrap();
        let other_pk = hex::encode(other.public_key().as_ref());
        assert!(!verify_proof(&other_pk, &challenge, &sig_hex));
    }
}
