//! Encrypted projects: the service side (decision 035; docs/E2EE-PROTOCOL-AND-MIGRATION.md
//! sections 4 to 6). Pre-release and not independently reviewed.
//!
//! The service stores device encryption-key bindings, the signed membership log, epoch
//! records and HPKE grants, and checks them without any key: signatures, chain links, the
//! authorization rules of `engine_core::e2ee::records::Log` (the same rules clients replay),
//! roles, and that every grant of a new epoch goes to exactly the recipients the log names.
//! It never receives an epoch root, a document key, a private key or plaintext content.
//!
//! Features that need plaintext answer `422 encrypted_project` with the feature and the
//! client-side alternative ([`refuse_sealed`], matrix in `engine_core::e2ee::features`).
use crate::{
    auth::{
        device::{HistoryRead, ProjectAuth},
        AuthContext,
    },
    devices,
    error::ApiError,
    product::audit,
    projects, AppState,
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use engine_core::e2ee::{
    features,
    grant::{self, Grant, Scope},
    records::{self, Binding, EpochRecord, Log, SignedEntry},
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgConnection, Postgres, Transaction};
use std::collections::BTreeSet;
use uuid::Uuid;

/// A new epoch carries at most this many grants (devices, recovery, escrow, document roots).
const MAX_GRANTS_PER_REQUEST: usize = 512;
/// Grant, log and epoch bytes per project (protocol 12.1 `E2EE_GRANT_BYTES_PER_PROJECT`).
const PROJECT_KEY_BYTES: i64 = 16 * 1024 * 1024;
const PAGE: i64 = 256;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/capabilities", get(capabilities))
        .route("/devices/{id}/encryption-key", post(register_key))
        .route("/projects/{id}/e2ee", get(status))
        .route("/projects/{id}/e2ee/directory", get(directory))
        .route("/projects/{id}/e2ee/begin", post(begin))
        .route("/projects/{id}/e2ee/log", get(log_list).post(log_append))
        .route(
            "/projects/{id}/e2ee/epochs",
            get(epochs_list).post(epoch_open),
        )
        .route(
            "/projects/{id}/e2ee/grants",
            get(grants_list).post(grants_add),
        )
        .route("/projects/{id}/e2ee/documents", post(document_create))
        .route("/projects/{id}/e2ee/complete", post(complete))
        .route(
            "/documents/{id}/e2ee/legacy-erasure",
            post(legacy_erasure_request),
        )
        .route("/admin/e2ee/legacy-erasures", get(legacy_erasure_list))
        .route(
            "/admin/e2ee/legacy-erasures/{id}/confirm",
            post(legacy_erasure_confirm),
        )
        .route(
            "/connector/documents/{id}/e2ee/grants",
            get(connector_grants),
        )
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
}

fn bad(reason: &str) -> ApiError {
    ApiError::BadRequest {
        reason: reason.into(),
    }
}
fn coded(status: StatusCode, code: &'static str, reason: &str, details: Value) -> ApiError {
    ApiError::Coded {
        status,
        code,
        reason: reason.into(),
        details,
    }
}
fn refused(error: engine_core::e2ee::Error) -> ApiError {
    // The message names the rule, never key bytes or content.
    bad(&format!("Refused by the encrypted-project rules: {error}"))
}

/// `422 encrypted_project` for a feature that needs plaintext on the service.
pub(crate) fn encrypted_project(feature: &str) -> ApiError {
    let row = features::feature(feature);
    coded(
        StatusCode::UNPROCESSABLE_ENTITY,
        "encrypted_project",
        "This file is in an encrypted project (pre-release, not independently reviewed): the service holds only ciphertext and cannot do this. Use the named alternative on your device.",
        json!({"feature": feature, "alternative": row.map_or("", |r| r.alternative), "phase": row.map_or("", |r| r.phase)}),
    )
}

/// Refuse `feature` for a document whose content the service cannot read: a sealed document,
/// or a ledger document with keyed block hashes.
pub(crate) async fn refuse_sealed(
    db: &mut PgConnection,
    document: Uuid,
    feature: &str,
) -> Result<(), ApiError> {
    if sealed_document(db, document).await? {
        return Err(encrypted_project(feature));
    }
    Ok(())
}

pub(crate) async fn sealed_document(
    db: &mut PgConnection,
    document: Uuid,
) -> Result<bool, ApiError> {
    Ok(sqlx::query_scalar("select exists(select 1 from document d where d.id=$1 and (d.encryption='sealed' or exists(select 1 from document_storage s where s.document_id=d.id and s.block_hash_key='keyed')))")
        .bind(document)
        .fetch_one(db)
        .await?)
}

/// `(encryption_mode, current_epoch)` of a project.
pub(crate) async fn mode(db: &mut PgConnection, project: Uuid) -> Result<(String, i32), ApiError> {
    sqlx::query_as("select encryption_mode,current_epoch from project_settings where space_id=$1")
        .bind(project)
        .fetch_optional(db)
        .await?
        .ok_or(ApiError::NotFound)
}

#[utoipa::path(get, path="/capabilities", responses((status=200, description="Encrypted-project formats and suites this server stores and checks", body=Value)))]
async fn capabilities(State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    // The installation id clients bind their encryption keys to (not secret).
    let installation: Uuid = sqlx::query_scalar("select id from device_authority where singleton")
        .fetch_one(&s.pool)
        .await?;
    Ok(Json(json!({"installation": installation, "e2ee": {
        "formats": ["seal-1", "typed-4", "commit-4"],
        "suites": [engine_core::e2ee::seal::SUITE],
        "grant_suite": {"kem": 32, "kdf": 1, "aead": 2},
        "relay_encodings": ["x25519-aes256gcm-v1"],
        "create": s.e2ee_create,
        "status": "pre-release, not independently reviewed",
    }})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterKey {
    public_key: String,
    binding: Binding,
    signature: String,
}

#[utoipa::path(post, path="/devices/{id}/encryption-key", params(("id"=Uuid,Path)), request_body=Value, security(("paseto"=[])), responses((status=201, description="X25519 key bound to this active signing key of yours", body=Value),(status=400, description="Binding or signature invalid"),(status=403, description="Not your active key"),(status=409, description="This signing key already has an encryption key")))]
async fn register_key(
    State(s): State<AppState>,
    auth: AuthContext,
    Path(key_id): Path<Uuid>,
    Json(input): Json<RegisterKey>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let mut tx = s.pool.begin().await?;
    devices::account_lock(&mut tx, &auth).await?;
    let signing: Option<String> = sqlx::query_scalar("select k.public_key from device_signing_key k where k.id=$1 and k.identity_id=$2 and not exists(select 1 from device_key_revocation r where r.key_id=k.id)")
        .bind(key_id).bind(auth.identity_id).fetch_optional(&mut *tx).await?;
    let signing = signing.ok_or(ApiError::Forbidden)?;
    let authority: Uuid = sqlx::query_scalar("select id from device_authority where singleton")
        .fetch_one(&mut *tx)
        .await?;
    let b = &input.binding;
    if b.identity != auth.identity_id
        || b.authority != authority
        || b.signing_key != signing
        || b.encryption_key != input.public_key
    {
        return Err(bad("The binding must name this installation, your account, this signing key and the encryption key"));
    }
    b.verify(&input.signature).map_err(refused)?;
    let (_, digits) = records::fingerprint(&b.signing_key, &b.encryption_key).map_err(refused)?;
    // Either key of a device rotates without the other (decision 035, OQ-CR-5): a signing key
    // may bind a new encryption key (the newest is current), and a new signing key may bind the
    // encryption key it kept. Another account's encryption key is never bound.
    let id: Option<Uuid> = sqlx::query_scalar("insert into device_encryption_key(signing_key_id,identity_id,public_key,binding,signature) select $1,$2,$3,$4,$5 where not exists(select 1 from device_encryption_key o where o.public_key=$3 and (o.identity_id<>$2 or o.signing_key_id=$1)) on conflict do nothing returning id")
        .bind(key_id).bind(auth.identity_id).bind(&input.public_key).bind(json!(b)).bind(&input.signature)
        .fetch_optional(&mut *tx).await?;
    let id = id.ok_or_else(|| ApiError::Conflict {
        reason: "This encryption key is already bound to this signing key, or to another account"
            .into(),
    })?;
    audit(
        &mut tx,
        auth.identity_id,
        "e2ee.encryption_key_registered",
        id,
        json!({"signing_key_id": key_id}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id": id, "fingerprint": digits})),
    ))
}

async fn entries(db: &mut PgConnection, project: Uuid) -> Result<Vec<SignedEntry>, ApiError> {
    let bodies: Vec<Vec<u8>> =
        sqlx::query_scalar("select body from project_e2ee_log where project_id=$1 order by index")
            .bind(project)
            .fetch_all(db)
            .await?;
    bodies
        .iter()
        .map(|b| serde_json::from_slice(b).map_err(|e| ApiError::Internal(e.to_string())))
        .collect()
}

/// The project's membership as its stored, verified log states it.
async fn replay(db: &mut PgConnection, project: Uuid) -> Result<Log, ApiError> {
    Log::replay(project, &entries(db, project).await?)
        .map_err(|e| ApiError::Internal(format!("stored membership log no longer verifies: {e}")))
}

async fn insert_entry(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    signed: &SignedEntry,
    hash: [u8; 32],
) -> Result<i64, ApiError> {
    let body = serde_json::to_vec(signed).map_err(|e| ApiError::Internal(e.to_string()))?;
    let index = signed.entry.index as i64;
    sqlx::query("insert into project_e2ee_log(project_id,index,entry_hash,previous_hash,entry_type,body,signer_key) values($1,$2,$3,$4,$5,$6,$7)")
        .bind(project).bind(index).bind(hex::encode(hash)).bind(&signed.entry.previous)
        .bind(&signed.entry.entry_type).bind(body).bind(&signed.entry.signer_key)
        .execute(&mut **tx).await?;
    Ok(index)
}

/// Grant, log and epoch bytes stay within the per-project budget.
async fn budget(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    adding: usize,
) -> Result<(), ApiError> {
    let used: i64 = sqlx::query_scalar("select coalesce((select sum(octet_length(body)) from project_e2ee_log where project_id=$1),0)::bigint + coalesce((select sum(octet_length(record)) from project_key_epoch where project_id=$1),0)::bigint + coalesce((select sum(octet_length(grant_body)) from project_key_grant where project_id=$1),0)::bigint")
        .bind(project).fetch_one(&mut **tx).await?;
    if used + adding as i64 > PROJECT_KEY_BYTES {
        return Err(ApiError::StorageLimit);
    }
    Ok(())
}

/// The caller's own active signing key, as the service knows it.
async fn own_key(tx: &mut Transaction<'_, Postgres>, me: Uuid, key: &str) -> Result<(), ApiError> {
    devices::current_key(tx, me, key).await.map(|_| ())
}

/// An active signing key of `who` whose registered encryption key is `enc`.
async fn bound(
    tx: &mut Transaction<'_, Postgres>,
    who: Uuid,
    signing: &str,
    enc: &str,
) -> Result<Uuid, ApiError> {
    sqlx::query_scalar("select e.id from device_encryption_key e join device_signing_key k on k.id=e.signing_key_id where e.identity_id=$1 and k.identity_id=$1 and k.public_key=$2 and e.public_key=$3 and not exists(select 1 from device_key_revocation r where r.key_id=k.id) and not exists(select 1 from device_encryption_key n where n.signing_key_id=e.signing_key_id and n.registered_at>e.registered_at)")
        .bind(who).bind(signing).bind(enc).fetch_optional(&mut **tx).await?
        .ok_or_else(|| bad("That device is not an active, registered device of that member"))
}

async fn server_role(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    who: Uuid,
) -> Result<Option<String>, ApiError> {
    Ok(
        sqlx::query_scalar::<_, Option<String>>("select inherited_space_role($1,$2)")
            .bind(project)
            .bind(who)
            .fetch_one(&mut **tx)
            .await?,
    )
}

#[utoipa::path(get, path="/projects/{id}/e2ee", params(("id"=Uuid,Path)), security(("paseto"=[]),("device_session"=["history:read"])), responses((status=200, description="Mode, epoch, log head and policy flags; no secrets", body=Value)))]
async fn status(
    State(s): State<AppState>,
    auth: ProjectAuth<HistoryRead>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let mut db = s.pool.acquire().await?;
    projects::require(&mut db, id, auth.identity_id).await?;
    let row: (String, i32, bool, bool, String, bool) = sqlx::query_as("select encryption_mode,current_epoch,sealed_name,escrow_required,agent_delegation,rotation_pending from project_settings where space_id=$1")
        .bind(id).fetch_one(&mut *db).await?;
    let head: Option<(i64, String)> = sqlx::query_as("select index,entry_hash from project_e2ee_log where project_id=$1 order by index desc limit 1")
        .bind(id).fetch_optional(&mut *db).await?;
    let legacy: i64 = sqlx::query_scalar("select count(*) from document d where document_project(d.id)=$1 and d.deleted_at is null and d.encryption='none' and not exists(select 1 from document_storage s where s.document_id=d.id and s.block_hash_key='keyed')")
        .bind(id).fetch_one(&mut *db).await?;
    Ok(Json(json!({
        "mode": row.0, "current_epoch": row.1, "sealed_name": row.2, "escrow_required": row.3,
        "agent_delegation": row.4, "rotation_pending": row.5,
        "log_head": head.map(|(i, h)| json!({"index": i, "hash": h})),
        "legacy_plaintext_files": if row.0 == "none" { 0 } else { legacy },
        "label": "Encrypted project (pre-release, not independently reviewed)",
    })))
}

#[utoipa::path(get, path="/projects/{id}/e2ee/directory", params(("id"=Uuid,Path)), security(("paseto"=[]),("device_session"=["history:read"])), responses((status=200, description="Members' active device encryption keys with bindings and fingerprints; clients verify them against the signed log", body=Value)))]
async fn directory(
    State(s): State<AppState>,
    auth: ProjectAuth<HistoryRead>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let mut db = s.pool.acquire().await?;
    projects::require(&mut db, id, auth.identity_id).await?;
    let rows: Vec<(Uuid, Uuid, String, Value, String, Option<String>)> = sqlx::query_as("select e.id,e.identity_id,e.public_key,e.binding,e.signature,inherited_space_role($1,e.identity_id) from device_encryption_key e join device_signing_key k on k.id=e.signing_key_id where not exists(select 1 from device_key_revocation r where r.key_id=k.id) and not exists(select 1 from device_encryption_key n where n.signing_key_id=e.signing_key_id and n.registered_at>e.registered_at) and inherited_space_role($1,e.identity_id) is not null order by e.identity_id,e.registered_at limit 2000")
        .bind(id).fetch_all(&mut *db).await?;
    let devices: Vec<Value> = rows
        .into_iter()
        .map(|(device, identity, key, binding, signature, role)| {
            let digits = binding["signing_key"]
                .as_str()
                .and_then(|sk| records::fingerprint(sk, &key).ok())
                .map(|(_, d)| d);
            json!({"device": device, "identity": identity, "role": role, "encryption_key": key, "binding": binding, "signature": signature, "fingerprint": digits})
        })
        .collect();
    Ok(Json(json!({"devices": devices})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Begin {
    genesis: SignedEntry,
}

#[utoipa::path(post, path="/projects/{id}/e2ee/begin", params(("id"=Uuid,Path)), request_body=Value, security(("paseto"=[])), responses((status=201, description="Mode migrating; the signed genesis entry stored", body=Value),(status=403, description="Owners only, or creation not enabled on this server"),(status=409, description="Already encrypted or migrating")))]
async fn begin(
    State(s): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<Begin>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    if !s.e2ee_create {
        return Err(ApiError::Denied {
            reason: "Encrypted projects (pre-release) are not enabled on this server".into(),
        });
    }
    let mut tx = s.pool.begin().await?;
    devices::account_lock(&mut tx, &auth).await?;
    if projects::lock(&mut tx, id, auth.identity_id).await? != "owner" {
        return Err(ApiError::Forbidden);
    }
    let (current, _) = mode(&mut tx, id).await?;
    if current != "none" {
        return Err(ApiError::Conflict {
            reason: "This project is already encrypted or migrating".into(),
        });
    }
    let g = &input.genesis.entry;
    let body = &g.body;
    if g.entry_type != "genesis" || body["identity"].as_str() != Some(&auth.identity_id.to_string())
    {
        return Err(bad("The genesis entry names its owner, the caller"));
    }
    own_key(&mut tx, auth.identity_id, &g.signer_key).await?;
    bound(
        &mut tx,
        auth.identity_id,
        &g.signer_key,
        body["encryption_key"].as_str().unwrap_or_default(),
    )
    .await?;
    let mut log = Log::new(id);
    let hash = log.append(&input.genesis).map_err(refused)?;
    budget(&mut tx, id, 0).await?;
    insert_entry(&mut tx, id, &input.genesis, hash).await?;
    sqlx::query("update project_settings set encryption_mode='migrating' where space_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "insert into project_e2ee_migration(project_id,direction,started_by) values($1,'seal',$2)",
    )
    .bind(id)
    .bind(auth.identity_id)
    .execute(&mut *tx)
    .await?;
    audit(&mut tx, auth.identity_id, "e2ee.begun", id, json!({})).await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"mode": "migrating", "log_index": 0})),
    ))
}

#[derive(Deserialize)]
struct After {
    after: Option<i64>,
}

#[utoipa::path(get, path="/projects/{id}/e2ee/log", params(("id"=Uuid,Path),("after"=Option<i64>,Query)), security(("paseto"=[]),("device_session"=["history:read"])), responses((status=200, description="Signed membership log entries in order, at most 256", body=Value)))]
async fn log_list(
    State(s): State<AppState>,
    auth: ProjectAuth<HistoryRead>,
    Path(id): Path<Uuid>,
    Query(q): Query<After>,
) -> Result<Json<Value>, ApiError> {
    let mut db = s.pool.acquire().await?;
    projects::require(&mut db, id, auth.identity_id).await?;
    let bodies: Vec<(i64, Vec<u8>)> = sqlx::query_as("select index,body from project_e2ee_log where project_id=$1 and index>$2 order by index limit $3")
        .bind(id).bind(q.after.unwrap_or(-1)).bind(PAGE).fetch_all(&mut *db).await?;
    let more = bodies.len() as i64 == PAGE;
    let entries: Vec<Value> = bodies
        .iter()
        .map(|(_, b)| serde_json::from_slice(b).unwrap_or(Value::Null))
        .collect();
    Ok(Json(json!({"entries": entries, "more": more})))
}

/// The entry types appended by [`log_append`]; the others have their own atomic routes.
const APPENDABLE: [&str; 13] = [
    "member_add",
    "role_change",
    "device_add",
    "device_revoke",
    "recovery_set",
    "escrow_set",
    "escrow_clear",
    "escrow_backfill",
    "escrow_recover",
    "policy_change",
    "agent_grant",
    "agent_revoke",
    "owner_transfer",
];

/// Server-side checks of an entry against the service's own records (roles, keys), after the
/// log's rules accepted it.
async fn mirror(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    me: Uuid,
    log: &Log,
    signed: &SignedEntry,
) -> Result<(), ApiError> {
    let e = &signed.entry;
    let recovery_signer = log
        .recovery
        .get(&e.signer_key)
        .is_some_and(|(who, _)| *who == me);
    if !recovery_signer {
        own_key(tx, me, &e.signer_key).await?;
    }
    let who = || -> Result<Uuid, ApiError> {
        e.body["identity"]
            .as_str()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| bad("identity"))
    };
    match e.entry_type.as_str() {
        "member_add" | "role_change" => {
            let who = who()?;
            if server_role(tx, project, who).await?.as_deref() != e.body["role"].as_str() {
                return Err(bad("The entry's role must be the member's role in this project: add or change the member first"));
            }
            for d in e.body["devices"].as_array().into_iter().flatten() {
                bound(
                    tx,
                    who,
                    d["signing_key"].as_str().unwrap_or_default(),
                    d["encryption_key"].as_str().unwrap_or_default(),
                )
                .await?;
            }
        }
        "device_add" => {
            bound(
                tx,
                who()?,
                e.body["signing_key"].as_str().unwrap_or_default(),
                e.body["encryption_key"].as_str().unwrap_or_default(),
            )
            .await?;
        }
        "device_revoke" => {
            sqlx::query("update project_settings set rotation_pending=true where space_id=$1")
                .bind(project)
                .execute(&mut **tx)
                .await?;
        }
        "agent_grant" => {
            let policy: String = sqlx::query_scalar(
                "select agent_delegation from project_settings where space_id=$1",
            )
            .bind(project)
            .fetch_one(&mut **tx)
            .await?;
            if policy == "none" {
                return Err(ApiError::Denied {
                    reason: "This project's policy does not allow delegating keys to agents".into(),
                });
            }
        }
        "policy_change" => {
            if let Some(p) = e.body["agent_delegation"].as_str() {
                if !["none", "local_only", "export_allowed"].contains(&p) {
                    return Err(bad("agent_delegation"));
                }
                sqlx::query("update project_settings set agent_delegation=$2 where space_id=$1")
                    .bind(project)
                    .bind(p)
                    .execute(&mut **tx)
                    .await?;
            }
        }
        "owner_transfer" if server_role(tx, project, who()?).await?.as_deref() != Some("owner") => {
            return Err(bad("Make the new owner an owner of the project first"));
        }
        _ => {}
    }
    Ok(())
}

#[utoipa::path(post, path="/projects/{id}/e2ee/log", params(("id"=Uuid,Path)), request_body=Value, security(("paseto"=[])), responses((status=201, description="Entry verified by the log's rules and the service's records, then stored", body=Value),(status=400, description="Refused by a rule"),(status=409, description="The log moved; fetch and re-sign")))]
async fn log_append(
    State(s): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(signed): Json<SignedEntry>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    if !APPENDABLE.contains(&signed.entry.entry_type.as_str()) {
        return Err(bad(
            "This entry type has its own route (begin, epochs, complete)",
        ));
    }
    let mut tx = s.pool.begin().await?;
    devices::account_lock(&mut tx, &auth).await?;
    projects::lock(&mut tx, id, auth.identity_id).await?;
    if mode(&mut tx, id).await?.0 == "none" {
        return Err(bad("This project is not encrypted"));
    }
    let mut log = replay(&mut tx, id).await?;
    if signed.entry.index != log.length {
        return Err(ApiError::Conflict {
            reason: "The membership log moved; fetch it and sign again".into(),
        });
    }
    let hash = log.append(&signed).map_err(refused)?;
    mirror(&mut tx, id, auth.identity_id, &log, &signed).await?;
    budget(&mut tx, id, 0).await?;
    let index = insert_entry(&mut tx, id, &signed, hash).await?;
    audit(
        &mut tx,
        auth.identity_id,
        "e2ee.log_appended",
        id,
        json!({"type": signed.entry.entry_type, "index": index}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"index": index, "hash": hex::encode(hash)})),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenEpoch {
    record: EpochRecord,
    signature: String,
    log_entry: SignedEntry,
    grants: Vec<Grant>,
    /// A signed `member_remove` or `device_revoke`, applied in the same transaction so a
    /// removed party never receives the new epoch (clients document 10.3).
    #[serde(default)]
    removal: Option<SignedEntry>,
}

async fn stored_grant(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    g: &Grant,
) -> Result<(), ApiError> {
    let body = serde_json::to_vec(g).map_err(|e| ApiError::Internal(e.to_string()))?;
    let document = match &g.scope {
        Scope::Project => None,
        Scope::Document { document } => Some(*document),
    };
    let inserted = sqlx::query("insert into project_key_grant(project_id,epoch,scope_document,recipient_kind,recipient_key,recipient_device,grant_body,created_by_key) values($1,$2,$3,$4,$5,$6,$7,$8) on conflict do nothing")
        .bind(project).bind(g.epoch as i32).bind(document).bind(&g.recipient_kind).bind(&g.recipient_key)
        .bind(g.recipient_device).bind(body).bind(&g.created_by_key)
        .execute(&mut **tx).await?.rows_affected();
    if inserted == 0 {
        return Err(ApiError::Conflict {
            reason: "A grant for that recipient, epoch and scope already exists".into(),
        });
    }
    Ok(())
}

/// Checks every grant shares: shape, creator signature, project, epoch and record.
fn check_grant(
    g: &Grant,
    project: Uuid,
    epoch: u32,
    record_hash: &str,
    creator: &str,
) -> Result<(), ApiError> {
    g.verify(creator).map_err(refused)?;
    if g.project != project || g.epoch != epoch || g.epoch_record != record_hash {
        return Err(bad("A grant names another project, epoch or epoch record"));
    }
    Ok(())
}

/// A device grant goes to a registered, non-revoked key of a current member, and the
/// recipient device row matches the key.
async fn device_recipient(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    g: &Grant,
) -> Result<Uuid, ApiError> {
    let who: Option<Uuid> = sqlx::query_scalar("select e.identity_id from device_encryption_key e join device_signing_key k on k.id=e.signing_key_id where e.id=$1 and e.public_key=$2 and not exists(select 1 from device_key_revocation r where r.key_id=k.id) and inherited_space_role($3,e.identity_id) is not null")
        .bind(g.recipient_device).bind(&g.recipient_key).bind(project).fetch_optional(&mut **tx).await?;
    who.ok_or_else(|| bad("A device grant must go to an active device of a current member"))
}

#[utoipa::path(post, path="/projects/{id}/e2ee/epochs", params(("id"=Uuid,Path)), request_body=Value, security(("paseto"=[])), responses((status=201, description="Epoch e+1 with its record, log entry and grants stored atomically; with `removal`, the member or device is removed in the same transaction", body=Value),(status=409, description="epoch_conflict: not exactly current + 1"),(status=422, description="recipient_set_mismatch")))]
async fn epoch_open(
    State(s): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<OpenEpoch>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    if input.grants.is_empty() || input.grants.len() > MAX_GRANTS_PER_REQUEST {
        return Err(bad("An epoch carries 1 to 512 grants"));
    }
    let mut tx = s.pool.begin().await?;
    devices::account_lock(&mut tx, &auth).await?;
    let role = projects::lock(&mut tx, id, auth.identity_id).await?;
    if !matches!(role.as_str(), "owner" | "manager") {
        return Err(ApiError::Forbidden);
    }
    let (current_mode, current) = mode(&mut tx, id).await?;
    if current_mode == "none" {
        return Err(bad("Begin encryption first"));
    }
    let r = &input.record;
    if r.epoch as i64 != current as i64 + 1 {
        return Err(coded(
            StatusCode::CONFLICT,
            "epoch_conflict",
            "Open exactly the next epoch",
            json!({"current": current}),
        ));
    }
    r.verify(&input.signature).map_err(refused)?;
    own_key(&mut tx, auth.identity_id, &r.created_by_key).await?;
    let previous: Option<String> = sqlx::query_scalar(
        "select record_hash from project_key_epoch where project_id=$1 and epoch=$2",
    )
    .bind(id)
    .bind(current)
    .fetch_optional(&mut *tx)
    .await?;
    if r.project != id || r.previous_epoch_record != previous {
        return Err(bad(
            "The record names another project or previous epoch record",
        ));
    }
    let mut log = replay(&mut tx, id).await?;
    let mut appended = Vec::new();
    let mut removed: Option<Uuid> = None;
    if let Some(removal) = &input.removal {
        if !matches!(
            removal.entry.entry_type.as_str(),
            "member_remove" | "device_revoke"
        ) {
            return Err(bad("A removal is a member_remove or device_revoke entry"));
        }
        own_key(&mut tx, auth.identity_id, &removal.entry.signer_key).await?;
        if removal.entry.entry_type == "member_remove" {
            removed = removal.entry.body["identity"]
                .as_str()
                .and_then(|v| v.parse().ok());
        }
        appended.push((removal.clone(), log.append(removal).map_err(refused)?));
    }
    // The record binds the membership the author saw, which must be the latest.
    if Some(r.membership_head.as_str()) != log.head.map(hex::encode).as_deref() {
        return Err(ApiError::Conflict {
            reason: "The membership log moved; rebuild the recipient set and sign again".into(),
        });
    }
    let e = &input.log_entry;
    let record_hash = hex::encode(r.hash().map_err(refused)?);
    if e.entry.entry_type != "epoch_open"
        || e.entry.signer_key != r.created_by_key
        || e.entry.body["record_hash"].as_str() != Some(&record_hash)
    {
        return Err(bad(
            "The epoch_open entry names this record and is signed by its author",
        ));
    }
    let epoch_entry_hash = log.append(e).map_err(refused)?;
    appended.push((e.clone(), epoch_entry_hash));
    // Grants: signed by the record's author, for this epoch and record, and the project-scope
    // recipients are exactly the log's recipient set (devices, recovery, escrow).
    let mut recipients = BTreeSet::new();
    for g in &input.grants {
        check_grant(g, id, r.epoch, &record_hash, &r.created_by_key)?;
        if g.delegation.is_some() {
            return Err(bad(
                "Delegations are added to an existing epoch, not with it",
            ));
        }
        if matches!(g.scope, Scope::Project) && !recipients.insert(g.recipient_key.clone()) {
            return Err(bad("Two project grants for one recipient"));
        }
        if g.recipient_kind == "device" {
            let who = device_recipient(&mut tx, id, g).await?;
            if Some(who) == removed {
                return Err(bad("A removed member receives no grant"));
            }
        }
    }
    let digest = grant::recipients_digest(&input.grants).map_err(refused)?;
    let expected = log.recipients();
    if digest != r.recipients_digest || recipients != expected {
        return Err(coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            "recipient_set_mismatch",
            "The grants must go to exactly the devices, recovery keys and escrow the membership log names",
            json!({"expected": expected.len(), "supplied": recipients.len()}),
        ));
    }
    let bytes: usize = input
        .grants
        .iter()
        .map(|g| serde_json::to_vec(g).map(|b| b.len()).unwrap_or(0))
        .sum();
    budget(&mut tx, id, bytes + 8192).await?;
    let mut epoch_index = 0;
    for (entry, hash) in &appended {
        epoch_index = insert_entry(&mut tx, id, entry, *hash).await?;
    }
    let record = serde_json::to_vec(r).map_err(|e| ApiError::Internal(e.to_string()))?;
    sqlx::query("insert into project_key_epoch(project_id,epoch,record_hash,record,signature,created_by_key,log_index) values($1,$2,$3,$4,$5,$6,$7)")
        .bind(id).bind(r.epoch as i32).bind(&record_hash).bind(record).bind(&input.signature).bind(&r.created_by_key).bind(epoch_index)
        .execute(&mut *tx).await?;
    for g in &input.grants {
        stored_grant(&mut tx, id, g).await?;
    }
    if let Some(who) = removed {
        // Access ends at the service in the same transaction as the rotation.
        sqlx::query("delete from space_member where space_id=$1 and identity_id=$2")
            .bind(id)
            .bind(who)
            .execute(&mut *tx)
            .await?;
        sqlx::query("update device_key_project_grant set revoked_at=now() where project_id=$1 and revoked_at is null and key_id in (select id from device_signing_key where identity_id=$2)")
            .bind(id).bind(who).execute(&mut *tx).await?;
        sqlx::query("delete from device_session where project_id=$1 and identity_id=$2")
            .bind(id)
            .bind(who)
            .execute(&mut *tx)
            .await?;
        if server_role(&mut tx, id, who).await?.is_some() {
            return Err(bad(
                "That member keeps access through a parent space; remove them there first",
            ));
        }
    }
    sqlx::query(
        "update project_settings set current_epoch=$2, rotation_pending=false where space_id=$1",
    )
    .bind(id)
    .bind(r.epoch as i32)
    .execute(&mut *tx)
    .await?;
    audit(
        &mut tx,
        auth.identity_id,
        "e2ee.epoch_opened",
        id,
        json!({"epoch": r.epoch, "reason": r.reason}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"epoch": r.epoch, "grants": input.grants.len(), "log_index": epoch_index})),
    ))
}

#[derive(Deserialize)]
struct AfterEpoch {
    after: Option<i32>,
}

#[utoipa::path(get, path="/projects/{id}/e2ee/epochs", params(("id"=Uuid,Path),("after"=Option<i32>,Query)), security(("paseto"=[]),("device_session"=["history:read"])), responses((status=200, description="Signed epoch records in order", body=Value)))]
async fn epochs_list(
    State(s): State<AppState>,
    auth: ProjectAuth<HistoryRead>,
    Path(id): Path<Uuid>,
    Query(q): Query<AfterEpoch>,
) -> Result<Json<Value>, ApiError> {
    let mut db = s.pool.acquire().await?;
    projects::require(&mut db, id, auth.identity_id).await?;
    let rows: Vec<(Vec<u8>, String)> = sqlx::query_as("select record,signature from project_key_epoch where project_id=$1 and epoch>$2 order by epoch limit $3")
        .bind(id).bind(q.after.unwrap_or(0)).bind(PAGE).fetch_all(&mut *db).await?;
    let records: Vec<Value> = rows
        .iter()
        .map(|(r, sig)| json!({"record": serde_json::from_slice::<Value>(r).unwrap_or(Value::Null), "signature": sig}))
        .collect();
    Ok(Json(json!({"epochs": records})))
}

#[derive(Deserialize)]
struct GrantQuery {
    recipient_key: String,
    epoch: Option<i32>,
}

/// Grants addressed to `key`: device grants only to the caller's own device; other kinds
/// (recovery, escrow, invitee, agent, add-in) to any current member who names the exact
/// public key. A grant opens only with the private key, so naming the key reveals nothing;
/// a former member is no longer a member and gets nothing.
async fn grants_for(
    db: &mut PgConnection,
    project: Uuid,
    me: Uuid,
    key: &str,
    epoch: Option<i32>,
    document: Option<Uuid>,
) -> Result<Vec<Value>, ApiError> {
    let bodies: Vec<Vec<u8>> = sqlx::query_scalar("select g.grant_body from project_key_grant g where g.project_id=$1 and g.recipient_key=$2 and g.superseded_at is null and ($3::int is null or g.epoch=$3) and ($5::uuid is null or g.scope_document=$5) and (g.recipient_kind<>'device' or exists(select 1 from device_encryption_key e where e.id=g.recipient_device and e.identity_id=$4)) order by g.epoch, g.id limit 1024")
        .bind(project).bind(key).bind(epoch).bind(me).bind(document).fetch_all(db).await?;
    Ok(bodies
        .iter()
        .map(|b| serde_json::from_slice(b).unwrap_or(Value::Null))
        .collect())
}

#[utoipa::path(get, path="/projects/{id}/e2ee/grants", params(("id"=Uuid,Path),("recipient_key"=String,Query),("epoch"=Option<i32>,Query)), security(("paseto"=[]),("device_session"=["history:read"])), responses((status=200, description="Sealed grants addressed to this key; the service cannot open them", body=Value)))]
async fn grants_list(
    State(s): State<AppState>,
    auth: ProjectAuth<HistoryRead>,
    Path(id): Path<Uuid>,
    Query(q): Query<GrantQuery>,
) -> Result<Json<Value>, ApiError> {
    let mut db = s.pool.acquire().await?;
    projects::require(&mut db, id, auth.identity_id).await?;
    let grants = grants_for(
        &mut db,
        id,
        auth.identity_id,
        &q.recipient_key,
        q.epoch,
        None,
    )
    .await?;
    Ok(Json(json!({"grants": grants})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddGrants {
    grants: Vec<Grant>,
}

#[utoipa::path(post, path="/projects/{id}/e2ee/grants", params(("id"=Uuid,Path)), request_body=Value, security(("paseto"=[])), responses((status=201, description="Grants to existing epochs: a new device of a member, recovery, escrow, an invitee or a delegation", body=Value)))]
async fn grants_add(
    State(s): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<AddGrants>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    if input.grants.is_empty() || input.grants.len() > MAX_GRANTS_PER_REQUEST {
        return Err(bad("Add 1 to 512 grants"));
    }
    let mut tx = s.pool.begin().await?;
    devices::account_lock(&mut tx, &auth).await?;
    let role = projects::lock(&mut tx, id, auth.identity_id).await?;
    let log = replay(&mut tx, id).await?;
    let manages = matches!(role.as_str(), "owner" | "manager");
    for g in &input.grants {
        own_key(&mut tx, auth.identity_id, &g.created_by_key).await?;
        if log.signer(&g.created_by_key).is_none() {
            return Err(bad(
                "The grant's creator key is not an active key in the membership log",
            ));
        }
        let hash: Option<String> = sqlx::query_scalar(
            "select record_hash from project_key_epoch where project_id=$1 and epoch=$2",
        )
        .bind(id)
        .bind(g.epoch as i32)
        .fetch_optional(&mut *tx)
        .await?;
        let hash = hash.ok_or_else(|| bad("No such epoch"))?;
        check_grant(g, id, g.epoch, &hash, &g.created_by_key)?;
        if let Scope::Document { document } = &g.scope {
            let here: bool = sqlx::query_scalar("select document_project($1)=$2")
                .bind(document)
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
            if !here {
                return Err(bad("The grant's document is not in this project"));
            }
        }
        match g.recipient_kind.as_str() {
            "device" => {
                let who = device_recipient(&mut tx, id, g).await?;
                if !log.encryption_keys.contains_key(&g.recipient_key) {
                    return Err(bad("Add the device to the membership log first"));
                }
                if who != auth.identity_id && !manages {
                    return Err(ApiError::Forbidden);
                }
            }
            "recovery" if !log.recovery.values().any(|(_, r)| *r == g.recipient_key) => {
                return Err(bad("Register the recovery key in the membership log first"));
            }
            "escrow" if log.escrow.as_deref() != Some(g.recipient_key.as_str()) => {
                return Err(bad("That is not the project's escrow recipient"));
            }
            "invitee" if !manages => return Err(ApiError::Forbidden),
            "agent" | "addin" => {
                let policy: String = sqlx::query_scalar(
                    "select agent_delegation from project_settings where space_id=$1",
                )
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
                if policy == "none" || !matches!(role.as_str(), "owner" | "manager" | "editor") {
                    return Err(ApiError::Denied { reason: "Delegating keys to an agent or add-in needs an editor role and a project policy that allows it".into() });
                }
            }
            _ => {}
        }
    }
    let bytes: usize = input
        .grants
        .iter()
        .map(|g| serde_json::to_vec(g).map(|b| b.len()).unwrap_or(0))
        .sum();
    budget(&mut tx, id, bytes).await?;
    for g in &input.grants {
        stored_grant(&mut tx, id, g).await?;
    }
    audit(
        &mut tx,
        auth.identity_id,
        "e2ee.grants_added",
        id,
        json!({"count": input.grants.len()}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"grants": input.grants.len()})),
    ))
}

#[utoipa::path(post, path="/projects/{id}/e2ee/documents", params(("id"=Uuid,Path)), request_body=Value, security(("paseto"=[])), responses((status=201, description="A sealed file in this project; its title is a placeholder, the real name is sealed in commits", body=Value)))]
async fn document_create(
    State(s): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let mut tx = s.pool.begin().await?;
    devices::account_lock(&mut tx, &auth).await?;
    let role = projects::lock(&mut tx, id, auth.identity_id).await?;
    if !matches!(role.as_str(), "owner" | "manager" | "editor") {
        return Err(ApiError::Forbidden);
    }
    if mode(&mut tx, id).await?.0 == "none" {
        return Err(bad("This project is not encrypted"));
    }
    let doc: Uuid = sqlx::query_scalar("insert into document(title,created_by,space_id,encryption) values('Encrypted file',$1,$2,'sealed') returning id")
        .bind(auth.identity_id).bind(id).fetch_one(&mut *tx).await?;
    sqlx::query("insert into document_access(document_id,identity_id,role) values($1,$2,'author')")
        .bind(doc)
        .bind(auth.identity_id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        auth.identity_id,
        "e2ee.document_created",
        doc,
        json!({"project": id}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id": doc, "encryption": "sealed"})),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Complete {
    entry: SignedEntry,
    /// The project name, typed, when no recovery path beyond one device exists.
    #[serde(default)]
    acknowledge_unrecoverable: Option<String>,
}

#[utoipa::path(post, path="/projects/{id}/e2ee/complete", params(("id"=Uuid,Path)), request_body=Value, security(("paseto"=[])), responses((status=200, description="Mode sealed; legacy plaintext files are archived and labelled", body=Value),(status=409, description="No epoch yet, or live plaintext files remain"),(status=422, description="recovery_required")))]
async fn complete(
    State(s): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<Complete>,
) -> Result<Json<Value>, ApiError> {
    let mut tx = s.pool.begin().await?;
    devices::account_lock(&mut tx, &auth).await?;
    if projects::lock(&mut tx, id, auth.identity_id).await? != "owner" {
        return Err(ApiError::Forbidden);
    }
    let (current_mode, epoch) = mode(&mut tx, id).await?;
    if current_mode != "migrating" || epoch < 1 {
        return Err(ApiError::Conflict {
            reason: "Open the first epoch before completing".into(),
        });
    }
    if input.entry.entry.entry_type != "migration_complete" {
        return Err(bad("Sign a migration_complete entry"));
    }
    own_key(&mut tx, auth.identity_id, &input.entry.entry.signer_key).await?;
    let mut log = replay(&mut tx, id).await?;
    let hash = log.append(&input.entry).map_err(refused)?;
    // Crypto design 11.5: a sole member with one device and no recovery or escrow types the
    // project name to accept that nobody, including the service, can recover the content.
    let one_path = log.recovery.is_empty() && log.escrow.is_none() && log.encryption_keys.len() < 2;
    if one_path {
        let name: String = sqlx::query_scalar("select name from access_space where id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
        if input.acknowledge_unrecoverable.as_deref() != Some(name.as_str()) {
            return Err(coded(StatusCode::UNPROCESSABLE_ENTITY, "recovery_required", "Add a recovery key, a second device or another member, or type the project name to accept that the content cannot be recovered", json!({})));
        }
    }
    let live: i64 = sqlx::query_scalar("select count(*) from document d where document_project(d.id)=$1 and d.deleted_at is null and d.status<>'archived' and d.encryption='none' and not exists(select 1 from document_storage s where s.document_id=d.id and s.block_hash_key='keyed')")
        .bind(id).fetch_one(&mut *tx).await?;
    if live > 0 {
        return Err(coded(
            StatusCode::CONFLICT,
            "legacy_plaintext",
            "Seal or archive every plaintext file first (successor documents)",
            json!({"files": live}),
        ));
    }
    insert_entry(&mut tx, id, &input.entry, hash).await?;
    sqlx::query("update project_settings set encryption_mode='sealed' where space_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("update project_e2ee_migration set step='completed', completed_at=now() where project_id=$1 and completed_at is null").bind(id).execute(&mut *tx).await?;
    audit(
        &mut tx,
        auth.identity_id,
        "e2ee.completed",
        id,
        json!({"epoch": epoch}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"mode": "sealed", "epoch": epoch})))
}

// --- Erasing legacy plaintext (OQ-PR-4; owner decision of 6 November 2026) ----------------

/// A person's own login, never an agent's. Connector keys, OAuth access tokens and device
/// sessions are not logins, so the extractor has already refused them.
async fn person(db: &mut PgConnection, auth: &AuthContext) -> Result<(), ApiError> {
    if auth.device.is_some() || crate::agent::identity::is_agent(db, auth.identity_id).await? {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

/// The project of `document` when it is a legacy plaintext file of a project that completed
/// its move to encryption; otherwise `409 not_legacy_plaintext`.
async fn legacy_project(db: &mut PgConnection, document: Uuid) -> Result<Uuid, ApiError> {
    let project: Option<Uuid> = sqlx::query_scalar("select p.space_id from document d join project_settings p on p.space_id=document_project(d.id) where d.id=$1 and d.encryption='none' and p.encryption_mode='sealed'")
        .bind(document).fetch_optional(db).await?;
    project.ok_or_else(|| {
        coded(
            StatusCode::CONFLICT,
            "not_legacy_plaintext",
            "Only a plaintext file of a project that completed its move to encryption can be erased this way",
            json!({}),
        )
    })
}

#[utoipa::path(post, path="/documents/{id}/e2ee/legacy-erasure", params(("id"=Uuid,Path)), security(("paseto"=[])), responses((status=201, description="Erasure asked for; it waits for an administrator other than you", body=Value),(status=403, description="Not the file's owner, or an agent"),(status=404, description="No such file"),(status=409, description="Not legacy plaintext of an encrypted project, or already asked for")))]
async fn legacy_erasure_request(
    State(s): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let mut tx = s.pool.begin().await?;
    person(&mut tx, &auth).await?;
    // The file's owner: its creator or the project's owner or administrator (0015).
    let access: Option<(Option<String>, bool)> = sqlx::query_as(
        "select effective_document_role(id,$2,true),can_manage_document(id,$2) from document where id=$1 for update",
    )
    .bind(id)
    .bind(auth.identity_id)
    .fetch_optional(&mut *tx)
    .await?;
    match access {
        None | Some((None, _)) => return Err(ApiError::NotFound),
        Some((Some(_), false)) => return Err(ApiError::Forbidden),
        Some((Some(_), true)) => {}
    }
    let project = legacy_project(&mut tx, id).await?;
    let request: Option<Uuid> = sqlx::query_scalar("insert into legacy_erasure_request(document_id,project_id,requested_by) values($1,$2,$3) on conflict do nothing returning id")
        .bind(id).bind(project).bind(auth.identity_id).fetch_optional(&mut *tx).await?;
    let request = request.ok_or_else(|| ApiError::Conflict {
        reason: "An erasure of this file is already waiting for an administrator".into(),
    })?;
    audit(
        &mut tx,
        auth.identity_id,
        "e2ee.legacy_erasure_requested",
        id,
        json!({"request": request, "project": project}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id": request, "status": "waiting_for_administrator"})),
    ))
}

#[utoipa::path(get, path="/admin/e2ee/legacy-erasures", security(("paseto"=[])), responses((status=200, description="Erasures of legacy plaintext waiting for an administrator", body=Value),(status=403, description="Administrators only")))]
async fn legacy_erasure_list(
    State(s): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Value>, ApiError> {
    crate::admin::require_admin(&s, &auth).await?;
    let items: Vec<Value> = sqlx::query_scalar("select jsonb_build_object('id',r.id,'document',r.document_id,'project',r.project_id,'title',d.title,'requested_by',r.requested_by,'requested_at',r.requested_at) from legacy_erasure_request r join document d on d.id=r.document_id where r.confirmed_at is null order by r.requested_at,r.id limit 200")
        .fetch_all(&s.pool).await?;
    Ok(Json(json!({ "items": items })))
}

#[derive(Deserialize)]
struct ConfirmErasure {
    /// The file's title, typed.
    confirmation: String,
    acknowledge_backups: bool,
}

#[utoipa::path(post, path="/admin/e2ee/legacy-erasures/{id}/confirm", params(("id"=Uuid,Path)), request_body=Value, security(("paseto"=[])), responses((status=200, description="The file's plaintext rows and stored objects are erased through the audited whole-document erasure, with its receipt", body=Value),(status=400, description="Confirmation missing"),(status=403, description="Not an administrator, an agent, or the person who asked"),(status=404, description="No waiting request"),(status=409, description="No longer legacy plaintext")))]
async fn legacy_erasure_confirm(
    State(s): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<ConfirmErasure>,
) -> Result<Json<Value>, ApiError> {
    crate::admin::require_admin(&s, &auth).await?;
    let mut tx = s.pool.begin().await?;
    person(&mut tx, &auth).await?;
    let row: Option<(Uuid, Uuid, String)> = sqlx::query_as("select r.document_id,r.requested_by,d.title from legacy_erasure_request r join document d on d.id=r.document_id where r.id=$1 and r.confirmed_at is null for update of r")
        .bind(id).fetch_optional(&mut *tx).await?;
    let (document, requested_by, title) = row.ok_or(ApiError::NotFound)?;
    // Two people: the owner who asked and a different administrator (also a table check).
    if requested_by == auth.identity_id {
        return Err(ApiError::Forbidden);
    }
    if !input.acknowledge_backups || input.confirmation != title {
        return Err(bad(
            "Type the file's title and acknowledge the backup retention policy",
        ));
    }
    legacy_project(&mut tx, document).await?;
    let target = crate::admin_controls::Target {
        kind: "documents".into(),
        id: document,
    };
    let objects = crate::admin_controls::erase_in(
        &mut tx,
        &s,
        auth.identity_id,
        &target,
        "owner_request",
        None,
    )
    .await?;
    sqlx::query("update legacy_erasure_request set confirmed_by=$2,confirmed_at=now() where id=$1")
        .bind(id)
        .bind(auth.identity_id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        auth.identity_id,
        "e2ee.legacy_erasure_confirmed",
        document,
        json!({"request": id, "requested_by": requested_by}),
    )
    .await?;
    tx.commit().await?;
    crate::admin_controls::purge(&s, &target, &objects).await;
    Ok(Json(json!({"erased": document, "receipt_id": document})))
}

#[utoipa::path(get, path="/connector/documents/{id}/e2ee/grants", params(("id"=Uuid,Path),("recipient_key"=String,Query)), security(("connector_key"=[])), responses((status=200, description="Add-in delegation grants for this file and the pane's one-time key", body=Value)))]
async fn connector_grants(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    c: crate::provenance::Connector,
    Query(q): Query<GrantQuery>,
) -> Result<Json<Value>, ApiError> {
    if c.document != id {
        return Err(ApiError::Forbidden);
    }
    let mut db = s.pool.acquire().await?;
    let project: Option<Uuid> = sqlx::query_scalar("select document_project($1)")
        .bind(id)
        .fetch_one(&mut *db)
        .await?;
    let project = project.ok_or(ApiError::NotFound)?;
    projects::require(&mut db, project, c.auth.identity_id).await?;
    let mut grants = grants_for(
        &mut db,
        project,
        c.auth.identity_id,
        &q.recipient_key,
        None,
        Some(id),
    )
    .await?;
    grants.retain(|g| g["recipient_kind"] == "addin");
    // The project lets the pane open the approval page before any grant exists.
    Ok(Json(json!({"project": project, "grants": grants})))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    capabilities,
    register_key,
    status,
    directory,
    begin,
    log_list,
    log_append,
    epoch_open,
    epochs_list,
    grants_list,
    grants_add,
    document_create,
    complete,
    legacy_erasure_request,
    legacy_erasure_list,
    legacy_erasure_confirm,
    connector_grants
))]
pub struct E2eeApi;

/// The mode rules of a staged or published commit (protocol 4.3 and 4.7). Returns whether
/// the commit is sealed: then every file is a sealed document, the epoch exists and the
/// membership head is an entry of the project's log. A plaintext project refuses sealed
/// commits and an encrypted one refuses plaintext commits.
pub(crate) async fn check_commit(
    tx: &mut Transaction<'_, Postgres>,
    project: Uuid,
    commit: &engine_core::repository::Commit,
) -> Result<bool, ApiError> {
    let (current_mode, epoch) = mode(tx, project).await?;
    let sealed = commit.sealed.as_deref();
    let mismatch = || {
        coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            "mode_mismatch",
            "An encrypted project takes only sealed (version 4) commits, and a plaintext project refuses them",
            json!({"mode": current_mode}),
        )
    };
    let Some(sealed) = sealed else {
        // A migrating project still reads its legacy plaintext files; new writes are sealed.
        if current_mode == "sealed" {
            return Err(mismatch());
        }
        let docs: Vec<Uuid> = commit.files.values().map(|f| f.document.0).collect();
        let any_sealed: bool = sqlx::query_scalar(
            "select exists(select 1 from document where id=any($1) and encryption='sealed')",
        )
        .bind(&docs)
        .fetch_one(&mut **tx)
        .await?;
        return if any_sealed {
            Err(mismatch())
        } else {
            Ok(false)
        };
    };
    if current_mode == "none" {
        return Err(mismatch());
    }
    if sealed.epoch as i64 > epoch as i64 {
        return Err(bad("The commit names an epoch that is not open yet"));
    }
    let known: bool = sqlx::query_scalar(
        "select exists(select 1 from project_e2ee_log where project_id=$1 and entry_hash=$2)",
    )
    .bind(project)
    .bind(&sealed.membership_head)
    .fetch_one(&mut **tx)
    .await?;
    if !known {
        return Err(bad(
            "The commit names a membership head that is not in this project's log",
        ));
    }
    let docs: Vec<Uuid> = commit.files.values().map(|f| f.document.0).collect();
    let all: i64 = sqlx::query_scalar(
        "select count(*) from document where id=any($1) and encryption='sealed'",
    )
    .bind(&docs)
    .fetch_one(&mut **tx)
    .await?;
    if all != docs.len() as i64 {
        return Err(mismatch());
    }
    Ok(true)
}

/// The matrix feature a document route needs plaintext for, by the path after
/// `/documents/{id}` (or `/connector/documents/{id}`); `None` for routes that work on sealed
/// files (members, connector grants, storage, the e2ee routes) or that a sealed file never
/// reaches with content.
fn feature_for(connector: bool, rest: &str) -> Option<&'static str> {
    let first = rest.split('/').nth(1).unwrap_or("");
    if connector {
        return (!matches!(first, "e2ee" | "storage" | "relay" | "manifest"))
            .then_some("office_google_addins");
    }
    Some(match first {
        "ops" | "batch" | "proposals" | "deploy" | "conflicts" => "web_block_edit",
        "drafts" if rest.ends_with("/sync") => "server_merge",
        "drafts" | "draft" => "drafts_autosave",
        "structure" | "state" | "history-points" | "compare" => "server_diff",
        "change-requests" => "server_review_rendering",
        "versions" => "server_restore",
        "copies" | "similarity" => "similarity",
        "public" | "public-view" | "publish" => "public_links",
        "provenance" | "nodes" => "office_google_addins",
        _ => return None,
    })
}

/// Middleware: a request to a plaintext-only route of a sealed file gets
/// `422 encrypted_project` with the feature and the alternative, before any handler runs.
pub(crate) async fn guard(
    State(pool): State<sqlx::PgPool>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let path = request.uri().path();
    let (connector, tail) = match path.strip_prefix("/connector/documents/") {
        Some(t) => (true, t),
        None => match path.strip_prefix("/documents/") {
            Some(t) => (false, t),
            None => return next.run(request).await,
        },
    };
    let (id, rest) = tail.split_at(tail.find('/').unwrap_or(tail.len()));
    // The router decodes `%31...` into the same id this guard would not parse; no client sends one.
    if id.contains('%') {
        return bad("A document id is never percent-encoded").into_response();
    }
    let (Ok(id), Some(feature)) = (id.parse::<Uuid>(), feature_for(connector, rest)) else {
        return next.run(request).await;
    };
    match sqlx::query_scalar::<_, bool>("select encryption='sealed' from document where id=$1")
        .bind(id)
        .fetch_optional(&pool)
        .await
    {
        Ok(Some(true)) => encrypted_project(feature).into_response(),
        Ok(_) => next.run(request).await,
        Err(e) => ApiError::from(e).into_response(),
    }
}
