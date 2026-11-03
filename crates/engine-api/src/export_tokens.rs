//! Per-export node tokens: map random export-scoped tokens to stable block IDs.
//!
//! Tokens are identity carriers, never bearer permission. Bindings associate each
//! export to a document, checked revision and creator. Raw tokens are generated as 32
//! securely random bytes (URL-safe unpadded Base64), and only their SHA-256 hashes are stored.

use std::collections::HashSet;

use axum::{
    extract::{Path, State},
    http::{header::AUTHORIZATION, HeaderMap},
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    access::{self, MemberRole},
    auth::{token, AuthContext},
    error::ApiError,
    idempotency,
    product::audit,
    projects, AppState,
};

pub const CARRIER_FORMAT: &str = "dynodoc.export-node-tokens";
pub const CARRIER_VERSION: u32 = 1;
pub const MAX_EXPORT_MAPPINGS: usize = 10_000;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/documents/{id}/export-tokens",
            post(create_export_tokens)
                .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route(
            "/documents/{id}/export-tokens/resolve",
            post(resolve_export_tokens)
                .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route(
            "/documents/{id}/export-tokens/{export_id}",
            get(get_export_tokens),
        )
        .route(
            "/documents/{id}/export-tokens/{export_id}/revoke",
            post(revoke_export_tokens),
        )
}

fn bad(reason: &str) -> ApiError {
    ApiError::BadRequest {
        reason: reason.into(),
    }
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateExportTokensRequest {
    /// Checked revision (sequence number) in document history. Omitted means current head.
    #[serde(default)]
    pub revision: Option<i64>,
    /// Specific node IDs to map. Omitted means all live (non-deleted) nodes at this revision.
    #[serde(default)]
    pub node_ids: Option<Vec<String>>,
    /// Creator-scoped idempotency key if not sent via Idempotency-Key header.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
pub struct ExportTokenMapping {
    pub node_id: String,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct ExportTokensResponse {
    pub format: String,
    pub version: u32,
    pub export_id: Uuid,
    pub document_id: Uuid,
    pub revision: i64,
    pub created_at: DateTime<Utc>,
    pub mappings: Vec<ExportTokenMapping>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolveExportTokensRequest {
    /// Versioned carrier format ("dynodoc.export-node-tokens").
    #[serde(default)]
    pub format: Option<String>,
    /// Carrier format version (1).
    #[serde(default)]
    pub version: Option<u32>,
    /// Export ID under which tokens were minted. Required when resolving export tokens.
    #[serde(default)]
    pub export_id: Option<Uuid>,
    /// Export tokens to resolve to node IDs.
    #[serde(default)]
    pub tokens: Vec<String>,
    /// Legacy node IDs to resolve directly, preserving spelling.
    #[serde(default)]
    pub legacy_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
pub struct ResolvedNodeTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_id: Option<String>,
    pub node_id: Option<String>,
    pub deleted: bool,
    pub resolved: bool,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct ResolveExportTokensResponse {
    pub document_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_id: Option<Uuid>,
    pub items: Vec<ResolvedNodeTarget>,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct RevokeExportResponse {
    pub revoked: bool,
    pub export_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize, utoipa::ToSchema)]
pub struct ExportDetailsResponse {
    pub export_id: Uuid,
    pub document_id: Uuid,
    pub revision: i64,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub token_count: i64,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Mint random export-scoped tokens for nodes in a document at a checked revision.
#[utoipa::path(
    post,
    path = "/documents/{id}/export-tokens",
    tag = "export tokens",
    params(("id" = Uuid, Path, description = "Document identifier")),
    request_body = CreateExportTokensRequest,
    security(("paseto" = [])),
    responses(
        (status = 200, description = "Export node tokens created", body = ExportTokensResponse),
        (status = 400, description = "Invalid request or revision"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Document access denied"),
        (status = 404, description = "Document not found"),
        (status = 409, description = "Idempotency conflict")
    )
)]
pub async fn create_export_tokens(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    auth: AuthContext,
    headers: HeaderMap,
    Json(req): Json<CreateExportTokensRequest>,
) -> Result<Json<ExportTokensResponse>, ApiError> {
    let idem_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .or(req.idempotency_key.clone());

    let path = format!("/documents/{id}/export-tokens");
    if let Some(ref key) = idem_key {
        match idempotency::reserve(&state.pool, auth.identity_id, key, &path).await? {
            idempotency::Reservation::Replay { body, .. } => {
                let parsed: ExportTokensResponse =
                    serde_json::from_value(body).map_err(|e| ApiError::Internal(e.to_string()))?;
                return Ok(Json(parsed));
            }
            idempotency::Reservation::InFlight => {
                return Err(ApiError::Conflict {
                    reason: "a request with this idempotency key is in progress".into(),
                });
            }
            idempotency::Reservation::Fresh => {}
        }
    }

    let result = execute_create_export_tokens(&state, id, &auth, req, idem_key.as_deref()).await;
    match result {
        Ok(resp) => {
            if let Some(ref key) = idem_key {
                let val =
                    serde_json::to_value(&resp).map_err(|e| ApiError::Internal(e.to_string()))?;
                idempotency::complete(&state.pool, auth.identity_id, key, 200, &val).await?;
            }
            Ok(Json(resp))
        }
        Err(err) => {
            if let Some(ref key) = idem_key {
                idempotency::release(&state.pool, auth.identity_id, key).await;
            }
            Err(err)
        }
    }
}

async fn execute_create_export_tokens(
    state: &AppState,
    id: Uuid,
    auth: &AuthContext,
    req: CreateExportTokensRequest,
    idem_key: Option<&str>,
) -> Result<ExportTokensResponse, ApiError> {
    let mut tx = state.pool.begin().await?;

    let doc_exists: Option<Uuid> = sqlx::query_scalar(
        "select id from document where id = $1 and deleted_at is null for share",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    if doc_exists.is_none() {
        return Err(ApiError::NotFound);
    }

    projects::lock_document_project(&mut tx, id).await?;
    access::require_member(&mut tx, id, auth.identity_id).await?;

    let head: i64 =
        sqlx::query_scalar("select coalesce(max(seq), 0) from event where document_id = $1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    let seq = req.revision.unwrap_or(head);
    if seq < 0 || seq > head {
        return Err(bad(
            "The requested revision is outside this document's history",
        ));
    }

    let target_nodes = match req.node_ids {
        Some(nodes) => {
            if nodes.is_empty() || nodes.len() > MAX_EXPORT_MAPPINGS {
                return Err(bad(&format!(
                    "node_ids must contain between 1 and {MAX_EXPORT_MAPPINGS} items"
                )));
            }
            let existing: Vec<String> =
                sqlx::query_scalar("select id from node where document_id = $1 and id = any($2)")
                    .bind(id)
                    .bind(&nodes)
                    .fetch_all(&mut *tx)
                    .await?;
            let existing_set: HashSet<String> = existing.into_iter().collect();
            for node in &nodes {
                if !existing_set.contains(node) {
                    return Err(bad(&format!("Node {node} does not exist in this document")));
                }
            }
            nodes
        }
        None => {
            let nodes: Vec<String> = sqlx::query_scalar(
                "select id from node where document_id = $1 and deleted = false order by id limit $2",
            )
            .bind(id)
            .bind((MAX_EXPORT_MAPPINGS + 1) as i64)
            .fetch_all(&mut *tx)
            .await?;
            if nodes.is_empty() {
                return Err(bad("Document has no nodes to export"));
            }
            if nodes.len() > MAX_EXPORT_MAPPINGS {
                return Err(bad(&format!(
                    "Document has more than {MAX_EXPORT_MAPPINGS} nodes; specify node_ids explicitly"
                )));
            }
            nodes
        }
    };

    let export_id = Uuid::new_v4();
    let rng = ring::rand::SystemRandom::new();
    let mut mappings = Vec::with_capacity(target_nodes.len());
    let mut hashes = Vec::with_capacity(target_nodes.len());

    for node_id in &target_nodes {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes)
            .map_err(|e| ApiError::Internal(format!("RNG error: {e:?}")))?;
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let hash = ring::digest::digest(&ring::digest::SHA256, token.as_bytes())
            .as_ref()
            .to_vec();
        mappings.push(ExportTokenMapping {
            node_id: node_id.clone(),
            token,
        });
        hashes.push(hash);
    }

    let created_at = Utc::now();
    sqlx::query(
        "insert into export_node_token
           (export_id, document_id, seq, created_by, created_at, token_hash, node_id, idempotency_key)
         select $1, $2, $3, $4, $5, u.h, u.n, $6
         from unnest($7::bytea[], $8::text[]) as u(h, n)",
    )
    .bind(export_id)
    .bind(id)
    .bind(seq)
    .bind(auth.identity_id)
    .bind(created_at)
    .bind(idem_key)
    .bind(&hashes)
    .bind(&target_nodes)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(ExportTokensResponse {
        format: CARRIER_FORMAT.to_string(),
        version: CARRIER_VERSION,
        export_id,
        document_id: id,
        revision: seq,
        created_at,
        mappings,
    })
}

/// Resolve export tokens and legacy block IDs to stable node targets.
#[utoipa::path(
    post,
    path = "/documents/{id}/export-tokens/resolve",
    tag = "export tokens",
    params(("id" = Uuid, Path, description = "Document identifier")),
    request_body = ResolveExportTokensRequest,
    security(("paseto" = []), ("connector_key" = [])),
    responses(
        (status = 200, description = "Export node tokens resolved", body = ResolveExportTokensResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Export revoked or access denied"),
        (status = 404, description = "Document or export not found")
    )
)]
pub async fn resolve_export_tokens(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(req): Json<ResolveExportTokensRequest>,
) -> Result<Json<ResolveExportTokensResponse>, ApiError> {
    if let Some(ref fmt) = req.format {
        if fmt != CARRIER_FORMAT {
            return Err(bad("Unsupported carrier format"));
        }
    }
    if let Some(ver) = req.version {
        if ver != CARRIER_VERSION {
            return Err(bad("Unsupported carrier version"));
        }
    }

    let total_count = req.tokens.len() + req.legacy_ids.len();
    if total_count > MAX_EXPORT_MAPPINGS {
        return Err(bad(&format!(
            "Cannot resolve more than {MAX_EXPORT_MAPPINGS} identifiers at once"
        )));
    }

    if !req.tokens.is_empty() && req.export_id.is_none() {
        return Err(bad(
            "export_id is required to resolve export tokens; do not pass tokens without an explicit export carrier",
        ));
    }

    let mut db = state.pool.acquire().await?;

    // Authenticate caller (account session, connector credential, or device token).
    authenticate_reader(&state, &mut db, id, &headers).await?;

    let doc_exists: Option<Uuid> =
        sqlx::query_scalar("select id from document where id = $1 and deleted_at is null")
            .bind(id)
            .fetch_optional(&mut *db)
            .await?;
    if doc_exists.is_none() {
        return Err(ApiError::NotFound);
    }

    // If an export_id is provided, verify it belongs to this document and is not revoked.
    if let Some(export_id) = req.export_id {
        let export_revoked: Option<Option<DateTime<Utc>>> = sqlx::query_scalar(
            "select revoked_at from export_node_token where document_id = $1 and export_id = $2 limit 1",
        )
        .bind(id)
        .bind(export_id)
        .fetch_optional(&mut *db)
        .await?;

        match export_revoked {
            None => {
                // Not found in this document: return 404 without leaking cross-document existence.
                return Err(ApiError::NotFound);
            }
            Some(Some(_)) => {
                // Export is explicitly revoked.
                return Err(ApiError::Forbidden);
            }
            Some(None) => {}
        }
    }

    let mut items = Vec::with_capacity(total_count);

    // Resolve export tokens.
    if let Some(export_id) = req.export_id {
        if !req.tokens.is_empty() {
            let hashes: Vec<Vec<u8>> = req
                .tokens
                .iter()
                .map(|t| {
                    ring::digest::digest(&ring::digest::SHA256, t.as_bytes())
                        .as_ref()
                        .to_vec()
                })
                .collect();

            let matched_rows: Vec<(Vec<u8>, String, bool)> = sqlx::query_as(
                "select e.token_hash, e.node_id, coalesce(n.deleted, true) as deleted
                 from export_node_token e
                 left join node n on n.document_id = e.document_id and n.id = e.node_id
                 where e.document_id = $1 and e.export_id = $2 and e.token_hash = any($3) and e.revoked_at is null",
            )
            .bind(id)
            .bind(export_id)
            .bind(&hashes)
            .fetch_all(&mut *db)
            .await?;

            let mut match_map: std::collections::HashMap<Vec<u8>, (String, bool)> =
                std::collections::HashMap::new();
            for (h, node_id, deleted) in matched_rows {
                match_map.insert(h, (node_id, deleted));
            }

            for (token_str, hash) in req.tokens.into_iter().zip(hashes) {
                if let Some((node_id, deleted)) = match_map.get(&hash) {
                    items.push(ResolvedNodeTarget {
                        token: Some(token_str),
                        legacy_id: None,
                        node_id: Some(node_id.clone()),
                        deleted: *deleted,
                        resolved: true,
                    });
                } else {
                    items.push(ResolvedNodeTarget {
                        token: Some(token_str),
                        legacy_id: None,
                        node_id: None,
                        deleted: false,
                        resolved: false,
                    });
                }
            }
        }
    }

    // Resolve legacy IDs, preserving spelling.
    if !req.legacy_ids.is_empty() {
        let matched_nodes: Vec<(String, bool)> =
            sqlx::query_as("select id, deleted from node where document_id = $1 and id = any($2)")
                .bind(id)
                .bind(&req.legacy_ids)
                .fetch_all(&mut *db)
                .await?;

        let mut node_map: std::collections::HashMap<String, bool> =
            std::collections::HashMap::new();
        for (node_id, deleted) in matched_nodes {
            node_map.insert(node_id, deleted);
        }

        for legacy_id in req.legacy_ids {
            if let Some(&deleted) = node_map.get(&legacy_id) {
                items.push(ResolvedNodeTarget {
                    token: None,
                    legacy_id: Some(legacy_id.clone()),
                    node_id: Some(legacy_id),
                    deleted,
                    resolved: true,
                });
            } else {
                items.push(ResolvedNodeTarget {
                    token: None,
                    legacy_id: Some(legacy_id),
                    node_id: None,
                    deleted: false,
                    resolved: false,
                });
            }
        }
    }

    Ok(Json(ResolveExportTokensResponse {
        document_id: id,
        export_id: req.export_id,
        items,
    }))
}

/// Revoke an export, permanently preventing further token resolution.
#[utoipa::path(
    post,
    path = "/documents/{id}/export-tokens/{export_id}/revoke",
    tag = "export tokens",
    params(
        ("id" = Uuid, Path, description = "Document identifier"),
        ("export_id" = Uuid, Path, description = "Export identifier")
    ),
    security(("paseto" = [])),
    responses(
        (status = 200, description = "Export tokens revoked", body = RevokeExportResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Document or export not found")
    )
)]
pub async fn revoke_export_tokens(
    State(state): State<AppState>,
    Path((id, export_id)): Path<(Uuid, Uuid)>,
    auth: AuthContext,
) -> Result<Json<RevokeExportResponse>, ApiError> {
    let mut tx = state.pool.begin().await?;

    let doc_exists: Option<Uuid> = sqlx::query_scalar(
        "select id from document where id = $1 and deleted_at is null for update",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    if doc_exists.is_none() {
        return Err(ApiError::NotFound);
    }

    projects::lock_document_project(&mut tx, id).await?;

    let role = access::require_member(&mut tx, id, auth.identity_id).await?;
    let creator: Option<Uuid> = sqlx::query_scalar(
        "select created_by from export_node_token where document_id = $1 and export_id = $2 limit 1",
    )
    .bind(id)
    .bind(export_id)
    .fetch_optional(&mut *tx)
    .await?;

    let creator = creator.ok_or(ApiError::NotFound)?;
    if role < MemberRole::Contributor && auth.identity_id != creator {
        return Err(ApiError::Forbidden);
    }

    let changed = sqlx::query(
        "update export_node_token
         set revoked_at = coalesce(revoked_at, now())
         where document_id = $1 and export_id = $2 and revoked_at is null",
    )
    .bind(id)
    .bind(export_id)
    .execute(&mut *tx)
    .await?;

    if changed.rows_affected() == 0 {
        let is_revoked: Option<bool> = sqlx::query_scalar(
            "select revoked_at is not null from export_node_token where document_id = $1 and export_id = $2 limit 1",
        )
        .bind(id)
        .bind(export_id)
        .fetch_optional(&mut *tx)
        .await?;
        if is_revoked.is_none() {
            return Err(ApiError::NotFound);
        }
    }

    audit(
        &mut tx,
        auth.identity_id,
        "document.export_revoked",
        id,
        json!({ "export_id": export_id }),
    )
    .await?;

    tx.commit().await?;

    Ok(Json(RevokeExportResponse {
        revoked: true,
        export_id,
    }))
}

#[derive(sqlx::FromRow)]
struct ExportDetailsRow {
    export_id: Uuid,
    document_id: Uuid,
    seq: i64,
    created_by: Uuid,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    token_count: i64,
}

/// Retrieve details and status of an export token map.
#[utoipa::path(
    get,
    path = "/documents/{id}/export-tokens/{export_id}",
    tag = "export tokens",
    params(
        ("id" = Uuid, Path, description = "Document identifier"),
        ("export_id" = Uuid, Path, description = "Export identifier")
    ),
    security(("paseto" = [])),
    responses(
        (status = 200, description = "Export token details", body = ExportDetailsResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Access denied"),
        (status = 404, description = "Document or export not found")
    )
)]
pub async fn get_export_tokens(
    State(state): State<AppState>,
    Path((id, export_id)): Path<(Uuid, Uuid)>,
    auth: AuthContext,
) -> Result<Json<ExportDetailsResponse>, ApiError> {
    let mut db = state.pool.acquire().await?;
    access::require_member(&mut db, id, auth.identity_id).await?;

    let row: Option<ExportDetailsRow> = sqlx::query_as(
        "select export_id, document_id, seq, created_by, created_at, revoked_at, count(*) as token_count
         from export_node_token
         where document_id = $1 and export_id = $2
         group by export_id, document_id, seq, created_by, created_at, revoked_at",
    )
    .bind(id)
    .bind(export_id)
    .fetch_optional(&mut *db)
    .await?;

    let row = row.ok_or(ApiError::NotFound)?;

    Ok(Json(ExportDetailsResponse {
        export_id: row.export_id,
        document_id: row.document_id,
        revision: row.seq,
        created_by: row.created_by,
        created_at: row.created_at,
        revoked_at: row.revoked_at,
        token_count: row.token_count,
    }))
}

// ---------------------------------------------------------------------------
// Auth Helper for Reader Endpoints
// ---------------------------------------------------------------------------

async fn authenticate_reader(
    state: &AppState,
    db: &mut PgConnection,
    document_id: Uuid,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    let raw = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .ok_or(ApiError::Unauthorized)?;

    // 1. Scoped connector key (64 hex characters)
    if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        let hash = ring::digest::digest(&ring::digest::SHA256, raw.as_bytes())
            .as_ref()
            .to_vec();
        let valid_grant: Option<Uuid> = sqlx::query_scalar(
            "select g.id from connector_grant g join identity i on i.id = g.identity_id
             where g.token_hash = $1 and g.document_id = $2 and g.revoked_at is null
               and g.expires_at > now() and i.disabled_at is null and i.erased_at is null
               and i.session_generation = g.session_generation",
        )
        .bind(hash)
        .bind(document_id)
        .fetch_optional(&mut *db)
        .await?;

        if valid_grant.is_some() {
            return Ok(());
        }
        return Err(ApiError::Unauthorized);
    }

    // 2. Project device session
    if token::is_project_device_token(raw) {
        let claims = token::verify_project_device(&state.auth.paseto_key, raw)?;
        let has_read_scope = claims
            .scopes
            .iter()
            .any(|s| s == "history:read" || s == "project:read" || s == "content:read");
        if !has_read_scope {
            return Err(ApiError::Forbidden);
        }

        let doc_project: Option<Uuid> = sqlx::query_scalar("select document_project($1)")
            .bind(document_id)
            .fetch_one(&mut *db)
            .await?;
        if doc_project != Some(claims.project) {
            return Err(ApiError::Forbidden);
        }

        let key_active: bool = sqlx::query_scalar(
            "select exists(
                 select 1 from identity i
                 join device_signing_key k on k.identity_id = i.id
                 where i.id = $1 and k.id = $2 and i.disabled_at is null and i.erased_at is null
                   and not exists(select 1 from device_key_revocation r where r.key_id = k.id)
             )",
        )
        .bind(claims.identity)
        .bind(claims.key)
        .fetch_one(&mut *db)
        .await?;

        if !key_active {
            return Err(ApiError::Unauthorized);
        }
        return Ok(());
    }

    // 3. Account login
    let (identity_id, session_generation, session_id) =
        token::verify_bound_session(&state.auth.paseto_key, raw)?;
    crate::auth::store::ensure_bound_session(
        &state.pool,
        identity_id,
        session_generation,
        session_id,
    )
    .await?;

    access::require_member(db, document_id, identity_id).await?;
    Ok(())
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        create_export_tokens,
        resolve_export_tokens,
        revoke_export_tokens,
        get_export_tokens,
    ),
    components(schemas(
        CreateExportTokensRequest,
        ExportTokensResponse,
        ExportTokenMapping,
        ResolveExportTokensRequest,
        ResolveExportTokensResponse,
        ResolvedNodeTarget,
        RevokeExportResponse,
        ExportDetailsResponse,
    ))
)]
pub struct ExportTokensApi;
