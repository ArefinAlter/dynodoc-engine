//! dynodoc HTTP API (library crate).
//!
//! The binary ([`main`](../main.rs)) is a thin wrapper that reads configuration from
//! the environment, connects to Postgres, and serves [`app`]. Exposing the app as a
//! library lets integration tests in `tests/` drive the real router and handlers, and
//! lets `engine-cli` emit the OpenAPI spec from the same [`ApiDoc`].
//!
//! Stage 18 lands the full REST + Server-Sent-Events surface on top of the stage-17
//! identity routes: documents (read + create), the write path through the stage-16
//! governance gate (ops, proposals, deploy), a per-document SSE stream, and the public
//! audit endpoints (verify / snapshot / merkle-proof). Cross-cutting: a single
//! [`error::ApiError`], opaque cursor [`pagination`], Postgres-backed [`idempotency`],
//! and a generated [`ApiDoc`] OpenAPI document.

#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

pub mod access;
pub mod admin;
mod admin_controls;
mod admin_identity;
pub mod agent;
pub mod audit;
pub mod auth;
pub mod config;
pub mod conflicts;
pub mod copies;
pub mod counters;
mod device_sessions;
mod devices;
pub mod directory;
mod discussions;
pub mod documents;
mod draft_storage;
mod e2ee;
mod egress;
pub mod error;
pub mod export_tokens;
pub mod fanout;
mod history;
pub mod idempotency;
pub mod identity_secrets;
pub mod ingest;
mod ledger;
mod mail_outbox;
mod mcp_http;
pub mod merge_policies;
pub mod metrics;
pub mod notifications;
mod oauth;
pub mod object_collector;
pub mod object_store;
pub mod ops;
pub mod org_sign_in;
pub mod pagination;
pub mod people;
pub mod product;
mod profiles;
mod project_activity;
mod project_history;
mod project_horizons;
mod project_issues;
mod project_staging;
pub mod projects;
pub mod provenance;
pub mod retention;
pub mod reviews;
pub mod secrets;
pub mod stream;
pub mod transparency;
pub mod uploads;
pub mod witness_service;
pub mod workloads;
pub mod workspace;

use axum::{routing::get, Json, Router};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;

pub use auth::AuthConfig;
pub use stream::Subscriptions;

/// Shared application state handed to every handler via `axum::extract::State`.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub auth: AuthConfig,
    /// Per-document SSE broadcast registry (live event fan-out).
    pub subscriptions: Subscriptions,
    pub admin_emails: String,
    /// Wakes the background copy-detection indexer ([`copies::spawn`]).
    pub copy_index: copies::CopyIndex,
    pub workloads: workloads::Workloads,
    /// Error responses counted by code since start (admin overview).
    pub counters: counters::Counters,
    /// Rows pruned by the retention loop since start (admin overview).
    pub retention: retention::Stats,
    /// Explicitly loaded secret outside the database; required for shared ref writes.
    pub ref_signer: Option<std::sync::Arc<ring::signature::Ed25519KeyPair>>,
    /// Explicit opt-in; new draft/rebase bases use typed shared objects.
    pub shared_draft_bases: bool,
    /// Explicit opt-in; named versions, public pins and deploys share typed state.
    pub named_snapshot_storage: engine_core::snapshot::NamedStorage,
    /// `AGENT_GATEWAY=on` mounts the agent data plane ([`agent`]); anything else leaves
    /// its routes absent. Off by default.
    pub agent_gateway: bool,
    /// `E2EE_ALLOW_CREATE=on` lets owners begin encrypted projects (pre-release, staged
    /// rollout, protocol 12.1). Existing encrypted projects keep working without it.
    pub e2ee_create: bool,
    /// Seal agent authorship into the event chain at merge (decision 038, layer C). On unless
    /// `DYNODOC_AGENT_ATTRIBUTION=audit`, which keeps layers A and B only, for installations
    /// whose other readers predate the `ChangeAttributed` event.
    pub sealed_attribution: bool,
    /// Bounded cache of verified document states for the agent routes.
    pub agent_cache: agent::StateCache,
    /// Opt-in checked write cache; authorization always precedes lookup.
    pub write_cache: Option<engine_core::snapshot::cache::CurrentStateCache>,
    /// The installation's transparency log, when `DYNODOC_TRANSPARENCY_ORIGIN` is set.
    pub transparency: Option<transparency::Transparency>,
    /// Shortest quarantine a shared horizon may have (design CP-Q5: 14 days), from
    /// `DYNODOC_HORIZON_MIN_QUARANTINE_DAYS`.
    pub horizon_min_quarantine_days: u32,
    /// The immutable installation ID, read once for device-session challenges.
    device_authority: std::sync::Arc<tokio::sync::OnceCell<uuid::Uuid>>,
    /// `IDENTITY_SECRETS_KEY`: the data key of stored identity secrets ([`identity_secrets`]).
    /// `None` keeps the legacy key derived from the server key.
    pub identity_key: Option<[u8; 32]>,
    /// Login lifetimes (`REFRESH_TTL_SECONDS`, idle timeout, absolute cap).
    pub session_policy: auth::SessionPolicy,
    /// Requests per minute one SCIM token may make (`SCIM_RATE_PER_MINUTE`, default 600).
    pub scim_rate_per_minute: i32,
    /// Cross-replica event fan-out (`DYNODOC_EVENT_FANOUT`, [`fanout`]); `local` by default.
    pub fanout: fanout::Fanout,
    /// Where originals and media bytes live (`DYNODOC_OBJECT_STORE`, [`object_store`]).
    pub objects: std::sync::Arc<object_store::ObjectStore>,
    /// How old a login may be for a sensitive action (`auth::sessions::require_recent_login`).
    /// `0` (the value of [`AppState::new`]) is off; the binary reads `REAUTH_MAX_AGE_SECONDS`
    /// (default 600).
    pub reauth_seconds: i64,
}

impl AppState {
    /// Construct state with a fresh, empty subscription registry.
    pub fn new(pool: PgPool, auth: AuthConfig) -> Self {
        Self {
            pool,
            auth,
            subscriptions: Subscriptions::new(),
            admin_emails: std::env::var("ADMIN_EMAILS").unwrap_or_default(),
            copy_index: copies::CopyIndex::default(),
            workloads: workloads::Workloads::default(),
            counters: Default::default(),
            retention: Default::default(),
            ref_signer: None,
            shared_draft_bases: std::env::var("DYNODOC_SHARED_DRAFT_BASES").as_deref()
                == Ok("shared-v2"),
            named_snapshot_storage: if std::env::var("DYNODOC_NAMED_SNAPSHOT_STORAGE").as_deref()
                == Ok("shared-v2")
            {
                engine_core::snapshot::NamedStorage::SharedV2
            } else {
                engine_core::snapshot::NamedStorage::Legacy
            },
            agent_gateway: std::env::var("AGENT_GATEWAY").as_deref() == Ok("on"),
            e2ee_create: std::env::var("E2EE_ALLOW_CREATE").as_deref() == Ok("on"),
            sealed_attribution: std::env::var("DYNODOC_AGENT_ATTRIBUTION").as_deref()
                != Ok("audit"),
            agent_cache: Default::default(),
            write_cache: (std::env::var("DYNODOC_WRITE_STATE_CACHE").as_deref() == Ok("on"))
                .then(engine_core::snapshot::cache::CurrentStateCache::default),
            // An invalid origin is refused at startup (main.rs); tests set the field.
            transparency: transparency::Transparency::from_env().ok().flatten(),
            horizon_min_quarantine_days: std::env::var("DYNODOC_HORIZON_MIN_QUARANTINE_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(14),
            device_authority: Default::default(),
            identity_key: None,
            session_policy: Default::default(),
            scim_rate_per_minute: 600,
            fanout: Default::default(),
            objects: Default::default(),
            reauth_seconds: 0,
        }
    }

    /// The installation ID (immutable; read once per process).
    pub(crate) async fn installation(&self) -> Result<uuid::Uuid, sqlx::Error> {
        self.device_authority
            .get_or_try_init(|| async {
                sqlx::query_scalar::<_, uuid::Uuid>(
                    "select id from device_authority where singleton",
                )
                .fetch_one(&self.pool)
                .await
            })
            .await
            .copied()
    }

    /// The key new identity secrets are sealed with.
    pub(crate) fn identity_sealing_key(&self) -> engine_core::at_rest::DataKey {
        identity_secrets::sealing_key(&self.auth.paseto_key, self.identity_key.as_ref())
    }

    /// Every key a stored identity secret may be sealed with (chosen by the envelope's key id).
    pub(crate) fn identity_opening_keys(&self) -> Vec<engine_core::at_rest::DataKey> {
        let mut keys = vec![identity_secrets::legacy_key(&self.auth.paseto_key)];
        keys.extend(
            self.identity_key
                .as_ref()
                .map(identity_secrets::identity_key),
        );
        keys
    }
}

/// Build the application router with all routes, cross-cutting middleware, and state.
///
/// Middleware (docs/18 §1): gzip compression, a CORS layer (permissive for the
/// local-only PoC — tighten origins for a deployment), and an OpenTelemetry-compatible
/// `TraceLayer`. Process-local admission/deadline controls are in [`workloads`];
/// these do not replace tenant quotas at a multi-instance gateway.
pub fn app(state: AppState) -> Router {
    // PoC: permissive CORS (local-only). A deployment restricts `allow_origin` to the
    // known frontend origins (docs/18 "restrict to known origins").
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    let routes = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/openapi.json", get(openapi_json))
        .merge(auth::router())
        .merge(admin::router())
        .merge(product::router())
        .merge(projects::router())
        .merge(project_activity::router())
        .merge(project_staging::router())
        .merge(project_history::router())
        .merge(project_horizons::router())
        .merge(merge_policies::router())
        .merge(transparency::router())
        .merge(project_issues::router())
        .merge(profiles::router())
        .merge(devices::router())
        .merge(device_sessions::router())
        .merge(provenance::router())
        .merge(ledger::router())
        .merge(e2ee::router())
        .merge(uploads::router())
        .merge(egress::router())
        .merge(documents::router())
        .merge(ops::router())
        .merge(conflicts::router())
        .merge(stream::router())
        .merge(audit::router())
        .merge(workspace::router())
        .merge(reviews::router())
        .merge(history::router())
        .merge(discussions::router())
        .merge(notifications::router())
        .merge(copies::router())
        .merge(people::router())
        .merge(export_tokens::router())
        .merge(directory::router())
        .merge(org_sign_in::router())
        .merge(mail_outbox::router());
    // Off (the default): the agent routes are not mounted at all, so they answer exactly
    // as a path that never existed.
    let routes = if state.agent_gateway {
        // Remote MCP and the OAuth grants behind it belong to the agent plane too.
        routes
            .merge(agent::router())
            .merge(oauth::router())
            .merge(mcp_http::router())
    } else {
        routes
    };
    // The policy and kill-switch routes belong to the account, not to the agent plane, so
    // a project can be prepared before the gateway is switched on.
    let routes = routes.merge(agent::manage_router());
    // So is the reviewers' list of what the agents proposed: proposals outlive the switch.
    let routes = routes.merge(agent::inbox_router());
    routes
        // Encrypted projects: routes that need plaintext refuse sealed files (decision 035).
        .layer(axum::middleware::from_fn_with_state(
            state.pool.clone(),
            e2ee::guard,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.workloads.clone(),
            workloads::admission,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.counters.clone(),
            counters::count,
        ))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            16 * 1024 * 1024,
        ))
        .with_state(state)
        .layer(cors)
        .layer(CompressionLayer::new())
        // The span records the path only (a query can hold search text), and capability
        // tokens inside the path are redacted (audit finding F-03).
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<_>| {
                tracing::info_span!("http", method = %request.method(), path = %redact_path(request.uri().path()))
            }),
        )
}

/// The request path as logged: any segment of 32 or more characters that is not a UUID
/// (public-link and export tokens, PASETO-like tokens with dots, content digests) is
/// replaced, so a log line never carries a secret. UUIDs and ULIDs (26) stay, so requests
/// remain traceable.
pub fn redact_path(path: &str) -> String {
    let uuid = |s: &str| {
        s.len() == 36
            && s.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
    };
    path.split('/')
        .map(|segment| {
            if segment.len() >= 32 && !uuid(segment) {
                "{redacted}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod redact_tests {
    #[test]
    fn tokens_in_paths_are_redacted_and_ids_kept() {
        let token = "a".repeat(64);
        assert_eq!(
            super::redact_path(&format!("/public/documents/{token}")),
            "/public/documents/{redacted}"
        );
        let doc = "0b6a1d6e-6c0a-4a64-9a43-1f2b7d0a0001";
        let node = "01JABCDEFGHJKMNPQRSTVWXYZ0";
        assert_eq!(
            super::redact_path(&format!("/connector/documents/{doc}/nodes/{node}/history")),
            format!("/connector/documents/{doc}/nodes/{node}/history")
        );
        assert_eq!(super::redact_path("/healthz"), "/healthz");
        let paseto = "v4.local.abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(super::redact_path(&format!("/x/{paseto}")), "/x/{redacted}");
    }
}

/// Liveness probe. Returns 200 with a small JSON body.
async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok", "service": "engine-api" }))
}

/// Readiness probe: the database answers within 2 s and, with `DYNODOC_EVENT_FANOUT=postgres`,
/// the event listener is connected. `503` names the failed check, never an error's detail.
async fn readyz(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> (axum::http::StatusCode, Json<Value>) {
    let database = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sqlx::query_scalar::<_, i32>("select 1").fetch_one(&state.pool),
    )
    .await
    .is_ok_and(|r| r.is_ok());
    let listener = state.fanout.ready();
    let ok = database && listener;
    (
        if ok {
            axum::http::StatusCode::OK
        } else {
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({
            "status": if ok { "ready" } else { "not_ready" },
            "checks": {"database": database, "event_listener": listener},
        })),
    )
}

/// Serve the generated OpenAPI document as JSON (the committed `openapi.yaml` is the
/// source of truth for codegen; this endpoint is a convenience for tooling).
async fn openapi_json(axum::extract::State(state): axum::extract::State<AppState>) -> Json<Value> {
    let mut doc = serde_json::to_value(ApiDoc::openapi()).unwrap_or_else(|_| json!({}));
    // With the agent gateway off, the document must not advertise it.
    if !state.agent_gateway {
        if let Some(paths) = doc.get_mut("paths").and_then(Value::as_object_mut) {
            paths.retain(|path, _| {
                !path.contains("/agent/") && path != "/.well-known/dynodoc-agent"
            });
        }
    }
    Json(doc)
}

/// The OpenAPI document, derived from the annotated handlers (docs/18 §3). `engine-cli
/// openapi` emits this to `openapi.yaml`; CI fails if the committed file drifts.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "dynodoc engine API",
        description = "Document version control, collaborative review and authorized administration. Canonical content history is append-only except explicit audited whole-document erasure.",
        version = "0.1.0"
    ),
    modifiers(&WorkspaceDocs),
    paths(
        auth::routes::logout,
        auth::handover::issue,
        auth::handover::redeem,
        profiles::own,
        profiles::read,
        profiles::save,
        profiles::storage,
        profiles::profile_activity,
        profiles::starred,
        documents::routes::list_documents,
        documents::routes::get_document,
        documents::routes::get_node,
        documents::routes::list_events,
        documents::routes::create_document,
        ops::routes::op_node_create,
        ops::routes::op_field_edit,
        ops::routes::op_comment,
        ops::routes::op_suggest,
        ops::routes::accept,
        ops::routes::reject,
        ops::routes::deploy,
        conflicts::routes::list_conflicts,
        conflicts::routes::resolve,
        audit::verify,
        audit::get_snapshot,
        audit::merkle_proof,
    ),
    components(schemas(
        auth::routes::RefreshRequest,
        auth::routes::TokenResponse,
        auth::handover::IssueRequest,
        auth::handover::IssueResponse,
        auth::handover::RedeemRequest,
        documents::routes::CreateDocumentRequest,
        ops::routes::NodeCreateRequest,
        ops::routes::FieldEditRequest,
        ops::routes::CommentRequest,
        ops::routes::SuggestRequest,
        ops::routes::RejectRequest,
        conflicts::routes::ResolveRequest,
        conflicts::derive::ConflictView,
        conflicts::derive::ConflictOption,
    )),
    tags(
        (name = "documents", description = "Document read + create"),
        (name = "operations", description = "The write path (governance-gated)"),
        (name = "conflicts", description = "Four-card conflict resolution"),
        (name = "audit", description = "Member-only hash-chain audit endpoints"),
    )
)]
pub struct ApiDoc;

struct WorkspaceDocs;
impl utoipa::Modify for WorkspaceDocs {
    fn modify(&self, api: &mut utoipa::openapi::OpenApi) {
        api.merge(workspace::WorkspaceApi::openapi());
        api.merge(reviews::ReviewApi::openapi());
        api.merge(history::HistoryApi::openapi());
        api.merge(product::ProductApi::openapi());
        api.merge(projects::ProjectsApi::openapi());
        api.merge(project_activity::ProjectActivityApi::openapi());
        api.merge(provenance::ProvenanceApi::openapi());
        api.merge(ledger::LedgerApi::openapi());
        api.merge(e2ee::E2eeApi::openapi());
        api.merge(export_tokens::ExportTokensApi::openapi());
        api.merge(admin::AdminApi::openapi());
        api.merge(admin_controls::AdminControlsApi::openapi());
        api.merge(discussions::DiscussionApi::openapi());
        api.merge(notifications::NotificationApi::openapi());
        api.merge(copies::CopiesApi::openapi());
        api.merge(people::PeopleApi::openapi());
        api.merge(devices::DevicesApi::openapi());
        api.merge(device_sessions::DeviceSessionsApi::openapi());
        api.merge(project_staging::ProjectStagingApi::openapi());
        api.merge(project_history::ProjectHistoryApi::openapi());
        api.merge(project_horizons::HorizonsApi::openapi());
        api.merge(merge_policies::MergePoliciesApi::openapi());
        api.merge(project_issues::ProjectIssuesApi::openapi());
        api.merge(agent::AgentApi::openapi());
        api.merge(agent::AgentManageApi::openapi());
        api.merge(agent::AgentInboxApi::openapi());
        // A workspace that declares no licence (`license-file` only) leaves the derived name
        // empty; an empty licence object is invalid OpenAPI, so drop it.
        if api.info.license.as_ref().is_some_and(|l| l.name.is_empty()) {
            api.info.license = None;
        }
        let components = api.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "connector_key",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                    .bearer_format("64 hexadecimal characters; file-scoped editor key")
                    .build(),
            ),
        );
        // Scopes are role names (OpenAPI 3.1): `project:read`, `history:read`,
        // `history:write` and `history:review`. Only the allow-listed project
        // operations list it.
        components.add_security_scheme(
            "device_session",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                    .bearer_format("PASETO v4.local project device session; one project, 1 hour")
                    .build(),
            ),
        );
        components.add_security_scheme(
            "paseto",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                    .bearer_format("PASETO v4.local")
                    .build(),
            ),
        );
    }
}
