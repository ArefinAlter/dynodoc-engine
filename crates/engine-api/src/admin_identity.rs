//! Administrator identity routes (docs/SELF-HOSTED-IDENTITY-AND-ACCESS.md 11, licensing 10, decision
//! 037): instance roles granted in Dynodoc (`admin`, and the read-only `auditor`), the audit-log
//! export, service accounts, and the local usage report.
//!
//! Writes need an administrator; the reads also accept an auditor ([`crate::admin::require_reader`]).
//! Every write is audited; nothing here returns a secret except the enrolment login, shown once.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    admin::{require_admin, require_reader},
    auth::{routes::SERVICE_DOMAIN, AuthContext, Login},
    error::ApiError,
    AppState,
};

/// The routes of this module.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/instance-roles/{identity}", put(set_role))
        .route("/admin/audit/export", get(export_audit))
        .route(
            "/admin/service-accounts",
            get(list_services).post(create_service),
        )
        .route(
            "/admin/service-accounts/{id}/enrolment-login",
            post(enrolment_login),
        )
        .route(
            "/admin/service-accounts/{id}/projects/{project}",
            put(set_service_project),
        )
        .route("/admin/usage-report", get(usage_report))
        .route("/internal/installation", get(installation))
}

fn bad(reason: &str) -> ApiError {
    ApiError::BadRequest {
        reason: reason.into(),
    }
}

#[derive(Deserialize)]
struct RoleInput {
    role: String,
    granted: bool,
}

/// `PUT /admin/instance-roles/{identity}`: grant or remove `admin` or `auditor` (source
/// `manual`). An administrator cannot remove their own `admin` role, and a role a mapping granted
/// stays with the mapping.
async fn set_role(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(identity): Path<Uuid>,
    Json(input): Json<RoleInput>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&state, &auth).await?;
    if !["admin", "auditor"].contains(&input.role.as_str()) {
        return Err(bad("The role is admin or auditor."));
    }
    if !input.granted && input.role == "admin" && identity == auth.identity_id {
        return Err(bad("You cannot remove your own administrator role."));
    }
    let mut tx = state.pool.begin().await?;
    let person: Option<String> = sqlx::query_scalar("select kind from identity where id=$1 and disabled_at is null and erased_at is null and not exists(select 1 from agent_identity a where a.identity_id=identity.id) for update")
        .bind(identity)
        .fetch_optional(&mut *tx)
        .await?;
    match person.as_deref() {
        None => return Err(ApiError::NotFound),
        Some("service") => return Err(bad("A service account holds no instance role.")),
        Some(_) => {}
    }
    let changed = if input.granted {
        sqlx::query("insert into identity_instance_role(identity_id,role,source) values($1,$2,'manual') on conflict do nothing")
            .bind(identity)
            .bind(&input.role)
            .execute(&mut *tx)
            .await?
            .rows_affected()
    } else {
        sqlx::query("delete from identity_instance_role where identity_id=$1 and role=$2 and source='manual'")
            .bind(identity)
            .bind(&input.role)
            .execute(&mut *tx)
            .await?
            .rows_affected()
    };
    if changed == 1 {
        crate::product::audit(
            &mut tx,
            auth.identity_id,
            if input.granted {
                "instance_role.granted"
            } else {
                "instance_role.removed"
            },
            identity,
            json!({"role": input.role}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(
        json!({"identity_id": identity, "role": input.role, "granted": input.granted, "changed": changed == 1}),
    ))
}

#[derive(Deserialize)]
pub(crate) struct ExportQuery {
    /// Rows after this audit id (the `x-next-after` of the previous page).
    #[serde(default)]
    after: i64,
    #[serde(default = "page")]
    limit: i64,
    since: Option<chrono::DateTime<chrono::Utc>>,
    until: Option<chrono::DateTime<chrono::Utc>>,
}
fn page() -> i64 {
    5_000
}

/// `GET /admin/audit/export`: the audit log as JSON lines (one object per row, oldest first),
/// details redacted and bounded as on the records screen. Pages of at most 10,000 rows; the
/// response header `x-next-after` names the cursor of the next page (absent on the last one).
/// The export itself is audited.
async fn export_audit(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(q): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    require_reader(&state, &auth).await?;
    export(&state, auth.identity_id, None, q).await
}

/// The export of [`export_audit`]; with `organisation`, only rows whose actor is a member of it
/// or whose resource is the organisation or one of its members.
pub(crate) async fn export(
    state: &AppState,
    actor: Uuid,
    organisation: Option<Uuid>,
    q: ExportQuery,
) -> Result<Response, ApiError> {
    if !(1..=10_000).contains(&q.limit) || q.after < 0 {
        return Err(bad("limit is 1 to 10000 and after is a row id."));
    }
    let rows: Vec<(i64, Value)> = sqlx::query_as("select a.id,jsonb_build_object('id',a.id,'created_at',a.created_at,'action',a.action,'actor_id',a.actor_id,'actor',i.email,'resource_id',a.resource_id,'detail',a.detail) from operation_audit a join identity i on i.id=a.actor_id where a.id>$1 and ($2::timestamptz is null or a.created_at>=$2) and ($3::timestamptz is null or a.created_at<$3) and ($5::uuid is null or a.resource_id=$5 or exists(select 1 from organisation_member m where m.organisation_id=$5 and (m.identity_id=a.actor_id or m.identity_id=a.resource_id))) order by a.id limit $4")
        .bind(q.after)
        .bind(q.since)
        .bind(q.until)
        .bind(q.limit)
        .bind(organisation)
        .fetch_all(&state.pool)
        .await?;
    let mut body = String::new();
    for (_, mut row) in rows.iter().cloned() {
        if let Some(detail) = row.get_mut("detail") {
            *detail = crate::admin::bounded_detail(detail.take());
        }
        body.push_str(&row.to_string());
        body.push('\n');
    }
    let mut tx = state.pool.begin().await?;
    crate::product::audit(
        &mut tx,
        actor,
        "audit.exported",
        organisation.unwrap_or(actor),
        json!({"rows": rows.len(), "after": q.after, "organisation": organisation}),
    )
    .await?;
    tx.commit().await?;
    let mut response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-ndjson"),
            (header::CACHE_CONTROL, "private, no-store"),
        ],
        body,
    )
        .into_response();
    if rows.len() as i64 == q.limit {
        if let Some((last, _)) = rows.last() {
            if let Ok(v) = HeaderValue::from_str(&last.to_string()) {
                response.headers_mut().insert("x-next-after", v);
            }
        }
    }
    Ok(response)
}

#[derive(Deserialize)]
struct ServiceInput {
    /// Lower-case letters, digits and `-`, 2 to 40 characters: the address is `svc-<name>@service.invalid`.
    name: String,
    /// The person responsible (default: the administrator creating it).
    owner: Option<Uuid>,
    display_name: Option<String>,
}

/// `POST /admin/service-accounts`: a non-human identity for automation. It never signs in through
/// a browser or an emailed link; it acts through device keys enrolled for it and per-project
/// grants (docs/SELF-HOSTED-IDENTITY-AND-ACCESS.md 11.2).
async fn create_service(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(input): Json<ServiceInput>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    require_admin(&state, &auth).await?;
    let name = input.name.trim();
    if !(2..=40).contains(&name.len())
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || name.starts_with('-')
    {
        return Err(bad(
            "A name of 2 to 40 lower-case letters, digits and dashes.",
        ));
    }
    let display = input
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .unwrap_or(name);
    if display.chars().count() > 200 || display.chars().any(char::is_control) {
        return Err(bad("A display name of at most 200 characters."));
    }
    let owner = input.owner.unwrap_or(auth.identity_id);
    let email = format!("svc-{name}@{SERVICE_DOMAIN}");
    let mut tx = state.pool.begin().await?;
    let owner_ok: bool = sqlx::query_scalar("select exists(select 1 from identity where id=$1 and kind='person' and disabled_at is null and erased_at is null)")
        .bind(owner)
        .fetch_one(&mut *tx)
        .await?;
    if !owner_ok {
        return Err(bad("The owner must be an active person."));
    }
    let id: Option<Uuid> = sqlx::query_scalar("insert into identity(email,display_name,kind,service_owner) values($1,$2,'service',$3) on conflict do nothing returning id")
        .bind(&email)
        .bind(display)
        .bind(owner)
        .fetch_optional(&mut *tx)
        .await?;
    let id = id.ok_or_else(|| ApiError::Conflict {
        reason: "A service account with this name exists.".into(),
    })?;
    crate::product::audit(
        &mut tx,
        auth.identity_id,
        "service_account.created",
        id,
        json!({"name": name, "owner": owner}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id": id, "email": email, "owner": owner})),
    ))
}

/// `GET /admin/service-accounts`: every service account with its owner, keys and grants count.
async fn list_services(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Value>, ApiError> {
    require_reader(&state, &auth).await?;
    let items: Value = sqlx::query_scalar("select coalesce(jsonb_agg(jsonb_build_object('id',i.id,'email',i.email,'display_name',i.display_name,'owner',i.service_owner,'owner_email',o.email,'disabled_at',i.disabled_at,'created_at',i.created_at,'active_keys',(select count(*) from device_signing_key k where k.identity_id=i.id and not exists(select 1 from device_key_revocation r where r.key_id=k.id)),'grants',(select count(*) from device_key_project_grant g join device_signing_key k on k.id=g.key_id where k.identity_id=i.id and g.revoked_at is null and (g.expires_at is null or g.expires_at>now()))) order by i.created_at),'[]'::jsonb) from identity i join identity o on o.id=i.service_owner where i.kind='service' and i.erased_at is null")
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(json!({"items": items})))
}

/// `POST /admin/service-accounts/{id}/enrolment-login`: a ten-minute login for the service account,
/// shown once, with which the administrator enrols its device key (`/devices/challenge` and
/// `/devices`) and grants it projects. It cannot be refreshed past the ten minutes; afterwards the
/// account acts only through its key's project sessions (one hour, one project, granted scopes).
async fn enrolment_login(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&state, &auth).await?;
    crate::auth::sessions::require_recent_login(&state, &auth).await?;
    let mut tx = state.pool.begin().await?;
    let generation: Option<i64> = sqlx::query_scalar("select session_generation from identity where id=$1 and kind='service' and disabled_at is null and erased_at is null for update")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    let generation = generation.ok_or(ApiError::NotFound)?;
    let login = Login {
        lifetime_seconds: Some(600),
        ..Login::plain("service-enrolment")
    };
    let (tokens, session) =
        crate::auth::routes::mint_session_with(&state, &mut *tx, id, generation, &login).await?;
    crate::product::audit(
        &mut tx,
        auth.identity_id,
        "service_account.enrolment_login",
        id,
        json!({"session_id": session}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        serde_json::to_value(tokens).map_err(|e| ApiError::Internal(e.to_string()))?,
    ))
}

#[derive(Deserialize)]
struct ProjectRole {
    /// `editor`, `reviewer` or `viewer`; `null` removes the membership.
    role: Option<String>,
}

/// `PUT /admin/service-accounts/{id}/projects/{project}`: the service account's role in a project
/// (a normal membership, so every project rule applies). Never `owner` or `manager`.
async fn set_service_project(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((id, project)): Path<(Uuid, Uuid)>,
    Json(input): Json<ProjectRole>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&state, &auth).await?;
    if input
        .role
        .as_deref()
        .is_some_and(|r| !["editor", "reviewer", "viewer"].contains(&r))
    {
        return Err(bad("A service account is an editor, reviewer or viewer."));
    }
    let mut tx = state.pool.begin().await?;
    let known: bool = sqlx::query_scalar("select exists(select 1 from identity where id=$1 and kind='service' and erased_at is null) and exists(select 1 from access_space where id=$2 and kind='project')")
        .bind(id)
        .bind(project)
        .fetch_one(&mut *tx)
        .await?;
    if !known {
        return Err(ApiError::NotFound);
    }
    match &input.role {
        Some(role) => {
            sqlx::query("insert into space_member(space_id,identity_id,role) values($1,$2,$3) on conflict(space_id,identity_id) do update set role=excluded.role")
                .bind(project)
                .bind(id)
                .bind(role)
                .execute(&mut *tx)
                .await?;
        }
        None => {
            sqlx::query("delete from space_member where space_id=$1 and identity_id=$2")
                .bind(project)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
    }
    crate::product::audit(
        &mut tx,
        auth.identity_id,
        "service_account.project_role",
        id,
        json!({"project_id": project, "role": input.role}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id": id, "project_id": project, "role": input.role}),
    ))
}

#[derive(Deserialize)]
struct UsageQuery {
    #[serde(default = "window")]
    window_days: i32,
}
fn window() -> i32 {
    90
}

/// `GET /internal/installation` (service key only): the installation id and its first start, from
/// which the self-hosted web tier binds the licence and counts the trial (decision 037).
async fn installation(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, ApiError> {
    crate::auth::routes::require_service(&state, &headers).map_err(|_| ApiError::Forbidden)?;
    let (id, started_at): (Uuid, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("select id, started_at from device_authority where singleton")
            .fetch_one(&state.pool)
            .await?;
    Ok(Json(
        json!({ "installation": id, "started_at": started_at }),
    ))
}

/// `GET /admin/usage-report`: seat and project counts computed here and never sent anywhere
/// (docs/SELF-HOSTED-LICENSING-AND-DISTRIBUTION.md 10). No names, addresses, titles or content.
/// The web tier adds the licence and its limits before offering the file for download.
async fn usage_report(
    State(state): State<AppState>,
    auth: AuthContext,
    Query(q): Query<UsageQuery>,
) -> Result<Json<Value>, ApiError> {
    require_reader(&state, &auth).await?;
    if !(1..=366).contains(&q.window_days) {
        return Err(bad("window_days is 1 to 366."));
    }
    let counts: Value = sqlx::query_scalar("select jsonb_build_object(
        'registered',(select count(*) from identity i where i.kind='person' and i.erased_at is null and not exists(select 1 from agent_identity a where a.identity_id=i.id)),
        'enabled',(select count(*) from identity i where i.kind='person' and i.erased_at is null and i.disabled_at is null and not exists(select 1 from agent_identity a where a.identity_id=i.id)),
        'active',(select count(*) from identity i where i.kind='person' and i.erased_at is null and i.disabled_at is null and (exists(select 1 from login_session s where s.identity_id=i.id and greatest(s.started_at,coalesce(s.last_refresh_at,s.started_at))>now()-make_interval(days=>$1)) or exists(select 1 from refresh_token r where r.identity_id=i.id and r.created_at>now()-make_interval(days=>$1)))),
        'contributors',(select count(distinct e.actor_id) from event e join identity i on i.id=e.actor_id and i.kind='person' where e.created_at>now()-make_interval(days=>$1)),
        'service_accounts',(select count(*) from identity where kind='service' and erased_at is null),
        'projects',(select count(*) from access_space where kind='project'),
        'documents',(select count(*) from document where deleted_at is null),
        'database_bytes',pg_database_size(current_database()))")
        .bind(q.window_days)
        .fetch_one(&state.pool)
        .await?;
    let installation = state.installation().await?;
    Ok(Json(json!({
        "report_format": 1,
        "generated_at": chrono::Utc::now(),
        "product_version": env!("CARGO_PKG_VERSION"),
        "installation": installation,
        "window_days": q.window_days,
        "counts": counts,
    })))
}
