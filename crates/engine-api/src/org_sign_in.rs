//! Organisation sign-in settings kept in the database (docs/decisions/031-enterprise-identity.md
//! section 10, migration 0077): an organisation's owners and admins configure its identity
//! providers, verified email domains, group mapping and who may join, from the web workspace.
//!
//! What this module enforces whatever the caller sends:
//!
//! - Only an organisation `owner` or `admin` (an active account, through an account login: agent,
//!   device and connector credentials are refused by the extractor) reads or changes the settings.
//!   Every change writes an audit row; none holds a secret.
//! - A client secret is accepted, sealed with the `DYNOENC` envelope ([`crate::identity_secrets`]:
//!   `IDENTITY_SECRETS_KEY`, else a key derived from the server key), bound to this installation and
//!   provider row, and never
//!   returned to a person. Only the web tier, with the service key, receives it to call the
//!   provider (`internal_providers`).
//! - Fields the server decides cannot be set: the domains a provider may link or create accounts
//!   in are the organisation's verified domains (DNS TXT, `verified`), never a list from the
//!   settings, and an organisation's mapping can neither grant the instance administrator role nor
//!   target a space the person saving it does not manage.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    admin::require_admin,
    auth::{routes::require_service, AuthContext},
    error::ApiError,
    AppState,
};

/// The routes of this module.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/organisations", get(mine).post(create))
        .route("/organisations/{id}/sign-in", get(read))
        .route("/organisations/{id}/sign-in/settings", put(save_settings))
        .route(
            "/organisations/{id}/sign-in/providers/{slug}",
            put(save_provider).delete(delete_provider),
        )
        .route("/organisations/{id}/domains", post(add_domain))
        .route(
            "/organisations/{id}/domains/{domain}",
            axum::routing::delete(remove_domain),
        )
        .route(
            "/organisations/{id}/domains/{domain}/verified",
            post(verified),
        )
        .route("/organisations/{id}/members", put(set_member))
        .route("/organisations/{id}/sign-in/options", put(save_options))
        .route(
            "/organisations/{id}/sign-in/mapping/preview",
            axum::routing::post(preview_mapping),
        )
        .route("/organisations/{id}/audit/export", get(export_audit))
        .route("/internal/sign-in/providers", get(internal_providers))
}

fn bad(reason: &str) -> ApiError {
    ApiError::BadRequest {
        reason: reason.into(),
    }
}

/// The caller's role in `organisation` if it is `owner` or `admin`; otherwise `403`. With
/// `instance_admin`, an instance administrator (`ADMIN_EMAILS` or the mapped role) also passes.
pub(crate) async fn require_manager(
    state: &AppState,
    auth: &AuthContext,
    organisation: Uuid,
    instance_admin: bool,
) -> Result<String, ApiError> {
    let role: Option<String> = sqlx::query_scalar("select m.role from organisation_member m join identity i on i.id=m.identity_id where m.organisation_id=$1 and m.identity_id=$2 and m.role in ('owner','admin') and i.disabled_at is null and i.erased_at is null")
        .bind(organisation)
        .bind(auth.identity_id)
        .fetch_optional(&state.pool)
        .await?;
    match role {
        Some(role) => Ok(role),
        None if instance_admin && require_admin(state, auth).await.is_ok() => {
            Ok("instance_admin".into())
        }
        None => Err(ApiError::Forbidden),
    }
}

/// The caller's role if they may read the organisation's settings: `owner`, `admin` or the
/// read-only `auditor`; an instance administrator or auditor also passes (`instance_reader`).
pub(crate) async fn require_org_reader(
    state: &AppState,
    auth: &AuthContext,
    organisation: Uuid,
) -> Result<String, ApiError> {
    let role: Option<String> = sqlx::query_scalar("select m.role from organisation_member m join identity i on i.id=m.identity_id where m.organisation_id=$1 and m.identity_id=$2 and m.role in ('owner','admin','auditor') and i.disabled_at is null and i.erased_at is null")
        .bind(organisation)
        .bind(auth.identity_id)
        .fetch_optional(&state.pool)
        .await?;
    match role {
        Some(role) => Ok(role),
        None if crate::admin::require_reader(state, auth).await.is_ok() => {
            Ok("instance_reader".into())
        }
        None => Err(ApiError::Forbidden),
    }
}

async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    actor: Uuid,
    action: &str,
    resource: Uuid,
    detail: Value,
) -> Result<(), ApiError> {
    crate::product::audit(tx, actor, action, resource, detail).await
}

// --- sealing client secrets ---------------------------------------------------------------------

async fn installation(db: &mut PgConnection) -> Result<Uuid, ApiError> {
    Ok(
        sqlx::query_scalar("select id from device_authority where singleton")
            .fetch_one(db)
            .await?,
    )
}

const SECRET_TABLE: &str = "organisation_sign_in_provider";
const SECRET_COLUMN: &str = "secret_sealed";

fn seal(
    state: &AppState,
    installation: Uuid,
    row: Uuid,
    secret: &str,
) -> Result<Vec<u8>, ApiError> {
    crate::identity_secrets::seal(
        &state.identity_sealing_key(),
        installation,
        SECRET_TABLE,
        SECRET_COLUMN,
        row.as_bytes(),
        secret.as_bytes(),
    )
    .map_err(|e| ApiError::Internal(e.to_string()))
}

fn open(state: &AppState, installation: Uuid, row: Uuid, sealed: &[u8]) -> Option<String> {
    let plain = crate::identity_secrets::open(
        &state.identity_opening_keys(),
        installation,
        SECRET_TABLE,
        SECRET_COLUMN,
        row.as_bytes(),
        sealed,
    )?;
    String::from_utf8(plain).ok()
}

// --- organisations ------------------------------------------------------------------------------

async fn mine(State(state): State<AppState>, auth: AuthContext) -> Result<Json<Value>, ApiError> {
    let items: Vec<Value> = sqlx::query_scalar("select jsonb_build_object('id',o.id,'name',o.name,'role',m.role) from organisation_member m join organisation o on o.id=m.organisation_id where m.identity_id=$1 order by o.created_at limit 100")
        .bind(auth.identity_id)
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(json!({"items": items})))
}

#[derive(Deserialize)]
struct NewOrganisation {
    name: String,
}

/// Anyone signed in may create an organisation and becomes its owner. It has no power over
/// accounts until a domain is verified.
async fn create(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(input): Json<NewOrganisation>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let name = input.name.trim();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(bad("Give a name of 1 to 200 characters."));
    }
    let owned: i64 = sqlx::query_scalar(
        "select count(*) from organisation_member where identity_id=$1 and role='owner'",
    )
    .bind(auth.identity_id)
    .fetch_one(&state.pool)
    .await?;
    if owned >= 20 {
        return Err(bad("You already own 20 organisations."));
    }
    let mut tx = state.pool.begin().await?;
    let id: Uuid =
        sqlx::query_scalar("insert into organisation(name,created_by) values($1,$2) returning id")
            .bind(name)
            .bind(auth.identity_id)
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query("insert into organisation_member(organisation_id,identity_id,source,role) values($1,$2,'manual','owner')")
        .bind(id)
        .bind(auth.identity_id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        auth.identity_id,
        "organisation.created",
        id,
        json!({"by": "member"}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id": id, "name": name, "role": "owner"})),
    ))
}

const RECORD_PREFIX: &str = "_dynodoc-verification";

fn domain_json(
    domain: &str,
    token: &str,
    verified_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Value {
    json!({
        "domain": domain,
        "verified_at": verified_at,
        "record_name": format!("{RECORD_PREFIX}.{domain}"),
        "record_value": format!("dynodoc-verification={token}"),
    })
}

/// Everything the settings screen shows. No secret: a provider only says whether it has one.
async fn read(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let role = require_org_reader(&state, &auth, id).await?;
    let organisation: Value = sqlx::query_scalar("select jsonb_build_object('id',id,'name',name,'restrict_join',restrict_join,'agents_enabled',agents_enabled,'agents_valid_after',agents_valid_after,'agent_clients_denied',agent_clients_denied,'mapping',sign_in_mapping,'revision',revision,'approval_email',approval_email,'mapping_frozen',mapping_frozen,'scim_breaker_percent',scim_breaker_percent,'scim_breaker_minimum',scim_breaker_minimum) from organisation where id=$1")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    let providers: Vec<Value> = sqlx::query_scalar("select jsonb_build_object('slug',slug,'kind',kind,'preset',preset,'display_name',display_name,'settings',settings,'enabled',enabled,'has_secret',secret_sealed is not null,'revision',revision,'updated_at',updated_at) from organisation_sign_in_provider where organisation_id=$1 order by created_at")
        .bind(id)
        .fetch_all(&state.pool)
        .await?;
    let rows: Vec<(String, String, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
        "select domain,token,verified_at from organisation_domain where organisation_id=$1 order by created_at",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    let members: Vec<Value> = sqlx::query_scalar("select jsonb_build_object('identity_id',i.id,'email',i.email,'role',m.role,'source',m.source) from organisation_member m join identity i on i.id=m.identity_id where m.organisation_id=$1 and i.erased_at is null order by m.role, i.email limit 500")
        .bind(id)
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(json!({
        "organisation": organisation,
        "role": role,
        "providers": providers,
        "domains": rows.iter().map(|(d, t, v)| domain_json(d, t, *v)).collect::<Vec<_>>(),
        "members": members,
    })))
}

// --- settings: who may join, the mapping, AI agents -------------------------------------------

#[derive(Deserialize)]
struct SettingsInput {
    revision: i64,
    restrict_join: Option<bool>,
    /// `{"ceiling", "on_removal", "rules": [...]}` as in MAPPINGS_FILE.
    mapping: Option<Value>,
    /// Remove the mapping.
    #[serde(default)]
    clear_mapping: bool,
    agents_enabled: Option<bool>,
    #[serde(default)]
    cut_off_agents: bool,
    /// AI client kinds no member may use (migration 0116); absent keeps the saved list.
    agent_clients_denied: Option<Vec<String>>,
}

/// An organisation's mapping may only target spaces the person saving it manages, and never
/// grants the instance administrator role (that stays with the operator's MAPPINGS_FILE).
async fn check_mapping(
    db: &mut PgConnection,
    person: Uuid,
    mapping: &Value,
) -> Result<(), ApiError> {
    let rules = mapping
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("A mapping has a list of rules."))?;
    if rules.len() > 500 {
        return Err(bad("At most 500 rules."));
    }
    for rule in rules {
        let grant = rule.get("grant").cloned().unwrap_or(Value::Null);
        if grant.get("instance_role").is_some() {
            return Err(ApiError::Denied {
                reason: "An organisation's rules cannot make anyone an administrator of this installation.".into(),
            });
        }
        let space = grant
            .get("space_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| bad("Each rule grants a role in a space, by its id."))?;
        let manages: bool = sqlx::query_scalar(
            "select coalesce(inherited_space_role($1,$2) in ('owner','manager'),false)",
        )
        .bind(space)
        .bind(person)
        .fetch_one(&mut *db)
        .await?;
        if !manages {
            return Err(ApiError::Denied {
                reason: "A rule names a space you do not manage.".into(),
            });
        }
    }
    Ok(())
}

async fn save_settings(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<SettingsInput>,
) -> Result<Json<Value>, ApiError> {
    require_manager(&state, &auth, id, false).await?;
    crate::auth::sessions::require_recent_login(&state, &auth).await?;
    let mut tx = state.pool.begin().await?;
    let current: i64 =
        sqlx::query_scalar("select revision from organisation where id=$1 for update")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if current != input.revision {
        return Err(ApiError::Conflict {
            reason: "The settings changed; read them again.".into(),
        });
    }
    if let Some(mapping) = &input.mapping {
        if mapping.to_string().len() > 262_144 {
            return Err(bad("The mapping is too large."));
        }
        check_mapping(&mut tx, auth.identity_id, mapping).await?;
    }
    let denied = match input.agent_clients_denied.clone() {
        Some(mut kinds) => {
            kinds.sort();
            kinds.dedup();
            if kinds
                .iter()
                .any(|k| !crate::agent::identity::CLIENT_KINDS.contains(&k.as_str()))
            {
                return Err(bad("agent_clients_denied lists unknown client kinds."));
            }
            Some(kinds)
        }
        None => None,
    };
    sqlx::query("update organisation set agent_clients_denied=coalesce($7,agent_clients_denied),restrict_join=coalesce($2,restrict_join),sign_in_mapping=case when $3 then $4 else sign_in_mapping end,agents_enabled=coalesce($5,agents_enabled),agents_valid_after=case when $6 then greatest(agents_valid_after,clock_timestamp()) else agents_valid_after end,revision=revision+1,updated_at=now() where id=$1")
        .bind(id)
        .bind(input.restrict_join)
        .bind(input.mapping.is_some() || input.clear_mapping)
        .bind(input.mapping.clone().filter(|_| !input.clear_mapping))
        .bind(input.agents_enabled)
        .bind(input.cut_off_agents)
        .bind(&denied)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        auth.identity_id,
        if input.cut_off_agents { "organisation.agents_cut_off" } else { "organisation.sign_in_settings.saved" },
        id,
        json!({"restrict_join": input.restrict_join, "mapping_changed": input.mapping.is_some() || input.clear_mapping, "agents_enabled": input.agents_enabled, "agent_clients_denied": denied}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok": true, "revision": current + 1})))
}

// --- identity providers ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ProviderInput {
    kind: String,
    preset: Option<String>,
    display_name: String,
    settings: Value,
    /// Write-only. Absent or empty keeps the stored secret.
    client_secret: Option<String>,
    #[serde(default)]
    enabled: bool,
    /// The revision read; 0 creates the provider.
    revision: i64,
}

/// Keys the server sets itself; a settings object that names one is refused.
const SERVER_KEYS: [&str; 7] = [
    "allowed_domains",
    "hosted_domains",
    "organisation_id",
    "client_secret",
    "client_secret_file",
    "idp_metadata_file",
    "id",
];

/// Google's issuer, shared by every Google Workspace customer: its tokens are signed with Google's
/// keys (never an organisation's) and `hd` is held to the organisation's verified domains.
const SHARED_ISSUER: &str = "https://accounts.google.com";

fn slug_ok(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 63
        && slug.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

async fn save_provider(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((id, slug)): Path<(Uuid, String)>,
    Json(input): Json<ProviderInput>,
) -> Result<Json<Value>, ApiError> {
    require_manager(&state, &auth, id, false).await?;
    crate::auth::sessions::require_recent_login(&state, &auth).await?;
    if !slug_ok(&slug) {
        return Err(bad(
            "The short name uses lower-case letters, digits, - or _.",
        ));
    }
    if !["oidc", "saml"].contains(&input.kind.as_str()) {
        return Err(bad("Choose OpenID Connect or SAML."));
    }
    if input
        .preset
        .as_deref()
        .is_some_and(|p| !["google", "microsoft", "okta", "other"].contains(&p))
    {
        return Err(bad("Unknown preset."));
    }
    let name = input.display_name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(bad("Give a button name of 1 to 80 characters."));
    }
    let settings = input
        .settings
        .as_object()
        .ok_or_else(|| bad("Settings are an object."))?;
    if let Some(key) = SERVER_KEYS.iter().find(|k| settings.contains_key(**k)) {
        return Err(bad(&format!(
            "{key} is set by the server, not in the settings."
        )));
    }
    if input.settings.to_string().len() > 1_100_000 {
        return Err(bad("The settings are too large."));
    }
    let secret = input.client_secret.as_deref().filter(|s| !s.is_empty());
    if secret.is_some_and(|s| s.len() > 4096) {
        return Err(bad("The client secret is too long."));
    }
    // The issuer (OIDC) or entity ID (SAML) the provider's sign-ins carry; the web tier runs a
    // SAML provider with only the metadata entity that has this ID.
    let saml = input.kind == "saml";
    let issuer = settings
        .get(if saml { "idp_entity_id" } else { "issuer" })
        .and_then(Value::as_str)
        .filter(|i| !i.is_empty() && i.len() <= 512)
        .ok_or_else(|| {
            bad(if saml {
                "Read the identity provider's metadata again, then save."
            } else {
                "Give the provider's issuer."
            })
        })?;
    let mut tx = state.pool.begin().await?;
    let existing: Option<(Uuid, Uuid, i64, bool, String)> = sqlx::query_as("select id,organisation_id,revision,secret_sealed is not null,kind from organisation_sign_in_provider where slug=$1 for update")
        .bind(&slug)
        .fetch_optional(&mut *tx)
        .await?;
    let row = match existing {
        Some((_, organisation, _, _, _)) if organisation != id => {
            return Err(ApiError::Conflict {
                reason: "This short name is taken; choose another.".into(),
            })
        }
        Some((_, _, revision, _, _)) if revision != input.revision => {
            return Err(ApiError::Conflict {
                reason: "The provider changed; read it again.".into(),
            })
        }
        Some((row, _, _, has_secret, kind)) => {
            if kind != input.kind {
                return Err(bad("The kind of a provider cannot change; add a new one."));
            }
            if input.kind == "oidc" && input.enabled && secret.is_none() && !has_secret {
                return Err(bad("Add the client secret before turning this on."));
            }
            row
        }
        None if input.revision != 0 => return Err(ApiError::NotFound),
        None => {
            if input.kind == "oidc" && input.enabled && secret.is_none() {
                return Err(bad("Add the client secret before turning this on."));
            }
            let count: i64 = sqlx::query_scalar(
                "select count(*) from organisation_sign_in_provider where organisation_id=$1",
            )
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
            if count >= 10 {
                return Err(bad("At most 10 sign-in providers per organisation."));
            }
            let row = Uuid::new_v4();
            sqlx::query("insert into organisation_sign_in_provider(id,organisation_id,slug,kind,preset,display_name,settings,enabled,created_by) values($1,$2,$3,$4,$5,$6,$7,false,$8)")
                .bind(row)
                .bind(id)
                .bind(&slug)
                .bind(&input.kind)
                .bind(&input.preset)
                .bind(name)
                .bind(&input.settings)
                .bind(auth.identity_id)
                .execute(&mut *tx)
                .await?;
            row
        }
    };
    // Two providers never share an issuer: a SAML provider brings its own certificate, so one
    // claiming another's entity ID could vouch for that provider's people. The web tier holds the
    // operator's files to the same rule.
    if saml || issuer != SHARED_ISSUER {
        // Two saves of one issuer at once: the second waits and then sees the first.
        sqlx::query("select pg_advisory_xact_lock(hashtextextended($1::text,141))")
            .bind(issuer)
            .execute(&mut *tx)
            .await?;
        let used: bool = sqlx::query_scalar("select exists(select 1 from organisation_sign_in_provider where slug<>$1 and (case kind when 'saml' then settings->>'idp_entity_id' else settings->>'issuer' end)=$2)")
            .bind(&slug)
            .bind(issuer)
            .fetch_one(&mut *tx)
            .await?;
        if used {
            return Err(ApiError::Conflict {
                reason: "Another sign-in provider already uses this identity provider.".into(),
            });
        }
    }
    let sealed = match secret {
        Some(secret) => {
            let installation = installation(&mut tx).await?;
            Some(seal(&state, installation, row, secret)?)
        }
        None => None,
    };
    let revision: i64 = sqlx::query_scalar("update organisation_sign_in_provider set preset=$2,display_name=$3,settings=$4,enabled=$5,secret_sealed=coalesce($6,secret_sealed),revision=revision+case when revision=1 and $7 then 0 else 1 end,updated_at=now() where id=$1 returning revision")
        .bind(row)
        .bind(&input.preset)
        .bind(name)
        .bind(&input.settings)
        .bind(input.enabled)
        .bind(&sealed)
        .bind(input.revision == 0)
        .fetch_one(&mut *tx)
        .await?;
    audit(
        &mut tx,
        auth.identity_id,
        "organisation.sign_in_provider.saved",
        id,
        json!({"slug": slug, "kind": input.kind, "preset": input.preset, "enabled": input.enabled, "secret_changed": sealed.is_some()}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"ok": true, "slug": slug, "revision": revision}),
    ))
}

async fn delete_provider(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((id, slug)): Path<(Uuid, String)>,
) -> Result<Json<Value>, ApiError> {
    require_manager(&state, &auth, id, false).await?;
    crate::auth::sessions::require_recent_login(&state, &auth).await?;
    let mut tx = state.pool.begin().await?;
    let gone = sqlx::query(
        "delete from organisation_sign_in_provider where organisation_id=$1 and slug=$2",
    )
    .bind(id)
    .bind(&slug)
    .execute(&mut *tx)
    .await?;
    if gone.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit(
        &mut tx,
        auth.identity_id,
        "organisation.sign_in_provider.deleted",
        id,
        json!({"slug": slug}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok": true})))
}

// --- domains ------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct DomainInput {
    domain: String,
}

async fn add_domain(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<DomainInput>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    require_manager(&state, &auth, id, false).await?;
    crate::auth::sessions::require_recent_login(&state, &auth).await?;
    let domain = crate::directory::normal_domain(&input.domain)
        .ok_or_else(|| bad("Enter a domain such as example.org."))?;
    let mut tx = state.pool.begin().await?;
    let count: i64 =
        sqlx::query_scalar("select count(*) from organisation_domain where organisation_id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if count >= 20 {
        return Err(bad("At most 20 domains per organisation."));
    }
    let token = crate::auth::random_token()?.0[..32].to_owned();
    sqlx::query("insert into organisation_domain(organisation_id,domain,token,created_by) values($1,$2,$3,$4) on conflict do nothing")
        .bind(id)
        .bind(&domain)
        .bind(&token)
        .bind(auth.identity_id)
        .execute(&mut *tx)
        .await?;
    let (token, verified_at): (String, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
        "select token,verified_at from organisation_domain where organisation_id=$1 and domain=$2",
    )
    .bind(id)
    .bind(&domain)
    .fetch_one(&mut *tx)
    .await?;
    audit(
        &mut tx,
        auth.identity_id,
        "organisation.domain.added",
        id,
        json!({"domain": domain}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(domain_json(&domain, &token, verified_at)),
    ))
}

async fn remove_domain(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((id, domain)): Path<(Uuid, String)>,
) -> Result<Json<Value>, ApiError> {
    require_manager(&state, &auth, id, false).await?;
    crate::auth::sessions::require_recent_login(&state, &auth).await?;
    let mut tx = state.pool.begin().await?;
    let gone =
        sqlx::query("delete from organisation_domain where organisation_id=$1 and domain=$2")
            .bind(id)
            .bind(&domain)
            .execute(&mut *tx)
            .await?;
    if gone.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit(
        &mut tx,
        auth.identity_id,
        "organisation.domain.removed",
        id,
        json!({"domain": domain}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok": true})))
}

/// The web tier found the TXT record (it resolves DNS; the API does not): it calls this with the
/// service key AND the manager's own login. Only one organisation can hold a verified domain.
async fn verified(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: AuthContext,
    Path((id, domain)): Path<(Uuid, String)>,
) -> Result<Json<Value>, ApiError> {
    require_service(&state, &headers).map_err(|_| ApiError::Forbidden)?;
    require_manager(&state, &auth, id, false).await?;
    let mut tx = state.pool.begin().await?;
    let taken: bool = sqlx::query_scalar("select exists(select 1 from organisation_domain where domain=$1 and organisation_id<>$2 and verified_at is not null)")
        .bind(&domain)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if taken {
        return Err(ApiError::Conflict {
            reason: "Another organisation has already verified this domain.".into(),
        });
    }
    let changed = sqlx::query("update organisation_domain set verified_at=coalesce(verified_at,now()) where organisation_id=$1 and domain=$2")
        .bind(id)
        .bind(&domain)
        .execute(&mut *tx)
        .await?;
    if changed.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit(
        &mut tx,
        auth.identity_id,
        "organisation.domain.verified",
        id,
        json!({"domain": domain}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok": true})))
}

/// The domains an organisation's sign-in may link or create accounts in, and that `restrict_join`
/// admits: those its owners verified by DNS, and those an instance administrator set.
pub(crate) async fn organisation_domains(
    db: &mut PgConnection,
    organisation: Uuid,
) -> Result<Vec<String>, ApiError> {
    Ok(sqlx::query_scalar("select domain from organisation_domain where organisation_id=$1 and verified_at is not null union select unnest(domains) from organisation where id=$1")
        .bind(organisation)
        .fetch_all(db)
        .await?)
}

/// Domain routing: a person whose address is in an organisation's verified domain becomes a
/// member of it at sign-in (source `domain`). Called after every kind of sign-in.
pub async fn join_by_domain(pool: &sqlx::PgPool, identity: Uuid) -> Result<(), ApiError> {
    sqlx::query("insert into organisation_member(organisation_id,identity_id,source,role) select d.organisation_id,i.id,'domain','member' from identity i join organisation_domain d on d.domain=lower(split_part(i.email,'@',2)) and d.verified_at is not null where i.id=$1 on conflict do nothing")
        .bind(identity)
        .execute(pool)
        .await?;
    Ok(())
}

// --- members --------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct MemberInput {
    email: String,
    role: String,
}

/// Approve an existing account as a member, or change a member's role. Only owners grant or
/// remove `owner` and `admin`; the last owner stays an owner; `restrict_join` keeps people from
/// other domains out.
async fn set_member(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<MemberInput>,
) -> Result<Json<Value>, ApiError> {
    let mine = require_manager(&state, &auth, id, false).await?;
    if !["owner", "admin", "member", "auditor"].contains(&input.role.as_str()) {
        return Err(bad("Choose owner, admin, member or auditor."));
    }
    let email = crate::directory::normal_email(&input.email)
        .ok_or_else(|| bad("Enter an email address."))?;
    if crate::agent::identity::is_reserved_email(&email)
        || crate::auth::routes::is_service_email(&email)
    {
        return Err(bad("This address cannot be a member."));
    }
    let mut tx = state.pool.begin().await?;
    let person: Option<(Uuid, bool)> = sqlx::query_as(
        "select id,disabled_at is null and erased_at is null from identity where lower(email)=$1",
    )
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await?;
    // An address with no account gets one, as sharing a project does; the web tier then emails
    // the invitation (unless the organisation turned approval email off).
    let person = match person {
        Some((_, false)) => {
            return Err(ApiError::Denied {
                reason: "This account is disabled.".into(),
            })
        }
        Some((person, true)) => person,
        None => sqlx::query_scalar(
            "insert into identity(email) values($1) on conflict do nothing returning id",
        )
        .bind(&email)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| ApiError::Conflict {
            reason: "The account was created at the same time; try again.".into(),
        })?,
    };
    let current: Option<String> = sqlx::query_scalar("select role from organisation_member where organisation_id=$1 and identity_id=$2 for update")
        .bind(id)
        .bind(person)
        .fetch_optional(&mut *tx)
        .await?;
    let touches_managers =
        input.role != "member" || current.as_deref().is_some_and(|r| r != "member");
    if touches_managers && mine != "owner" {
        return Err(ApiError::Denied {
            reason: "Only an owner can make or remove owners and admins.".into(),
        });
    }
    if current.as_deref() == Some("owner") && input.role != "owner" {
        let owners: i64 = sqlx::query_scalar(
            "select count(*) from organisation_member where organisation_id=$1 and role='owner'",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if owners <= 1 {
            return Err(bad("An organisation keeps at least one owner."));
        }
    }
    if current.is_none() {
        let restrict: bool =
            sqlx::query_scalar("select restrict_join from organisation where id=$1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        if restrict
            && !crate::directory::in_domains(&email, &organisation_domains(&mut tx, id).await?)
        {
            return Err(ApiError::Denied {
                reason: "Only people from the organisation's domains may join.".into(),
            });
        }
    }
    sqlx::query("insert into organisation_member(organisation_id,identity_id,source,role) values($1,$2,'manual',$3) on conflict(organisation_id,identity_id) do update set role=excluded.role,updated_at=now()")
        .bind(id)
        .bind(person)
        .bind(&input.role)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        auth.identity_id,
        "organisation.member.set",
        id,
        json!({"identity_id": person, "role": input.role}),
    )
    .await?;
    let (name, approval_email): (String, bool) =
        sqlx::query_as("select name,approval_email from organisation where id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(Json(json!({
        "ok": true,
        "identity_id": person,
        "email": email,
        "role": input.role,
        "added": current.is_none(),
        "approval_email": approval_email,
        "organisation_name": name,
    })))
}

#[derive(Deserialize)]
struct OptionsInput {
    approval_email: Option<bool>,
    mapping_frozen: Option<bool>,
    scim_breaker_percent: Option<i32>,
    scim_breaker_minimum: Option<i32>,
}

/// `PUT /organisations/{id}/sign-in/options`: the approval email, the mapping freeze (an
/// incident switch: reconciliation stops, sign-in keeps working) and the SCIM circuit breaker.
async fn save_options(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<OptionsInput>,
) -> Result<Json<Value>, ApiError> {
    require_manager(&state, &auth, id, true).await?;
    crate::auth::sessions::require_recent_login(&state, &auth).await?;
    if input
        .scim_breaker_percent
        .is_some_and(|p| !(1..=100).contains(&p))
        || input
            .scim_breaker_minimum
            .is_some_and(|m| !(1..=100_000).contains(&m))
    {
        return Err(bad(
            "The breaker is 1 to 100 percent and at least 1 to 100000 accounts per hour.",
        ));
    }
    let mut tx = state.pool.begin().await?;
    let row: Option<Value> = sqlx::query_scalar("update organisation set approval_email=coalesce($2,approval_email),mapping_frozen=coalesce($3,mapping_frozen),scim_breaker_percent=coalesce($4,scim_breaker_percent),scim_breaker_minimum=coalesce($5,scim_breaker_minimum),updated_at=now() where id=$1 returning jsonb_build_object('approval_email',approval_email,'mapping_frozen',mapping_frozen,'scim_breaker_percent',scim_breaker_percent,'scim_breaker_minimum',scim_breaker_minimum)")
        .bind(id)
        .bind(input.approval_email)
        .bind(input.mapping_frozen)
        .bind(input.scim_breaker_percent)
        .bind(input.scim_breaker_minimum)
        .fetch_optional(&mut *tx)
        .await?;
    let row = row.ok_or(ApiError::NotFound)?;
    audit(
        &mut tx,
        auth.identity_id,
        "organisation.sign_in.options",
        id,
        row.clone(),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(row))
}

#[derive(Deserialize)]
struct PreviewInput {
    identity_id: Uuid,
    /// `scim` or `idp:<provider>`: the rows the mapping would own.
    source: String,
    memberships: crate::directory::Mapped,
}

/// `POST /organisations/{id}/sign-in/mapping/preview`: the exact change set the mapping result
/// (computed by the web tier from the person's groups) would make for one member, without making
/// it (identity document 10.4). Owners, admins and auditors of the organisation.
async fn preview_mapping(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<PreviewInput>,
) -> Result<Json<Value>, ApiError> {
    require_org_reader(&state, &auth, id).await?;
    let source_ok = input.source == "scim"
        || input.source.strip_prefix("idp:").is_some_and(|p| {
            !p.is_empty()
                && p.len() <= 63
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        });
    if !source_ok {
        return Err(bad("The source is scim or idp:<provider>."));
    }
    let mut tx = state.pool.begin().await?;
    let member: bool = sqlx::query_scalar("select exists(select 1 from organisation_member where organisation_id=$1 and identity_id=$2)")
        .bind(id)
        .bind(input.identity_id)
        .fetch_one(&mut *tx)
        .await?;
    if !member {
        return Err(ApiError::NotFound);
    }
    let mut mapped = input.memberships;
    // Never shown as possible: an organisation's mapping does not grant the instance role.
    mapped.instance_admin = None;
    let mut result =
        crate::directory::reconcile(&mut tx, input.identity_id, &input.source, &mapped).await?;
    tx.rollback().await?;
    result["dry_run"] = json!(true);
    Ok(Json(result))
}

/// `GET /organisations/{id}/audit/export`: the organisation's part of the audit log as JSON lines
/// (owners, admins and auditors of the organisation; see [`crate::admin_identity`]).
async fn export_audit(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    axum::extract::Query(q): axum::extract::Query<crate::admin_identity::ExportQuery>,
) -> Result<axum::response::Response, ApiError> {
    require_org_reader(&state, &auth, id).await?;
    crate::admin_identity::export(&state, auth.identity_id, Some(id), q).await
}

// --- the web tier's feed ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct ProviderRow {
    id: Uuid,
    organisation_id: Uuid,
    slug: String,
    kind: String,
    preset: Option<String>,
    display_name: String,
    settings: Value,
    secret_sealed: Option<Vec<u8>>,
    enabled: bool,
    mapping: Option<Value>,
    restrict_join: bool,
}

/// Every configured provider with what the web tier needs to run it: the opened client secret, the
/// organisation's sign-in domains and mapping. Service key only; never reachable with a login.
async fn internal_providers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    require_service(&state, &headers).map_err(|_| ApiError::Forbidden)?;
    let mut db = state.pool.acquire().await?;
    let installation = installation(&mut db).await?;
    let rows: Vec<ProviderRow> = sqlx::query_as("select p.id,p.organisation_id,p.slug,p.kind,p.preset,p.display_name,p.settings,p.secret_sealed,p.enabled,o.sign_in_mapping as mapping,o.restrict_join from organisation_sign_in_provider p join organisation o on o.id=p.organisation_id order by p.created_at")
        .fetch_all(&mut *db)
        .await?;
    let mut items = Vec::with_capacity(rows.len());
    for r in rows {
        let (row, organisation, slug, sealed) = (r.id, r.organisation_id, r.slug, r.secret_sealed);
        let secret = sealed
            .as_deref()
            .and_then(|s| open(&state, installation, row, s));
        if sealed.is_some() && secret.is_none() {
            tracing::warn!(%slug, "a provider's client secret could not be opened (server key changed?)");
        }
        items.push(json!({
            "slug": slug,
            "organisation_id": organisation,
            "kind": r.kind,
            "preset": r.preset,
            "display_name": r.display_name,
            "settings": r.settings,
            "client_secret": secret,
            "enabled": r.enabled,
            "domains": organisation_domains(&mut db, organisation).await?,
            "mapping": r.mapping,
            "restrict_join": r.restrict_join,
        }));
    }
    Ok(Json(json!({"items": items})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert!(slug_ok("acme-sso") && slug_ok("g1_x"));
        assert!(
            !slug_ok("")
                && !slug_ok("Acme")
                && !slug_ok("-x")
                && !slug_ok("a/b")
                && !slug_ok(&"a".repeat(64))
        );
    }
}
