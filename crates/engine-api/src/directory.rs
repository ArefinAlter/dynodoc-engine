//! Directory primitives for enterprise identity (docs/decisions/031-enterprise-identity.md,
//! docs/SELF-HOSTED-IDENTITY-AND-ACCESS.md sections 4, 7, 10 and 14).
//!
//! No protocol code lives here: the web tier speaks OpenID Connect and SCIM 2.0 and calls these
//! generic routes. What this module enforces, whatever the web tier sends:
//!
//! - **Sign-in by an identity provider** (`external_sign_in`, reached through `/auth/exchange`
//!   with the service key): an account is found by `(provider, issuer, subject)` only (a link
//!   belongs to the provider that made it, so a second provider claiming the same issuer finds
//!   nothing); an organisation's provider signs nobody in until it has a verified domain; email
//!   links or creates an account only under the provider's policy, from a verified address in an
//!   allowed domain, and never re-links an account another subject of the same issuer already holds.
//! - **The SCIM directory** (`/internal/directory/*`): the service key AND an organisation's SCIM
//!   token (`Authorization: Bearer`). Every query is scoped to that organisation; an account is
//!   managed by at most one organisation's SCIM client, and only in the organisation's domains.
//! - **Deactivation** ([`deactivate`]): in one transaction the account is disabled, its account
//!   generation moves (every access token fails), its logins, device keys (so project device and
//!   agent sessions), connector grants and public links are revoked.
//! - **Mapped memberships** ([`reconcile`]): only rows tagged with the caller's source are added,
//!   changed or removed; manual memberships are never touched, `owner` is never granted.
//! - **The organisation record** (`/admin/organisations`, administrators only): its domains, its
//!   SCIM tokens (shown once, stored as SHA-256) and the AI-agent policy and kill switch that
//!   `crate::auth::agent::verify_current` reads on every agent request.

use axum::{
    extract::{Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    routing::{get, post, put},
    Json, Router,
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    admin::require_admin,
    auth::{random_token, routes::require_service, sha256, AuthContext, AuthError},
    error::ApiError,
    AppState,
};

/// The routes of this module (internal, and the administrators' organisation routes).
pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/internal/directory/users",
            get(list_users).post(create_user),
        )
        .route(
            "/internal/directory/users/{id}",
            get(get_user).patch(patch_user).delete(delete_user),
        )
        .route(
            "/internal/directory/users/{id}/memberships",
            put(put_memberships),
        )
        .route(
            "/internal/directory/groups",
            get(list_groups).post(create_group),
        )
        .route(
            "/internal/directory/groups/{id}",
            get(get_group).patch(patch_group).delete(delete_group),
        )
        .route("/internal/auth/once", post(record_once))
        .route(
            "/admin/organisations",
            get(list_organisations).post(create_organisation),
        )
        .route(
            "/admin/organisations/{id}",
            axum::routing::patch(update_organisation),
        )
        .route(
            "/admin/organisations/{id}/scim-tokens",
            get(list_tokens).post(create_token),
        )
        .route(
            "/admin/organisations/{id}/scim-tokens/{token}/revoke",
            post(revoke_token),
        )
        // The same token routes for the organisation's owners and admins.
        .route(
            "/organisations/{id}/scim-tokens",
            get(list_tokens).post(create_token),
        )
        .route(
            "/organisations/{id}/scim-tokens/{token}/revoke",
            post(revoke_token),
        )
        .route(
            "/organisations/{id}/scim-tokens/{token}/rotate",
            post(rotate_token),
        )
        .route("/organisations/{id}/scim/held", get(list_held))
        .route(
            "/organisations/{id}/scim/held/{identity}/{decision}",
            post(decide_held),
        )
}

fn bad(reason: &str) -> ApiError {
    ApiError::BadRequest {
        reason: reason.into(),
    }
}
fn conflict(reason: &str) -> ApiError {
    ApiError::Conflict {
        reason: reason.into(),
    }
}

/// A provider id, as in the provider file: lower-case letters, digits, `-` and `_`.
fn provider_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 63
        && id.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// A plain email address, lower-cased: one `@`, a dotted domain, no space or control character.
pub fn normal_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_lowercase();
    let (local, domain) = email.split_once('@')?;
    let fine = email.len() <= 254
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
        && !email.chars().any(|c| c.is_whitespace() || c.is_control());
    fine.then_some(email)
}

/// Whether `email`'s domain is one of `domains` (exact, lower-case).
pub fn in_domains(email: &str, domains: &[String]) -> bool {
    email
        .rsplit_once('@')
        .is_some_and(|(_, domain)| domains.iter().any(|d| d == domain))
}

/// A domain an administrator lists for an organisation, lower-cased, or `None` if it is not one.
pub(crate) fn normal_domain(raw: &str) -> Option<String> {
    let domain = raw.trim().trim_end_matches('.').to_lowercase();
    let fine = domain.len() <= 253
        && domain.contains('.')
        && domain
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63)
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    fine.then_some(domain)
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

// --- deactivation ----------------------------------------------------------------------------

/// End every way `identity` can act, in the caller's transaction: disabled, account generation
/// moved (every access token and emailed link fails its per-request check), logins revoked,
/// device keys revoked for good (project device sessions, agent sessions and OAuth grants hang on
/// them), connector grants and the public links the person made revoked. Authorship stays.
/// `source` goes into the audit row (`scim:<organisation>` or `admin`).
pub async fn deactivate(
    tx: &mut Transaction<'_, Postgres>,
    identity: Uuid,
    actor: Uuid,
    source: &str,
) -> Result<(), ApiError> {
    // Before the update: its trigger (migration 0033) also revokes the keys, and this count is
    // the audit's. A missing account rolls the whole transaction back.
    let keys = sqlx::query("insert into device_key_revocation(key_id) select id from device_signing_key where identity_id=$1 on conflict do nothing")
        .bind(identity)
        .execute(&mut **tx)
        .await?
        .rows_affected();
    let changed = sqlx::query("update identity set disabled_at=coalesce(disabled_at,now()),session_generation=session_generation+1 where id=$1 and erased_at is null")
        .bind(identity)
        .execute(&mut **tx)
        .await?
        .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    sqlx::query(
        "update refresh_token set revoked_at=now() where identity_id=$1 and revoked_at is null",
    )
    .bind(identity)
    .execute(&mut **tx)
    .await?;
    let grants = sqlx::query(
        "update connector_grant set revoked_at=now() where identity_id=$1 and revoked_at is null",
    )
    .bind(identity)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    sqlx::query("update public_document_view set revoked_at=now() where created_by=$1 and revoked_at is null")
        .bind(identity)
        .execute(&mut **tx)
        .await?;
    audit(
        tx,
        actor,
        "identity.deactivated",
        identity,
        json!({"source": source, "device_keys_revoked": keys, "connector_grants_revoked": grants}),
    )
    .await
}

// --- sign-in through an identity provider ---------------------------------------------------

/// What the web tier asserts after validating a provider's ID token, and the provider's policy
/// from its configuration file. Nested under `external` in the `/auth/exchange` body.
#[derive(Deserialize)]
pub struct ExternalSignIn {
    /// The configured provider id (`oidc-providers.json`).
    pub provider: String,
    /// The validated `iss`.
    pub issuer: String,
    /// The validated `sub`.
    pub subject: String,
    /// Whether the address is verified (the claim, or the provider's `trust_email`).
    #[serde(default)]
    pub email_verified: bool,
    /// `link_by_email: verified`: an unlinked account with this verified address may be linked.
    #[serde(default)]
    pub link_by_email: bool,
    /// `jit`, `invite_only` or `scim_only`; only `jit` creates an account at sign-in.
    #[serde(default)]
    pub provisioning: String,
    /// When not empty, the address must be in one of these domains to link or create.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// The organisation the provider belongs to; the person becomes a member (`idp:<provider>`).
    pub organisation_id: Option<Uuid>,
    /// The mapping engine's result for this sign-in; `None` when the groups are unknown (an
    /// overage, or groups that come from SCIM), which changes nothing.
    pub memberships: Option<Mapped>,
    /// The provider comes from the operator's file, not from an organisation's settings.
    #[serde(default)]
    pub operator: bool,
    /// The provider's session: OIDC `sid` or SAML `SessionIndex` (back-channel logout).
    pub idp_session: Option<String>,
    /// The validated OIDC ID token, kept sealed for RP-initiated logout.
    pub id_token: Option<String>,
    /// `auth_time` from the ID token (seconds since the epoch).
    pub auth_time: Option<i64>,
}

/// Sign `email` in through `claims`, in one transaction with the session it mints. Errors are
/// [`AuthError::Forbidden`] for a refusal under the provider's policy and
/// [`AuthError::TokenInvalid`] for a disabled account (the same answer as today).
pub(crate) async fn external_sign_in(
    state: &AppState,
    email: Option<&str>,
    display_name: Option<&str>,
    mut claims: ExternalSignIn,
) -> Result<Value, ApiError> {
    if !provider_ok(&claims.provider)
        || claims.issuer.is_empty()
        || claims.issuer.len() > 512
        || claims.subject.is_empty()
        || claims.subject.len() > 512
    {
        return Err(AuthError::Forbidden.into());
    }
    // A provider an organisation configured (migration 0077) is held to that organisation and its
    // verified domains, whatever the web tier sends, and never grants the instance admin role.
    let configured: Option<(Uuid, Uuid, bool)> = if claims.operator {
        None
    } else {
        sqlx::query_as(
            "select id,organisation_id,enabled from organisation_sign_in_provider where slug=$1",
        )
        .bind(&claims.provider)
        .fetch_optional(&state.pool)
        .await?
    };
    // The link key: an organisation's provider is its row, an operator's provider its id alone.
    let provider_row = configured.map(|(row, _, _)| row);
    if let Some((_, organisation, enabled)) = configured {
        if !enabled {
            return Err(AuthError::Forbidden.into());
        }
        let mut db = state.pool.acquire().await?;
        claims.allowed_domains =
            crate::org_sign_in::organisation_domains(&mut db, organisation).await?;
        // Until the organisation proves a domain, its provider signs nobody in, linked or not.
        if claims.allowed_domains.is_empty() {
            return Err(AuthError::Forbidden.into());
        }
        claims.organisation_id = Some(organisation);
        if let Some(mapped) = claims.memberships.as_mut() {
            mapped.instance_admin = None;
        }
    }
    // An organisation's provider with no verified domain links and creates nothing by address.
    let restricted = configured.is_some();
    let domain_allowed = |email: &str| {
        (claims.allowed_domains.is_empty() && !restricted)
            || in_domains(email, &claims.allowed_domains)
    };
    let email = email.and_then(normal_email);
    let display_name = display_name.map(|n| n.chars().take(200).collect::<String>());
    let source = format!("idp:{}", claims.provider);
    let mut tx = state.pool.begin().await?;
    let linked: Option<(Uuid, Uuid)> = sqlx::query_as(
        "select id,identity_id from identity_external where provider=$1 and provider_row is not distinct from $2 and issuer=$3 and subject=$4 for update",
    )
    .bind(&claims.provider)
    .bind(provider_row)
    .bind(&claims.issuer)
    .bind(&claims.subject)
    .fetch_optional(&mut *tx)
    .await?;
    let (identity, created, newly_linked) = match linked {
        Some((link, identity)) => {
            let row: Option<(String, i64)> = sqlx::query_as("select email,profile_revision from identity where id=$1 and disabled_at is null and erased_at is null for update")
                .bind(identity)
                .fetch_optional(&mut *tx)
                .await?;
            let (current, profile_revision) = row.ok_or(AuthError::TokenInvalid)?;
            sqlx::query("update identity_external set last_login_at=now() where id=$1")
                .bind(link)
                .execute(&mut *tx)
                .await?;
            // The address follows the provider only when it is verified, allowed and unused.
            if let Some(email) = email
                .as_deref()
                .filter(|e| claims.email_verified && *e != current.to_lowercase())
            {
                let allowed = domain_allowed(email);
                let taken: bool = sqlx::query_scalar(
                    "select exists(select 1 from identity where lower(email)=$1)",
                )
                .bind(email)
                .fetch_one(&mut *tx)
                .await?;
                if allowed && !taken && !crate::agent::identity::is_reserved_email(email) {
                    sqlx::query("update identity set email=$2 where id=$1")
                        .bind(identity)
                        .bind(email)
                        .execute(&mut *tx)
                        .await?;
                    audit(
                        &mut tx,
                        identity,
                        "identity.email_changed",
                        identity,
                        json!({"source": source}),
                    )
                    .await?;
                } else {
                    audit(&mut tx, identity, "identity.email_change_refused", identity, json!({"source": source, "reason": if taken { "in_use" } else { "not_allowed" }})).await?;
                }
            }
            if profile_revision == 0 && display_name.is_some() {
                sqlx::query("update identity set display_name=$2 where id=$1")
                    .bind(identity)
                    .bind(&display_name)
                    .execute(&mut *tx)
                    .await?;
            }
            (identity, false, false)
        }
        None => {
            // Linking or creating needs a verified address in an allowed domain.
            let email = email
                .filter(|_| claims.email_verified)
                .filter(|e| domain_allowed(e))
                .filter(|e| !crate::agent::identity::is_reserved_email(e))
                .filter(|e| !crate::auth::routes::is_service_email(e))
                .ok_or(AuthError::Forbidden)?;
            let existing: Option<(Uuid, bool)> = sqlx::query_as("select id,disabled_at is not null or erased_at is not null from identity where lower(email)=$1 for update")
                .bind(&email)
                .fetch_optional(&mut *tx)
                .await?;
            let (identity, created) = match existing {
                Some((_, true)) => return Err(AuthError::TokenInvalid.into()),
                Some((identity, false)) => {
                    // An account already linked to another subject of this issuer is that
                    // subject's (a reassigned address must not take it over).
                    let held: bool = sqlx::query_scalar("select exists(select 1 from identity_external where identity_id=$1 and issuer=$2)")
                        .bind(identity)
                        .bind(&claims.issuer)
                        .fetch_one(&mut *tx)
                        .await?;
                    if !claims.link_by_email || held {
                        return Err(AuthError::Forbidden.into());
                    }
                    (identity, false)
                }
                None if claims.provisioning == "jit" => {
                    let identity: Uuid = sqlx::query_scalar(
                        "insert into identity(email,display_name) values($1,$2) returning id",
                    )
                    .bind(&email)
                    .bind(&display_name)
                    .fetch_one(&mut *tx)
                    .await?;
                    (identity, true)
                }
                None => return Err(AuthError::Forbidden.into()),
            };
            let inserted = sqlx::query("insert into identity_external(identity_id,provider,provider_row,issuer,subject,email_at_link,last_login_at) values($1,$2,$3,$4,$5,$6,now()) on conflict do nothing")
                .bind(identity)
                .bind(&claims.provider)
                .bind(provider_row)
                .bind(&claims.issuer)
                .bind(&claims.subject)
                .bind(&email)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            if inserted == 0 {
                // A simultaneous first sign-in of the same subject won; the person tries again.
                return Err(AuthError::TokenInvalid.into());
            }
            audit(
                &mut tx,
                identity,
                if created {
                    "identity.created_by_provider"
                } else {
                    "identity.linked"
                },
                identity,
                json!({"provider": claims.provider}),
            )
            .await?;
            (identity, created, true)
        }
    };
    if let Some(organisation) = claims.organisation_id {
        let known: bool =
            sqlx::query_scalar("select exists(select 1 from organisation where id=$1)")
                .bind(organisation)
                .fetch_one(&mut *tx)
                .await?;
        if !known {
            return Err(bad(
                "The provider names an organisation that does not exist.",
            ));
        }
        // "Only people from these domains may join" (migration 0077) holds for new members.
        let (member, restrict, address): (bool, bool, String) = sqlx::query_as("select exists(select 1 from organisation_member where organisation_id=$1 and identity_id=$2),(select restrict_join from organisation where id=$1),(select email from identity where id=$2)")
            .bind(organisation)
            .bind(identity)
            .fetch_one(&mut *tx)
            .await?;
        if !member
            && restrict
            && !in_domains(
                &address.to_lowercase(),
                &crate::org_sign_in::organisation_domains(&mut tx, organisation).await?,
            )
        {
            return Err(AuthError::Forbidden.into());
        }
        sqlx::query("insert into organisation_member(organisation_id,identity_id,source) values($1,$2,$3) on conflict do nothing")
            .bind(organisation)
            .bind(identity)
            .bind(&source)
            .execute(&mut *tx)
            .await?;
    }
    // A frozen mapping (an incident with a bad rule) changes nothing; sign-in still works.
    let frozen: bool = match claims.organisation_id {
        Some(organisation) => {
            sqlx::query_scalar("select mapping_frozen from organisation where id=$1")
                .bind(organisation)
                .fetch_one(&mut *tx)
                .await?
        }
        None => false,
    };
    let changes = match &claims.memberships {
        Some(mapped) if !frozen => Some(reconcile(&mut tx, identity, &source, mapped).await?),
        _ => None,
    };
    let auth_time = match claims.auth_time {
        Some(t) => Some(auth_time_at(t, Utc::now()).ok_or(AuthError::Forbidden)?),
        None => None,
    };
    let generation: i64 = sqlx::query_scalar("select session_generation from identity where id=$1")
        .bind(identity)
        .fetch_one(&mut *tx)
        .await?;
    let login = crate::auth::Login {
        provider: &claims.provider,
        issuer: Some(&claims.issuer),
        subject: Some(&claims.subject),
        idp_session: claims
            .idp_session
            .as_deref()
            .filter(|s| !s.is_empty() && s.len() <= 512),
        id_token: claims.id_token.as_deref(),
        auth_time,
        lifetime_seconds: None,
    };
    let (tokens, _) =
        crate::auth::routes::mint_session_with(state, &mut *tx, identity, generation, &login)
            .await?;
    tx.commit().await?;
    crate::org_sign_in::join_by_domain(&state.pool, identity).await?;
    let mut body = serde_json::to_value(tokens).map_err(|e| ApiError::Internal(e.to_string()))?;
    body["identity_id"] = json!(identity);
    body["created"] = json!(created);
    body["linked"] = json!(newly_linked);
    body["memberships"] = json!(changes);
    body["mapping_frozen"] = json!(frozen);
    Ok(body)
}

/// The provider's `auth_time` as the login records it: never later than `now` (a future value
/// would make every later re-authentication check pass), and `None` (sign-in refused) when it is
/// more than five minutes ahead or not a time at all.
fn auth_time_at(seconds: i64, now: chrono::DateTime<Utc>) -> Option<chrono::DateTime<Utc>> {
    let at = chrono::DateTime::from_timestamp(seconds, 0)?;
    (at <= now + Duration::minutes(5)).then(|| at.min(now))
}

// --- mapped memberships ----------------------------------------------------------------------

/// One grant from the mapping engine.
#[derive(Deserialize)]
pub struct Grant {
    /// An existing space (organisation, team, folder or project).
    pub space_id: Uuid,
    /// `manager`, `editor`, `reviewer` or `viewer` (never `owner`).
    pub role: String,
    /// The rule's name, kept on the row and in the audit.
    pub rule: String,
}

/// The mapping engine's desired state for one identity and one source.
#[derive(Deserialize)]
pub struct Mapped {
    /// Space memberships to hold.
    #[serde(default)]
    pub grants: Vec<Grant>,
    /// The rule that grants the instance `admin` role, or `None`.
    #[serde(default)]
    pub instance_admin: Option<String>,
    /// What happens to a mapped membership that is no longer desired: `remove` (default),
    /// `downgrade_to_viewer` or `keep_until_review`.
    #[serde(default)]
    pub on_removal: Option<String>,
}

const MAX_CHANGES: usize = 500;
const MAPPABLE: [&str; 4] = ["manager", "editor", "reviewer", "viewer"];

/// Bring the rows tagged `source` for `identity` to `mapped`. Manual rows and rows of another
/// source are left as they are and reported. Returns the change list (also in the audit row).
pub async fn reconcile(
    tx: &mut Transaction<'_, Postgres>,
    identity: Uuid,
    source: &str,
    mapped: &Mapped,
) -> Result<Value, ApiError> {
    let on_removal = mapped.on_removal.as_deref().unwrap_or("remove");
    if !["remove", "downgrade_to_viewer", "keep_until_review"].contains(&on_removal) {
        return Err(bad(
            "on_removal must be remove, downgrade_to_viewer or keep_until_review.",
        ));
    }
    // The strongest grant per space wins.
    let mut desired: Vec<(Uuid, &str, &str)> = Vec::new();
    for grant in &mapped.grants {
        if !MAPPABLE.contains(&grant.role.as_str()) || grant.rule.len() > 200 {
            return Err(bad(
                "A mapping grants manager, editor, reviewer or viewer only.",
            ));
        }
        let rank = |r: &str| MAPPABLE.len() - MAPPABLE.iter().position(|m| *m == r).unwrap_or(3);
        match desired
            .iter_mut()
            .find(|(space, _, _)| *space == grant.space_id)
        {
            Some(entry) if rank(&grant.role) > rank(entry.1) => {
                *entry = (grant.space_id, &grant.role, &grant.rule)
            }
            Some(_) => {}
            None => desired.push((grant.space_id, &grant.role, &grant.rule)),
        }
    }
    let current: Vec<(Uuid, String, String)> = sqlx::query_as(
        "select space_id,role,source from space_member where identity_id=$1 for update",
    )
    .bind(identity)
    .fetch_all(&mut **tx)
    .await?;
    let mut changes = Vec::new();
    let mut kept = Vec::new();
    let mut admin_removal_skipped = false;
    for (space, role, rule) in &desired {
        match current.iter().find(|(s, _, _)| s == space) {
            Some((_, have, from)) if from != source => {
                kept.push(json!({"space_id": space, "role": have, "source": from}))
            }
            Some((_, have, _)) if have == role => {}
            Some((_, have, _)) => {
                sqlx::query("update space_member set role=$3,mapping_rule=$4 where space_id=$1 and identity_id=$2")
                    .bind(space).bind(identity).bind(role).bind(rule).execute(&mut **tx).await?;
                changes.push(json!({"space_id": space, "from": have, "to": role, "rule": rule}));
            }
            None => {
                let added = sqlx::query("insert into space_member(space_id,identity_id,role,source,mapping_rule) select id,$2,$3,$4,$5 from access_space where id=$1")
                    .bind(space).bind(identity).bind(role).bind(source).bind(rule).execute(&mut **tx).await?;
                if added.rows_affected() == 1 {
                    changes
                        .push(json!({"space_id": space, "from": null, "to": role, "rule": rule}));
                } else {
                    kept.push(json!({"space_id": space, "missing": true}));
                }
            }
        }
    }
    for (space, have, from) in &current {
        // An owner row is never removed by mapping (it may be the space's last owner).
        if from != source || have == "owner" || desired.iter().any(|(s, _, _)| s == space) {
            continue;
        }
        let to = match on_removal {
            "remove" => None,
            "downgrade_to_viewer" if have != "viewer" => Some("viewer"),
            _ => continue,
        };
        match to {
            None => {
                sqlx::query("delete from space_member where space_id=$1 and identity_id=$2")
                    .bind(space)
                    .bind(identity)
                    .execute(&mut **tx)
                    .await?
            }
            Some(role) => {
                sqlx::query("update space_member set role=$3 where space_id=$1 and identity_id=$2")
                    .bind(space)
                    .bind(identity)
                    .bind(role)
                    .execute(&mut **tx)
                    .await?
            }
        };
        changes.push(json!({"space_id": space, "from": have, "to": to}));
    }
    let admin_before: Option<String> = sqlx::query_scalar(
        "select source from identity_instance_role where identity_id=$1 and role='admin'",
    )
    .bind(identity)
    .fetch_optional(&mut **tx)
    .await?;
    match (&mapped.instance_admin, admin_before.as_deref()) {
        (Some(rule), None) => {
            sqlx::query("insert into identity_instance_role(identity_id,role,source,mapping_rule) values($1,'admin',$2,$3)")
                .bind(identity).bind(source).bind(rule).execute(&mut **tx).await?;
            changes
                .push(json!({"instance_role": "admin", "from": null, "to": "admin", "rule": rule}));
        }
        (None, Some(from)) if from == source => {
            // Owner's decision (5 November 2026): a mapping never removes a Dynodoc
            // administrator; the skip is reported and audited, an administrator acts in Dynodoc.
            kept.push(json!({"instance_role": "admin", "source": from, "reason": "administrators are not removed by mapping"}));
            admin_removal_skipped = true;
        }
        _ => {}
    }
    if changes.len() > MAX_CHANGES {
        return Err(bad(
            "The mapping would change more than 500 memberships at once; review the rules.",
        ));
    }
    let result = json!({"changes": changes, "kept": kept});
    if admin_removal_skipped {
        audit(
            tx,
            identity,
            "membership.admin_removal_skipped",
            identity,
            json!({"source": source}),
        )
        .await?;
    }
    if !changes.is_empty() {
        audit(
            tx,
            identity,
            "membership.mapped",
            identity,
            json!({"source": source, "changes": changes}),
        )
        .await?;
    }
    Ok(result)
}

// --- the SCIM directory --------------------------------------------------------------------

/// The organisation a directory request acts for, from its SCIM token.
struct Tenant {
    organisation: Uuid,
    /// The administrator who created the token: the actor of the audit rows.
    actor: Uuid,
    domains: Vec<String>,
}

/// Service key first, then the SCIM token. An unknown, revoked or expired token is `401`; a SCIM
/// token is never accepted by any other route (nothing else reads `scim_token`).
async fn tenant(state: &AppState, headers: &HeaderMap) -> Result<Tenant, ApiError> {
    require_service(state, headers).map_err(|_| ApiError::Forbidden)?;
    let raw = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or(ApiError::Unauthorized)?;
    let row: Option<(Uuid, Uuid, Vec<String>)> = sqlx::query_as("update scim_token t set last_used_at=now() from organisation o where o.id=t.organisation_id and t.token_hash=$1 and t.revoked_at is null and (t.expires_at is null or t.expires_at>now()) returning t.organisation_id,t.created_by,o.domains||coalesce(array(select d.domain from organisation_domain d where d.organisation_id=o.id and d.verified_at is not null),'{}'::text[])")
        .bind(sha256(raw.as_bytes()))
        .fetch_optional(&state.pool)
        .await?;
    let (organisation, actor, domains) = row.ok_or(ApiError::Unauthorized)?;
    // A per-token request window of one minute (identity document 7.5): a runaway provisioning
    // job is slowed, not refused for good. The table and its pruning are the sign-in windows'.
    let window = sha256(format!("scim-rate-v1:{}", hex::encode(sha256(raw.as_bytes()))).as_bytes());
    let used: i32 = sqlx::query_scalar("insert into auth_request_window(key_hash) values($1) on conflict(key_hash) do update set attempts=case when auth_request_window.started_at < now()-interval '1 minute' then 1 else least(auth_request_window.attempts+1,1000000) end, started_at=case when auth_request_window.started_at < now()-interval '1 minute' then now() else auth_request_window.started_at end returning attempts")
        .bind(window)
        .fetch_one(&state.pool)
        .await?;
    if used > state.scim_rate_per_minute {
        return Err(ApiError::RateLimited { retry_after: 60 });
    }
    Ok(Tenant {
        organisation,
        actor,
        domains,
    })
}

const USER_JSON: &str = "select jsonb_build_object('id',i.id,'user_name',i.email,'external_id',m.external_id,'display_name',i.display_name,'active',i.disabled_at is null,'created',m.added_at,'last_modified',m.updated_at,'version',m.version,'groups',coalesce((select jsonb_agg(jsonb_build_object('id',g.id,'display_name',g.display_name) order by g.display_name) from directory_group_member gm join directory_group g on g.id=gm.group_id where gm.identity_id=i.id and g.organisation_id=m.organisation_id),'[]'::jsonb)) from organisation_member m join identity i on i.id=m.identity_id where m.organisation_id=$1 and m.source='scim' and m.scim_deleted_at is null and i.erased_at is null";

async fn user_json(db: &mut PgConnection, organisation: Uuid, id: Uuid) -> Result<Value, ApiError> {
    sqlx::query_scalar(&format!("{USER_JSON} and i.id=$2"))
        .bind(organisation)
        .bind(id)
        .fetch_optional(db)
        .await?
        .ok_or(ApiError::NotFound)
}

#[derive(Deserialize)]
struct ListQuery {
    user_name: Option<String>,
    external_id: Option<String>,
    display_name: Option<String>,
    #[serde(default = "one")]
    start: i64,
    #[serde(default = "hundred")]
    count: i64,
}
fn one() -> i64 {
    1
}
fn hundred() -> i64 {
    100
}

async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let t = tenant(&state, &headers).await?;
    let filter = "and ($2::text is null or lower(i.email)=lower($2)) and ($3::text is null or m.external_id=$3)";
    let mut db = state.pool.acquire().await?;
    let total: i64 = sqlx::query_scalar(&format!("select count(*) from ({USER_JSON} {filter}) x"))
        .bind(t.organisation)
        .bind(&q.user_name)
        .bind(&q.external_id)
        .fetch_one(&mut *db)
        .await?;
    let items: Vec<Value> = sqlx::query_scalar(&format!(
        "{USER_JSON} {filter} order by m.added_at,i.id offset $4 limit $5"
    ))
    .bind(t.organisation)
    .bind(&q.user_name)
    .bind(&q.external_id)
    .bind((q.start.max(1) - 1).min(1_000_000))
    .bind(q.count.clamp(0, 100))
    .fetch_all(&mut *db)
    .await?;
    Ok(Json(json!({"total": total, "items": items})))
}

async fn get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let t = tenant(&state, &headers).await?;
    let mut db = state.pool.acquire().await?;
    Ok(Json(user_json(&mut db, t.organisation, id).await?))
}

#[derive(Deserialize)]
struct UserInput {
    user_name: Option<String>,
    external_id: Option<String>,
    display_name: Option<String>,
    active: Option<bool>,
}

fn external_ok(value: &Option<String>) -> Result<(), ApiError> {
    match value {
        Some(v) if v.is_empty() || v.len() > 256 => Err(bad("externalId is empty or too long.")),
        _ => Ok(()),
    }
}

/// Create an account in the organisation, or take over the lifecycle of an existing account in
/// its domains that no other organisation's SCIM client manages.
async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<UserInput>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let t = tenant(&state, &headers).await?;
    let email = input
        .user_name
        .as_deref()
        .and_then(normal_email)
        .ok_or_else(|| bad("userName must be an email address."))?;
    if !in_domains(&email, &t.domains) || crate::agent::identity::is_reserved_email(&email) {
        return Err(ApiError::Denied {
            reason: "The address is outside the organisation's domains.".into(),
        });
    }
    external_ok(&input.external_id)?;
    let mut tx = state.pool.begin().await?;
    let existing: Option<(Uuid, bool, i64)> = sqlx::query_as(
        "select id,erased_at is not null,profile_revision from identity where lower(email)=$1 for update",
    )
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await?;
    let mut returning = false;
    let identity = match existing {
        Some((_, true, _)) => return Err(conflict("uniqueness")),
        Some((identity, false, profile_revision)) => {
            // Managed by another organisation, or already here: refused. Deleted here: back.
            let managed: Option<(Uuid, bool)> = sqlx::query_as("select organisation_id,scim_deleted_at is not null from organisation_member where identity_id=$1 and source='scim'")
                .bind(identity)
                .fetch_optional(&mut *tx)
                .await?;
            match managed {
                Some((organisation, true)) if organisation == t.organisation => returning = true,
                Some(_) => return Err(conflict("uniqueness")),
                None => {}
            }
            if profile_revision == 0 && input.display_name.is_some() {
                sqlx::query("update identity set display_name=$2 where id=$1")
                    .bind(identity)
                    .bind(&input.display_name)
                    .execute(&mut *tx)
                    .await?;
            }
            identity
        }
        None => {
            sqlx::query_scalar(
                "insert into identity(email,display_name) values($1,$2) returning id",
            )
            .bind(&email)
            .bind(&input.display_name)
            .fetch_one(&mut *tx)
            .await?
        }
    };
    let taken: bool = sqlx::query_scalar("select exists(select 1 from organisation_member where organisation_id=$1 and external_id=$2 and identity_id<>$3)")
        .bind(t.organisation)
        .bind(&input.external_id)
        .bind(identity)
        .fetch_one(&mut *tx)
        .await?;
    if taken {
        return Err(conflict("uniqueness"));
    }
    sqlx::query("insert into organisation_member(organisation_id,identity_id,source,external_id) values($1,$2,'scim',$3) on conflict(organisation_id,identity_id) do update set source='scim',external_id=excluded.external_id,scim_deleted_at=null,version=organisation_member.version+1,updated_at=now()")
        .bind(t.organisation)
        .bind(identity)
        .bind(&input.external_id)
        .execute(&mut *tx)
        .await?;
    let scim = format!("scim:{}", t.organisation);
    audit(
        &mut tx,
        t.actor,
        "directory.user.provisioned",
        identity,
        json!({"source": scim}),
    )
    .await?;
    if input.active == Some(false) {
        if protected_admin(&mut tx, &state.admin_emails, identity).await? {
            tx.rollback().await?;
            return Err(refuse_admin(&state, &t, identity, "create").await);
        }
        deactivate(&mut tx, identity, t.actor, &scim).await?;
    } else if returning {
        // Deleted by this directory earlier and provisioned again: a new sign-in is needed.
        sqlx::query("update identity set disabled_at=null where id=$1")
            .bind(identity)
            .execute(&mut *tx)
            .await?;
        audit(
            &mut tx,
            t.actor,
            "identity.restored",
            identity,
            json!({"source": scim}),
        )
        .await?;
    }
    let body = user_json(&mut tx, t.organisation, identity).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(body)))
}

/// The SCIM user `id` of the tenant, locked for the change.
/// `If-Match` as the web tier forwards it from the SCIM client (`W/"<version>"`, `"<version>"`
/// or `*`): the version the client read, or `None` when absent or `*`.
fn if_match(headers: &HeaderMap) -> Result<Option<i64>, ApiError> {
    let Some(value) = headers.get(axum::http::header::IF_MATCH) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| bad("If-Match is not valid."))?
        .trim();
    if value == "*" {
        return Ok(None);
    }
    let value = value.strip_prefix("W/").unwrap_or(value).trim_matches('"');
    value
        .parse()
        .map(Some)
        .map_err(|_| bad("If-Match is not a version of this resource."))
}

/// `412` when the client read another version than the current one (RFC 7644 3.14).
fn precondition(expected: Option<i64>, current: i64) -> Result<(), ApiError> {
    match expected {
        Some(version) if version != current => Err(ApiError::Coded {
            status: StatusCode::PRECONDITION_FAILED,
            code: "precondition_failed",
            reason: "The resource changed since it was read.".into(),
            details: json!({ "version": current }),
        }),
        _ => Ok(()),
    }
}

/// The version of a SCIM user of `t`'s organisation (locked by [`managed_user`]).
async fn user_version(tx: &mut PgConnection, t: &Tenant, id: Uuid) -> Result<i64, ApiError> {
    Ok(sqlx::query_scalar(
        "select version from organisation_member where organisation_id=$1 and identity_id=$2",
    )
    .bind(t.organisation)
    .bind(id)
    .fetch_one(tx)
    .await?)
}

/// The SCIM deactivation circuit breaker (identity document 7.5): `true` when this organisation's
/// directory already deactivated as many accounts in the last hour as its threshold allows, the
/// larger of `scim_breaker_minimum` and `scim_breaker_percent` of its active SCIM members.
async fn breaker_tripped(tx: &mut PgConnection, organisation: Uuid) -> Result<bool, ApiError> {
    let (recent, active, percent, minimum): (i64, i64, i32, i32) = sqlx::query_as("select (select count(*) from operation_audit where action='identity.deactivated' and created_at>now()-interval '1 hour' and detail->>'source'=$2),(select count(*) from organisation_member m join identity i on i.id=m.identity_id where m.organisation_id=$1 and m.source='scim' and i.disabled_at is null),o.scim_breaker_percent,o.scim_breaker_minimum from organisation o where o.id=$1")
        .bind(organisation)
        .bind(format!("scim:{organisation}"))
        .fetch_one(tx)
        .await?;
    let threshold = (minimum as i64).max((active * percent as i64 + 99) / 100);
    Ok(recent >= threshold)
}

/// Hold a deactivation (or a delete, which supersedes a held deactivation) for an owner or admin.
async fn hold(
    tx: &mut Transaction<'_, Postgres>,
    t: &Tenant,
    identity: Uuid,
    operation: &str,
) -> Result<(), ApiError> {
    if operation == "delete" {
        sqlx::query("delete from scim_held_deactivation where organisation_id=$1 and identity_id=$2 and operation='deactivate'")
            .bind(t.organisation)
            .bind(identity)
            .execute(&mut **tx)
            .await?;
    }
    sqlx::query("insert into scim_held_deactivation(organisation_id,identity_id,operation) values($1,$2,$3) on conflict do nothing")
        .bind(t.organisation)
        .bind(identity)
        .bind(operation)
        .execute(&mut **tx)
        .await?;
    audit(
        tx,
        t.actor,
        "directory.deactivation_held",
        identity,
        json!({"source": format!("scim:{}", t.organisation), "operation": operation}),
    )
    .await
}

async fn managed_user(tx: &mut PgConnection, t: &Tenant, id: Uuid) -> Result<(), ApiError> {
    let found: Option<Uuid> = sqlx::query_scalar("select m.identity_id from organisation_member m join identity i on i.id=m.identity_id where m.organisation_id=$1 and m.identity_id=$2 and m.source='scim' and m.scim_deleted_at is null and i.erased_at is null for update of m, i")
        .bind(t.organisation)
        .bind(id)
        .fetch_optional(tx)
        .await?;
    found.map(|_| ()).ok_or(ApiError::NotFound)
}

async fn patch_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<UserInput>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let t = tenant(&state, &headers).await?;
    external_ok(&input.external_id)?;
    let expected = if_match(&headers)?;
    let scim = format!("scim:{}", t.organisation);
    let mut tx = state.pool.begin().await?;
    managed_user(&mut tx, &t, id).await?;
    precondition(expected, user_version(&mut tx, &t, id).await?)?;
    let mut held = false;
    if let Some(raw) = &input.user_name {
        let email = normal_email(raw).ok_or_else(|| bad("userName must be an email address."))?;
        if !in_domains(&email, &t.domains) || crate::agent::identity::is_reserved_email(&email) {
            return Err(ApiError::Denied {
                reason: "The address is outside the organisation's domains.".into(),
            });
        }
        let other: bool = sqlx::query_scalar(
            "select exists(select 1 from identity where lower(email)=$1 and id<>$2)",
        )
        .bind(&email)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if other {
            return Err(conflict("uniqueness"));
        }
        let changed = sqlx::query("update identity set email=$2 where id=$1 and lower(email)<>$2")
            .bind(id)
            .bind(&email)
            .execute(&mut *tx)
            .await?;
        if changed.rows_affected() == 1 {
            audit(
                &mut tx,
                t.actor,
                "identity.email_changed",
                id,
                json!({"source": scim}),
            )
            .await?;
        }
    }
    if let Some(external) = &input.external_id {
        let taken: bool = sqlx::query_scalar("select exists(select 1 from organisation_member where organisation_id=$1 and external_id=$2 and identity_id<>$3)")
            .bind(t.organisation).bind(external).bind(id).fetch_one(&mut *tx).await?;
        if taken {
            return Err(conflict("uniqueness"));
        }
        sqlx::query("update organisation_member set external_id=$3 where organisation_id=$1 and identity_id=$2")
            .bind(t.organisation).bind(id).bind(external).execute(&mut *tx).await?;
    }
    if input.display_name.is_some() {
        sqlx::query("update identity set display_name=$2 where id=$1 and profile_revision=0")
            .bind(id)
            .bind(&input.display_name)
            .execute(&mut *tx)
            .await?;
    }
    match input.active {
        Some(false) => {
            let active: bool =
                sqlx::query_scalar("select disabled_at is null from identity where id=$1")
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await?;
            if active {
                if protected_admin(&mut tx, &state.admin_emails, id).await? {
                    tx.rollback().await?;
                    return Err(refuse_admin(&state, &t, id, "patch").await);
                }
                if breaker_tripped(&mut tx, t.organisation).await? {
                    hold(&mut tx, &t, id, "deactivate").await?;
                    held = true;
                } else {
                    deactivate(&mut tx, id, t.actor, &scim).await?;
                }
            }
        }
        Some(true) => {
            // Back in: a new sign-in is needed; revoked keys stay revoked.
            let restored = sqlx::query(
                "update identity set disabled_at=null where id=$1 and disabled_at is not null",
            )
            .bind(id)
            .execute(&mut *tx)
            .await?;
            if restored.rows_affected() == 1 {
                audit(
                    &mut tx,
                    t.actor,
                    "identity.restored",
                    id,
                    json!({"source": scim}),
                )
                .await?;
            }
        }
        None => {}
    }
    sqlx::query("update organisation_member set version=version+1,updated_at=now() where organisation_id=$1 and identity_id=$2")
        .bind(t.organisation)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let mut body = user_json(&mut tx, t.organisation, id).await?;
    tx.commit().await?;
    if held {
        // Accepted, not done: an owner or admin confirms it (the account stays active meanwhile).
        body["held"] = json!(true);
        return Ok((StatusCode::ACCEPTED, Json(body)));
    }
    Ok((StatusCode::OK, Json(body)))
}

/// SCIM DELETE: deactivation plus a deleted marker; the account is never erased here.
async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response, ApiError> {
    use axum::response::IntoResponse;
    let t = tenant(&state, &headers).await?;
    let expected = if_match(&headers)?;
    let mut tx = state.pool.begin().await?;
    managed_user(&mut tx, &t, id).await?;
    precondition(expected, user_version(&mut tx, &t, id).await?)?;
    if protected_admin(&mut tx, &state.admin_emails, id).await? {
        tx.rollback().await?;
        return Err(refuse_admin(&state, &t, id, "delete").await);
    }
    let active: bool = sqlx::query_scalar("select disabled_at is null from identity where id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if active && breaker_tripped(&mut tx, t.organisation).await? {
        hold(&mut tx, &t, id, "delete").await?;
        tx.commit().await?;
        return Ok((StatusCode::ACCEPTED, Json(json!({"held": true}))).into_response());
    }
    delete_member(&mut tx, &t.organisation, id, t.actor, active).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// SCIM DELETE once allowed: group memberships go, the account is deactivated and marked deleted.
async fn delete_member(
    tx: &mut Transaction<'_, Postgres>,
    organisation: &Uuid,
    id: Uuid,
    actor: Uuid,
    active: bool,
) -> Result<(), ApiError> {
    let scim = format!("scim:{organisation}");
    let t = Tenant {
        organisation: *organisation,
        actor,
        domains: Vec::new(),
    };
    let groups: Vec<Value> = sqlx::query_scalar("delete from directory_group_member gm using directory_group g where g.id=gm.group_id and g.organisation_id=$1 and gm.identity_id=$2 returning to_jsonb(g.id)")
        .bind(t.organisation)
        .bind(id)
        .fetch_all(&mut **tx)
        .await?;
    if active {
        deactivate(tx, id, t.actor, &scim).await?;
    }
    sqlx::query("update organisation_member set scim_deleted_at=now(),version=version+1,updated_at=now() where organisation_id=$1 and identity_id=$2")
        .bind(t.organisation)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    audit(
        tx,
        t.actor,
        "directory.user.deleted",
        id,
        json!({"source": scim, "groups_left": groups.len()}),
    )
    .await
}

/// Whether `identity` is a Dynodoc administrator: an address in `ADMIN_EMAILS` or the instance
/// `admin` role. A directory never deactivates one (owner's decision, 5 November 2026).
async fn protected_admin(
    db: &mut PgConnection,
    admin_emails: &str,
    identity: Uuid,
) -> Result<bool, ApiError> {
    let (email, mapped): (String, bool) = sqlx::query_as("select email,exists(select 1 from identity_instance_role r where r.identity_id=identity.id and r.role='admin') from identity where id=$1")
        .bind(identity)
        .fetch_one(db)
        .await?;
    Ok(mapped || crate::admin::is_admin(&email, admin_emails))
}

/// The answer to a directory that tried to deactivate an administrator, after an audit row in a
/// transaction of its own (the caller rolled its own back first, so no row lock is held).
async fn refuse_admin(state: &AppState, t: &Tenant, identity: Uuid, operation: &str) -> ApiError {
    let audited = async {
        let mut tx = state.pool.begin().await?;
        audit(
            &mut tx,
            t.actor,
            "directory.admin_deactivation_refused",
            identity,
            json!({"source": format!("scim:{}", t.organisation), "operation": operation}),
        )
        .await?;
        tx.commit().await?;
        Ok::<_, ApiError>(())
    }
    .await;
    if let Err(error) = audited {
        tracing::warn!(%error, "audit of a refused directory deactivation failed");
    }
    ApiError::Denied {
        reason: "Dynodoc administrators are never deactivated by the directory. Another administrator can do it in Dynodoc.".into(),
    }
}

// --- the one-time ledger of sign-in flows ------------------------------------------------------

#[derive(Deserialize)]
struct OnceInput {
    kind: String,
    key: String,
    ttl_seconds: i64,
}

/// Accept a sign-in flow value once across every web process (migration 0076): an OpenID Connect
/// state, a SAML request id or a SAML assertion id. `200` the first time, `409` while it is
/// remembered. Only its SHA-256 is stored; expired rows are pruned on the way in.
async fn record_once(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<OnceInput>,
) -> Result<Json<Value>, ApiError> {
    require_service(&state, &headers).map_err(|_| ApiError::Forbidden)?;
    if !["oidc_state", "saml_request", "saml_assertion"].contains(&input.kind.as_str())
        || input.key.is_empty()
        || input.key.len() > 1024
        || !(1..=86_400).contains(&input.ttl_seconds)
    {
        return Err(bad(
            "A known kind, a key of 1 to 1024 bytes and 1 to 86400 seconds.",
        ));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("delete from auth_flow_once where expires_at<=now()")
        .execute(&mut *tx)
        .await?;
    let first = sqlx::query("insert into auth_flow_once(kind,key_hash,expires_at) values($1,$2,now()+make_interval(secs=>$3::double precision)) on conflict do nothing")
        .bind(&input.kind)
        .bind(sha256(input.key.as_bytes()))
        .bind(input.ttl_seconds)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 1;
    tx.commit().await?;
    if first {
        Ok(Json(json!({"ok": true})))
    } else {
        Err(conflict("This sign-in step was already used."))
    }
}

/// Mapping for SCIM-sourced groups: the web tier evaluates the rules on the user's groups and
/// sends the result here; the rows are tagged `scim`.
async fn put_memberships(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(options): Query<DryRun>,
    Json(mapped): Json<Mapped>,
) -> Result<Json<Value>, ApiError> {
    let t = tenant(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    managed_user(&mut tx, &t, id).await?;
    let frozen: bool = sqlx::query_scalar("select mapping_frozen from organisation where id=$1")
        .bind(t.organisation)
        .fetch_one(&mut *tx)
        .await?;
    if frozen && !options.dry_run {
        // An incident switch: nothing is reconciled until it is turned off (identity document 10.4).
        return Ok(Json(json!({"frozen": true, "changes": [], "kept": []})));
    }
    let mut result = reconcile(&mut tx, id, "scim", &mapped).await?;
    if options.dry_run {
        tx.rollback().await?;
        result["dry_run"] = json!(true);
        result["frozen"] = json!(frozen);
        return Ok(Json(result));
    }
    tx.commit().await?;
    Ok(Json(result))
}

/// `?dry_run=true`: compute the exact change set and change nothing.
#[derive(Deserialize, Default)]
pub(crate) struct DryRun {
    #[serde(default)]
    pub dry_run: bool,
}

/// `GET /organisations/{id}/scim/held`: deactivations the circuit breaker held (owners, admins
/// and auditors of the organisation).
async fn list_held(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    crate::org_sign_in::require_org_reader(&state, &auth, id).await?;
    let items: Value = sqlx::query_scalar("select coalesce(jsonb_agg(jsonb_build_object('identity_id',h.identity_id,'email',i.email,'operation',h.operation,'requested_at',h.requested_at) order by h.requested_at),'[]'::jsonb) from scim_held_deactivation h join identity i on i.id=h.identity_id where h.organisation_id=$1")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(json!({"items": items})))
}

/// `POST /organisations/{id}/scim/held/{identity}/{confirm|discard}`: an owner or admin carries
/// out a held deactivation (the administrator rule still applies) or drops it.
async fn decide_held(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((id, identity, decision)): Path<(Uuid, Uuid, String)>,
) -> Result<Json<Value>, ApiError> {
    crate::org_sign_in::require_manager(&state, &auth, id, true).await?;
    if decision != "confirm" && decision != "discard" {
        return Err(ApiError::NotFound);
    }
    let mut tx = state.pool.begin().await?;
    let operation: Option<String> = sqlx::query_scalar("delete from scim_held_deactivation where organisation_id=$1 and identity_id=$2 returning operation")
        .bind(id)
        .bind(identity)
        .fetch_optional(&mut *tx)
        .await?;
    let operation = operation.ok_or(ApiError::NotFound)?;
    if decision == "confirm" {
        if protected_admin(&mut tx, &state.admin_emails, identity).await? {
            return Err(ApiError::Denied {
                reason: "Dynodoc administrators are never deactivated by the directory.".into(),
            });
        }
        let active: bool =
            sqlx::query_scalar("select disabled_at is null from identity where id=$1")
                .bind(identity)
                .fetch_one(&mut *tx)
                .await?;
        if operation == "delete" {
            delete_member(&mut tx, &id, identity, auth.identity_id, active).await?;
        } else if active {
            deactivate(&mut tx, identity, auth.identity_id, &format!("scim:{id}")).await?;
        }
    }
    audit(
        &mut tx,
        auth.identity_id,
        if decision == "confirm" {
            "directory.deactivation_confirmed"
        } else {
            "directory.deactivation_discarded"
        },
        identity,
        json!({"organisation": id, "operation": operation}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"ok": true, "operation": operation, "decision": decision}),
    ))
}

const GROUP_JSON: &str = "select jsonb_build_object('id',g.id,'display_name',g.display_name,'external_id',g.external_id,'created',g.created_at,'last_modified',g.updated_at,'version',g.version,'members',coalesce((select jsonb_agg(jsonb_build_object('id',i.id,'user_name',i.email) order by i.email) from directory_group_member gm join identity i on i.id=gm.identity_id where gm.group_id=g.id),'[]'::jsonb)) from directory_group g where g.organisation_id=$1";

async fn group_json(
    db: &mut PgConnection,
    organisation: Uuid,
    id: Uuid,
) -> Result<Value, ApiError> {
    sqlx::query_scalar(&format!("{GROUP_JSON} and g.id=$2"))
        .bind(organisation)
        .bind(id)
        .fetch_optional(db)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let t = tenant(&state, &headers).await?;
    let filter =
        "and ($2::text is null or g.display_name=$2) and ($3::text is null or g.external_id=$3)";
    let mut db = state.pool.acquire().await?;
    let total: i64 = sqlx::query_scalar(&format!("select count(*) from ({GROUP_JSON} {filter}) x"))
        .bind(t.organisation)
        .bind(&q.display_name)
        .bind(&q.external_id)
        .fetch_one(&mut *db)
        .await?;
    let items: Vec<Value> = sqlx::query_scalar(&format!(
        "{GROUP_JSON} {filter} order by g.created_at,g.id offset $4 limit $5"
    ))
    .bind(t.organisation)
    .bind(&q.display_name)
    .bind(&q.external_id)
    .bind((q.start.max(1) - 1).min(1_000_000))
    .bind(q.count.clamp(0, 100))
    .fetch_all(&mut *db)
    .await?;
    Ok(Json(json!({"total": total, "items": items})))
}

async fn get_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let t = tenant(&state, &headers).await?;
    let mut db = state.pool.acquire().await?;
    Ok(Json(group_json(&mut db, t.organisation, id).await?))
}

#[derive(Deserialize)]
struct GroupInput {
    display_name: Option<String>,
    external_id: Option<String>,
    /// Members to add (SCIM user ids of this organisation).
    #[serde(default)]
    add: Vec<Uuid>,
    /// Members to remove.
    #[serde(default)]
    remove: Vec<Uuid>,
    /// The whole member list (POST, PUT, or a PATCH `replace` of `members`).
    replace: Option<Vec<Uuid>>,
}

const MAX_MEMBERS: usize = 5000;

/// Apply a member change; returns the identities whose group set changed, with that set, so the
/// web tier can run the mapping rules for each.
async fn apply_members(
    tx: &mut Transaction<'_, Postgres>,
    t: &Tenant,
    group: Uuid,
    input: &GroupInput,
) -> Result<Vec<Uuid>, ApiError> {
    let listed = input.add.len() + input.remove.len() + input.replace.as_ref().map_or(0, Vec::len);
    if listed > MAX_MEMBERS {
        return Err(bad("At most 5,000 members per request."));
    }
    let incoming: Vec<Uuid> = input
        .add
        .iter()
        .chain(input.replace.iter().flatten())
        .copied()
        .collect();
    let known: i64 = sqlx::query_scalar("select count(distinct identity_id) from organisation_member where organisation_id=$1 and source='scim' and scim_deleted_at is null and identity_id=any($2)")
        .bind(t.organisation)
        .bind(&incoming)
        .fetch_one(&mut **tx)
        .await?;
    let distinct = {
        let mut ids = incoming.clone();
        ids.sort();
        ids.dedup();
        ids.len()
    };
    if usize::try_from(known).unwrap_or(0) != distinct {
        return Err(bad("A member is not a user of this directory."));
    }
    let mut affected: Vec<Uuid> = Vec::new();
    if let Some(all) = &input.replace {
        let gone: Vec<Uuid> = sqlx::query_scalar("delete from directory_group_member where group_id=$1 and not (identity_id=any($2)) returning identity_id")
            .bind(group).bind(all).fetch_all(&mut **tx).await?;
        affected.extend(gone);
    }
    let added: Vec<Uuid> = sqlx::query_scalar("insert into directory_group_member(group_id,identity_id) select $1,unnest($2::uuid[]) on conflict do nothing returning identity_id")
        .bind(group).bind(&incoming).fetch_all(&mut **tx).await?;
    affected.extend(added);
    let removed: Vec<Uuid> = sqlx::query_scalar("delete from directory_group_member where group_id=$1 and identity_id=any($2) returning identity_id")
        .bind(group).bind(&input.remove).fetch_all(&mut **tx).await?;
    affected.extend(removed);
    affected.sort();
    affected.dedup();
    Ok(affected)
}

/// For each affected identity: its id and the display names of its groups in the organisation.
async fn affected_json(
    db: &mut PgConnection,
    organisation: Uuid,
    ids: &[Uuid],
) -> Result<Value, ApiError> {
    let rows: Vec<Value> = sqlx::query_scalar("select jsonb_build_object('identity_id',m.identity_id,'groups',coalesce((select jsonb_agg(g.display_name order by g.display_name) from directory_group_member gm join directory_group g on g.id=gm.group_id where gm.identity_id=m.identity_id and g.organisation_id=m.organisation_id),'[]'::jsonb)) from organisation_member m where m.organisation_id=$1 and m.source='scim' and m.scim_deleted_at is null and m.identity_id=any($2) order by m.identity_id")
        .bind(organisation)
        .bind(ids)
        .fetch_all(db)
        .await?;
    Ok(Value::Array(rows))
}

fn group_name(input: &GroupInput) -> Result<Option<&str>, ApiError> {
    match input.display_name.as_deref().map(str::trim) {
        Some(name) if name.is_empty() || name.chars().count() > 256 => {
            Err(bad("displayName is empty or too long."))
        }
        other => Ok(other),
    }
}

async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<GroupInput>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let t = tenant(&state, &headers).await?;
    let name = group_name(&input)?.ok_or_else(|| bad("displayName is required."))?;
    external_ok(&input.external_id)?;
    let mut tx = state.pool.begin().await?;
    let id: Option<Uuid> = sqlx::query_scalar("insert into directory_group(organisation_id,display_name,external_id) values($1,$2,$3) on conflict do nothing returning id")
        .bind(t.organisation)
        .bind(name)
        .bind(&input.external_id)
        .fetch_optional(&mut *tx)
        .await?;
    let id = id.ok_or_else(|| conflict("uniqueness"))?;
    let affected = apply_members(&mut tx, &t, id, &input).await?;
    audit(
        &mut tx,
        t.actor,
        "directory.group.created",
        id,
        json!({"source": format!("scim:{}", t.organisation), "members": affected.len()}),
    )
    .await?;
    let mut body = group_json(&mut tx, t.organisation, id).await?;
    body["affected"] = affected_json(&mut tx, t.organisation, &affected).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(body)))
}

async fn patch_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<GroupInput>,
) -> Result<Json<Value>, ApiError> {
    let t = tenant(&state, &headers).await?;
    let name = group_name(&input)?;
    external_ok(&input.external_id)?;
    let expected = if_match(&headers)?;
    let mut tx = state.pool.begin().await?;
    let found: Option<i64> = sqlx::query_scalar(
        "select version from directory_group where organisation_id=$1 and id=$2 for update",
    )
    .bind(t.organisation)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    precondition(expected, found.ok_or(ApiError::NotFound)?)?;
    let clash: bool = sqlx::query_scalar("select exists(select 1 from directory_group where organisation_id=$1 and id<>$2 and (display_name=$3 or external_id=$4))")
        .bind(t.organisation).bind(id).bind(name).bind(&input.external_id).fetch_one(&mut *tx).await?;
    if clash {
        return Err(conflict("uniqueness"));
    }
    sqlx::query("update directory_group set display_name=coalesce($2,display_name),external_id=coalesce($3,external_id),version=version+1,updated_at=now() where id=$1")
        .bind(id).bind(name).bind(&input.external_id).execute(&mut *tx).await?;
    let mut affected = apply_members(&mut tx, &t, id, &input).await?;
    if name.is_some() {
        // A renamed group can match other rules: every member's mapping runs again.
        affected =
            sqlx::query_scalar("select identity_id from directory_group_member where group_id=$1")
                .bind(id)
                .fetch_all(&mut *tx)
                .await?;
        affected.sort();
    }
    let mut body = group_json(&mut tx, t.organisation, id).await?;
    body["affected"] = affected_json(&mut tx, t.organisation, &affected).await?;
    tx.commit().await?;
    Ok(Json(body))
}

async fn delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let t = tenant(&state, &headers).await?;
    let mut tx = state.pool.begin().await?;
    let members: Vec<Uuid> = sqlx::query_scalar("select gm.identity_id from directory_group_member gm join directory_group g on g.id=gm.group_id where g.organisation_id=$1 and g.id=$2")
        .bind(t.organisation).bind(id).fetch_all(&mut *tx).await?;
    let gone = sqlx::query("delete from directory_group where organisation_id=$1 and id=$2")
        .bind(t.organisation)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    if gone.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit(
        &mut tx,
        t.actor,
        "directory.group.deleted",
        id,
        json!({"source": format!("scim:{}", t.organisation)}),
    )
    .await?;
    let affected = affected_json(&mut tx, t.organisation, &members).await?;
    tx.commit().await?;
    Ok(Json(json!({"affected": affected})))
}

// --- the organisation record (administrators) ---------------------------------------------------

const ORG_JSON: &str = "select jsonb_build_object('id',id,'name',name,'domains',domains,'agents_enabled',agents_enabled,'agents_valid_after',agents_valid_after,'revision',revision,'created_at',created_at,'updated_at',updated_at,'members',(select count(*) from organisation_member m where m.organisation_id=o.id)) from organisation o";

fn domains_of(raw: &[String]) -> Result<Vec<String>, ApiError> {
    if raw.len() > 50 {
        return Err(bad("At most 50 domains."));
    }
    let mut domains = raw
        .iter()
        .map(|d| normal_domain(d).ok_or_else(|| bad("A domain is not a valid domain name.")))
        .collect::<Result<Vec<_>, _>>()?;
    domains.sort();
    domains.dedup();
    Ok(domains)
}

#[derive(Deserialize)]
struct OrganisationInput {
    name: Option<String>,
    domains: Option<Vec<String>>,
    agents_enabled: Option<bool>,
    /// Pull the kill switch: every agent session issued so far stops at its next request.
    #[serde(default)]
    cut_off_agents: bool,
    /// The revision read (required for a change).
    revision: Option<i64>,
}

fn org_name(raw: Option<&str>) -> Result<Option<String>, ApiError> {
    match raw.map(str::trim) {
        Some(n) if n.is_empty() || n.chars().count() > 200 => {
            Err(bad("Give a name of 1 to 200 characters."))
        }
        other => Ok(other.map(str::to_owned)),
    }
}

async fn create_organisation(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(input): Json<OrganisationInput>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    require_admin(&state, &auth).await?;
    let name = org_name(input.name.as_deref())?
        .ok_or_else(|| bad("Give a name of 1 to 200 characters."))?;
    let domains = domains_of(input.domains.as_deref().unwrap_or_default())?;
    let mut tx = state.pool.begin().await?;
    let id: Uuid = sqlx::query_scalar("insert into organisation(name,domains,agents_enabled,created_by) values($1,$2,$3,$4) returning id")
        .bind(&name)
        .bind(&domains)
        .bind(input.agents_enabled.unwrap_or(true))
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
        json!({"domains": domains}),
    )
    .await?;
    let body: Value = sqlx::query_scalar(&format!("{ORG_JSON} where id=$1"))
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(body)))
}

async fn list_organisations(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<Value>, ApiError> {
    crate::admin::require_reader(&state, &auth).await?;
    let items: Vec<Value> =
        sqlx::query_scalar(&format!("{ORG_JSON} order by created_at limit 200"))
            .fetch_all(&state.pool)
            .await?;
    Ok(Json(json!({"items": items})))
}

async fn update_organisation(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<OrganisationInput>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&state, &auth).await?;
    let revision = input
        .revision
        .ok_or_else(|| bad("Send the revision you read."))?;
    let name = org_name(input.name.as_deref())?;
    let domains = input.domains.as_deref().map(domains_of).transpose()?;
    let mut tx = state.pool.begin().await?;
    let current: Option<i64> =
        sqlx::query_scalar("select revision from organisation where id=$1 for update")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if current.ok_or(ApiError::NotFound)? != revision {
        return Err(conflict("The organisation changed; read it again."));
    }
    sqlx::query("update organisation set name=coalesce($2,name),domains=coalesce($3,domains),agents_enabled=coalesce($4,agents_enabled),agents_valid_after=case when $5 then greatest(agents_valid_after,clock_timestamp()) else agents_valid_after end,revision=revision+1,updated_at=now() where id=$1")
        .bind(id)
        .bind(&name)
        .bind(&domains)
        .bind(input.agents_enabled)
        .bind(input.cut_off_agents)
        .execute(&mut *tx)
        .await?;
    let body: Value = sqlx::query_scalar(&format!("{ORG_JSON} where id=$1"))
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    audit(
        &mut tx,
        auth.identity_id,
        if input.cut_off_agents {
            "organisation.agents_cut_off"
        } else {
            "organisation.updated"
        },
        id,
        json!({"name": name.is_some(), "domains": domains, "agents_enabled": input.agents_enabled}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(body))
}

#[derive(Deserialize)]
struct TokenInput {
    label: String,
    /// Days until the token stops working (1 to 730); none means until revoked.
    expires_in_days: Option<i64>,
}

/// A new SCIM token for the organisation, shown once.
async fn create_token(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<TokenInput>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    crate::org_sign_in::require_manager(&state, &auth, id, true).await?;
    crate::auth::sessions::require_recent_login(&state, &auth).await?;
    let label = input.label.trim();
    if label.is_empty() || label.chars().count() > 100 {
        return Err(bad("Give a label of 1 to 100 characters."));
    }
    let expires_at = match input.expires_in_days {
        Some(days) if (1..=730).contains(&days) => Some(Utc::now() + Duration::days(days)),
        Some(_) => return Err(bad("A token lasts 1 to 730 days.")),
        None => None,
    };
    let (token, hash) = random_token()?;
    let mut tx = state.pool.begin().await?;
    let row: Option<Uuid> = sqlx::query_scalar("insert into scim_token(organisation_id,token_hash,label,created_by,expires_at) select id,$2,$3,$4,$5 from organisation where id=$1 returning id")
        .bind(id)
        .bind(hash)
        .bind(label)
        .bind(auth.identity_id)
        .bind(expires_at)
        .fetch_optional(&mut *tx)
        .await?;
    let token_id = row.ok_or(ApiError::NotFound)?;
    audit(
        &mut tx,
        auth.identity_id,
        "organisation.scim_token.created",
        id,
        json!({"token_id": token_id, "label": label}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id": token_id, "token": token, "expires_at": expires_at})),
    ))
}

async fn list_tokens(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    crate::org_sign_in::require_manager(&state, &auth, id, true).await?;
    let items: Vec<Value> = sqlx::query_scalar("select jsonb_build_object('id',id,'label',label,'created_by',created_by,'created_at',created_at,'expires_at',expires_at,'last_used_at',last_used_at,'revoked_at',revoked_at) from scim_token where organisation_id=$1 order by created_at desc limit 100")
        .bind(id)
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(json!({"items": items})))
}

/// A new token in place of `token`, same label and lifetime left, the old one revoked at once.
async fn rotate_token(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((id, token)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    crate::org_sign_in::require_manager(&state, &auth, id, true).await?;
    crate::auth::sessions::require_recent_login(&state, &auth).await?;
    let (plain, hash) = random_token()?;
    let mut tx = state.pool.begin().await?;
    let new: Option<Uuid> = sqlx::query_scalar("with old as (update scim_token set revoked_at=now() where id=$2 and organisation_id=$1 and revoked_at is null returning label,expires_at) insert into scim_token(organisation_id,token_hash,label,created_by,expires_at) select $1,$3,label,$4,expires_at from old returning id")
        .bind(id)
        .bind(token)
        .bind(hash)
        .bind(auth.identity_id)
        .fetch_optional(&mut *tx)
        .await?;
    let new = new.ok_or(ApiError::NotFound)?;
    audit(
        &mut tx,
        auth.identity_id,
        "organisation.scim_token.rotated",
        id,
        json!({"token_id": new, "replaced": token}),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id": new, "token": plain})),
    ))
}

async fn revoke_token(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((id, token)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, ApiError> {
    crate::org_sign_in::require_manager(&state, &auth, id, true).await?;
    let mut tx = state.pool.begin().await?;
    let changed = sqlx::query("update scim_token set revoked_at=coalesce(revoked_at,now()) where id=$2 and organisation_id=$1")
        .bind(id)
        .bind(token)
        .execute(&mut *tx)
        .await?;
    if changed.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit(
        &mut tx,
        auth.identity_id,
        "organisation.scim_token.revoked",
        id,
        json!({"token_id": token}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok": true})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_and_domains() {
        assert_eq!(
            normal_email(" Ana@Example.ORG "),
            Some("ana@example.org".into())
        );
        for bad in [
            "",
            "a",
            "a@b",
            "@example.org",
            "a@.example.org",
            "a b@example.org",
            "a@b@example.org",
            "a@example.org.",
        ] {
            assert_eq!(normal_email(bad), None, "{bad}");
        }
        let domains = vec!["example.org".to_string()];
        assert!(in_domains("a@example.org", &domains));
        assert!(!in_domains("a@sub.example.org", &domains));
        assert!(!in_domains("a@example.org.evil.test", &domains));
        assert_eq!(normal_domain("Example.ORG."), Some("example.org".into()));
        assert_eq!(normal_domain("exa mple.org"), None);
        assert_eq!(normal_domain("localhost"), None);
        assert!(
            provider_ok("uni-sso_1")
                && !provider_ok("Uni")
                && !provider_ok("")
                && !provider_ok("-x")
        );
    }

    #[test]
    fn auth_time_is_never_in_the_future() {
        let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let earlier = auth_time_at(1_799_999_000, now).unwrap();
        assert_eq!(earlier.timestamp(), 1_799_999_000);
        // A little ahead (clock skew) is recorded as now; far ahead is refused.
        assert_eq!(auth_time_at(1_800_000_200, now), Some(now));
        assert_eq!(auth_time_at(1_800_000_000 + 86_400 * 365, now), None);
        assert_eq!(auth_time_at(i64::MAX, now), None);
    }
}
