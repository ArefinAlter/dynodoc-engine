//! Project merge policies and organisation floors (docs/DESIGN-NODE-CONFLICT-RESOLUTION.md
//! 6.2 and 8, decision 042).
//!
//! | Route | Who | What |
//! |---|---|---|
//! | `GET /projects/{id}/merge-policy` | any project member | the stored policy, its hash and revision, the organisation floor and the effective floor |
//! | `PUT /projects/{id}/merge-policy` | a person: project owner or manager | save a policy; `If-Match` revision; refused below the effective organisation floor; a manager may not lower the project's own floors |
//! | `GET /organisations/{id}/merge-floor` | an organisation member | the floor and its revision |
//! | `PUT /organisations/{id}/merge-floor` | a person: organisation owner or admin | save the floor; `If-Match` revision |
//!
//! Account sessions only: a device, agent or connector token is refused, and the database
//! refuses a save by any identity that is not a person. Every save writes a revision row and
//! an `operation_audit` row with the old and new hashes in the same transaction.
//!
//! The organisation floor of a project is the strictest floor of every organisation that one
//! of the project's owners belongs to (a project has no organisation of its own; decision
//! 042). The effective floor at publication adds the stored project policy's own floors.
use crate::{auth::AuthContext, error::ApiError, product::audit, projects, AppState};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use engine_core::merge_policy::{policy::Floors, MergePolicy, Registry};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgConnection;
use uuid::Uuid;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/projects/{id}/merge-policy",
            get(get_policy).put(put_policy),
        )
        .route(
            "/organisations/{id}/merge-floor",
            get(get_floor).put(put_floor),
        )
        .layer(DefaultBodyLimit::max(32 * 1024))
}

fn bad(reason: impl Into<String>) -> ApiError {
    ApiError::BadRequest {
        reason: reason.into(),
    }
}

/// 400 `below_floor`: the policy is weaker than a floor it must keep.
fn below(reason: String) -> ApiError {
    ApiError::Coded {
        status: StatusCode::BAD_REQUEST,
        code: "below_floor",
        reason,
        details: json!({}),
    }
}

/// `If-Match` as a revision: `"3"`, `W/"3"` or `3`; 0 when nothing was saved yet.
fn if_match(headers: &HeaderMap) -> Result<i64, ApiError> {
    headers
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| {
            raw.trim()
                .trim_start_matches("W/")
                .trim_matches('"')
                .parse::<i64>()
                .ok()
        })
        .filter(|revision| *revision >= 0)
        .ok_or_else(|| bad("Send If-Match with the revision you read (0 when none was saved yet)"))
}

fn stale() -> ApiError {
    ApiError::Conflict {
        reason: "It changed since you read it. Reload before saving.".into(),
    }
}

/// A person on an account session; devices, agents, connectors and services are refused.
async fn require_person(db: &mut PgConnection, auth: &AuthContext) -> Result<(), ApiError> {
    let person: bool =
        sqlx::query_scalar("select exists(select 1 from identity where id=$1 and kind='person')")
            .bind(auth.identity_id)
            .fetch_one(&mut *db)
            .await?;
    if auth.device.is_some() || !person {
        return Err(ApiError::Denied {
            reason: "Merge policies are saved by a person on an account session".into(),
        });
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes))
}

/// For every strategy, the strictest gate of `a` and `b`.
pub(crate) fn strictest(mut a: Floors, b: &Floors) -> Floors {
    for (strategy, gate) in &b.gate_at_least.0 {
        let entry = a.gate_at_least.0.entry(strategy.clone()).or_insert(*gate);
        *entry = (*entry).max(*gate);
    }
    a
}

/// Floors from stored bytes or a request body; every strategy must exist.
fn parse_floors(value: &Value) -> Result<Floors, ApiError> {
    let floors: Floors = serde_json::from_value(value.clone())
        .map_err(|e| bad(format!("Not a valid floor: {e}")))?;
    let registry = Registry::builtin();
    if let Some(unknown) = floors
        .gate_at_least
        .0
        .keys()
        .find(|s| registry.get(s).is_none())
    {
        return Err(bad(format!("Unknown strategy `{unknown}` in the floor")));
    }
    Ok(floors)
}

fn stored_floors(bytes: &[u8]) -> Result<Floors, ApiError> {
    serde_json::from_slice(bytes).map_err(|e| ApiError::Internal(e.to_string()))
}

/// The strictest floor of every organisation one of the project's owners belongs to.
pub(crate) async fn organisation_floor(
    db: &mut PgConnection,
    project: Uuid,
) -> Result<Floors, ApiError> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(
        "select distinct f.floors from space_member s join organisation_member m on m.identity_id=s.identity_id
         join organisation_merge_floor f on f.organisation_id=m.organisation_id
         where s.space_id=$1 and s.role='owner' and m.scim_deleted_at is null",
    )
    .bind(project)
    .fetch_all(&mut *db)
    .await?;
    rows.iter().try_fold(Floors::default(), |acc, bytes| {
        Ok(strictest(acc, &stored_floors(bytes)?))
    })
}

/// The stored project policy, if any: `(policy, revision)`.
async fn stored_policy(
    db: &mut PgConnection,
    project: Uuid,
    lock: bool,
) -> Result<Option<(MergePolicy, String, i64)>, ApiError> {
    let row: Option<(Vec<u8>, String, i64)> = sqlx::query_as(&format!(
        "select policy,policy_hash,revision from project_merge_policy where project_id=$1{}",
        if lock { " for update" } else { "" }
    ))
    .bind(project)
    .fetch_optional(&mut *db)
    .await?;
    row.map(|(bytes, hash, revision)| {
        MergePolicy::from_json(&bytes, &Registry::builtin())
            .map(|policy| (policy, hash, revision))
            .map_err(|e| ApiError::Internal(e.message))
    })
    .transpose()
}

/// The floor a v4 merge's embedded policy must keep at publication: the organisation
/// floor and the stored project policy's own floors.
pub(crate) async fn effective_floor(
    db: &mut PgConnection,
    project: Uuid,
) -> Result<Floors, ApiError> {
    let organisation = organisation_floor(db, project).await?;
    Ok(match stored_policy(db, project, false).await? {
        Some((policy, _, _)) => strictest(organisation, &policy.floors),
        None => organisation,
    })
}

#[utoipa::path(operation_id="project_merge_policy",get,path="/projects/{id}/merge-policy",tag="merge policy",params(("id"=Uuid,Path)),security(("paseto"=[])),responses((status=200,description="The stored policy (null when the project merges by the default policy), its hash and revision, the organisation floor its owners' organisations set, and the effective floor a v4 merge must keep at publication",body=Value),(status=403,description="Not a project member")))]
async fn get_policy(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let mut tx = state.pool.begin().await?;
    projects::require(&mut tx, id, auth.identity_id).await?;
    let organisation = organisation_floor(&mut tx, id).await?;
    let stored = stored_policy(&mut tx, id, false).await?;
    tx.commit().await?;
    let effective = match &stored {
        Some((policy, _, _)) => strictest(organisation.clone(), &policy.floors),
        None => organisation.clone(),
    };
    Ok(Json(json!({
        "policy": stored.as_ref().map(|(p, _, _)| p.canonical_value()),
        "hash": stored.as_ref().map(|(_, h, _)| h),
        "revision": stored.as_ref().map_or(0, |(_, _, r)| *r),
        "organisation_floor": organisation,
        "effective_floor": effective,
    })))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MergePolicyBody {
    /// A `dynodoc.merge-policy.v1` document (JSON).
    #[schema(value_type = Object)]
    policy: Value,
}

#[utoipa::path(operation_id="project_merge_policy_put",put,path="/projects/{id}/merge-policy",tag="merge policy",params(("id"=Uuid,Path),("If-Match"=String,Header,description="The revision you read; 0 when none was saved")),request_body=MergePolicyBody,security(("paseto"=[])),responses((status=200,description="Saved: the canonical policy, its hash and the new revision; an audit row records the old and new hashes. Unchanged when the canonical policy equals the stored one",body=Value),(status=400,description="Invalid policy, a missing If-Match, or `below_floor`: weaker than the organisation floor"),(status=403,description="A person's account session as project owner or manager is required; a manager may not lower the project's floors"),(status=409,description="Changed since the revision in If-Match")))]
async fn put_policy(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<MergePolicyBody>,
) -> Result<Json<Value>, ApiError> {
    let expected = if_match(&headers)?;
    let bytes = serde_json::to_vec(&body.policy).map_err(|e| ApiError::Internal(e.to_string()))?;
    let policy = MergePolicy::from_json(&bytes, &Registry::builtin()).map_err(|e| {
        bad(format!(
            "Invalid merge policy at `{}`: {}",
            e.path, e.message
        ))
    })?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("select id from access_space where id=$1 and kind='project' for share")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    require_person(&mut tx, &auth).await?;
    let role = projects::require(&mut tx, id, auth.identity_id).await?;
    if !matches!(role.as_str(), "owner" | "manager") {
        return Err(ApiError::Forbidden);
    }
    let organisation = organisation_floor(&mut tx, id).await?;
    policy.check_floor(&organisation).map_err(|e| {
        below(format!(
            "The policy is below the organisation floor: {}",
            e.message
        ))
    })?;
    let current = stored_policy(&mut tx, id, true).await?;
    let revision = current.as_ref().map_or(0, |(_, _, r)| *r);
    if expected != revision {
        return Err(stale());
    }
    if let Some((before, _, _)) = &current {
        if role != "owner" && !policy.floors.at_least(&before.floors) {
            return Err(ApiError::Denied {
                reason: "Only a project owner can lower the project's merge floors".into(),
            });
        }
    }
    let canonical = policy.canonical_bytes();
    let hash = policy.hash_hex();
    let previous = current.as_ref().map(|(_, h, _)| h.clone());
    if previous.as_deref() == Some(hash.as_str()) {
        tx.commit().await?;
        return Ok(Json(
            json!({"policy":policy.canonical_value(),"hash":hash,"revision":revision,"changed":false}),
        ));
    }
    let saved: i64 = if current.is_some() {
        sqlx::query_scalar("update project_merge_policy set policy=$2,policy_hash=$3,revision=revision+1,updated_by=$4,updated_at=now() where project_id=$1 returning revision")
            .bind(id)
            .bind(&canonical)
            .bind(&hash)
            .bind(auth.identity_id)
            .fetch_one(&mut *tx)
            .await?
    } else {
        sqlx::query_scalar("insert into project_merge_policy(project_id,policy,policy_hash,revision,updated_by) values($1,$2,$3,1,$4) on conflict do nothing returning revision")
            .bind(id)
            .bind(&canonical)
            .bind(&hash)
            .bind(auth.identity_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(stale)?
    };
    sqlx::query("insert into project_merge_policy_revision(project_id,revision,policy,policy_hash,actor) values($1,$2,$3,$4,$5)")
        .bind(id)
        .bind(saved)
        .bind(&canonical)
        .bind(&hash)
        .bind(auth.identity_id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        auth.identity_id,
        "project.merge_policy.changed",
        id,
        json!({"revision":saved,"previous_hash":previous,"hash":hash}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"policy":policy.canonical_value(),"hash":hash,"revision":saved,"changed":true}),
    ))
}

async fn organisation_role(
    db: &mut PgConnection,
    organisation: Uuid,
    who: Uuid,
) -> Result<String, ApiError> {
    sqlx::query_scalar(
        "select role from organisation_member where organisation_id=$1 and identity_id=$2 and scim_deleted_at is null",
    )
    .bind(organisation)
    .bind(who)
    .fetch_optional(db)
    .await?
    .ok_or(ApiError::Forbidden)
}

#[utoipa::path(operation_id="organisation_merge_floor",get,path="/organisations/{id}/merge-floor",tag="merge policy",params(("id"=Uuid,Path)),security(("paseto"=[])),responses((status=200,description="The organisation's merge floor (empty when none was saved) and its revision",body=Value),(status=403,description="Not an organisation member")))]
async fn get_floor(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let mut tx = state.pool.begin().await?;
    organisation_role(&mut tx, id, auth.identity_id).await?;
    let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
        "select floors,revision from organisation_merge_floor where organisation_id=$1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    let (floors, revision) = match row {
        Some((bytes, revision)) => (stored_floors(&bytes)?, revision),
        None => (Floors::default(), 0),
    };
    Ok(Json(json!({"floors": floors, "revision": revision})))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MergeFloorBody {
    /// `{"gate_at_least": {"<strategy id>": "auto" | "auto-with-review" | "blocked"}}`.
    #[schema(value_type = Object)]
    floors: Value,
}

#[utoipa::path(operation_id="organisation_merge_floor_put",put,path="/organisations/{id}/merge-floor",tag="merge policy",params(("id"=Uuid,Path),("If-Match"=String,Header,description="The revision you read; 0 when none was saved")),request_body=MergeFloorBody,security(("paseto"=[])),responses((status=200,description="Saved floor and its new revision; every policy of a project an organisation member owns must keep it from now on (stored policies are checked again when saved, and every v4 merge at publication)",body=Value),(status=400,description="Invalid floor or a missing If-Match"),(status=403,description="A person's account session as organisation owner or admin is required"),(status=409,description="Changed since the revision in If-Match")))]
async fn put_floor(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<MergeFloorBody>,
) -> Result<Json<Value>, ApiError> {
    let expected = if_match(&headers)?;
    let floors = parse_floors(&body.floors)?;
    let canonical = engine_core::hashing::canonical_json(
        &serde_json::to_value(&floors).map_err(|e| ApiError::Internal(e.to_string()))?,
    );
    let mut tx = state.pool.begin().await?;
    require_person(&mut tx, &auth).await?;
    if !matches!(
        organisation_role(&mut tx, id, auth.identity_id)
            .await?
            .as_str(),
        "owner" | "admin"
    ) {
        return Err(ApiError::Forbidden);
    }
    let current: Option<(Vec<u8>, i64)> = sqlx::query_as(
        "select floors,revision from organisation_merge_floor where organisation_id=$1 for update",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let revision = current.as_ref().map_or(0, |c| c.1);
    if expected != revision {
        return Err(stale());
    }
    if current.as_ref().is_some_and(|c| c.0 == canonical) {
        tx.commit().await?;
        return Ok(Json(
            json!({"floors":floors,"revision":revision,"changed":false}),
        ));
    }
    let saved: i64 = if current.is_some() {
        sqlx::query_scalar("update organisation_merge_floor set floors=$2,revision=revision+1,updated_by=$3,updated_at=now() where organisation_id=$1 returning revision")
            .bind(id)
            .bind(&canonical)
            .bind(auth.identity_id)
            .fetch_one(&mut *tx)
            .await?
    } else {
        sqlx::query_scalar("insert into organisation_merge_floor(organisation_id,floors,revision,updated_by) values($1,$2,1,$3) on conflict do nothing returning revision")
            .bind(id)
            .bind(&canonical)
            .bind(auth.identity_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(stale)?
    };
    sqlx::query("insert into organisation_merge_floor_revision(organisation_id,revision,floors,actor) values($1,$2,$3,$4)")
        .bind(id)
        .bind(saved)
        .bind(&canonical)
        .bind(auth.identity_id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        auth.identity_id,
        "organisation.merge_floor.changed",
        id,
        json!({"revision":saved,"previous_digest":current.as_ref().map(|c| hex_digest(&c.0)),"digest":hex_digest(&canonical)}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"floors":floors,"revision":saved,"changed":true}),
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_policy, put_policy, get_floor, put_floor),
    components(schemas(MergePolicyBody, MergeFloorBody))
)]
pub struct MergePoliciesApi;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_strictest_gate_of_two_floors_wins_per_strategy() {
        let a: Floors = serde_json::from_value(
            json!({"gate_at_least":{"dynodoc.text.diff3-grapheme.v1":"auto-with-review"}}),
        )
        .unwrap();
        let b: Floors = serde_json::from_value(json!({"gate_at_least":{"dynodoc.text.diff3-grapheme.v1":"blocked","dynodoc.marks.set.v1":"auto"}})).unwrap();
        let both = strictest(a, &b);
        assert_eq!(
            serde_json::to_value(&both).unwrap(),
            json!({"gate_at_least":{"dynodoc.marks.set.v1":"auto","dynodoc.text.diff3-grapheme.v1":"blocked"}})
        );
    }
}
