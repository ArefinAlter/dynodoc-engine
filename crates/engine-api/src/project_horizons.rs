//! Shared history horizons (docs/DESIGN-COMMIT-PRUNING.md sections 5.4, 6.3 and 8.2,
//! decision 032).
//!
//! Off unless the receipt authority is installed and its key mounted: a horizon is
//! created only when the service can countersign it with that key, in the same
//! transaction that inserts it (the pattern of atomic ref receipts). Creating and
//! releasing need an account session of a project owner (not a device session) and
//! an owner signature by one of that person's active device keys; clients verify the
//! chain against their pinned authority (`sync horizons`). Release is logical first:
//! released commits answer 410 at once, bytes stay for `quarantine_days`, and only a
//! later explicit release batch deletes bodies and reachability rows. Physical object
//! bytes go only through the operator's shared object collector.
use crate::{
    auth::{
        device::{HistoryRead, ProjectAuth},
        AuthContext,
    },
    devices,
    error::ApiError,
    product::audit,
    project_staging::{authorize, bad, start},
    AppState,
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use engine_core::{
    repository::{
        horizon::{
            self,
            plan::{self, HistoryView, ObjectGraph, PlanOptions},
            policy::{LoadOptions, Policy, ReviewedCandidates, Topology},
            Envelope, HeadRef, Hold, HorizonRecord, Role, Scope, Signature, SkeletonEntry,
            MAX_HOLDS,
        },
        server_authority, SignedCommit,
    },
    shared_checkpoint::Address,
};
use ring::signature::KeyPair;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgConnection;
use std::collections::{BTreeSet, HashMap, VecDeque};
use uuid::Uuid;

/// A shared horizon needs the authority plus at least one owner (design CP-Q2).
const SHARED_MIN_SIGNATURES: u32 = 2;
/// Released bodies deleted per release batch (the trigger's own limit).
const RELEASE_BATCH: i64 = 256;
const PAGE: i64 = 64;
const SKELETON_PAGE: i64 = 256;
const MAX_COMMITS: usize = 1_000_000;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/projects/{id}/history/horizons", get(list).post(create))
        .route("/projects/{id}/history/horizons/plan", post(plan_route))
        .route(
            "/projects/{id}/history/horizons/{sequence}/skeleton",
            get(skeleton),
        )
        .route(
            "/projects/{id}/history/horizons/{sequence}/release",
            post(release),
        )
        .route(
            "/projects/{id}/history/horizons/{sequence}/progress",
            get(progress),
        )
        .route(
            "/projects/{id}/history/holds",
            get(list_holds).post(create_hold),
        )
        .route(
            "/projects/{id}/history/holds/{hold}/release",
            post(release_hold),
        )
        // A record and a policy of up to 64 KiB each, plus signatures.
        .layer(DefaultBodyLimit::max(160 * 1024))
}

fn horizon_error(error: horizon::Error) -> ApiError {
    ApiError::Conflict {
        reason: error.to_string(),
    }
}

/// The skeleton row of a commit a horizon released: `(sequence, parents, height)`.
pub(crate) async fn skeleton_entry(
    db: &mut PgConnection,
    project: Uuid,
    address: &Address,
) -> Result<Option<(i64, Vec<String>, i64)>, ApiError> {
    Ok(sqlx::query_as(
        "select horizon_sequence,parents,height from project_history_skeleton where project_id=$1 and address=$2",
    )
    .bind(project)
    .bind(address.as_str())
    .fetch_optional(db)
    .await?)
}

/// 410 `history_pruned` for a released commit.
pub(crate) fn pruned(address: &Address, entry: (i64, Vec<String>, i64)) -> ApiError {
    ApiError::Coded {
        status: StatusCode::GONE,
        code: "history_pruned",
        reason: "This commit was released by a history horizon; only its address, parents and height remain".into(),
        details: json!({"address":address,"horizon":entry.0,"parents":entry.1,"height":entry.2}),
    }
}

async fn require_owner(
    db: &mut PgConnection,
    auth: &AuthContext,
    project: Uuid,
) -> Result<(), ApiError> {
    // Retention is decided on an account session, never by a device or agent key.
    if auth.device.is_some() {
        return Err(ApiError::Denied {
            reason: "History horizons need a signed-in project owner, not a device session".into(),
        });
    }
    if crate::projects::require(db, project, auth.identity_id).await? != "owner" {
        return Err(ApiError::Denied {
            reason: "Only a project owner can plan or release history".into(),
        });
    }
    Ok(())
}

fn load_policy(value: &Value, min_quarantine_days: u32) -> Result<Policy, ApiError> {
    let bytes = serde_json::to_vec(value).map_err(|e| ApiError::Internal(e.to_string()))?;
    let policy = Policy::load(
        &bytes,
        LoadOptions {
            min_signatures: SHARED_MIN_SIGNATURES,
        },
    )
    .map_err(|errors| bad(&format!("Invalid retention policy: {errors}")))?;
    // Shared defaults (decision 032): keep topology (CP-Q1), keep review evidence
    // (CP-Q4), no archive written by the service (operators archive offline).
    if policy.topology == Topology::Drop {
        return Err(bad("topology: drop is not offered on the shared service"));
    }
    if policy.protect.reviewed_candidates == ReviewedCandidates::None {
        return Err(bad(
            "Review evidence is kept on the shared service; reviewed_candidates: none is refused",
        ));
    }
    if policy.archive.required {
        return Err(bad(
            "The shared service writes no archive; take an operator backup first",
        ));
    }
    if policy.quarantine_days < min_quarantine_days {
        return Err(bad(&format!(
            "Shared horizons keep released bytes for at least {min_quarantine_days} days (quarantine_days)"
        )));
    }
    Ok(policy)
}

/// The service's history as the planner sees it, read in the caller's transaction.
/// Commits in a skeleton are released even while their bodies wait out the
/// quarantine; time rules use the server's `published_at`, not declared times.
async fn view(
    db: &mut PgConnection,
    project: Uuid,
    policy: &Policy,
) -> Result<HistoryView, ApiError> {
    let mut view = HistoryView::new(project);
    let heads: Vec<(String, String, i64)> = sqlx::query_as(
        "select distinct on (branch) branch,commit_address,generation from project_ref_event where project_id=$1 order by branch,generation desc",
    )
    .bind(project)
    .fetch_all(&mut *db)
    .await?;
    let mut head_addresses = Vec::new();
    for (branch, commit, generation) in heads {
        let commit = Address::try_from(commit).map_err(|e| ApiError::Internal(e.to_string()))?;
        head_addresses.push(commit.clone());
        view.add_branch(HeadRef {
            branch,
            commit,
            generation,
        })
        .map_err(horizon_error)?;
    }
    let mut parents: HashMap<Address, Vec<Address>> = HashMap::new();
    let mut states: BTreeSet<(Uuid, String)> = BTreeSet::new();
    let mut after = String::new();
    loop {
        let rows: Vec<(String, Vec<u8>, i64, i64)> = sqlx::query_as(
            "select c.address,c.body,c.height,(extract(epoch from c.published_at)*1000)::bigint from project_published_commit c
             where c.project_id=$1 and c.address>$2
               and not exists(select 1 from project_history_skeleton s where s.project_id=c.project_id and s.address=c.address)
             order by c.address limit 256",
        )
        .bind(project)
        .bind(&after)
        .fetch_all(&mut *db)
        .await?;
        let Some(last) = rows.last() else { break };
        after = last.0.clone();
        for (address, body, height, published_ms) in rows {
            let address =
                Address::try_from(address).map_err(|e| ApiError::Internal(e.to_string()))?;
            let signed: SignedCommit =
                serde_json::from_slice(&body).map_err(|e| ApiError::Internal(e.to_string()))?;
            if signed.verify().ok().as_ref() != Some(&address) || signed.commit.project != project {
                return Err(ApiError::Internal(
                    "Published commit address/project mismatch".into(),
                ));
            }
            let mut commit = signed.commit;
            commit.authored_at_ms = published_ms;
            for file in commit.files.values() {
                states.insert((file.document.0, file.state.as_str().to_owned()));
            }
            parents.insert(address.clone(), commit.parents.clone());
            view.add_commit(
                &address,
                &commit,
                body.len() as u64,
                u64::try_from(height).ok(),
            )
            .map_err(horizon_error)?;
            if parents.len() > MAX_COMMITS {
                return Err(bad("Project history is too large to plan in one request"));
            }
        }
    }
    let skeleton: Vec<(String, Vec<String>, i64)> = sqlx::query_as(
        "select address,parents,height from project_history_skeleton where project_id=$1 order by address",
    )
    .bind(project)
    .fetch_all(&mut *db)
    .await?;
    for (address, list, height) in skeleton {
        let parse = |a: String| Address::try_from(a).map_err(|e| ApiError::Internal(e.to_string()));
        view.add_prior_skeleton(SkeletonEntry {
            address: parse(address)?,
            parents: list.into_iter().map(parse).collect::<Result<_, _>>()?,
            height: u64::try_from(height).map_err(|_| ApiError::Internal("height".into()))?,
        });
    }
    let released: Vec<(Uuid, String)> = sqlx::query_as(
        "select document_id,state_root from project_history_released_state where project_id=$1",
    )
    .bind(project)
    .fetch_all(&mut *db)
    .await?;
    for (document, root) in &released {
        let root =
            Address::try_from(root.clone()).map_err(|e| ApiError::Internal(e.to_string()))?;
        view.add_prior_released_state(*document, &root);
    }
    // Review evidence and open candidates are pinned as holds (design 7.2): a reviewed
    // candidate's review rows reference its body, and an unmerged candidate may be under
    // review. shortcut: at most MAX_HOLDS such commits per horizon; a project with more
    // (candidates, named releases and history holds together) is refused until candidates
    // are merged or holds released.
    let mut pins: BTreeSet<(Address, String)> = BTreeSet::new();
    let reviewed: Vec<String> = sqlx::query_scalar(
        "select distinct candidate from project_history_review where project_id=$1",
    )
    .bind(project)
    .fetch_all(&mut *db)
    .await?;
    for candidate in reviewed {
        let candidate =
            Address::try_from(candidate).map_err(|e| ApiError::Internal(e.to_string()))?;
        if parents.contains_key(&candidate) {
            pins.insert((candidate, "reviewed-candidate".into()));
        }
    }
    // Named releases are named versions; their rows reference the body.
    if policy.protect.named_versions {
        let released: Vec<String> = sqlx::query_scalar(
            "select distinct commit_address from project_release where project_id=$1",
        )
        .bind(project)
        .fetch_all(&mut *db)
        .await?;
        for commit in released {
            let commit =
                Address::try_from(commit).map_err(|e| ApiError::Internal(e.to_string()))?;
            if parents.contains_key(&commit) && !pins.iter().any(|(a, _)| *a == commit) {
                pins.insert((commit, "named-release".into()));
            }
        }
    } else {
        return Err(bad("Named releases reference their commits; named_versions: false is refused on the shared service"));
    }
    if policy.protect.open_review_candidates {
        let mut reachable: BTreeSet<Address> = BTreeSet::new();
        let mut queue: VecDeque<Address> = head_addresses.into();
        while let Some(next) = queue.pop_front() {
            if reachable.insert(next.clone()) {
                queue.extend(parents.get(&next).into_iter().flatten().cloned());
            }
        }
        for address in parents.keys() {
            if !reachable.contains(address) && !pins.iter().any(|(a, _)| a == address) {
                pins.insert((address.clone(), "open-candidate".into()));
            }
        }
    }
    // History holds (decision 042): a project hold refuses any horizon; a commit hold pins.
    for commit in active_holds(db, project).await? {
        let Some(commit) = commit else {
            return Err(held());
        };
        let commit = Address::try_from(commit).map_err(|e| ApiError::Internal(e.to_string()))?;
        if parents.contains_key(&commit) && !pins.iter().any(|(a, _)| *a == commit) {
            pins.insert((commit, "history-hold".into()));
        }
    }
    if pins.len() > MAX_HOLDS {
        return Err(bad(
            "Too many review candidates or holds to plan a horizon; merge or close candidates first",
        ));
    }
    for (commit, reason) in pins {
        view.add_hold(Hold { commit, reason })
            .map_err(horizon_error)?;
    }
    // Objects: every publication row of each state, as the state's reachable set.
    let mut objects = ObjectGraph::default();
    let mut index: HashMap<(Uuid, String), u32> = HashMap::new();
    let mut intern = |objects: &mut ObjectGraph, key: (Uuid, String), size: u64| {
        *index.entry(key).or_insert_with(|| {
            objects.sizes.push(size);
            objects.children.push(Vec::new());
            (objects.sizes.len() - 1) as u32
        })
    };
    let released: BTreeSet<(Uuid, String)> = released.into_iter().collect();
    for (document, root) in states.difference(&released) {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "select p.address,octet_length(o.bytes)::bigint from project_published_object p join checkpoint_object o using(document_id,address)
             where p.project_id=$1 and p.state_root=$2 and p.document_id=$3",
        )
        .bind(project)
        .bind(root)
        .bind(document)
        .fetch_all(&mut *db)
        .await?;
        // The root's own row carries every other object of the state as children:
        // conservative (an object shared with another state counts as reached by both).
        let root_size = rows
            .iter()
            .find(|(a, _)| a == root)
            .map_or(0, |(_, s)| *s as u64);
        let root_index = intern(&mut objects, (*document, root.clone()), root_size);
        for (address, size) in rows.into_iter().filter(|(a, _)| a != root) {
            let child = intern(&mut objects, (*document, address), size as u64);
            objects.children[root_index as usize].push(child);
        }
        let root =
            Address::try_from(root.clone()).map_err(|e| ApiError::Internal(e.to_string()))?;
        view.set_state_object(*document, &root, root_index);
    }
    view.objects = objects;
    Ok(view)
}

async fn next_sequence(
    db: &mut PgConnection,
    project: Uuid,
) -> Result<(u64, Option<Address>), ApiError> {
    let row: Option<(i64, String)> = sqlx::query_as(
        "select sequence,address from project_history_horizon where project_id=$1 order by sequence desc limit 1",
    )
    .bind(project)
    .fetch_optional(db)
    .await?;
    Ok(match row {
        None => (1, None),
        Some((sequence, address)) => (
            sequence as u64 + 1,
            Some(Address::try_from(address).map_err(|e| ApiError::Internal(e.to_string()))?),
        ),
    })
}

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanInput {
    policy: Value,
    as_of_ms: Option<i64>,
}

#[utoipa::path(operation_id="project_history_horizon_plan",post,path="/projects/{id}/history/horizons/plan",tag="project history",params(("id"=Uuid,Path)),request_body=Value,security(("paseto"=[])),responses((status=200,description="Read-only horizon plan and the draft record each owner signs offline; nothing changes",body=Value),(status=403,description="Project owner on an account session required")))]
async fn plan_route(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<PlanInput>,
) -> Result<Json<Value>, ApiError> {
    let policy = load_policy(&input.policy, state.horizon_min_quarantine_days)?;
    let mut tx = start(&state, &auth).await?;
    require_owner(&mut tx, &auth, id).await?;
    authorize(&mut tx, &auth, id, &[], false).await?;
    let _permit = state.workloads.enter(auth.identity_id, Some(id))?;
    let as_of_ms = input
        .as_of_ms
        .or(policy.window.keep_within_days.map(|_| now_ms() as i64));
    let view = view(&mut tx, id, &policy).await?;
    let plan =
        plan::plan(&view, &policy, &PlanOptions { as_of_ms, list: 10 }).map_err(horizon_error)?;
    let (sequence, previous) = next_sequence(&mut tx, id).await?;
    let record = plan
        .draft_record(sequence, previous, now_ms())
        .map_err(horizon_error)?;
    tx.rollback().await?;
    let plan_json: Value = serde_json::from_slice(&plan.canonical_bytes().map_err(horizon_error)?)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(json!({
        "plan": plan_json,
        "plan_hash": plan.plan_hash,
        "as_of_ms": as_of_ms,
        "record": record,
        "record_address": record.address().map_err(horizon_error)?,
        "instruction": "Review the plan; each owner signs the record offline (engine-cli horizon-sign); then POST /horizons with the policy, plan_hash, as_of_ms, record and signatures.",
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateInput {
    policy: Value,
    plan_hash: String,
    as_of_ms: Option<i64>,
    record: HorizonRecord,
    signatures: Vec<Signature>,
}

#[utoipa::path(operation_id="project_history_horizon_create",post,path="/projects/{id}/history/horizons",tag="project history",params(("id"=Uuid,Path)),request_body=Value,security(("paseto"=[])),responses((status=200,description="Horizon recorded with the authority's countersignature; released commits answer 410 at once and their bytes stay until the quarantine ends",body=Value),(status=403,description="Owner account session, an active owner device key signature and an installed receipt authority are required"),(status=409,description="Stale plan or a record that does not describe it")))]
async fn create(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<CreateInput>,
) -> Result<Json<Value>, ApiError> {
    let policy = load_policy(&input.policy, state.horizon_min_quarantine_days)?;
    // Shared horizons stay off until an authority key is installed and mounted.
    let signer = state.ref_signer.as_deref().ok_or_else(|| ApiError::Denied {
        reason: "Shared history horizons need the receipt authority; the operator has not installed it".into(),
    })?;
    let mut tx = start(&state, &auth).await?;
    require_owner(&mut tx, &auth, id).await?;
    authorize(&mut tx, &auth, id, &[], false).await?;
    crate::project_history::serial(&mut tx, id).await?;
    let _permit = state.workloads.enter(auth.identity_id, Some(id))?;
    let active = server_authority::active(&mut tx).await?;
    if active.revocation.is_some() || active.public_key != hex::encode(signer.public_key().as_ref())
    {
        return Err(ApiError::Denied {
            reason: "The mounted receipt authority key is not the active, unrevoked authority"
                .into(),
        });
    }
    let view = view(&mut tx, id, &policy).await?;
    let plan = plan::plan(
        &view,
        &policy,
        &PlanOptions {
            as_of_ms: input.as_of_ms,
            list: 0,
        },
    )
    .map_err(horizon_error)?;
    if plan.plan_hash != input.plan_hash.to_ascii_lowercase() {
        return Err(ApiError::Conflict {
            reason: "The plan hash differs from the project now (a branch moved or history changed); plan again".into(),
        });
    }
    let (sequence, previous) = next_sequence(&mut tx, id).await?;
    let draft = plan
        .draft_record(sequence, previous, input.record.created_at_ms)
        .map_err(horizon_error)?;
    if draft != input.record {
        return Err(ApiError::Conflict {
            reason: "The signed record does not describe this plan; refusing to release history outside the policy".into(),
        });
    }
    // Owner signatures: active device keys of project owners, the caller's among them.
    let mut caller_signed = false;
    for signature in &input.signatures {
        if signature.role != Role::Owner {
            return Err(bad(
                "Only owner signatures are accepted; the service adds the authority's",
            ));
        }
        let owner: Option<Uuid> = sqlx::query_scalar(
            "select k.identity_id from device_signing_key k where k.public_key=$1 and not exists(select 1 from device_key_revocation r where r.key_id=k.id)",
        )
        .bind(&signature.key)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(owner) = owner else {
            return Err(ApiError::Denied {
                reason: "An owner signature is not by an active device key".into(),
            });
        };
        if crate::projects::require(&mut tx, id, owner).await? != "owner" {
            return Err(ApiError::Denied {
                reason: "An owner signature is by someone who is not a project owner".into(),
            });
        }
        if owner == auth.identity_id {
            devices::current_key(&mut tx, auth.identity_id, &signature.key).await?;
            caller_signed = true;
        }
    }
    if !caller_signed {
        return Err(ApiError::Denied {
            reason: "The record must carry your own owner signature".into(),
        });
    }
    let mut signatures = input.signatures.clone();
    signatures.push(horizon::sign(&input.record, Role::Authority, signer).map_err(horizon_error)?);
    let envelope = Envelope::assemble(input.record.clone(), signatures).map_err(horizon_error)?;
    let address = envelope
        .verify(Scope::Shared, policy.signatures_required)
        .map_err(|e| ApiError::Denied {
            reason: e.to_string(),
        })?;
    let bytes = envelope.bytes().map_err(horizon_error)?;
    let tier = match envelope.horizon.tier {
        horizon::Tier::Content => "content",
        horizon::Tier::History => "history",
    };
    sqlx::query("insert into project_history_horizon(project_id,sequence,address,envelope,policy,tier,actor,quarantine_until) values($1,$2,$3,$4,$5,$6,$7,now()+make_interval(days=>$8))")
        .bind(id)
        .bind(sequence as i64)
        .bind(address.as_str())
        .bind(&bytes)
        .bind(policy.canonical_bytes())
        .bind(tier)
        .bind(auth.identity_id)
        .bind(policy.quarantine_days as i32)
        .execute(&mut *tx)
        .await?;
    for batch in plan.sets.skeleton.chunks(256) {
        let addresses: Vec<&str> = batch.iter().map(|e| e.address.as_str()).collect();
        let parents: Vec<String> = batch
            .iter()
            .map(|e| {
                e.parents
                    .iter()
                    .map(Address::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect();
        let heights: Vec<i64> = batch.iter().map(|e| e.height as i64).collect();
        sqlx::query("insert into project_history_skeleton(project_id,address,parents,height,horizon_sequence) select $1,u.a,coalesce(string_to_array(nullif(u.p,''),','),'{}'),u.h,$5 from unnest($2::text[],$3::text[],$4::bigint[]) as u(a,p,h)")
            .bind(id)
            .bind(addresses)
            .bind(parents)
            .bind(heights)
            .bind(sequence as i64)
            .execute(&mut *tx)
            .await?;
    }
    for batch in plan.sets.released_states.chunks(256) {
        let documents: Vec<Uuid> = batch.iter().map(|s| s.document).collect();
        let roots: Vec<&str> = batch.iter().map(|s| s.state_root.as_str()).collect();
        sqlx::query("insert into project_history_released_state(project_id,document_id,state_root,horizon_sequence) select $1,u.d,u.r,$4 from unnest($2::uuid[],$3::text[]) as u(d,r)")
            .bind(id)
            .bind(documents)
            .bind(roots)
            .bind(sequence as i64)
            .execute(&mut *tx)
            .await?;
    }
    crate::transparency::enqueue_horizon(&mut tx, &state, id, sequence, &address).await?;
    audit(
        &mut tx,
        auth.identity_id,
        "project.history_horizon_created",
        id,
        json!({"sequence":sequence,"address":address,"counts":envelope.horizon.counts}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({
        "sequence": sequence,
        "address": address,
        "envelope": envelope,
        "quarantine_days": policy.quarantine_days,
    })))
}

/// `sequence, envelope, policy, quarantine_until` of one stored horizon.
type HorizonRow = (i64, Vec<u8>, Vec<u8>, chrono::DateTime<chrono::Utc>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    after_sequence: Option<i64>,
    limit: Option<i64>,
}

#[utoipa::path(operation_id="project_history_horizons",get,path="/projects/{id}/history/horizons",tag="project history",params(("id"=Uuid,Path),("after_sequence"=Option<i64>,Query),("limit"=Option<i64>,Query)),security(("paseto"=[]),("device_session"=["history:read"])),responses((status=200,description="Signed horizon envelopes with their normalized policies, ascending, at most 64 per page",body=Value)))]
async fn list(
    State(state): State<AppState>,
    auth: ProjectAuth<HistoryRead>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = query.limit.unwrap_or(PAGE).clamp(1, PAGE);
    let mut tx = start(&state, &auth).await?;
    authorize(&mut tx, &auth, id, &[], false).await?;
    let rows: Vec<HorizonRow> = sqlx::query_as(
        "select sequence,envelope,policy,quarantine_until from project_history_horizon where project_id=$1 and sequence>$2 order by sequence limit $3",
    )
    .bind(id)
    .bind(query.after_sequence.unwrap_or(0))
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let items = rows
        .into_iter()
        .map(|(sequence, envelope, policy, until)| {
            let envelope: Value = serde_json::from_slice(&envelope).map_err(|e| ApiError::Internal(e.to_string()))?;
            let policy: Value = serde_json::from_slice(&policy).map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok(json!({"sequence":sequence,"envelope":envelope,"policy":policy,"quarantine_until":until}))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(json!({ "items": items })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SkeletonQuery {
    after: Option<String>,
    limit: Option<i64>,
}

#[utoipa::path(operation_id="project_history_horizon_skeleton",get,path="/projects/{id}/history/horizons/{sequence}/skeleton",tag="project history",params(("id"=Uuid,Path),("sequence"=i64,Path),("after"=Option<String>,Query),("limit"=Option<i64>,Query)),security(("paseto"=[]),("device_session"=["history:read"])),responses((status=200,description="Skeleton entries of one horizon by address, at most 256 per page; the client checks them against the signed skeleton root",body=Value)))]
async fn skeleton(
    State(state): State<AppState>,
    auth: ProjectAuth<HistoryRead>,
    Path((id, sequence)): Path<(Uuid, i64)>,
    Query(query): Query<SkeletonQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = query.limit.unwrap_or(SKELETON_PAGE).clamp(1, SKELETON_PAGE);
    let mut tx = start(&state, &auth).await?;
    authorize(&mut tx, &auth, id, &[], false).await?;
    let rows: Vec<(String, Vec<String>, i64)> = sqlx::query_as(
        "select address,parents,height from project_history_skeleton where project_id=$1 and horizon_sequence=$2 and address>$3 order by address limit $4",
    )
    .bind(id)
    .bind(sequence)
    .bind(query.after.unwrap_or_default())
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|(address, parents, height)| json!({"address":address,"parents":parents,"height":height}))
        .collect();
    Ok(Json(json!({ "items": items })))
}

async fn remaining(
    db: &mut PgConnection,
    project: Uuid,
    sequence: i64,
) -> Result<(i64, i64), ApiError> {
    Ok(sqlx::query_as(
        "select (select count(*) from project_history_skeleton s join project_published_commit c on c.project_id=s.project_id and c.address=s.address where s.project_id=$1 and s.horizon_sequence=$2),
                (select count(*) from project_history_released_state s join project_published_object o on o.project_id=s.project_id and o.document_id=s.document_id and o.state_root=s.state_root where s.project_id=$1 and s.horizon_sequence=$2)",
    )
    .bind(project)
    .bind(sequence)
    .fetch_one(db)
    .await?)
}

async fn phase(db: &mut PgConnection, project: Uuid, sequence: i64) -> Result<Value, ApiError> {
    let row: Option<(chrono::DateTime<chrono::Utc>, bool, i64)> = sqlx::query_as(
        "select quarantine_until,quarantine_until>now(),(select count(*) from project_history_horizon_batch b where b.project_id=h.project_id and b.sequence=h.sequence) from project_history_horizon h where project_id=$1 and sequence=$2",
    )
    .bind(project)
    .bind(sequence)
    .fetch_optional(&mut *db)
    .await?;
    let (until, quarantined, batches) = row.ok_or(ApiError::NotFound)?;
    let (bodies, reachability) = remaining(db, project, sequence).await?;
    let phase = if quarantined {
        "quarantined"
    } else if bodies + reachability > 0 {
        "releasing"
    } else {
        "released"
    };
    Ok(
        json!({"sequence":sequence,"phase":phase,"quarantine_until":until,"batches":batches,"remaining_bodies":bodies,"remaining_reachability_rows":reachability}),
    )
}

#[utoipa::path(operation_id="project_history_horizon_progress",get,path="/projects/{id}/history/horizons/{sequence}/progress",tag="project history",params(("id"=Uuid,Path),("sequence"=i64,Path)),security(("paseto"=[]),("device_session"=["history:read"])),responses((status=200,description="Quarantine, batches and what is still stored",body=Value)))]
async fn progress(
    State(state): State<AppState>,
    auth: ProjectAuth<HistoryRead>,
    Path((id, sequence)): Path<(Uuid, i64)>,
) -> Result<Json<Value>, ApiError> {
    let mut tx = start(&state, &auth).await?;
    authorize(&mut tx, &auth, id, &[], false).await?;
    let value = phase(&mut tx, id, sequence).await?;
    tx.commit().await?;
    Ok(Json(value))
}

#[utoipa::path(operation_id="project_history_horizon_release",post,path="/projects/{id}/history/horizons/{sequence}/release",tag="project history",params(("id"=Uuid,Path),("sequence"=i64,Path)),security(("paseto"=[])),responses((status=200,description="One hard-release batch after the quarantine (idempotent once nothing remains)",body=Value),(status=409,description="Still in quarantine")))]
async fn release(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((id, sequence)): Path<(Uuid, i64)>,
) -> Result<Json<Value>, ApiError> {
    let mut tx = start(&state, &auth).await?;
    require_owner(&mut tx, &auth, id).await?;
    authorize(&mut tx, &auth, id, &[], false).await?;
    crate::project_history::serial(&mut tx, id).await?;
    let _permit = state.workloads.enter(auth.identity_id, Some(id))?;
    let before = phase(&mut tx, id, sequence).await?;
    if before["phase"] == "quarantined" {
        return Err(ApiError::Conflict {
            reason: "This horizon is still in quarantine; its bytes are kept until it ends".into(),
        });
    }
    if before["phase"] == "released" {
        tx.commit().await?;
        return Ok(Json(before));
    }
    let blocked: bool = sqlx::query_scalar(
        "select exists(select 1 from project_history_hold h where h.project_id=$1 and h.released_at is null and (h.commit_address is null or exists(select 1 from project_history_skeleton s where s.project_id=h.project_id and s.horizon_sequence=$2 and s.address=h.commit_address)))",
    )
    .bind(id)
    .bind(sequence)
    .fetch_one(&mut *tx)
    .await?;
    if blocked {
        return Err(held());
    }
    sqlx::query("insert into project_history_horizon_batch(project_id,sequence,batch) select $1,$2,coalesce(max(batch),0)+1 from project_history_horizon_batch where project_id=$1 and sequence=$2")
        .bind(id)
        .bind(sequence)
        .execute(&mut *tx)
        .await?;
    let after = phase(&mut tx, id, sequence).await?;
    audit(
        &mut tx,
        auth.identity_id,
        "project.history_horizon_released",
        id,
        json!({"sequence":sequence,"batch_limit":RELEASE_BATCH,"remaining_bodies":after["remaining_bodies"]}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(after))
}

// ---- history holds (decision 042) ----------------------------------------------------

/// 409 `history_held`: a hold in force keeps this history.
fn held() -> ApiError {
    ApiError::Coded {
        status: StatusCode::CONFLICT,
        code: "history_held",
        reason: "History of this project is on hold; a person must release the hold first".into(),
        details: json!({}),
    }
}

/// The commit of every hold in force; `None` holds the whole project.
async fn active_holds(
    db: &mut PgConnection,
    project: Uuid,
) -> Result<Vec<Option<String>>, ApiError> {
    Ok(sqlx::query_scalar(
        "select commit_address from project_history_hold where project_id=$1 and released_at is null order by commit_address nulls first",
    )
    .bind(project)
    .fetch_all(db)
    .await?)
}

/// Holds are decided by people: an account session (never a device, agent or service
/// identity) of a project owner or manager; a legal hold by an owner only.
async fn require_hold_manager(
    db: &mut PgConnection,
    auth: &AuthContext,
    project: Uuid,
    legal: bool,
) -> Result<(), ApiError> {
    let person: bool =
        sqlx::query_scalar("select exists(select 1 from identity where id=$1 and kind='person')")
            .bind(auth.identity_id)
            .fetch_one(&mut *db)
            .await?;
    if auth.device.is_some() || !person {
        return Err(ApiError::Denied {
            reason: "History holds are set and released by a person on an account session".into(),
        });
    }
    let role = crate::projects::require(db, project, auth.identity_id).await?;
    match (role.as_str(), legal) {
        ("owner", _) | ("manager", false) => Ok(()),
        _ => Err(ApiError::Denied {
            reason: if legal {
                "Only a project owner sets or releases a legal hold".into()
            } else {
                "Only a project owner or manager sets or releases a hold".into()
            },
        }),
    }
}

/// `id, commit, legal, reason, created_by, created_at, released_by, released_at`.
type HoldRow = (
    Uuid,
    Option<String>,
    bool,
    String,
    Uuid,
    chrono::DateTime<chrono::Utc>,
    Option<Uuid>,
    Option<chrono::DateTime<chrono::Utc>>,
);

fn hold_json(row: HoldRow) -> Value {
    let (id, commit, legal, reason, created_by, created_at, released_by, released_at) = row;
    json!({"id":id,"commit":commit,"legal":legal,"reason":reason,"created_by":created_by,"created_at":created_at,"released_by":released_by,"released_at":released_at,"active":released_at.is_none()})
}

const HOLD_COLUMNS: &str =
    "id,commit_address,legal,reason,created_by,created_at,released_by,released_at";

#[utoipa::path(operation_id="project_history_holds",get,path="/projects/{id}/history/holds",tag="project history",params(("id"=Uuid,Path)),security(("paseto"=[]),("device_session"=["history:read"])),responses((status=200,description="History holds of the project, those in force first, newest first; at most 200",body=Value)))]
async fn list_holds(
    State(state): State<AppState>,
    auth: ProjectAuth<HistoryRead>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let mut tx = start(&state, &auth).await?;
    authorize(&mut tx, &auth, id, &[], false).await?;
    let rows: Vec<HoldRow> = sqlx::query_as(&format!(
        "select {HOLD_COLUMNS} from project_history_hold where project_id=$1 order by released_at is not null,created_at desc limit 200"
    ))
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"items": rows.into_iter().map(hold_json).collect::<Vec<_>>()}),
    ))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct HoldInput {
    /// A published commit to pin; leave it out to hold the whole project.
    #[schema(value_type = Option<String>)]
    commit: Option<Address>,
    /// Shown to project members: 1 to 200 bytes, no control characters, no personal data.
    reason: String,
    /// A legal hold holds the whole project, and only an owner sets or releases it.
    #[serde(default)]
    legal: bool,
}

#[utoipa::path(operation_id="project_history_hold_create",post,path="/projects/{id}/history/holds",tag="project history",params(("id"=Uuid,Path)),request_body=HoldInput,security(("paseto"=[])),responses((status=200,description="The hold, in force at once: a project hold refuses every horizon and release batch, a commit hold pins its commit",body=Value),(status=400,description="Reason empty, too long or with control characters, or a legal hold on one commit"),(status=403,description="A person's account session as project owner or manager (owner for a legal hold) is required"),(status=404,description="The commit is not published in this project")))]
async fn create_hold(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(id): Path<Uuid>,
    Json(input): Json<HoldInput>,
) -> Result<Json<Value>, ApiError> {
    let reason = input.reason.trim();
    if reason.is_empty() || reason.len() > 200 || reason.chars().any(char::is_control) {
        return Err(bad(
            "A hold reason is 1 to 200 bytes without control characters",
        ));
    }
    if input.legal && input.commit.is_some() {
        return Err(bad(
            "A legal hold holds the whole project; leave out the commit",
        ));
    }
    let mut tx = start(&state, &auth).await?;
    require_hold_manager(&mut tx, &auth, id, input.legal).await?;
    crate::project_history::serial(&mut tx, id).await?;
    if let Some(commit) = &input.commit {
        let published: bool = sqlx::query_scalar(
            "select exists(select 1 from project_published_commit where project_id=$1 and address=$2)",
        )
        .bind(id)
        .bind(commit.as_str())
        .fetch_one(&mut *tx)
        .await?;
        if !published {
            return Err(ApiError::NotFound);
        }
    }
    let row: HoldRow = sqlx::query_as(&format!(
        "insert into project_history_hold(project_id,commit_address,legal,reason,created_by) values($1,$2,$3,$4,$5) returning {HOLD_COLUMNS}"
    ))
    .bind(id)
    .bind(input.commit.as_ref().map(Address::as_str))
    .bind(input.legal)
    .bind(reason)
    .bind(auth.identity_id)
    .fetch_one(&mut *tx)
    .await?;
    audit(
        &mut tx,
        auth.identity_id,
        "project.history_hold_set",
        id,
        json!({"hold":row.0,"commit":row.1,"legal":row.2}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(hold_json(row)))
}

#[utoipa::path(operation_id="project_history_hold_release",post,path="/projects/{id}/history/holds/{hold}/release",tag="project history",params(("id"=Uuid,Path),("hold"=Uuid,Path)),security(("paseto"=[])),responses((status=200,description="The hold, released; releasing it again changes nothing",body=Value),(status=403,description="A person's account session as project owner or manager (owner for a legal hold) is required"),(status=404,description="No such hold in this project")))]
async fn release_hold(
    State(state): State<AppState>,
    auth: AuthContext,
    Path((id, hold)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, ApiError> {
    let mut tx = start(&state, &auth).await?;
    // A non-member learns nothing about holds: the membership check answers first.
    crate::projects::require(&mut tx, id, auth.identity_id).await?;
    let legal: bool = sqlx::query_scalar(
        "select legal from project_history_hold where project_id=$1 and id=$2 for update",
    )
    .bind(id)
    .bind(hold)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    require_hold_manager(&mut tx, &auth, id, legal).await?;
    let changed = sqlx::query(
        "update project_history_hold set released_by=$3,released_at=now() where project_id=$1 and id=$2 and released_at is null",
    )
    .bind(id)
    .bind(hold)
    .bind(auth.identity_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed == 1 {
        audit(
            &mut tx,
            auth.identity_id,
            "project.history_hold_released",
            id,
            json!({"hold":hold,"legal":legal}),
        )
        .await?;
    }
    let row: HoldRow = sqlx::query_as(&format!(
        "select {HOLD_COLUMNS} from project_history_hold where id=$1"
    ))
    .bind(hold)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(hold_json(row)))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        plan_route,
        create,
        list,
        skeleton,
        progress,
        release,
        list_holds,
        create_hold,
        release_hold
    ),
    components(schemas(HoldInput))
)]
pub struct HorizonsApi;
