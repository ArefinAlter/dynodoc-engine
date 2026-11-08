//! Enterprise identity (docs/decisions/031-enterprise-identity.md) against a real PostgreSQL, the
//! real router and the restricted runtime login: sign-in by an identity provider's (issuer,
//! subject) with the takeover rules, the SCIM directory's authentication and organisation scope,
//! what a deactivation ends, mapped memberships, and the organisation's AI-agent kill switch.
mod common;

mod agent_world;
use agent_world::*;

use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const SERVICE: &str = "isolated-enterprise-identity-test-service-key";
const ISSUER: &str = "https://idp.example.test/realms/main";

async fn world(pool: PgPool) -> World {
    let w = World::bare_with(pool, true, Some(SERVICE.into())).await;
    w.enable_agents(w.project).await;
    w
}

/// A call with the service key, and optionally a bearer token (a SCIM token).
async fn internal(
    w: &World,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> Reply {
    raw(
        &w.app,
        method,
        uri,
        bearer,
        &[("x-dynodoc-service-key", SERVICE)],
        body,
    )
    .await
}

/// `/auth/exchange` for a provider sign-in with the given claims and policy.
async fn exchange(w: &World, email: &str, external: Value) -> Reply {
    let mut body = json!({"email": email, "display_name": "Person"});
    let mut defaults = json!({
        "provider": "corp",
        "issuer": ISSUER,
        "subject": "subject-1",
        "email_verified": true,
        "link_by_email": false,
        "provisioning": "jit",
        "allowed_domains": ["example.test"]
    });
    for (key, value) in external.as_object().unwrap() {
        defaults[key] = value.clone();
    }
    body["external"] = defaults;
    internal(w, "POST", "/auth/exchange", None, Some(body)).await
}

/// An emailed-link login for `email` (account created if new): (access, refresh).
async fn login(w: &World, email: &str) -> (String, String) {
    let link = internal(
        w,
        "POST",
        "/auth/magic-link",
        None,
        Some(json!({"email": email})),
    )
    .await;
    assert_eq!(link.code(), 200, "{}", link.text());
    let tokens = raw(
        &w.app,
        "POST",
        "/auth/verify",
        None,
        &[],
        Some(json!({"token": link.json()["magic_link_token"]})),
    )
    .await;
    assert_eq!(tokens.code(), 200, "{}", tokens.text());
    let v = tokens.json();
    (
        v["access_token"].as_str().unwrap().into(),
        v["refresh_token"].as_str().unwrap().into(),
    )
}

async fn me(w: &World, access: &str) -> u16 {
    get(&w.app, "/auth/me", access).await.code()
}

/// An organisation for `domains` and a SCIM token for it, made by the instance administrator.
async fn organisation(w: &World, domains: &[&str]) -> (Uuid, String, String) {
    let (_, admin) = person(w.pool(), "admin@example.test").await;
    let org = raw(
        &w.app,
        "POST",
        "/admin/organisations",
        Some(&admin),
        &[],
        Some(json!({"name": "Example Ltd", "domains": domains})),
    )
    .await;
    assert_eq!(org.code(), 201, "{}", org.text());
    let id: Uuid = serde_json::from_value(org.json()["id"].clone()).unwrap();
    let token = raw(
        &w.app,
        "POST",
        &format!("/admin/organisations/{id}/scim-tokens"),
        Some(&admin),
        &[],
        Some(json!({"label": "Entra provisioning"})),
    )
    .await;
    assert_eq!(token.code(), 201, "{}", token.text());
    (id, token.json()["token"].as_str().unwrap().into(), admin)
}

async fn scim_user(w: &World, token: &str, email: &str) -> Uuid {
    let made = internal(
        w,
        "POST",
        "/internal/directory/users",
        Some(token),
        Some(json!({"user_name": email, "external_id": format!("ext-{email}")})),
    )
    .await;
    assert_eq!(made.code(), 201, "{}", made.text());
    serde_json::from_value(made.json()["id"].clone()).unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn provider_sign_in_finds_accounts_by_subject_never_by_email_alone(pool: PgPool) {
    let w = world(pool).await;
    // First sign-in: a new account in an allowed domain (jit).
    let first = exchange(&w, "ana@example.test", json!({})).await;
    assert_eq!(first.code(), 200, "{}", first.text());
    let ana: Uuid = serde_json::from_value(first.json()["identity_id"].clone()).unwrap();
    assert_eq!(first.json()["created"], true);
    assert_eq!(
        me(&w, first.json()["access_token"].as_str().unwrap()).await,
        200
    );
    // The provider changes the address: the same subject is the same account, address updated.
    let moved = exchange(&w, "ana.new@example.test", json!({})).await;
    assert_eq!(moved.json()["identity_id"], json!(ana));
    let email: String = sqlx::query_scalar("select email from identity where id=$1")
        .bind(ana)
        .fetch_one(w.pool())
        .await
        .unwrap();
    assert_eq!(email, "ana.new@example.test");
    // Another subject of the same issuer claiming that address cannot take the account, even
    // with email linking on.
    let takeover = exchange(
        &w,
        "ana.new@example.test",
        json!({"subject": "subject-2", "link_by_email": true}),
    )
    .await;
    assert_eq!(takeover.code(), 403);

    // An existing account with no link: refused unless the provider links by verified email.
    let (bob_access, _) = login(&w, "bob@example.test").await;
    let bob: Uuid = serde_json::from_value(
        get(&w.app, "/auth/me", &bob_access).await.json()["identity_id"].clone(),
    )
    .unwrap();
    assert_eq!(
        exchange(&w, "bob@example.test", json!({"subject": "bob"}))
            .await
            .code(),
        403
    );
    assert_eq!(
        exchange(
            &w,
            "bob@example.test",
            json!({"subject": "bob", "link_by_email": true, "email_verified": false})
        )
        .await
        .code(),
        403
    );
    assert_eq!(
        exchange(
            &w,
            "bob@example.test",
            json!({"subject": "bob", "link_by_email": true, "allowed_domains": ["other.test"]})
        )
        .await
        .code(),
        403
    );
    let linked = exchange(
        &w,
        "bob@example.test",
        json!({"subject": "bob", "link_by_email": true}),
    )
    .await;
    assert_eq!(linked.code(), 200, "{}", linked.text());
    assert_eq!(linked.json()["identity_id"], json!(bob));
    assert_eq!(linked.json()["linked"], true);

    // No account for the address: only jit creates one, only in an allowed domain.
    assert_eq!(
        exchange(
            &w,
            "cy@example.test",
            json!({"subject": "cy", "provisioning": "invite_only"})
        )
        .await
        .code(),
        403
    );
    assert_eq!(
        exchange(&w, "cy@outside.test", json!({"subject": "cy"}))
            .await
            .code(),
        403
    );
    assert_eq!(exchange(&w, "", json!({"subject": "cy"})).await.code(), 403);
    let none: i64 = sqlx::query_scalar("select count(*) from identity where email like 'cy@%'")
        .fetch_one(w.pool())
        .await
        .unwrap();
    assert_eq!(none, 0);

    // A disabled account is refused like an invalid token, and the old exchange body still works.
    sqlx::query("update identity set disabled_at=now() where id=$1")
        .bind(ana)
        .execute(&w.runtime.owner)
        .await
        .unwrap();
    assert_eq!(
        exchange(&w, "ana.new@example.test", json!({})).await.code(),
        401
    );
    let plain = internal(
        &w,
        "POST",
        "/auth/exchange",
        None,
        Some(json!({"email": "dee@example.test"})),
    )
    .await;
    assert_eq!(plain.code(), 200);
    assert!(plain.json()["access_token"].is_string());
    // Without the service key nothing is exchanged.
    let anonymous = raw(
        &w.app,
        "POST",
        "/auth/exchange",
        None,
        &[],
        Some(json!({"email": "eve@example.test"})),
    )
    .await;
    assert_eq!(anonymous.code(), 403);
    let links: i64 = sqlx::query_scalar("select count(*) from operation_audit where action in ('identity.created_by_provider','identity.linked')").fetch_one(w.pool()).await.unwrap();
    assert_eq!(links, 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn scim_needs_the_service_key_and_a_live_token_and_stays_in_its_organisation(pool: PgPool) {
    let w = world(pool).await;
    let (org_a, token_a, admin) = organisation(&w, &["a.example.test"]).await;
    let (org_b, token_b, _) = organisation(&w, &["b.example.test"]).await;
    // Authentication: the service key, then a token of a live organisation.
    let list = "/internal/directory/users";
    assert_eq!(
        raw(&w.app, "GET", list, Some(&token_a), &[], None)
            .await
            .code(),
        403
    );
    assert_eq!(internal(&w, "GET", list, None, None).await.code(), 401);
    assert_eq!(
        internal(&w, "GET", list, Some(&"ab".repeat(32)), None)
            .await
            .code(),
        401
    );
    assert_eq!(
        internal(&w, "GET", list, Some("not-hex"), None)
            .await
            .code(),
        401
    );
    assert_eq!(
        internal(&w, "GET", list, Some(&token_a), None).await.code(),
        200
    );
    // A SCIM token is no account login.
    assert_eq!(me(&w, &token_a).await, 401);

    let ana = scim_user(&w, &token_a, "ana@a.example.test").await;
    // Outside the organisation's domains, nothing is provisioned.
    let outside = internal(
        &w,
        "POST",
        list,
        Some(&token_a),
        Some(json!({"user_name": "x@b.example.test"})),
    )
    .await;
    assert_eq!(outside.code(), 403);
    // Organisation B sees nothing of A's directory, and cannot change or delete it.
    let path = format!("/internal/directory/users/{ana}");
    assert_eq!(
        internal(&w, "GET", &path, Some(&token_b), None)
            .await
            .code(),
        404
    );
    assert_eq!(
        internal(
            &w,
            "PATCH",
            &path,
            Some(&token_b),
            Some(json!({"active": false}))
        )
        .await
        .code(),
        404
    );
    assert_eq!(
        internal(&w, "DELETE", &path, Some(&token_b), None)
            .await
            .code(),
        404
    );
    assert_eq!(
        internal(
            &w,
            "PUT",
            &format!("{path}/memberships"),
            Some(&token_b),
            Some(json!({"grants": []}))
        )
        .await
        .code(),
        404
    );
    assert_eq!(
        internal(&w, "GET", list, Some(&token_b), None).await.json()["total"],
        0
    );
    // Even with the domain, B cannot take over an account A manages.
    let (_, admin_token) = person(w.pool(), "admin@example.test").await;
    let widen = raw(
        &w.app,
        "PATCH",
        &format!("/admin/organisations/{org_b}"),
        Some(&admin_token),
        &[],
        Some(json!({"revision": 1, "domains": ["a.example.test", "b.example.test"]})),
    )
    .await;
    assert_eq!(widen.code(), 200, "{}", widen.text());
    let grab = internal(
        &w,
        "POST",
        list,
        Some(&token_b),
        Some(json!({"user_name": "ana@a.example.test"})),
    )
    .await;
    assert_eq!(grab.code(), 409);
    // A group of B cannot hold a user of A.
    let group = internal(
        &w,
        "POST",
        "/internal/directory/groups",
        Some(&token_b),
        Some(json!({"display_name": "Staff", "replace": [ana]})),
    )
    .await;
    assert_eq!(group.code(), 400);

    // Filtering finds the user by userName and externalId.
    let found = internal(
        &w,
        "GET",
        &format!("{list}?user_name=ANA@a.example.test"),
        Some(&token_a),
        None,
    )
    .await;
    assert_eq!(found.json()["total"], 1);
    assert_eq!(found.json()["items"][0]["id"], json!(ana));
    let by_external = internal(
        &w,
        "GET",
        &format!("{list}?external_id=ext-ana@a.example.test"),
        Some(&token_a),
        None,
    )
    .await;
    assert_eq!(by_external.json()["total"], 1);

    // A revoked or expired token stops at once.
    let tokens = raw(
        &w.app,
        "GET",
        &format!("/admin/organisations/{org_a}/scim-tokens"),
        Some(&admin),
        &[],
        None,
    )
    .await;
    let token_id = tokens.json()["items"][0]["id"].as_str().unwrap().to_owned();
    assert!(
        !tokens.text().contains(&token_a),
        "the token is shown once only"
    );
    let revoked = raw(
        &w.app,
        "POST",
        &format!("/admin/organisations/{org_a}/scim-tokens/{token_id}/revoke"),
        Some(&admin),
        &[],
        None,
    )
    .await;
    assert_eq!(revoked.code(), 200);
    assert_eq!(
        internal(&w, "GET", list, Some(&token_a), None).await.code(),
        401
    );
    sqlx::query(
        "update scim_token set expires_at=now()-interval '1 second' where organisation_id=$1",
    )
    .bind(org_b)
    .execute(&w.runtime.owner)
    .await
    .unwrap();
    assert_eq!(
        internal(&w, "GET", list, Some(&token_b), None).await.code(),
        401
    );
    // Only administrators manage organisations and tokens.
    let (_, someone) = person(w.pool(), "someone@example.test").await;
    assert_eq!(
        raw(
            &w.app,
            "POST",
            "/admin/organisations",
            Some(&someone),
            &[],
            Some(json!({"name": "Mine"}))
        )
        .await
        .code(),
        403
    );
    assert_eq!(
        raw(
            &w.app,
            "POST",
            &format!("/admin/organisations/{org_a}/scim-tokens"),
            Some(&someone),
            &[],
            Some(json!({"label": "x"}))
        )
        .await
        .code(),
        403
    );
    let stored: Vec<Vec<u8>> = sqlx::query_scalar("select token_hash from scim_token")
        .fetch_all(w.pool())
        .await
        .unwrap();
    assert!(stored
        .iter()
        .all(|h| h.len() == 32 && h.as_slice() != token_a.as_bytes()));
}

#[sqlx::test(migrations = "../../migrations")]
async fn scim_deactivation_ends_logins_device_keys_agent_sessions_and_grants(pool: PgPool) {
    let w = world(pool).await;
    let (_, token, _) = organisation(&w, &["example.test"]).await;
    // The project owner's existing account comes under the directory.
    let owner = scim_user(&w, &token, "owner@example.test").await;
    assert_eq!(owner, w.owner);
    let (access, refresh) = login(&w, "owner@example.test").await;
    let (agent, agent_token) = w.owner_reader().await;
    assert_eq!(
        get(&w.app, &w.url("/files"), &agent_token).await.code(),
        200
    );
    let doc = w.empty_file("Plan", "document").await;
    let grant: Uuid = sqlx::query_scalar("insert into connector_grant(document_id,identity_id,token_hash,session_generation,host) select $1,id,sha256('grant'::bytea),session_generation,'word' from identity where id=$2 returning id")
        .bind(doc)
        .bind(owner)
        .fetch_one(&w.runtime.owner)
        .await
        .unwrap();

    let off = internal(
        &w,
        "PATCH",
        &format!("/internal/directory/users/{owner}"),
        Some(&token),
        Some(json!({"active": false})),
    )
    .await;
    assert_eq!(off.code(), 200, "{}", off.text());
    assert_eq!(off.json()["active"], false);
    // Every way in has ended.
    assert_eq!(me(&w, &access).await, 401);
    assert_eq!(me(&w, &w.owner_login).await, 401);
    let refreshed = raw(
        &w.app,
        "POST",
        "/auth/refresh",
        None,
        &[],
        Some(json!({"refresh_token": refresh})),
    )
    .await;
    assert_eq!(refreshed.code(), 401);
    assert!(get(&w.app, &w.url("/files"), &agent_token).await.code() >= 400);
    let key_revoked: bool =
        sqlx::query_scalar("select exists(select 1 from device_key_revocation where key_id=$1)")
            .bind(agent.key_id)
            .fetch_one(w.pool())
            .await
            .unwrap();
    assert!(key_revoked);
    let grant_revoked: bool =
        sqlx::query_scalar("select revoked_at is not null from connector_grant where id=$1")
            .bind(grant)
            .fetch_one(w.pool())
            .await
            .unwrap();
    assert!(grant_revoked);
    let link = internal(
        &w,
        "POST",
        "/auth/magic-link",
        None,
        Some(json!({"email": "owner@example.test"})),
    )
    .await;
    assert_ne!(link.code(), 200, "a disabled account gets no sign-in link");
    let audited: Value = sqlx::query_scalar(
        "select detail from operation_audit where action='identity.deactivated' and resource_id=$1",
    )
    .bind(owner)
    .fetch_one(w.pool())
    .await
    .unwrap();
    assert_eq!(audited["device_keys_revoked"], 1);
    assert_eq!(audited["connector_grants_revoked"], 1);
    assert!(audited["source"].as_str().unwrap().starts_with("scim:"));

    // Back on: a new sign-in works, the old login and the revoked key stay dead.
    let on = internal(
        &w,
        "PATCH",
        &format!("/internal/directory/users/{owner}"),
        Some(&token),
        Some(json!({"active": true})),
    )
    .await;
    assert_eq!(on.json()["active"], true);
    assert_eq!(me(&w, &access).await, 401);
    let (fresh, _) = login(&w, "owner@example.test").await;
    assert_eq!(me(&w, &fresh).await, 200);
    assert!(get(&w.app, &w.url("/files"), &agent_token).await.code() >= 400);

    // DELETE deactivates and hides the user from the directory; the account is not erased.
    let gone = internal(
        &w,
        "DELETE",
        &format!("/internal/directory/users/{owner}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(gone.code(), 204);
    assert_eq!(me(&w, &fresh).await, 401);
    assert_eq!(
        internal(
            &w,
            "GET",
            &format!("/internal/directory/users/{owner}"),
            Some(&token),
            None
        )
        .await
        .code(),
        404
    );
    let erased: bool = sqlx::query_scalar("select erased_at is not null from identity where id=$1")
        .bind(owner)
        .fetch_one(w.pool())
        .await
        .unwrap();
    assert!(!erased);
}

#[sqlx::test(migrations = "../../migrations")]
async fn mapping_changes_only_its_own_rows_and_never_grants_owner(pool: PgPool) {
    let w = world(pool).await;
    let space = |name: &'static str| {
        let owner = w.runtime.owner.clone();
        let by = w.owner;
        async move {
            sqlx::query_scalar::<_, Uuid>("insert into access_space(kind,name,created_by) values('organization',$1,$2) returning id")
                .bind(name)
                .bind(by)
                .fetch_one(&owner)
                .await
                .unwrap()
        }
    };
    let lab = space("Lab").await;
    let manual = space("Manual").await;
    let first = exchange(&w, "ana@example.test", json!({})).await;
    let ana: Uuid = serde_json::from_value(first.json()["identity_id"].clone()).unwrap();
    sqlx::query("insert into space_member(space_id,identity_id,role) values($1,$2,'viewer')")
        .bind(manual)
        .bind(ana)
        .execute(&w.runtime.owner)
        .await
        .unwrap();
    let mapped = |grants: Value, admin: Option<&str>, removal: &str| json!({"memberships": {"grants": grants, "instance_admin": admin, "on_removal": removal}});
    let signed = exchange(&w, "ana@example.test", mapped(json!([{"space_id": lab, "role": "editor", "rule": "Lab staff"}, {"space_id": manual, "role": "manager", "rule": "Leads"}]), Some("Admins"), "remove")).await;
    assert_eq!(signed.code(), 200, "{}", signed.text());
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "select space_id,role,source from space_member where identity_id=$1 order by role",
    )
    .bind(ana)
    .fetch_all(w.pool())
    .await
    .unwrap();
    assert!(rows.contains(&(lab, "editor".into(), "idp:corp".into())));
    // The manual membership is neither raised nor retagged.
    assert!(rows.contains(&(manual, "viewer".into(), "manual".into())));
    assert_eq!(signed.json()["memberships"]["kept"][0]["source"], "manual");
    // The mapped instance role opens the administrators' routes.
    let token = signed.json()["access_token"].as_str().unwrap().to_owned();
    assert_eq!(
        get(&w.app, "/admin/organisations", &token).await.code(),
        200
    );

    // Groups gone at the provider: the mapped rows go, the manual row stays, and the
    // administrator role is NOT removed (owner's decision): the skip is reported and audited.
    let later = exchange(&w, "ana@example.test", mapped(json!([]), None, "remove")).await;
    let token = later.json()["access_token"].as_str().unwrap().to_owned();
    let left: Vec<(Uuid, String)> =
        sqlx::query_as("select space_id,source from space_member where identity_id=$1")
            .bind(ana)
            .fetch_all(w.pool())
            .await
            .unwrap();
    assert_eq!(left, vec![(manual, "manual".to_owned())]);
    assert_eq!(
        get(&w.app, "/admin/organisations", &token).await.code(),
        200
    );
    let kept = later.json()["memberships"]["kept"].clone();
    assert!(
        kept.as_array()
            .unwrap()
            .iter()
            .any(|k| k["instance_role"] == "admin" && k["reason"].is_string()),
        "{kept}"
    );
    let skipped: i64 = sqlx::query_scalar(
        "select count(*) from operation_audit where action='membership.admin_removal_skipped' and resource_id=$1",
    )
    .bind(ana)
    .fetch_one(w.pool())
    .await
    .unwrap();
    assert_eq!(skipped, 1);
    // Unknown groups (no memberships in the body) change nothing.
    exchange(
        &w,
        "ana@example.test",
        mapped(
            json!([{"space_id": lab, "role": "viewer", "rule": "R"}]),
            None,
            "downgrade_to_viewer",
        ),
    )
    .await;
    exchange(&w, "ana@example.test", json!({})).await;
    let kept: i64 = sqlx::query_scalar(
        "select count(*) from space_member where identity_id=$1 and source='idp:corp'",
    )
    .bind(ana)
    .fetch_one(w.pool())
    .await
    .unwrap();
    assert_eq!(kept, 1);
    // Owner is never granted by a mapping.
    let owner = exchange(
        &w,
        "ana@example.test",
        mapped(
            json!([{"space_id": lab, "role": "owner", "rule": "R"}]),
            None,
            "remove",
        ),
    )
    .await;
    assert_eq!(owner.code(), 400);
    let audit: i64 = sqlx::query_scalar(
        "select count(*) from operation_audit where action='membership.mapped' and resource_id=$1",
    )
    .bind(ana)
    .fetch_one(w.pool())
    .await
    .unwrap();
    assert!(audit >= 3);
}

#[sqlx::test(migrations = "../../migrations")]
async fn scim_groups_feed_the_mapping_for_their_members(pool: PgPool) {
    let w = world(pool).await;
    let (_, token, _) = organisation(&w, &["example.test"]).await;
    let ana = scim_user(&w, &token, "ana@example.test").await;
    let group = internal(
        &w,
        "POST",
        "/internal/directory/groups",
        Some(&token),
        Some(json!({"display_name": "Editors", "replace": [ana]})),
    )
    .await;
    assert_eq!(group.code(), 201, "{}", group.text());
    assert_eq!(
        group.json()["affected"],
        json!([{"identity_id": ana, "groups": ["Editors"]}])
    );
    let id = group.json()["id"].as_str().unwrap().to_owned();
    let user = internal(
        &w,
        "GET",
        &format!("/internal/directory/users/{ana}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(user.json()["groups"][0]["display_name"], "Editors");
    let space: Uuid = sqlx::query_scalar("insert into access_space(kind,name,created_by) values('organization','Lab',$1) returning id").bind(w.owner).fetch_one(&w.runtime.owner).await.unwrap();
    let mapped = internal(
        &w,
        "PUT",
        &format!("/internal/directory/users/{ana}/memberships"),
        Some(&token),
        Some(json!({"grants": [{"space_id": space, "role": "editor", "rule": "Editors"}]})),
    )
    .await;
    assert_eq!(mapped.code(), 200, "{}", mapped.text());
    let source: String =
        sqlx::query_scalar("select source from space_member where space_id=$1 and identity_id=$2")
            .bind(space)
            .bind(ana)
            .fetch_one(w.pool())
            .await
            .unwrap();
    assert_eq!(source, "scim");
    let removed = internal(
        &w,
        "PATCH",
        &format!("/internal/directory/groups/{id}"),
        Some(&token),
        Some(json!({"remove": [ana]})),
    )
    .await;
    assert_eq!(
        removed.json()["affected"],
        json!([{"identity_id": ana, "groups": []}])
    );
    let duplicate = internal(
        &w,
        "POST",
        "/internal/directory/groups",
        Some(&token),
        Some(json!({"display_name": "Editors"})),
    )
    .await;
    assert_eq!(duplicate.code(), 409);
}

#[sqlx::test(migrations = "../../migrations")]
async fn organisation_kill_switch_stops_its_members_agents(pool: PgPool) {
    let w = world(pool).await;
    let (agent, token) = w.owner_reader().await;
    assert_eq!(get(&w.app, &w.url("/files"), &token).await.code(), 200);
    let (org, _, admin) = organisation(&w, &["example.test"]).await;
    sqlx::query("insert into organisation_member(organisation_id,identity_id,source) values($1,$2,'manual')").bind(org).bind(w.owner).execute(&w.runtime.owner).await.unwrap();
    assert_eq!(
        get(&w.app, &w.url("/files"), &token).await.code(),
        200,
        "membership alone changes nothing"
    );
    // A member who is not an administrator cannot pull it.
    let refused = raw(
        &w.app,
        "PATCH",
        &format!("/admin/organisations/{org}"),
        Some(&w.owner_login),
        &[],
        Some(json!({"revision": 1, "cut_off_agents": true})),
    )
    .await;
    assert_eq!(refused.code(), 403);
    let cut = raw(
        &w.app,
        "PATCH",
        &format!("/admin/organisations/{org}"),
        Some(&admin),
        &[],
        Some(json!({"revision": 1, "cut_off_agents": true})),
    )
    .await;
    assert_eq!(cut.code(), 200, "{}", cut.text());
    assert_eq!(get(&w.app, &w.url("/files"), &token).await.code(), 403);
    // A session issued after the cut-off is honoured again.
    let fresh = w.token(&agent, w.project, &["content:read"]).await;
    assert_eq!(get(&w.app, &w.url("/files"), &fresh).await.code(), 200);
    // Agents off for the organisation: no session works. A stale revision is refused.
    let stale = raw(
        &w.app,
        "PATCH",
        &format!("/admin/organisations/{org}"),
        Some(&admin),
        &[],
        Some(json!({"revision": 1, "agents_enabled": false})),
    )
    .await;
    assert_eq!(stale.code(), 409);
    let off = raw(
        &w.app,
        "PATCH",
        &format!("/admin/organisations/{org}"),
        Some(&admin),
        &[],
        Some(json!({"revision": 2, "agents_enabled": false})),
    )
    .await;
    assert_eq!(off.code(), 200);
    assert_eq!(get(&w.app, &w.url("/files"), &fresh).await.code(), 403);
    let actions: Vec<String> =
        sqlx::query_scalar("select action from operation_audit where resource_id=$1 order by id")
            .bind(org)
            .fetch_all(w.pool())
            .await
            .unwrap();
    assert_eq!(
        actions,
        [
            "organisation.created",
            "organisation.scim_token.created",
            "organisation.agents_cut_off",
            "organisation.updated"
        ]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn scim_never_deactivates_a_dynodoc_administrator(pool: PgPool) {
    let w = world(pool).await;
    let (_, token, _) = organisation(&w, &["example.test"]).await;
    // admin@example.test is in ADMIN_EMAILS; ana gets the mapped instance role.
    let admin = scim_user(&w, &token, "admin@example.test").await;
    let ana = scim_user(&w, &token, "ana@example.test").await;
    sqlx::query(
        "insert into identity_instance_role(identity_id,role,source) values($1,'admin','scim')",
    )
    .bind(ana)
    .execute(&w.runtime.owner)
    .await
    .unwrap();
    let (admin_access, _) = login(&w, "admin@example.test").await;
    for id in [admin, ana] {
        let path = format!("/internal/directory/users/{id}");
        let off = internal(
            &w,
            "PATCH",
            &path,
            Some(&token),
            Some(json!({"active": false})),
        )
        .await;
        assert_eq!(off.code(), 403, "{}", off.text());
        assert!(off.text().contains("never deactivated"), "{}", off.text());
        assert_eq!(
            internal(&w, "DELETE", &path, Some(&token), None)
                .await
                .code(),
            403
        );
        let disabled: bool =
            sqlx::query_scalar("select disabled_at is not null from identity where id=$1")
                .bind(id)
                .fetch_one(w.pool())
                .await
                .unwrap();
        assert!(!disabled);
    }
    // Re-provisioning an administrator as inactive is refused too.
    let deleted_here = internal(
        &w,
        "POST",
        "/internal/directory/users",
        Some(&token),
        Some(json!({"user_name": "admin@example.test", "active": false})),
    )
    .await;
    assert!(
        deleted_here.code() == 403 || deleted_here.code() == 409,
        "{}",
        deleted_here.text()
    );
    assert_eq!(
        me(&w, &admin_access).await,
        200,
        "the administrator's login still works"
    );
    let refused: i64 = sqlx::query_scalar(
        "select count(*) from operation_audit where action='directory.admin_deactivation_refused'",
    )
    .fetch_one(w.pool())
    .await
    .unwrap();
    assert!(refused >= 4, "{refused}");
    // An ordinary member is still deactivated as before.
    let bob = scim_user(&w, &token, "bob@example.test").await;
    let off = internal(
        &w,
        "PATCH",
        &format!("/internal/directory/users/{bob}"),
        Some(&token),
        Some(json!({"active": false})),
    )
    .await;
    assert_eq!(off.code(), 200);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_sign_in_flow_value_is_accepted_once_by_every_web_process(pool: PgPool) {
    let w = world(pool).await;
    let once = |key: &'static str, ttl: i64| {
        internal(
            &w,
            "POST",
            "/internal/auth/once",
            None,
            Some(json!({"kind": "oidc_state", "key": key, "ttl_seconds": ttl})),
        )
    };
    assert_eq!(once("state-a", 600).await.code(), 200);
    // A second process presenting the same state (same database) is refused.
    assert_eq!(once("state-a", 600).await.code(), 409);
    assert_eq!(once("state-b", 600).await.code(), 200);
    // Kinds are separate; bounds hold; the service key is required.
    let other_kind = internal(
        &w,
        "POST",
        "/internal/auth/once",
        None,
        Some(json!({"kind": "saml_request", "key": "state-a", "ttl_seconds": 600})),
    )
    .await;
    assert_eq!(other_kind.code(), 200);
    assert_eq!(once("state-c", 0).await.code(), 400);
    assert_eq!(once("state-c", 86_401).await.code(), 400);
    let bad_kind = internal(
        &w,
        "POST",
        "/internal/auth/once",
        None,
        Some(json!({"kind": "other", "key": "x", "ttl_seconds": 60})),
    )
    .await;
    assert_eq!(bad_kind.code(), 400);
    let anonymous = raw(
        &w.app,
        "POST",
        "/internal/auth/once",
        None,
        &[],
        Some(json!({"kind": "oidc_state", "key": "state-d", "ttl_seconds": 60})),
    )
    .await;
    assert_eq!(anonymous.code(), 403);
    // Only hashes are stored, and an expired value is pruned.
    let raw_kept: bool = sqlx::query_scalar(
        "select exists(select 1 from auth_flow_once where key_hash=convert_to('state-a','utf8'))",
    )
    .fetch_one(w.pool())
    .await
    .unwrap();
    assert!(!raw_kept);
    sqlx::query(
        "update auth_flow_once set expires_at=now()-interval '1 second' where kind='oidc_state'",
    )
    .execute(&w.runtime.owner)
    .await
    .unwrap();
    assert_eq!(once("state-e", 60).await.code(), 200);
    let left: i64 =
        sqlx::query_scalar("select count(*) from auth_flow_once where kind='oidc_state'")
            .fetch_one(w.pool())
            .await
            .unwrap();
    assert_eq!(left, 1);
}

/// An organisation made by `owner_email` through the member route; (id, owner token).
async fn own_organisation(w: &World, owner_email: &str) -> (Uuid, String) {
    let (_, token) = person(w.pool(), owner_email).await;
    let made = raw(
        &w.app,
        "POST",
        "/organisations",
        Some(&token),
        &[],
        Some(json!({"name": "Acme"})),
    )
    .await;
    assert_eq!(made.code(), 201, "{}", made.text());
    (
        serde_json::from_value(made.json()["id"].clone()).unwrap(),
        token,
    )
}

fn oidc_provider(revision: i64, enabled: bool, secret: Option<&str>) -> Value {
    json!({
        "kind": "oidc",
        "preset": "microsoft",
        "display_name": "Microsoft 365",
        "settings": {"issuer": "https://login.microsoftonline.com/1a2b3c4d-0000-4000-8000-000000000000/v2.0", "client_id": "app-1", "link_by_email": "verified", "provisioning": "jit"},
        "client_secret": secret,
        "enabled": enabled,
        "revision": revision
    })
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_organisation_owners_and_admins_change_sign_in_and_secrets_never_come_back(
    pool: PgPool,
) {
    let w = world(pool).await;
    let (org, owner) = own_organisation(&w, "owner2@example.test").await;
    let path = format!("/organisations/{org}/sign-in/providers/acme");
    let secret = "client-secret-made-for-this-test-ZZ";
    let saved = raw(
        &w.app,
        "PUT",
        &path,
        Some(&owner),
        &[],
        Some(oidc_provider(0, true, Some(secret))),
    )
    .await;
    assert_eq!(saved.code(), 200, "{}", saved.text());
    // Read back: no secret anywhere, only that one exists. The stored form is an envelope.
    let read = raw(
        &w.app,
        "GET",
        &format!("/organisations/{org}/sign-in"),
        Some(&owner),
        &[],
        None,
    )
    .await;
    assert_eq!(read.code(), 200);
    assert!(!read.text().contains(secret), "{}", read.text());
    assert_eq!(read.json()["providers"][0]["has_secret"], true);
    let sealed: Vec<u8> = sqlx::query_scalar(
        "select secret_sealed from organisation_sign_in_provider where slug='acme'",
    )
    .fetch_one(w.pool())
    .await
    .unwrap();
    assert!(sealed.starts_with(b"DYNOENC") && !String::from_utf8_lossy(&sealed).contains(secret));
    let audit: Vec<Value> =
        sqlx::query_scalar("select detail from operation_audit where resource_id=$1")
            .bind(org)
            .fetch_all(w.pool())
            .await
            .unwrap();
    assert!(audit.iter().all(|d| !d.to_string().contains(secret)));
    assert!(audit.iter().any(|d| d["secret_changed"] == true));
    // The web tier, with the service key, gets it to call the provider; nobody else does.
    let feed = internal(&w, "GET", "/internal/sign-in/providers", None, None).await;
    assert_eq!(feed.code(), 200);
    assert_eq!(feed.json()["items"][0]["client_secret"], secret);
    assert_eq!(
        raw(
            &w.app,
            "GET",
            "/internal/sign-in/providers",
            Some(&owner),
            &[],
            None
        )
        .await
        .code(),
        403
    );
    // A member, an outsider and an agent session cannot read or change anything.
    let (member_id, member) = person(w.pool(), "member@example.test").await;
    sqlx::query("insert into organisation_member(organisation_id,identity_id,source,role) values($1,$2,'manual','member')").bind(org).bind(member_id).execute(&w.runtime.owner).await.unwrap();
    let (_, outsider) = person(w.pool(), "outsider@example.test").await;
    let (_, agent_token) = w.owner_reader().await;
    for token in [&member, &outsider, &agent_token] {
        assert_eq!(
            raw(
                &w.app,
                "GET",
                &format!("/organisations/{org}/sign-in"),
                Some(token),
                &[],
                None
            )
            .await
            .code()
                / 100,
            4
        );
        let changed = raw(
            &w.app,
            "PUT",
            &path,
            Some(token),
            &[],
            Some(oidc_provider(1, false, Some("x"))),
        )
        .await;
        assert!(
            changed.code() == 401 || changed.code() == 403,
            "{}",
            changed.code()
        );
        assert!(
            raw(
                &w.app,
                "POST",
                &format!("/organisations/{org}/domains"),
                Some(token),
                &[],
                Some(json!({"domain": "example.test"}))
            )
            .await
            .code()
                >= 400
        );
        assert!(
            raw(
                &w.app,
                "POST",
                &format!("/organisations/{org}/scim-tokens"),
                Some(token),
                &[],
                Some(json!({"label": "x"}))
            )
            .await
            .code()
                >= 400
        );
    }
    // A stale revision, a server-decided key and turning on without a secret are refused.
    assert_eq!(
        raw(
            &w.app,
            "PUT",
            &path,
            Some(&owner),
            &[],
            Some(oidc_provider(0, false, None))
        )
        .await
        .code(),
        409
    );
    let mut sneaky = oidc_provider(1, false, None);
    sneaky["settings"]["allowed_domains"] = json!(["evil.test"]);
    assert_eq!(
        raw(&w.app, "PUT", &path, Some(&owner), &[], Some(sneaky))
            .await
            .code(),
        400
    );
    let fresh = raw(
        &w.app,
        "PUT",
        &format!("/organisations/{org}/sign-in/providers/other"),
        Some(&owner),
        &[],
        Some(oidc_provider(0, true, None)),
    )
    .await;
    assert_eq!(fresh.code(), 400);
    // Another organisation cannot take the short name.
    let (org2, owner2) = own_organisation(&w, "owner3@example.test").await;
    let taken = raw(
        &w.app,
        "PUT",
        &format!("/organisations/{org2}/sign-in/providers/acme"),
        Some(&owner2),
        &[],
        Some(oidc_provider(0, false, None)),
    )
    .await;
    assert_eq!(taken.code(), 409);
    // The mapping of an organisation can neither make an instance administrator nor name a space
    // its author does not manage.
    let settings = format!("/organisations/{org}/sign-in/settings");
    let admin_rule = json!({"revision": 1, "mapping": {"rules": [{"name": "A", "group": "g", "grant": {"instance_role": "admin"}}]}});
    assert_eq!(
        raw(
            &w.app,
            "PUT",
            &settings,
            Some(&owner),
            &[],
            Some(admin_rule)
        )
        .await
        .code(),
        403
    );
    let foreign: Uuid = sqlx::query_scalar("insert into access_space(kind,name,created_by) values('organization','Not yours',$1) returning id").bind(w.owner).fetch_one(&w.runtime.owner).await.unwrap();
    let space_rule = json!({"revision": 1, "mapping": {"rules": [{"name": "S", "group": "g", "grant": {"space_id": foreign, "role": "viewer"}}]}});
    assert_eq!(
        raw(
            &w.app,
            "PUT",
            &settings,
            Some(&owner),
            &[],
            Some(space_rule)
        )
        .await
        .code(),
        403
    );
    // Members: an admin cannot make owners; the last owner stays.
    let promoted = raw(
        &w.app,
        "PUT",
        &format!("/organisations/{org}/members"),
        Some(&owner),
        &[],
        Some(json!({"email": "member@example.test", "role": "admin"})),
    )
    .await;
    assert_eq!(promoted.code(), 200, "{}", promoted.text());
    let escalate = raw(
        &w.app,
        "PUT",
        &format!("/organisations/{org}/members"),
        Some(&member),
        &[],
        Some(json!({"email": "member@example.test", "role": "owner"})),
    )
    .await;
    assert_eq!(escalate.code(), 403);
    let last = raw(
        &w.app,
        "PUT",
        &format!("/organisations/{org}/members"),
        Some(&owner),
        &[],
        Some(json!({"email": "owner2@example.test", "role": "member"})),
    )
    .await;
    assert_eq!(last.code(), 400);
}

#[sqlx::test(migrations = "../../migrations")]
async fn domain_routing_and_provider_domains_need_a_verified_domain(pool: PgPool) {
    let w = world(pool).await;
    let (org, owner) = own_organisation(&w, "boss@acme.test").await;
    let saved = raw(
        &w.app,
        "PUT",
        &format!("/organisations/{org}/sign-in/providers/acme"),
        Some(&owner),
        &[],
        Some(oidc_provider(0, true, Some("s3cret-value"))),
    )
    .await;
    assert_eq!(saved.code(), 200, "{}", saved.text());
    let added = raw(
        &w.app,
        "POST",
        &format!("/organisations/{org}/domains"),
        Some(&owner),
        &[],
        Some(json!({"domain": "Acme.TEST"})),
    )
    .await;
    assert_eq!(added.code(), 201, "{}", added.text());
    assert_eq!(
        added.json()["record_name"],
        "_dynodoc-verification.acme.test"
    );
    assert!(added.json()["record_value"]
        .as_str()
        .unwrap()
        .starts_with("dynodoc-verification="));
    // Not verified: an address at the domain neither joins nor can be created by the provider,
    // whatever domains the web tier claims.
    let (ana, _) = login(&w, "ana@acme.test").await;
    let joined = |email: &'static str| {
        let pool = w.pool().clone();
        async move {
            sqlx::query_scalar::<_, bool>("select exists(select 1 from organisation_member m join identity i on i.id=m.identity_id where m.organisation_id=$1 and i.email=$2)")
                .bind(org).bind(email).fetch_one(&pool).await.unwrap()
        }
    };
    assert!(!joined("ana@acme.test").await);
    let blocked = exchange(
        &w,
        "cy@acme.test",
        json!({"provider": "acme", "subject": "cy", "allowed_domains": ["acme.test"]}),
    )
    .await;
    assert_eq!(blocked.code(), 403, "{}", blocked.text());
    // The verified step needs the service key AND an owner login.
    let verify = format!("/organisations/{org}/domains/acme.test/verified");
    assert_eq!(
        raw(&w.app, "POST", &verify, Some(&owner), &[], None)
            .await
            .code(),
        403
    );
    assert_eq!(
        raw(
            &w.app,
            "POST",
            &verify,
            Some(&ana),
            &[("x-dynodoc-service-key", SERVICE)],
            None
        )
        .await
        .code(),
        403
    );
    assert_eq!(
        raw(
            &w.app,
            "POST",
            &verify,
            Some(&owner),
            &[("x-dynodoc-service-key", SERVICE)],
            None
        )
        .await
        .code(),
        200
    );
    // Verified: the next sign-in joins, and the provider may create accounts there only.
    login(&w, "ana@acme.test").await;
    assert!(joined("ana@acme.test").await);
    let created = exchange(
        &w,
        "cy@acme.test",
        json!({"provider": "acme", "subject": "cy", "allowed_domains": []}),
    )
    .await;
    assert_eq!(created.code(), 200, "{}", created.text());
    let outside = exchange(
        &w,
        "dee@other.test",
        json!({"provider": "acme", "subject": "dee", "allowed_domains": ["other.test"]}),
    )
    .await;
    assert_eq!(outside.code(), 403);
    // The mapping of an organisation provider never grants the instance administrator role.
    let admin = exchange(&w, "cy@acme.test", json!({"provider": "acme", "subject": "cy", "memberships": {"grants": [], "instance_admin": "Admins"}})).await;
    assert_eq!(admin.code(), 200);
    let role: bool = sqlx::query_scalar("select exists(select 1 from identity_instance_role r join identity i on i.id=r.identity_id where i.email='cy@acme.test')").fetch_one(w.pool()).await.unwrap();
    assert!(!role);
    // A second organisation cannot verify the same domain; a provider turned off signs nobody in.
    let (org2, owner2) = own_organisation(&w, "boss@rival.test").await;
    raw(
        &w.app,
        "POST",
        &format!("/organisations/{org2}/domains"),
        Some(&owner2),
        &[],
        Some(json!({"domain": "acme.test"})),
    )
    .await;
    let rival = raw(
        &w.app,
        "POST",
        &format!("/organisations/{org2}/domains/acme.test/verified"),
        Some(&owner2),
        &[("x-dynodoc-service-key", SERVICE)],
        None,
    )
    .await;
    assert_eq!(rival.code(), 409);
    raw(
        &w.app,
        "PUT",
        &format!("/organisations/{org}/sign-in/providers/acme"),
        Some(&owner),
        &[],
        Some(oidc_provider(1, false, None)),
    )
    .await;
    assert_eq!(
        exchange(
            &w,
            "cy@acme.test",
            json!({"provider": "acme", "subject": "cy"})
        )
        .await
        .code(),
        403
    );
    // Only people from the verified domains may join, when the owner says so.
    let settings = format!("/organisations/{org}/sign-in/settings");
    let restrict = raw(
        &w.app,
        "PUT",
        &settings,
        Some(&owner),
        &[],
        Some(json!({"revision": 1, "restrict_join": true})),
    )
    .await;
    assert_eq!(restrict.code(), 200, "{}", restrict.text());
    login(&w, "guest@elsewhere.test").await;
    let guest = raw(
        &w.app,
        "PUT",
        &format!("/organisations/{org}/members"),
        Some(&owner),
        &[],
        Some(json!({"email": "guest@elsewhere.test", "role": "member"})),
    )
    .await;
    assert_eq!(guest.code(), 403);
}

fn saml_provider(entity: &str) -> Value {
    json!({
        "kind": "saml",
        "preset": "other",
        "display_name": "Single sign-on",
        "settings": {"idp_metadata": "<EntityDescriptor/>", "idp_entity_id": entity, "provisioning": "jit", "link_by_email": "verified", "trust_email": true},
        "enabled": true,
        "revision": 0
    })
}

async fn verify_domain(w: &World, org: Uuid, owner: &str, domain: &str) {
    let added = raw(
        &w.app,
        "POST",
        &format!("/organisations/{org}/domains"),
        Some(owner),
        &[],
        Some(json!({ "domain": domain })),
    )
    .await;
    assert_eq!(added.code(), 201, "{}", added.text());
    let verified = raw(
        &w.app,
        "POST",
        &format!("/organisations/{org}/domains/{domain}/verified"),
        Some(owner),
        &[("x-dynodoc-service-key", SERVICE)],
        None,
    )
    .await;
    assert_eq!(verified.code(), 200, "{}", verified.text());
}

/// Security review of main 362d4b1, finding 1: an organisation's SAML provider claiming another
/// identity provider's entity ID (with its own certificate) signs in none of that provider's
/// accounts, is refused at save, and nobody signs in through it before a verified domain.
#[sqlx::test(migrations = "../../migrations")]
async fn a_provider_claiming_another_providers_issuer_signs_in_none_of_its_accounts(pool: PgPool) {
    const ENTITY: &str = "https://idp.acme.test/saml";
    let w = world(pool).await;
    let (acme, acme_owner) = own_organisation(&w, "boss@acme.test").await;
    verify_domain(&w, acme, &acme_owner, "acme.test").await;
    let saved = raw(
        &w.app,
        "PUT",
        &format!("/organisations/{acme}/sign-in/providers/acme-sso"),
        Some(&acme_owner),
        &[],
        Some(saml_provider(ENTITY)),
    )
    .await;
    assert_eq!(saved.code(), 200, "{}", saved.text());
    let sso = |provider: &'static str, subject: &'static str| json!({"provider": provider, "issuer": ENTITY, "subject": subject, "link_by_email": true});
    let first = exchange(&w, "ana@acme.test", sso("acme-sso", "ana")).await;
    assert_eq!(first.code(), 200, "{}", first.text());
    let ana = first.json()["identity_id"].clone();

    // A rival organisation's provider, saved before the duplicate check existed.
    let (rival, rival_owner) = own_organisation(&w, "boss@rival.test").await;
    let creator: Uuid = sqlx::query_scalar("select id from identity where email='boss@rival.test'")
        .fetch_one(w.pool())
        .await
        .unwrap();
    let forged: Uuid = sqlx::query_scalar("insert into organisation_sign_in_provider(organisation_id,slug,kind,display_name,settings,enabled,created_by) values($1,'rival-sso','saml','SSO',$2,true,$3) returning id")
        .bind(rival)
        .bind(&saml_provider(ENTITY)["settings"])
        .bind(creator)
        .fetch_one(&w.runtime.owner)
        .await
        .unwrap();
    let (bob, _) = person(w.pool(), "bob@rival.test").await;
    sqlx::query("insert into identity_external(identity_id,provider,provider_row,issuer,subject) values($1,'rival-sso',$2,$3,'bob')")
        .bind(bob)
        .bind(forged)
        .bind(ENTITY)
        .execute(&w.runtime.owner)
        .await
        .unwrap();
    // No verified domain yet: the provider signs nobody in, not even an account it linked.
    let early = exchange(&w, "bob@rival.test", sso("rival-sso", "bob")).await;
    assert_eq!(early.code(), 403, "{}", early.text());
    verify_domain(&w, rival, &rival_owner, "rival.test").await;
    let linked = exchange(&w, "bob@rival.test", sso("rival-sso", "bob")).await;
    assert_eq!(linked.code(), 200, "{}", linked.text());
    assert_eq!(linked.json()["identity_id"], json!(bob));

    // The forged provider presents Ana's subject: Ana's link is Acme's provider's, not this one.
    let takeover = exchange(&w, "ana@acme.test", sso("rival-sso", "ana")).await;
    assert_eq!(takeover.code(), 403, "{}", takeover.text());
    let other = exchange(&w, "ana@rival.test", sso("rival-sso", "ana")).await;
    assert_eq!(other.code(), 200, "{}", other.text());
    assert_ne!(other.json()["identity_id"], ana);
    let again = exchange(&w, "ana@acme.test", sso("acme-sso", "ana")).await;
    assert_eq!(again.json()["identity_id"], ana);

    // A new provider with an entity ID or issuer another provider uses is refused at save.
    let duplicate = raw(
        &w.app,
        "PUT",
        &format!("/organisations/{rival}/sign-in/providers/rival-two"),
        Some(&rival_owner),
        &[],
        Some(saml_provider(ENTITY)),
    )
    .await;
    assert_eq!(duplicate.code(), 409, "{}", duplicate.text());
    let mut oidc = oidc_provider(0, true, Some("s3cret-value"));
    oidc["settings"]["issuer"] = json!(ENTITY);
    let cross = raw(
        &w.app,
        "PUT",
        &format!("/organisations/{rival}/sign-in/providers/rival-oidc"),
        Some(&rival_owner),
        &[],
        Some(oidc),
    )
    .await;
    assert_eq!(cross.code(), 409, "{}", cross.text());
    let mut no_entity = saml_provider(ENTITY);
    no_entity["settings"]
        .as_object_mut()
        .unwrap()
        .remove("idp_entity_id");
    let missing = raw(
        &w.app,
        "PUT",
        &format!("/organisations/{rival}/sign-in/providers/rival-three"),
        Some(&rival_owner),
        &[],
        Some(no_entity),
    )
    .await;
    assert_eq!(missing.code(), 400, "{}", missing.text());

    // Deleting a provider deletes its links (a later provider of that name starts with none).
    let deleted = raw(
        &w.app,
        "DELETE",
        &format!("/organisations/{rival}/sign-in/providers/rival-sso"),
        Some(&rival_owner),
        &[],
        None,
    )
    .await;
    assert_eq!(deleted.code(), 200, "{}", deleted.text());
    let left: i64 =
        sqlx::query_scalar("select count(*) from identity_external where provider='rival-sso'")
            .fetch_one(&w.runtime.owner)
            .await
            .unwrap();
    assert_eq!(left, 0);
}

/// Migration 0141 on existing links: a link goes to the organisation's provider of its short name
/// only when that provider names the link's issuer; the rest stay the operator's.
#[sqlx::test(migrations = false)]
async fn existing_links_are_bound_to_the_provider_that_made_them(pool: PgPool) {
    let all = sqlx::migrate!("../../migrations");
    let old = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            all.iter().filter(|m| m.version <= 140).cloned().collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    };
    old.run(&pool).await.unwrap();
    let person: Uuid =
        sqlx::query_scalar("insert into identity(email) values('ana@acme.test') returning id")
            .fetch_one(&pool)
            .await
            .unwrap();
    let org: Uuid = sqlx::query_scalar(
        "insert into organisation(name,created_by) values('Acme',$1) returning id",
    )
    .bind(person)
    .fetch_one(&pool)
    .await
    .unwrap();
    let provider = |slug: &'static str, kind: &'static str, settings: Value| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Uuid>("insert into organisation_sign_in_provider(organisation_id,slug,kind,display_name,settings,created_by) values($1,$2,$3,'SSO',$4,$5) returning id")
                .bind(org).bind(slug).bind(kind).bind(settings).bind(person)
                .fetch_one(&pool).await.unwrap()
        }
    };
    let oidc = provider("acme", "oidc", json!({"issuer": ISSUER})).await;
    let saml = provider(
        "acme-saml",
        "saml",
        json!({"idp_metadata": "<EntityDescriptor entityID=\"https://idp.acme.test/saml\"/>"}),
    )
    .await;
    // "corp" also names an organisation's provider, with another issuer: the operator's link.
    provider(
        "corp",
        "oidc",
        json!({"issuer": "https://other.example.test"}),
    )
    .await;
    for (slug, issuer, subject) in [
        ("acme", ISSUER, "s1"),
        ("acme-saml", "https://idp.acme.test/saml", "s2"),
        ("corp", ISSUER, "s3"),
        ("file-only", ISSUER, "s4"),
    ] {
        sqlx::query("insert into identity_external(identity_id,provider,issuer,subject) values($1,$2,$3,$4)")
            .bind(person).bind(slug).bind(issuer).bind(subject)
            .execute(&pool).await.unwrap();
    }
    all.run(&pool).await.unwrap();
    let bound: Vec<(String, Option<Uuid>)> =
        sqlx::query_as("select subject,provider_row from identity_external order by subject")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        bound,
        vec![
            ("s1".into(), Some(oidc)),
            ("s2".into(), Some(saml)),
            ("s3".into(), None),
            ("s4".into(), None)
        ]
    );
}
