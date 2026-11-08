//! Self-hosted identity, second part (docs/decisions/037-self-hosted-identity-ha-and-licensing.md)
//! against a real PostgreSQL, the real router and the restricted runtime login: the read-only
//! auditor role (instance and organisation), logins as records with logout propagation and the
//! session lifetimes, service accounts and their scoped grants, the SCIM circuit breaker, rate
//! limit and ETag, the mapping freeze and dry run, and the separate identity-secrets key.
mod common;

mod agent_world;
use agent_world::*;

use axum::Router;
use engine_api::{
    app,
    auth::{AuthConfig, SessionPolicy},
    AppState,
};
use engine_core::repository::{
    device::{Challenge, Proof},
    device_session::{SessionChallenge, SessionProof},
};
use ring::signature::KeyPair;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const SERVICE: &str = "isolated-self-host-identity-test-service-key";
const ISSUER: &str = "https://idp.example.test/realms/main";

struct Harness {
    app: Router,
    runtime: common::RuntimeDatabase,
}

impl Harness {
    async fn new(pool: PgPool, tune: impl FnOnce(&mut AppState)) -> Self {
        let runtime = common::RuntimeDatabase::new(pool).await;
        let mut state = AppState::new(
            runtime.pool.clone(),
            AuthConfig {
                paseto_key: KEY,
                service_key: Some(SERVICE.into()),
                token_ttl_seconds: 3600,
                public_base_url: "http://test.local".into(),
            },
        );
        state.admin_emails = "admin@example.test".into();
        tune(&mut state);
        Self {
            app: app(state),
            runtime,
        }
    }
    fn pool(&self) -> &PgPool {
        &self.runtime.pool
    }
    async fn internal(&self, method: &str, uri: &str, bearer: Option<&str>, body: Value) -> Reply {
        let body = (!body.is_null()).then_some(body);
        raw(
            &self.app,
            method,
            uri,
            bearer,
            &[("x-dynodoc-service-key", SERVICE)],
            body,
        )
        .await
    }
    async fn as_(&self, method: &str, uri: &str, token: &str, body: Value) -> Reply {
        let body = (!body.is_null()).then_some(body);
        raw(&self.app, method, uri, Some(token), &[], body).await
    }
    /// A provider sign-in with a provider session and an ID token: the token response.
    async fn sso(&self, email: &str, subject: &str, sid: &str) -> Value {
        let reply = self
            .internal(
                "POST",
                "/auth/exchange",
                None,
                json!({"email": email, "display_name": "Person", "external": {
                    "provider": "corp", "issuer": ISSUER, "subject": subject,
                    "email_verified": true, "provisioning": "jit",
                    "allowed_domains": ["example.test"], "operator": true,
                    "idp_session": sid, "id_token": format!("header.{subject}.signature"),
                    "auth_time": 1_700_000_000
                }}),
            )
            .await;
        assert_eq!(reply.code(), 200, "{}", reply.text());
        reply.json()
    }
    /// An emailed-link login: the token response.
    async fn login(&self, email: &str) -> Value {
        let link = self
            .internal("POST", "/auth/magic-link", None, json!({"email": email}))
            .await;
        assert_eq!(link.code(), 200, "{}", link.text());
        let tokens = raw(
            &self.app,
            "POST",
            "/auth/verify",
            None,
            &[],
            Some(json!({"token": link.json()["magic_link_token"]})),
        )
        .await;
        assert_eq!(tokens.code(), 200, "{}", tokens.text());
        tokens.json()
    }
    async fn me(&self, access: &str) -> u16 {
        get(&self.app, "/auth/me", access).await.code()
    }
    async fn refresh(&self, refresh: &str) -> Reply {
        raw(
            &self.app,
            "POST",
            "/auth/refresh",
            None,
            &[],
            Some(json!({"refresh_token": refresh})),
        )
        .await
    }
}

fn s(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap().to_owned()
}
fn id(v: &Value) -> Uuid {
    serde_json::from_value(v["id"].clone()).unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_auditor_reads_administration_and_changes_nothing(pool: PgPool) {
    let h = Harness::new(pool, |_| {}).await;
    let (_, admin) = person(h.pool(), "admin@example.test").await;
    let (auditor_id, auditor) = person(h.pool(), "audit@example.test").await;
    let (victim, outsider) = person(h.pool(), "someone@example.test").await;
    // Not yet an auditor: nothing.
    assert_eq!(get(&h.app, "/admin/overview", &auditor).await.code(), 403);
    let granted = h
        .as_(
            "PUT",
            &format!("/admin/instance-roles/{auditor_id}"),
            &admin,
            json!({"role": "auditor", "granted": true}),
        )
        .await;
    assert_eq!(granted.code(), 200, "{}", granted.text());

    for read in [
        "/admin/overview",
        "/admin/records?kind=users",
        "/admin/records?kind=audit",
        "/admin/organisations",
        "/admin/service-accounts",
        "/admin/usage-report",
        &format!("/admin/sessions?identity={victim}"),
        &format!("/admin/impact?kind=users&id={victim}"),
    ] {
        let reply = get(&h.app, read, &auditor).await;
        assert_eq!(reply.code(), 200, "{read}: {}", reply.text());
    }
    let export = get(&h.app, "/admin/audit/export?limit=50", &auditor).await;
    assert_eq!(export.code(), 200, "{}", export.text());
    assert_eq!(
        export.header("content-type").as_deref(),
        Some("application/x-ndjson")
    );
    let lines: Vec<Value> = export
        .text()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(lines.iter().any(|l| l["action"] == "instance_role.granted"));

    // Every write refuses the auditor.
    let writes = [
        (
            "POST",
            "/admin/actions".to_string(),
            json!({"kind":"users","id":victim,"removed":true,"confirmation":"someone@example.test"}),
        ),
        (
            "POST",
            "/admin/organisations".into(),
            json!({"name":"X","domains":["x.test"]}),
        ),
        (
            "PUT",
            format!("/admin/instance-roles/{auditor_id}"),
            json!({"role":"admin","granted":true}),
        ),
        (
            "POST",
            "/admin/service-accounts".into(),
            json!({"name":"ci"}),
        ),
        (
            "POST",
            "/admin/erase".into(),
            json!({"kind":"users","id":victim,"confirmation":"x","revision":"x","reason":"other","acknowledge_backups":true}),
        ),
        ("POST", "/admin/control".into(), json!({})),
    ];
    for (method, uri, body) in writes {
        let reply = h.as_(method, &uri, &auditor, body).await;
        assert!(
            [403, 422].contains(&reply.code()),
            "{method} {uri}: {} {}",
            reply.code(),
            reply.text()
        );
        assert_ne!(reply.code(), 200);
    }
    let disabled: bool =
        sqlx::query_scalar("select disabled_at is not null from identity where id=$1")
            .bind(victim)
            .fetch_one(h.pool())
            .await
            .unwrap();
    assert!(!disabled);
    // A person with no role reads nothing either.
    assert_eq!(
        get(&h.app, "/admin/audit/export", &outsider).await.code(),
        403
    );
    // An administrator cannot remove their own administrator role (a mapped or ADMIN_EMAILS
    // administrator has no manual row to remove; the rule is checked first).
    let (admin_id, _) = person(h.pool(), "admin@example.test").await;
    let own = h
        .as_(
            "PUT",
            &format!("/admin/instance-roles/{admin_id}"),
            &admin,
            json!({"role": "admin", "granted": false}),
        )
        .await;
    assert_eq!(own.code(), 400);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_organisation_auditor_reads_its_settings_and_audit_and_changes_nothing(pool: PgPool) {
    let h = Harness::new(pool, |_| {}).await;
    let (_, owner) = person(h.pool(), "owner@example.test").await;
    let (_, auditor) = person(h.pool(), "auditor@example.test").await;
    let made = h
        .as_(
            "POST",
            "/organisations",
            &owner,
            json!({"name": "Example Ltd"}),
        )
        .await;
    assert_eq!(made.code(), 201, "{}", made.text());
    let org = id(&made.json());
    let set = h
        .as_(
            "PUT",
            &format!("/organisations/{org}/members"),
            &owner,
            json!({"email": "auditor@example.test", "role": "auditor"}),
        )
        .await;
    assert_eq!(set.code(), 200, "{}", set.text());
    assert_eq!(set.json()["added"], true);
    assert_eq!(set.json()["approval_email"], true);

    let read = get(&h.app, &format!("/organisations/{org}/sign-in"), &auditor).await;
    assert_eq!(read.code(), 200, "{}", read.text());
    assert_eq!(read.json()["role"], "auditor");
    let export = get(
        &h.app,
        &format!("/organisations/{org}/audit/export"),
        &auditor,
    )
    .await;
    assert_eq!(export.code(), 200, "{}", export.text());
    assert!(export.text().contains("organisation.member.set"));
    assert_eq!(
        get(&h.app, &format!("/organisations/{org}/scim/held"), &auditor)
            .await
            .code(),
        200
    );
    for (method, uri, body) in [
        (
            "PUT",
            format!("/organisations/{org}/sign-in/options"),
            json!({"mapping_frozen": true}),
        ),
        (
            "PUT",
            format!("/organisations/{org}/members"),
            json!({"email":"x@example.test","role":"member"}),
        ),
        (
            "POST",
            format!("/organisations/{org}/scim-tokens"),
            json!({"label":"x"}),
        ),
        (
            "POST",
            format!("/organisations/{org}/domains"),
            json!({"domain":"example.test"}),
        ),
        (
            "PUT",
            format!("/organisations/{org}/sign-in/settings"),
            json!({"revision":1,"restrict_join":true}),
        ),
    ] {
        let reply = h.as_(method, &uri, &auditor, body).await;
        assert_eq!(reply.code(), 403, "{method} {uri}: {}", reply.text());
    }
    let frozen: bool = sqlx::query_scalar("select mapping_frozen from organisation where id=$1")
        .bind(org)
        .fetch_one(h.pool())
        .await
        .unwrap();
    assert!(!frozen);
    // Approving an address with no account makes it, so an invitation can be sent.
    let invited = h
        .as_(
            "PUT",
            &format!("/organisations/{org}/members"),
            &owner,
            json!({"email": "new.person@example.test", "role": "member"}),
        )
        .await;
    assert_eq!(invited.code(), 200, "{}", invited.text());
    assert_eq!(invited.json()["added"], true);
    // A service address is never a member.
    let svc = h
        .as_(
            "PUT",
            &format!("/organisations/{org}/members"),
            &owner,
            json!({"email": "svc-x@service.invalid", "role": "member"}),
        )
        .await;
    assert_eq!(svc.code(), 400);
}

#[sqlx::test(migrations = "../../migrations")]
async fn logout_and_identity_provider_logout_end_the_right_logins(pool: PgPool) {
    let h = Harness::new(pool, |state| state.identity_key = Some([5; 32])).await;
    let first = h.sso("ana@example.test", "ana", "sid-1").await;
    let second = h.sso("ana@example.test", "ana", "sid-2").await;
    let (a1, a2) = (s(&first, "access_token"), s(&second, "access_token"));
    assert_eq!(h.me(&a1).await, 200);
    // The login is a record: provider, issuer, the provider session, a sealed ID token.
    let sealed: Vec<u8> =
        sqlx::query_scalar("select id_token_hint from login_session where idp_session='sid-1'")
            .fetch_one(h.pool())
            .await
            .unwrap();
    assert!(
        !sealed.windows(3).any(|w| w == b"ana"),
        "the ID token is stored sealed"
    );
    let mine = get(&h.app, "/auth/sessions", &a1).await;
    assert_eq!(mine.code(), 200);
    assert_eq!(mine.json()["items"].as_array().unwrap().len(), 2);
    assert_eq!(
        mine.json()["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["current"] == true)
            .count(),
        1
    );

    // Back-channel logout needs the service key and names the issuer and the session.
    let body = json!({"issuer": ISSUER, "idp_session": "sid-1"});
    let refused = raw(
        &h.app,
        "POST",
        "/internal/auth/logout-propagation",
        None,
        &[],
        Some(body.clone()),
    )
    .await;
    assert_eq!(refused.code(), 403);
    let wrong_issuer = h
        .internal(
            "POST",
            "/internal/auth/logout-propagation",
            None,
            json!({"issuer": "https://other.example.test", "idp_session": "sid-1"}),
        )
        .await;
    assert_eq!(wrong_issuer.json()["revoked"], 0);
    assert_eq!(h.me(&a1).await, 200);
    let ended = h
        .internal("POST", "/internal/auth/logout-propagation", None, body)
        .await;
    assert_eq!(ended.code(), 200, "{}", ended.text());
    assert_eq!(ended.json()["revoked"], 1);
    assert_eq!(h.me(&a1).await, 401, "the ended login fails at once");
    assert_eq!(h.refresh(&s(&first, "refresh_token")).await.code(), 401);
    assert_eq!(h.me(&a2).await, 200, "the other provider session lives on");

    // RP-initiated logout: the web tier (service key) gets the ID token back to send to the IdP.
    let out = h
        .internal(
            "POST",
            "/auth/logout",
            None,
            json!({"refresh_token": s(&second, "refresh_token")}),
        )
        .await;
    assert_eq!(out.code(), 200);
    assert_eq!(out.json()["login"]["id_token_hint"], "header.ana.signature");
    assert_eq!(out.json()["login"]["issuer"], ISSUER);
    assert_eq!(h.me(&a2).await, 401);
    // Without the service key a logout says nothing about the login.
    let third = h.sso("ana@example.test", "ana", "sid-3").await;
    let plain = raw(
        &h.app,
        "POST",
        "/auth/logout",
        None,
        &[],
        Some(json!({"refresh_token": s(&third, "refresh_token")})),
    )
    .await;
    assert!(plain.json().get("login").is_none());

    // By subject alone: every login of that subject at that issuer.
    let fourth = h.sso("ana@example.test", "ana", "sid-4").await;
    let other = h.sso("bea@example.test", "bea", "sid-9").await;
    let ended = h
        .internal(
            "POST",
            "/internal/auth/logout-propagation",
            None,
            json!({"issuer": ISSUER, "subject": "ana"}),
        )
        .await;
    assert_eq!(ended.json()["revoked"], 1);
    assert_eq!(h.me(&s(&fourth, "access_token")).await, 401);
    assert_eq!(h.me(&s(&other, "access_token")).await, 200);

    // A person ends their own login; another person's login id is unknown to them.
    let bea_login = get(&h.app, "/auth/sessions", &s(&other, "access_token"))
        .await
        .json()["items"][0]["id"]
        .clone();
    let fifth = h.sso("ana@example.test", "ana", "sid-5").await;
    let theirs = h
        .as_(
            "POST",
            &format!("/auth/sessions/{}/revoke", bea_login.as_str().unwrap()),
            &s(&fifth, "access_token"),
            Value::Null,
        )
        .await;
    assert_eq!(theirs.code(), 404);
    assert_eq!(h.me(&s(&other, "access_token")).await, 200);
    let own = h
        .as_(
            "POST",
            &format!("/auth/sessions/{}/revoke", bea_login.as_str().unwrap()),
            &s(&other, "access_token"),
            Value::Null,
        )
        .await;
    assert_eq!(own.json()["revoked"], 1);
    assert_eq!(h.me(&s(&other, "access_token")).await, 401);
}

#[sqlx::test(migrations = "../../migrations")]
async fn session_lifetimes_bound_every_refresh_and_the_absolute_cap_ends_the_login(pool: PgPool) {
    let h = Harness::new(pool, |state| {
        state.session_policy = SessionPolicy {
            refresh_ttl_seconds: 30 * 86_400,
            idle_timeout_seconds: 3_600,
            absolute_timeout_seconds: 7_200,
        }
    })
    .await;
    let login = h.login("cap@example.test").await;
    let expiry = |pool: PgPool| async move {
        let (expires, cap): (f64, f64) = sqlx::query_as("select extract(epoch from r.expires_at-now())::float8, extract(epoch from s.absolute_expires_at-now())::float8 from refresh_token r join login_session s on s.session_id=r.session_id where r.rotated_at is null and r.revoked_at is null")
            .fetch_one(&pool)
            .await
            .unwrap();
        (expires, cap)
    };
    let (expires, cap) = expiry(h.pool().clone()).await;
    assert!(
        expires <= 3_600.5 && expires > 3_500.0,
        "idle timeout bounds the refresh row: {expires}"
    );
    assert!(cap <= 7_200.5 && cap > 7_100.0);
    // The provider is recorded; the access token never outlives the refresh row.
    let provider: String = sqlx::query_scalar("select provider from login_session")
        .fetch_one(h.pool())
        .await
        .unwrap();
    assert_eq!(provider, "email");
    assert!(login["expires_in"].as_i64().unwrap() <= 3_600);

    // Near the cap, a refresh is given no more than what is left, and past it the login is over.
    sqlx::query("update login_session set absolute_expires_at=now()+interval '10 minutes'")
        .execute(&h.runtime.owner)
        .await
        .unwrap();
    let rotated = h.refresh(&s(&login, "refresh_token")).await;
    assert_eq!(rotated.code(), 200, "{}", rotated.text());
    let (expires, _) = expiry(h.pool().clone()).await;
    assert!(expires <= 600.5, "capped by the absolute end: {expires}");
    assert!(rotated.json()["expires_in"].as_i64().unwrap() <= 600);
    // Time passes beyond the cap: the refresh row, capped at it, has expired with it.
    sqlx::query("update login_session set absolute_expires_at=now()-interval '1 second'")
        .execute(&h.runtime.owner)
        .await
        .unwrap();
    sqlx::query(
        "update refresh_token set expires_at=now()-interval '1 second' where rotated_at is null",
    )
    .execute(&h.runtime.owner)
    .await
    .unwrap();
    assert_eq!(
        h.me(&s(&rotated.json(), "access_token")).await,
        401,
        "past the cap the login is over"
    );
    let late = h.refresh(&s(&rotated.json(), "refresh_token")).await;
    assert_eq!(late.code(), 401, "and it cannot be refreshed");
}

/// Enrol a person-class key for the login `token` (the account of the token).
async fn enrol(app: &Router, token: &str, seed: u8) -> (ring::signature::Ed25519KeyPair, Uuid) {
    let key = key(seed);
    let (status, challenge) = call(
        app,
        "POST",
        "/devices/challenge",
        Some(token),
        json!({"public_key": hex::encode(key.public_key().as_ref())}),
    )
    .await;
    assert_eq!(status.as_u16(), 200, "{challenge}");
    let challenge: Challenge = serde_json::from_value(challenge).unwrap();
    let proof = Proof::sign(
        challenge.clone(),
        challenge.authority,
        challenge.identity,
        &key,
    )
    .unwrap();
    let (status, body) = call(app, "POST", "/devices", Some(token), json!(proof)).await;
    assert_eq!(status.as_u16(), 200, "{body}");
    (key, challenge.id)
}

/// Open a project device session (the scoped token) with `key`.
async fn open(
    app: &Router,
    key: &ring::signature::Ed25519KeyPair,
    project: Uuid,
    scopes: &[&str],
) -> (u16, Value) {
    let (status, body) = call(
        app,
        "POST",
        &format!("/projects/{project}/device-sessions/challenge"),
        None,
        json!({"public_key": hex::encode(key.public_key().as_ref()), "scopes": scopes}),
    )
    .await;
    assert_eq!(status.as_u16(), 200, "{body}");
    let challenge: SessionChallenge = serde_json::from_value(body["challenge"].clone()).unwrap();
    let wanted: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    let proof = SessionProof::sign(
        challenge.clone(),
        body["mac"].as_str().unwrap().to_owned(),
        challenge.authority,
        project,
        &wanted,
        key,
    )
    .unwrap();
    let (status, body) = call(
        app,
        "POST",
        &format!("/projects/{project}/device-sessions"),
        None,
        json!(proof),
    )
    .await;
    (status.as_u16(), body)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_service_account_never_signs_in_and_acts_only_through_its_scoped_grants(pool: PgPool) {
    let h = Harness::new(pool, |_| {}).await;
    let (_, admin) = person(h.pool(), "admin@example.test").await;
    let (_, owner) = person(h.pool(), "owner@example.test").await;
    let (status, project) = call(
        &h.app,
        "POST",
        "/projects",
        Some(&owner),
        json!({"name": "Exports"}),
    )
    .await;
    assert_eq!(status.as_u16(), 200, "{project}");
    let project = id(&project);
    let made = h
        .as_(
            "POST",
            "/admin/service-accounts",
            &admin,
            json!({"name": "ci-export"}),
        )
        .await;
    assert_eq!(made.code(), 201, "{}", made.text());
    let svc = id(&made.json());
    assert_eq!(made.json()["email"], "svc-ci-export@service.invalid");
    // Owner only an administrator; a second account with the same name is refused.
    assert_eq!(
        h.as_(
            "POST",
            "/admin/service-accounts",
            &owner,
            json!({"name": "x1"})
        )
        .await
        .code(),
        403
    );
    assert_eq!(
        h.as_(
            "POST",
            "/admin/service-accounts",
            &admin,
            json!({"name": "ci-export"})
        )
        .await
        .code(),
        409
    );

    // No sign-in of any kind: emailed link, Google exchange, provider sign-in.
    let link = h
        .internal(
            "POST",
            "/auth/magic-link",
            None,
            json!({"email": "svc-ci-export@service.invalid"}),
        )
        .await;
    assert_eq!(link.code(), 403);
    let google = h
        .internal(
            "POST",
            "/auth/exchange",
            None,
            json!({"email": "svc-ci-export@service.invalid"}),
        )
        .await;
    assert_ne!(google.code(), 200, "{}", google.text());
    let sso = h
        .internal(
            "POST",
            "/auth/exchange",
            None,
            json!({"email": "svc-ci-export@service.invalid", "external": {"provider": "corp", "issuer": ISSUER, "subject": "svc", "email_verified": true, "provisioning": "jit", "operator": true}}),
        )
        .await;
    assert_ne!(sso.code(), 200, "{}", sso.text());

    // The administrator's ten-minute enrolment login enrols the account's key.
    let enrolment = h
        .as_(
            "POST",
            &format!("/admin/service-accounts/{svc}/enrolment-login"),
            &admin,
            Value::Null,
        )
        .await;
    assert_eq!(enrolment.code(), 200, "{}", enrolment.text());
    assert!(enrolment.json()["expires_in"].as_i64().unwrap() <= 600);
    let cap: f64 = sqlx::query_scalar("select extract(epoch from max(expires_at)-now())::float8 from refresh_token where identity_id=$1")
        .bind(svc)
        .fetch_one(h.pool())
        .await
        .unwrap();
    assert!(
        cap <= 600.5,
        "the enrolment login cannot outlive ten minutes: {cap}"
    );
    let login = s(&enrolment.json(), "access_token");
    let (key, key_id) = enrol(&h.app, &login, 41).await;

    // A role in the project through a normal membership (never owner or manager).
    assert_eq!(
        h.as_(
            "PUT",
            &format!("/admin/service-accounts/{svc}/projects/{project}"),
            &admin,
            json!({"role": "manager"})
        )
        .await
        .code(),
        400
    );
    let role = h
        .as_(
            "PUT",
            &format!("/admin/service-accounts/{svc}/projects/{project}"),
            &admin,
            json!({"role": "viewer"}),
        )
        .await;
    assert_eq!(role.code(), 200, "{}", role.text());
    let grant = h
        .as_(
            "PUT",
            &format!("/devices/{key_id}/projects/{project}"),
            &login,
            json!({"scopes": ["project:read"], "expires_in_days": 30}),
        )
        .await;
    assert_eq!(grant.code(), 200, "{}", grant.text());

    // The scoped token: what was granted, nothing more.
    let (code, session) = open(&h.app, &key, project, &["project:read"]).await;
    assert_eq!(code, 200, "{session}");
    let (code, _) = open(&h.app, &key, project, &["history:write"]).await;
    assert_ne!(code, 200, "a scope that was not granted is refused");

    // An expired grant is no grant.
    sqlx::query("update device_key_project_grant set revoked_at=clock_timestamp() where key_id=$1 and revoked_at is null")
        .bind(key_id)
        .execute(&h.runtime.owner)
        .await
        .unwrap();
    sqlx::query("insert into device_key_project_grant(key_id,project_id,scopes,created_at,created_by,expires_at) values($1,$2,array['project:read'],clock_timestamp(),$3,now()-interval '1 minute')")
        .bind(key_id)
        .bind(project)
        .bind(svc)
        .execute(&h.runtime.owner)
        .await
        .unwrap();
    let (code, _) = open(&h.app, &key, project, &["project:read"]).await;
    assert_ne!(code, 200, "an expired grant opens nothing");
    // The grant's expiry cannot be moved afterwards, even by the runtime login.
    let moved = sqlx::query("update device_key_project_grant set expires_at=null where key_id=$1 and revoked_at is null")
        .bind(key_id)
        .execute(h.pool())
        .await;
    assert!(moved.is_err());
}

/// An organisation with `example.test`, a SCIM token, and its id.
async fn directory(h: &Harness, admin: &str) -> (Uuid, String) {
    let org = h
        .as_(
            "POST",
            "/admin/organisations",
            admin,
            json!({"name": "Example Ltd", "domains": ["example.test"]}),
        )
        .await;
    assert_eq!(org.code(), 201, "{}", org.text());
    let org = id(&org.json());
    let token = h
        .as_(
            "POST",
            &format!("/admin/organisations/{org}/scim-tokens"),
            admin,
            json!({"label": "sync"}),
        )
        .await;
    assert_eq!(token.code(), 201, "{}", token.text());
    (org, s(&token.json(), "token"))
}

async fn scim_user(h: &Harness, token: &str, email: &str) -> Uuid {
    let made = h
        .internal(
            "POST",
            "/internal/directory/users",
            Some(token),
            json!({"user_name": email}),
        )
        .await;
    assert_eq!(made.code(), 201, "{}", made.text());
    id(&made.json())
}

async fn disabled(h: &Harness, who: Uuid) -> bool {
    sqlx::query_scalar("select disabled_at is not null from identity where id=$1")
        .bind(who)
        .fetch_one(h.pool())
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_scim_circuit_breaker_holds_mass_deactivations_for_a_person(pool: PgPool) {
    let h = Harness::new(pool, |_| {}).await;
    let (_, admin) = person(h.pool(), "admin@example.test").await;
    let (org, token) = directory(&h, &admin).await;
    let options = h
        .as_(
            "PUT",
            &format!("/organisations/{org}/sign-in/options"),
            &admin,
            json!({"scim_breaker_percent": 1, "scim_breaker_minimum": 1}),
        )
        .await;
    assert_eq!(options.code(), 200, "{}", options.text());
    let a = scim_user(&h, &token, "a@example.test").await;
    let b = scim_user(&h, &token, "b@example.test").await;
    let c = scim_user(&h, &token, "c@example.test").await;
    let off = json!({"active": false});
    let first = h
        .internal(
            "PATCH",
            &format!("/internal/directory/users/{a}"),
            Some(&token),
            off.clone(),
        )
        .await;
    assert_eq!(first.code(), 200, "{}", first.text());
    assert!(disabled(&h, a).await);
    // The threshold (one an hour here) is reached: the next ones wait for a person.
    let second = h
        .internal(
            "PATCH",
            &format!("/internal/directory/users/{b}"),
            Some(&token),
            off,
        )
        .await;
    assert_eq!(second.code(), 202, "{}", second.text());
    assert_eq!(second.json()["held"], true);
    assert!(
        !disabled(&h, b).await,
        "a held deactivation changes nothing yet"
    );
    let gone = h
        .internal(
            "DELETE",
            &format!("/internal/directory/users/{c}"),
            Some(&token),
            Value::Null,
        )
        .await;
    assert_eq!(gone.code(), 202, "{}", gone.text());
    assert!(!disabled(&h, c).await);
    let held = get(&h.app, &format!("/organisations/{org}/scim/held"), &admin).await;
    assert_eq!(
        held.json()["items"].as_array().unwrap().len(),
        2,
        "{}",
        held.text()
    );
    // A member of the organisation cannot decide; an admin confirms one and discards the other.
    let (_, member) = person(h.pool(), "m@example.test").await;
    assert_eq!(
        h.as_(
            "POST",
            &format!("/organisations/{org}/scim/held/{b}/confirm"),
            &member,
            Value::Null
        )
        .await
        .code(),
        403
    );
    let confirmed = h
        .as_(
            "POST",
            &format!("/organisations/{org}/scim/held/{b}/confirm"),
            &admin,
            Value::Null,
        )
        .await;
    assert_eq!(confirmed.code(), 200, "{}", confirmed.text());
    assert!(disabled(&h, b).await);
    let discarded = h
        .as_(
            "POST",
            &format!("/organisations/{org}/scim/held/{c}/discard"),
            &admin,
            Value::Null,
        )
        .await;
    assert_eq!(discarded.code(), 200);
    assert!(!disabled(&h, c).await);
    assert_eq!(
        h.as_(
            "POST",
            &format!("/organisations/{org}/scim/held/{c}/confirm"),
            &admin,
            Value::Null
        )
        .await
        .code(),
        404
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn scim_honours_if_match_and_its_rate_limit(pool: PgPool) {
    let h = Harness::new(pool, |state| state.scim_rate_per_minute = 6).await;
    let (_, admin) = person(h.pool(), "admin@example.test").await;
    let (_, token) = directory(&h, &admin).await;
    let a = scim_user(&h, &token, "a@example.test").await; // 1
    let read = h
        .internal(
            "GET",
            &format!("/internal/directory/users/{a}"),
            Some(&token),
            Value::Null,
        )
        .await; // 2
    let version = read.json()["version"].as_i64().unwrap();
    let stale = raw(
        &h.app,
        "PATCH",
        &format!("/internal/directory/users/{a}"),
        Some(&token),
        &[
            ("x-dynodoc-service-key", SERVICE),
            ("if-match", &format!("W/\"{}\"", version + 7)),
        ],
        Some(json!({"display_name": "A"})),
    )
    .await; // 3
    assert_eq!(stale.code(), 412, "{}", stale.text());
    let fresh = raw(
        &h.app,
        "PATCH",
        &format!("/internal/directory/users/{a}"),
        Some(&token),
        &[
            ("x-dynodoc-service-key", SERVICE),
            ("if-match", &format!("W/\"{version}\"")),
        ],
        Some(json!({"display_name": "A"})),
    )
    .await; // 4
    assert_eq!(fresh.code(), 200, "{}", fresh.text());
    assert_eq!(fresh.json()["version"].as_i64().unwrap(), version + 1);
    for _ in 0..2 {
        let ok = h
            .internal(
                "GET",
                "/internal/directory/users",
                Some(&token),
                Value::Null,
            )
            .await;
        assert_eq!(ok.code(), 200); // 5, 6
    }
    let limited = h
        .internal(
            "GET",
            "/internal/directory/users",
            Some(&token),
            Value::Null,
        )
        .await;
    assert_eq!(limited.code(), 429, "{}", limited.text());
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_frozen_mapping_changes_nothing_and_a_dry_run_only_reports(pool: PgPool) {
    let h = Harness::new(pool, |_| {}).await;
    let (_, admin) = person(h.pool(), "admin@example.test").await;
    let (_, owner) = person(h.pool(), "owner@example.test").await;
    let (status, space) = call(
        &h.app,
        "POST",
        "/projects",
        Some(&owner),
        json!({"name": "Mapped"}),
    )
    .await;
    assert_eq!(status.as_u16(), 200, "{space}");
    let space = id(&space);
    let (org, token) = directory(&h, &admin).await;
    let a = scim_user(&h, &token, "a@example.test").await;
    let grants = json!({"grants": [{"space_id": space, "role": "viewer", "rule": "staff"}]});
    let rows = |pool: PgPool| async move {
        sqlx::query_scalar::<_, i64>("select count(*) from space_member where source='scim'")
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let dry = h
        .internal(
            "PUT",
            &format!("/internal/directory/users/{a}/memberships?dry_run=true"),
            Some(&token),
            grants.clone(),
        )
        .await;
    assert_eq!(dry.code(), 200, "{}", dry.text());
    assert_eq!(dry.json()["dry_run"], true);
    assert_eq!(dry.json()["changes"].as_array().unwrap().len(), 1);
    assert_eq!(rows(h.pool().clone()).await, 0, "a dry run writes nothing");
    let preview = h
        .as_(
            "POST",
            &format!("/organisations/{org}/sign-in/mapping/preview"),
            &admin,
            json!({"identity_id": a, "source": "scim", "memberships": grants}),
        )
        .await;
    assert_eq!(preview.code(), 200, "{}", preview.text());
    assert_eq!(preview.json()["changes"].as_array().unwrap().len(), 1);
    assert_eq!(rows(h.pool().clone()).await, 0);

    let frozen = h
        .as_(
            "PUT",
            &format!("/organisations/{org}/sign-in/options"),
            &admin,
            json!({"mapping_frozen": true}),
        )
        .await;
    assert_eq!(frozen.code(), 200, "{}", frozen.text());
    let blocked = h
        .internal(
            "PUT",
            &format!("/internal/directory/users/{a}/memberships"),
            Some(&token),
            grants.clone(),
        )
        .await;
    assert_eq!(blocked.json()["frozen"], true);
    assert_eq!(
        rows(h.pool().clone()).await,
        0,
        "a frozen mapping changes nothing"
    );
    h.as_(
        "PUT",
        &format!("/organisations/{org}/sign-in/options"),
        &admin,
        json!({"mapping_frozen": false}),
    )
    .await;
    let applied = h
        .internal(
            "PUT",
            &format!("/internal/directory/users/{a}/memberships"),
            Some(&token),
            grants,
        )
        .await;
    assert_eq!(
        applied.json()["changes"].as_array().unwrap().len(),
        1,
        "{}",
        applied.text()
    );
    assert_eq!(rows(h.pool().clone()).await, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn identity_secrets_move_to_their_own_key_and_survive_a_server_key_rotation(pool: PgPool) {
    use engine_api::identity_secrets::{self as secrets, ResealReport};
    let runtime = common::RuntimeDatabase::new(pool).await;
    let owner = &runtime.owner;
    let (person, _) = agent_world::person(&runtime.pool, "owner@example.test").await;
    let org: Uuid = sqlx::query_scalar(
        "insert into organisation(name,created_by) values('Org',$1) returning id",
    )
    .bind(person)
    .fetch_one(owner)
    .await
    .unwrap();
    let installation: Uuid = sqlx::query_scalar("select id from device_authority where singleton")
        .fetch_one(owner)
        .await
        .unwrap();
    let row = Uuid::new_v4();
    let old_server_key = [3u8; 32];
    let sealed = secrets::seal(
        &secrets::legacy_key(&old_server_key),
        installation,
        "organisation_sign_in_provider",
        "secret_sealed",
        row.as_bytes(),
        b"client-secret-value",
    )
    .unwrap();
    sqlx::query("insert into organisation_sign_in_provider(id,organisation_id,slug,kind,display_name,settings,secret_sealed,created_by) values($1,$2,'corp','oidc','Corp','{}',$3,$4)")
        .bind(row)
        .bind(org)
        .bind(&sealed)
        .bind(person)
        .execute(owner)
        .await
        .unwrap();
    let identity_key = [4u8; 32];
    // A wrong source key reads nothing and changes nothing.
    let none = secrets::reseal_all(
        owner,
        &[secrets::legacy_key(&[8; 32])],
        &secrets::identity_key(&identity_key),
    )
    .await
    .unwrap();
    assert_eq!(
        none,
        ResealReport {
            resealed: 0,
            current: 0,
            unreadable: 1
        }
    );
    let report = secrets::reseal_all(
        owner,
        &[secrets::legacy_key(&old_server_key)],
        &secrets::identity_key(&identity_key),
    )
    .await
    .unwrap();
    assert_eq!(
        report,
        ResealReport {
            resealed: 1,
            current: 0,
            unreadable: 0
        }
    );
    let stored: Vec<u8> =
        sqlx::query_scalar("select secret_sealed from organisation_sign_in_provider where id=$1")
            .bind(row)
            .fetch_one(owner)
            .await
            .unwrap();
    // After a rotation of the server key, the secret still opens with the identity key alone.
    let opened = secrets::open(
        &[
            secrets::legacy_key(&[6; 32]),
            secrets::identity_key(&identity_key),
        ],
        installation,
        "organisation_sign_in_provider",
        "secret_sealed",
        row.as_bytes(),
        &stored,
    );
    assert_eq!(opened.as_deref(), Some(&b"client-secret-value"[..]));
    // Running it again is a no-op.
    let again = secrets::reseal_all(owner, &[], &secrets::identity_key(&identity_key))
        .await
        .unwrap();
    assert_eq!(
        again,
        ResealReport {
            resealed: 0,
            current: 1,
            unreadable: 0
        }
    );
}

/// The web tier counts the self-hosted trial from the installation's first start: only the
/// service key reads it, and the runtime login cannot move it.
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_service_reads_the_first_start_and_the_runtime_cannot_move_it(pool: PgPool) {
    let h = Harness::new(pool, |_| {}).await;
    let anonymous = raw(&h.app, "GET", "/internal/installation", None, &[], None).await;
    assert_eq!(anonymous.code(), 403, "{}", anonymous.text());
    let reply = h
        .internal("GET", "/internal/installation", None, Value::Null)
        .await;
    assert_eq!(reply.code(), 200, "{}", reply.text());
    let body = reply.json();
    assert!(body["installation"].as_str().is_some_and(|v| v.len() == 36));
    assert!(chrono::DateTime::parse_from_rfc3339(body["started_at"].as_str().unwrap()).is_ok());
    let moved = sqlx::query("update device_authority set started_at = now()")
        .execute(h.pool())
        .await;
    assert!(
        moved.is_err(),
        "the runtime login must not move the first start"
    );
}
