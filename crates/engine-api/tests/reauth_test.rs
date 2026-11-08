//! Re-authentication for sensitive actions (docs/decisions/043-platform-third-part.md section 1),
//! against a real PostgreSQL, the real router and the restricted runtime login: erasing,
//! sign-in settings, SCIM tokens and service-account enrolment logins need a person's login made
//! within `REAUTH_MAX_AGE_SECONDS`. A refresh does not renew it, a legacy token without a login
//! record never has it, and agent, device-session and service-account credentials never satisfy it.
mod common;

mod agent_world;
use agent_world::*;

use axum::Router;
use engine_api::{app, auth::AuthConfig, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const SERVICE: &str = "isolated-reauth-test-service-key";

async fn login(app: &Router, email: &str) -> Value {
    let link = raw(
        app,
        "POST",
        "/auth/magic-link",
        None,
        &[("x-dynodoc-service-key", SERVICE)],
        Some(json!({"email": email})),
    )
    .await;
    assert_eq!(link.code(), 200, "{}", link.text());
    let tokens = raw(
        app,
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

fn access(tokens: &Value) -> String {
    tokens["access_token"].as_str().unwrap().to_owned()
}

/// Every sensitive request, with a body each handler accepts up to the re-authentication check.
fn sensitive(org: Uuid) -> Vec<(&'static str, String, Value)> {
    let nobody = Uuid::new_v4();
    vec![
        (
            "POST",
            "/admin/erase".into(),
            json!({"kind":"documents","id":nobody,"confirmation":"x","revision":"x","reason":"other","acknowledge_backups":true}),
        ),
        (
            "POST",
            "/admin/erase-batch".into(),
            json!({"ids":[nobody],"confirmation":"DELETE 1 DOCUMENT","reason":"other","acknowledge_backups":true}),
        ),
        (
            "PUT",
            format!("/organisations/{org}/sign-in/settings"),
            json!({"revision":0}),
        ),
        (
            "PUT",
            format!("/organisations/{org}/sign-in/providers/corp"),
            json!({"kind":"oidc","display_name":"Corp","settings":{},"revision":0}),
        ),
        (
            "DELETE",
            format!("/organisations/{org}/sign-in/providers/corp"),
            Value::Null,
        ),
        (
            "POST",
            format!("/organisations/{org}/domains"),
            json!({"domain":"example.test"}),
        ),
        (
            "DELETE",
            format!("/organisations/{org}/domains/example.test"),
            Value::Null,
        ),
        (
            "PUT",
            format!("/organisations/{org}/sign-in/options"),
            json!({}),
        ),
        (
            "POST",
            format!("/organisations/{org}/scim-tokens"),
            json!({"label":"directory"}),
        ),
        (
            "POST",
            format!("/admin/organisations/{org}/scim-tokens"),
            json!({"label":"directory"}),
        ),
        (
            "POST",
            format!("/organisations/{org}/scim-tokens/{nobody}/rotate"),
            Value::Null,
        ),
        (
            "POST",
            format!("/admin/service-accounts/{nobody}/enrolment-login"),
            Value::Null,
        ),
    ]
}

async fn send(app: &Router, method: &str, uri: &str, token: &str, body: &Value) -> Reply {
    raw(
        app,
        method,
        uri,
        Some(token),
        &[],
        (!body.is_null()).then(|| body.clone()),
    )
    .await
}

fn reauth(reply: &Reply) -> bool {
    reply.code() == 403 && reply.json()["code"] == "reauth_required"
}

#[sqlx::test(migrations = "../../migrations")]
async fn sensitive_actions_need_a_fresh_login_of_a_person(pool: PgPool) {
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
    state.reauth_seconds = 600;
    state.agent_gateway = true;
    let cache = state.agent_cache.clone();
    let app = app(state);

    // The administrator owns an organisation (made with a plain token: creating one is not
    // sensitive) and a project agents may read.
    let (admin, legacy) = person(&runtime.pool, "admin@example.test").await;
    let (status, org) = call(
        &app,
        "POST",
        "/organisations",
        Some(&legacy),
        json!({"name":"Org"}),
    )
    .await;
    assert_eq!(status.as_u16(), 201, "{org}");
    let org: Uuid = serde_json::from_value(org["id"].clone()).unwrap();
    let (status, project) = call(
        &app,
        "POST",
        "/projects",
        Some(&legacy),
        json!({"name":"Policy"}),
    )
    .await;
    assert_eq!(status.as_u16(), 200, "{project}");

    // A fresh emailed-link login passes the check on every route (whatever the route then says).
    let fresh = login(&app, "admin@example.test").await;
    for (method, uri, body) in sensitive(org) {
        let reply = send(&app, method, &uri, &access(&fresh), &body).await;
        assert!(
            !reauth(&reply),
            "{method} {uri}: a fresh login is refused: {}",
            reply.text()
        );
    }

    // Twenty minutes later every route asks for a sign-in, and a refresh does not renew it.
    sqlx::query(
        "update login_session set started_at=now()-interval '20 minutes' where identity_id=$1",
    )
    .bind(admin)
    .execute(&runtime.owner)
    .await
    .unwrap();
    let refreshed = raw(
        &app,
        "POST",
        "/auth/refresh",
        None,
        &[],
        Some(json!({"refresh_token": fresh["refresh_token"]})),
    )
    .await;
    assert_eq!(refreshed.code(), 200, "{}", refreshed.text());
    for token in [access(&fresh), access(&refreshed.json())] {
        for (method, uri, body) in sensitive(org) {
            let reply = send(&app, method, &uri, &token, &body).await;
            assert!(
                reauth(&reply),
                "{method} {uri}: a stale login passes: {}",
                reply.text()
            );
            assert_eq!(reply.json()["details"]["max_age_seconds"], 600);
        }
    }
    // An identity provider's old auth_time is not a fresh sign-in, even in a new Dynodoc login.
    let sso = login(&app, "admin@example.test").await;
    sqlx::query("update login_session set auth_time=now()-interval '2 hours' where session_id=(select session_id from login_session where identity_id=$1 order by started_at desc limit 1)")
        .bind(admin)
        .execute(&runtime.owner)
        .await
        .unwrap();
    let (method, uri, body) = &sensitive(org)[2];
    assert!(reauth(&send(&app, method, uri, &access(&sso), body).await));
    // A token without a login record never qualifies.
    for (method, uri, body) in sensitive(org) {
        assert!(
            reauth(&send(&app, method, &uri, &legacy, &body).await),
            "{method} {uri}: legacy token"
        );
    }

    // A service account's enrolment login, even as an organisation owner, never qualifies.
    let again = login(&app, "admin@example.test").await;
    let made = send(
        &app,
        "POST",
        "/admin/service-accounts",
        &access(&again),
        &json!({"name":"ci-export"}),
    )
    .await;
    assert_eq!(made.code(), 201, "{}", made.text());
    let svc = made.json()["id"].as_str().unwrap().to_owned();
    let enrolment = send(
        &app,
        "POST",
        &format!("/admin/service-accounts/{svc}/enrolment-login"),
        &access(&again),
        &Value::Null,
    )
    .await;
    assert_eq!(enrolment.code(), 200, "{}", enrolment.text());
    let service = access(&enrolment.json());
    let (status, own) = call(
        &app,
        "POST",
        "/organisations",
        Some(&service),
        json!({"name":"Bots"}),
    )
    .await;
    if status.as_u16() == 201 {
        let own: Uuid = serde_json::from_value(own["id"].clone()).unwrap();
        for (method, uri, body) in sensitive(own).into_iter().skip(2).take(7) {
            let reply = send(&app, method, &uri, &service, &body).await;
            assert!(
                reauth(&reply),
                "{method} {uri}: a service login passes: {}",
                reply.text()
            );
        }
    }
    for (method, uri, body) in sensitive(org) {
        let reply = send(&app, method, &uri, &service, &body).await;
        assert!(
            matches!(reply.code(), 401 | 403),
            "{method} {uri}: {}",
            reply.text()
        );
    }

    // An agent's device session is refused by every sensitive route.
    let world = World {
        app: app.clone(),
        runtime,
        cache,
        owner_login: legacy.clone(),
        owner: admin,
        project: serde_json::from_value(project["id"].clone()).unwrap(),
    };
    world.enable_agents(world.project).await;
    let (_, agent) = world.owner_reader().await;
    for (method, uri, body) in sensitive(org) {
        let reply = send(&app, method, &uri, &agent, &body).await;
        assert!(
            matches!(reply.code(), 401 | 403),
            "{method} {uri}: an agent passes: {}",
            reply.text()
        );
        assert!(!reply.text().contains("\"ok\":true"));
    }
}
