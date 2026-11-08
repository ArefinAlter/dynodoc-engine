//! The mail outbox (migration 0111) through the real router and the restricted runtime login: only
//! the web tier (service key) queues, claims and reports; a leased message is not claimed twice;
//! a sent or given-up message keeps no content; retries back off; the administrators' view shows
//! no subject or body and is open to auditors, not to people.
mod common;

mod agent_world;
use agent_world::*;

use axum::Router;
use engine_api::{app, auth::AuthConfig, AppState};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const SERVICE: &str = "isolated-mail-outbox-test-service-key-0001";

struct Harness {
    app: Router,
    runtime: common::RuntimeDatabase,
}

impl Harness {
    async fn new(pool: PgPool) -> Self {
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
        Self {
            app: app(state),
            runtime,
        }
    }
    async fn internal(&self, uri: &str, body: Value) -> Reply {
        raw(
            &self.app,
            "POST",
            uri,
            None,
            &[("x-dynodoc-service-key", SERVICE)],
            Some(body),
        )
        .await
    }
    async fn queue(&self, to: &str) -> Uuid {
        let reply = self
            .internal(
                "/internal/mail/outbox",
                json!({"kind": "invitation", "to": to, "subject": "Ana added you to Example", "text": "Open it: https://docs.example.test/x", "html": "<p>Open it</p>"}),
            )
            .await;
        assert_eq!(reply.code(), 200, "{}", reply.text());
        serde_json::from_value(reply.json()["id"].clone()).unwrap()
    }
    async fn claim(&self, limit: i64) -> Vec<Value> {
        let reply = self
            .internal(
                "/internal/mail/outbox/claim",
                json!({"limit": limit, "lease_seconds": 60}),
            )
            .await;
        assert_eq!(reply.code(), 200, "{}", reply.text());
        reply.json()["items"].as_array().unwrap().clone()
    }
    async fn report(&self, id: Uuid, body: Value) -> Reply {
        self.internal(&format!("/internal/mail/outbox/{id}/result"), body)
            .await
    }
    async fn row(&self, id: Uuid) -> (String, String, String, i32, bool, bool) {
        sqlx::query_as("select subject,text_body,html_body,attempts,sent_at is not null,failed_at is not null from mail_outbox where id=$1")
            .bind(id)
            .fetch_one(&self.runtime.pool)
            .await
            .unwrap()
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_the_web_tier_queues_claims_and_reports(pool: PgPool) {
    let h = Harness::new(pool).await;
    let id = h.queue("bea@example.test").await;
    let (_, person_login) = person(&h.runtime.pool, "bea@example.test").await;
    for (uri, body) in [
        (
            "/internal/mail/outbox".to_string(),
            json!({"kind": "notice", "to": "x@example.test", "subject": "s", "text": "t", "html": "h"}),
        ),
        (
            "/internal/mail/outbox/claim".into(),
            json!({"limit": 5, "lease_seconds": 60}),
        ),
        (
            format!("/internal/mail/outbox/{id}/result"),
            json!({"ok": true}),
        ),
    ] {
        let none = raw(&h.app, "POST", &uri, None, &[], Some(body.clone())).await;
        assert_eq!(none.code(), 403, "{uri}");
        let wrong = raw(
            &h.app,
            "POST",
            &uri,
            None,
            &[(
                "x-dynodoc-service-key",
                "not-the-service-key-but-long-enough-0000",
            )],
            Some(body.clone()),
        )
        .await;
        assert_eq!(wrong.code(), 403, "{uri}");
        let login = raw(&h.app, "POST", &uri, Some(&person_login), &[], Some(body)).await;
        assert_eq!(
            login.code(),
            403,
            "{uri}: a person's login is not the service key"
        );
    }
    // A sign-in link is never queued, nor mail to a reserved address, nor a header line break.
    for body in [
        json!({"kind": "sign_in", "to": "a@example.test", "subject": "Your link", "text": "t", "html": "h"}),
        json!({"kind": "notice", "to": "svc-ci@service.invalid", "subject": "s", "text": "t", "html": "h"}),
        json!({"kind": "notice", "to": "agent+x@agents.invalid", "subject": "s", "text": "t", "html": "h"}),
        json!({"kind": "notice", "to": "a@example.test", "subject": "s\r\nBcc: x@evil.test", "text": "t", "html": "h"}),
        json!({"kind": "notice", "to": "a@example.test", "subject": "s", "text": "t".repeat(300_000), "html": "h"}),
    ] {
        let refused = h.internal("/internal/mail/outbox", body.clone()).await;
        assert_eq!(refused.code(), 400, "{body}");
    }
    let queued: i64 = sqlx::query_scalar("select count(*) from mail_outbox")
        .fetch_one(&h.runtime.pool)
        .await
        .unwrap();
    assert_eq!(queued, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_leased_message_is_claimed_once_and_a_sent_one_keeps_no_content(pool: PgPool) {
    let h = Harness::new(pool).await;
    let first = h.queue("a@example.test").await;
    let second = h.queue("b@example.test").await;
    let one = h.claim(1).await;
    assert_eq!(one.len(), 1);
    assert_eq!(one[0]["id"], json!(first));
    assert_eq!(one[0]["attempts"], 1);
    assert_eq!(one[0]["to"], "a@example.test");
    // The leased one is not handed out again; the other is.
    let rest = h.claim(20).await;
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0]["id"], json!(second));
    assert!(h.claim(20).await.is_empty());

    let sent = h.report(first, json!({"ok": true})).await;
    assert_eq!(sent.code(), 200, "{}", sent.text());
    assert_eq!(sent.json()["state"], "sent");
    let (subject, text, html, _, is_sent, _) = h.row(first).await;
    assert!(is_sent);
    assert_eq!(
        (subject.as_str(), text.as_str(), html.as_str()),
        ("", "", "")
    );
    // Reported once: a second report, or one for a message nobody leased, is unknown.
    assert_eq!(h.report(first, json!({"ok": true})).await.code(), 404);
    let unleased = h.queue("c@example.test").await;
    assert_eq!(h.report(unleased, json!({"ok": true})).await.code(), 404);
    // An expired lease makes the message due again.
    sqlx::query("update mail_outbox set lease_until=now()-interval '1 second' where id=$1")
        .bind(second)
        .execute(&h.runtime.owner)
        .await
        .unwrap();
    let again = h.claim(20).await;
    let ids: Vec<&Value> = again.iter().map(|i| &i["id"]).collect();
    assert!(ids.contains(&&json!(second)));
    assert_eq!(
        again.iter().find(|i| i["id"] == json!(second)).unwrap()["attempts"],
        2
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn failures_back_off_and_permanent_or_repeated_ones_are_given_up(pool: PgPool) {
    let h = Harness::new(pool).await;
    let id = h.queue("a@example.test").await;
    assert_eq!(h.claim(1).await.len(), 1);
    let bad_class = h
        .report(id, json!({"ok": false, "error_class": "Timeout: 10.0.0.1"}))
        .await;
    assert_eq!(bad_class.code(), 400, "an error class carries no free text");
    let retry = h
        .report(id, json!({"ok": false, "error_class": "timeout"}))
        .await;
    assert_eq!(retry.code(), 200, "{}", retry.text());
    assert_eq!(retry.json()["state"], "queued");
    let wait: f64 = sqlx::query_scalar(
        "select extract(epoch from next_attempt_at-now())::float8 from mail_outbox where id=$1",
    )
    .bind(id)
    .fetch_one(&h.runtime.pool)
    .await
    .unwrap();
    assert!(
        (100.0..=121.0).contains(&wait),
        "first retry after two minutes: {wait}"
    );
    assert!(h.claim(20).await.is_empty(), "not due yet");
    let (subject, ..) = h.row(id).await;
    assert!(
        !subject.is_empty(),
        "a message waiting for a retry keeps its content"
    );

    // The eighth attempt that fails gives it up, content cleared.
    sqlx::query("update mail_outbox set next_attempt_at=now(),attempts=7 where id=$1")
        .bind(id)
        .execute(&h.runtime.owner)
        .await
        .unwrap();
    assert_eq!(h.claim(1).await.len(), 1);
    let gone = h
        .report(id, json!({"ok": false, "error_class": "timeout"}))
        .await;
    assert_eq!(gone.json()["state"], "failed");
    let (subject, text, html, attempts, sent, failed) = h.row(id).await;
    assert_eq!((attempts, sent, failed), (8, false, true));
    assert_eq!(
        (subject.as_str(), text.as_str(), html.as_str()),
        ("", "", "")
    );

    // A permanent refusal is given up at once.
    let other = h.queue("b@example.test").await;
    assert_eq!(h.claim(1).await.len(), 1);
    let permanent = h
        .report(
            other,
            json!({"ok": false, "permanent": true, "error_class": "rejected"}),
        )
        .await;
    assert_eq!(permanent.json()["state"], "failed");
    assert!(h.claim(20).await.is_empty());
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_administrators_view_shows_states_and_never_content(pool: PgPool) {
    let h = Harness::new(pool).await;
    let pool = h.runtime.pool.clone();
    let (_, admin) = person(&pool, "admin@example.test").await;
    let (auditor_id, auditor) = person(&pool, "audit@example.test").await;
    let (_, someone) = person(&pool, "someone@example.test").await;
    let sent = h.queue("a@example.test").await;
    h.queue("b@other.test").await;
    h.claim(1).await;
    h.report(sent, json!({"ok": true})).await;

    assert_eq!(
        get(&h.app, "/admin/mail-outbox", &someone).await.code(),
        403
    );
    assert_eq!(
        get(&h.app, "/admin/mail-outbox", &auditor).await.code(),
        403
    );
    let granted = raw(
        &h.app,
        "PUT",
        &format!("/admin/instance-roles/{auditor_id}"),
        Some(&admin),
        &[],
        Some(json!({"role": "auditor", "granted": true})),
    )
    .await;
    assert_eq!(granted.code(), 200, "{}", granted.text());
    for login in [&admin, &auditor] {
        let view = get(&h.app, "/admin/mail-outbox", login).await;
        assert_eq!(view.code(), 200, "{}", view.text());
        let body = view.json();
        assert_eq!(body["counts"]["sent"], 1);
        assert_eq!(body["counts"]["queued"], 1);
        let text = view.text();
        assert!(!text.contains("Ana added you"), "no subject: {text}");
        assert!(!text.contains("Open it"), "no body: {text}");
        assert!(
            !text.contains("a@example.test") && !text.contains("b@other.test"),
            "domain only: {text}"
        );
        let domains: Vec<&str> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["recipient_domain"].as_str().unwrap())
            .collect();
        assert!(domains.contains(&"other.test") && domains.contains(&"example.test"));
    }
}
