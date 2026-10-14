//! `engine-cli` verification commands as the restricted runtime login.

use std::process::Command;

use engine_core::log;
use engine_shared::{DocumentId, EventPayload, IdentityId, NodeId, NodeType};
use serde_json::json;
use sqlx::PgPool;

async fn actor(pool: &PgPool) -> IdentityId {
    let id: uuid::Uuid = sqlx::query_scalar(
        "insert into identity(email,display_name) values('cli@example.test','CLI') returning id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    IdentityId(id)
}

/// A document with one root node, written as the API does: event plus node row.
async fn document(pool: &PgPool, actor: IdentityId, title: &str) -> (DocumentId, String) {
    let doc: uuid::Uuid =
        sqlx::query_scalar("insert into document(title,created_by) values($1,$2) returning id")
            .bind(title)
            .bind(actor.0)
            .fetch_one(pool)
            .await
            .unwrap();
    let root = format!("01CLIROOT{}", title.to_uppercase());
    sqlx::query(
        "insert into node(id,document_id,type,pos,current_fields) values($1,$2,'form','a0',$3)",
    )
    .bind(&root)
    .bind(doc)
    .bind(json!({ "title": title }))
    .execute(pool)
    .await
    .unwrap();
    let created = EventPayload::NodeCreated {
        node_id: NodeId(root.clone()),
        node_type: NodeType::Form,
        parent_id: None,
        pos: "a0".into(),
        fields: json!({ "title": title }),
        var_name: None,
    };
    log::append(pool, DocumentId(doc), &created, actor)
        .await
        .unwrap();
    (DocumentId(doc), root)
}

/// A fresh login with the runtime grants, and its database URL.
async fn runtime_login(pool: &PgPool) -> (String, String) {
    let role = format!("verify_cli_{}", uuid::Uuid::new_v4().simple());
    let password = uuid::Uuid::new_v4().simple().to_string();
    sqlx::raw_sql(&format!(
        "create role {role} login password '{password}' nosuperuser nocreatedb nocreaterole noreplication nobypassrls"
    ))
    .execute(pool)
    .await
    .unwrap();
    engine_core::database::grant_runtime(pool, &role)
        .await
        .unwrap();
    let options = pool.connect_options();
    let url = format!(
        "postgres://{role}:{password}@{}:{}/{}",
        options.get_host(),
        options.get_port(),
        options.get_database().unwrap()
    );
    (url, role)
}

async fn drop_login(pool: &PgPool, role: &str) {
    sqlx::raw_sql(&format!("drop owned by {role}; drop role {role}"))
        .execute(pool)
        .await
        .unwrap();
}

fn run(url: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_engine-cli"))
        .args(args)
        .env("DATABASE_URL", url)
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    (out.status.success(), String::from_utf8(out.stdout).unwrap())
}

#[sqlx::test(migrations = "../../migrations")]
async fn all_mode_reports_only_the_drifted_document(pool: PgPool) {
    let actor = actor(&pool).await;
    let (clean, _) = document(&pool, actor, "Clean").await;
    let (drifted, root) = document(&pool, actor, "Drifted").await;
    sqlx::query("update node set pos='zz' where id=$1")
        .bind(&root)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("insert into node(id,document_id,parent_id,type,pos) values('01CLIEXTRA',$1,$2,'item','b0')")
        .bind(drifted.0)
        .bind(&root)
        .execute(&pool)
        .await
        .unwrap();
    let (url, role) = runtime_login(&pool).await;

    let (ok, out) = run(&url, &["verify-projection", "--all"]);
    assert!(!ok, "{out}");
    assert_eq!(
        out.lines().filter(|l| l.starts_with("FAIL:")).count(),
        1,
        "{out}"
    );
    assert!(out.contains(&format!("OK: document {}", clean.0)), "{out}");
    let drift = format!("DIFF: document {} node", drifted.0);
    assert!(
        out.contains(&format!("{drift} {root} pos: replay=\"a0\" table=\"zz\"")),
        "{out}"
    );
    assert!(
        out.contains(&format!("{drift} 01CLIEXTRA row: replay=null")),
        "{out}"
    );
    assert!(run(&url, &["verify-projection", &clean.0.to_string()]).0);

    drop_login(&pool, &role).await;
}
