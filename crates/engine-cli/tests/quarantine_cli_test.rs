//! `engine-cli quarantine` and `release`, run with operator credentials.
use std::process::Command;

use sqlx::PgPool;

fn run(url: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_engine-cli"))
        .args(args)
        .env("MIGRATION_DATABASE_URL", url)
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap() + &String::from_utf8(out.stderr).unwrap();
    (out.status.success(), text)
}

async fn paused(pool: &PgPool, doc: uuid::Uuid) -> Option<i64> {
    sqlx::query_scalar("select seq from document_quarantine where document_id=$1")
        .bind(doc)
        .fetch_optional(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn operators_pause_and_release_writes(pool: PgPool) {
    let actor: uuid::Uuid = sqlx::query_scalar(
        "insert into identity(email,display_name) values('operator@example.test','Operator') returning id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let doc: uuid::Uuid = sqlx::query_scalar(
        "insert into document(title,created_by) values('Paused',$1) returning id",
    )
    .bind(actor)
    .fetch_one(&pool)
    .await
    .unwrap();
    // A stand-in for the operator login that may write only the quarantine table.
    let role = format!("operator_{}", uuid::Uuid::new_v4().simple());
    let password = uuid::Uuid::new_v4().simple().to_string();
    sqlx::raw_sql(&format!(
        "create role {role} login password '{password}'; grant select, insert, update, delete on document_quarantine to {role}"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let options = pool.connect_options();
    let url = format!(
        "postgres://{role}:{password}@{}:{}/{}",
        options.get_host(),
        options.get_port(),
        options.get_database().unwrap()
    );
    let id = doc.to_string();

    let (ok, out) = run(
        &url,
        &["quarantine", &id, "--seq", "3", "--reason", "replay fails"],
    );
    assert!(ok, "{out}");
    assert_eq!(paused(&pool, doc).await, Some(3));
    let (ok, out) = run(&url, &["release", &id]);
    assert!(ok, "{out}");
    assert_eq!(paused(&pool, doc).await, None);
    let (ok, out) = run(&url, &["release", &id]);
    assert!(!ok && out.contains("was not quarantined"), "{out}");

    sqlx::raw_sql(&format!("drop owned by {role}; drop role {role}"))
        .execute(&pool)
        .await
        .unwrap();
}
