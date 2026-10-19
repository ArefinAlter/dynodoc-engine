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
    // A stand-in operator login with quarantine access and document-lock privileges.
    let role = format!("operator_{}", uuid::Uuid::new_v4().simple());
    let password = uuid::Uuid::new_v4().simple().to_string();
    sqlx::raw_sql(&format!(
        "create role {role} login password '{password}'; grant select, insert, update, delete on document_quarantine to {role}; grant select, update on document to {role}"
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
    let (ok, out) = run(
        &url,
        &[
            "quarantine",
            &id,
            "--seq",
            "5",
            "--reason",
            "updated reason",
        ],
    );
    assert!(ok, "{out}");
    assert_eq!(paused(&pool, doc).await, Some(5));
    for args in [
        vec!["quarantine", &id, "--seq", "0", "--reason", "invalid"],
        vec!["quarantine", &id, "--seq", "6", "--reason", ""],
    ] {
        let (ok, out) = run(&url, &args);
        assert!(!ok, "{out}");
        assert_eq!(paused(&pool, doc).await, Some(5));
    }
    // A pause must wait for an in-flight writer before reporting success.
    let mut writer = pool.begin().await.unwrap();
    sqlx::query("select id from document where id=$1 for no key update")
        .bind(doc)
        .execute(&mut *writer)
        .await
        .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_engine-cli"))
        .args([
            "quarantine",
            &id,
            "--seq",
            "7",
            "--reason",
            "serialized pause",
        ])
        .env("MIGRATION_DATABASE_URL", &url)
        .env("RUST_LOG", "off")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut blocked = false;
    for _ in 0..100 {
        blocked = sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from pg_stat_activity where usename=$1 and wait_event_type='Lock')",
        )
        .bind(&role)
        .fetch_one(&pool)
        .await
        .unwrap();
        if blocked {
            break;
        }
        assert!(
            command.try_wait().unwrap().is_none(),
            "pause bypassed the document lock"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    writer.commit().await.unwrap();
    let output = command.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(blocked, "pause never waited for the document lock");
    assert_eq!(paused(&pool, doc).await, Some(7));
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
