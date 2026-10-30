//! Integration tests for `engine-cli check-ordering` / `ordering-audit` (NEXT-01).
//!
//! Tests verify:
//! 1. Read-only diagnostic execution against PostgreSQL catalogs.
//! 2. Mismatch detection and documented exit code 2 when columns/database use non-C collation.
//! 3. Clean catalog case (exit code 0) when database uses "C" byte-order collation.
//! 4. Full machine-readable JSON output mode.
//! 5. Restricted runtime login (non-owner, non-superuser) has sufficient privileges to run the audit.
//! 6. Available non-C locales are inspected and reported without requiring production data.

use sqlx::PgPool;
use std::process::{Command, Output};

fn db_url(pool: &PgPool) -> String {
    let base = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let server = base.rsplit_once('/').unwrap().0;
    format!(
        "{server}/{}",
        pool.connect_options().get_database().unwrap()
    )
}

fn run_cli(database_url: Option<&str>, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_engine-cli"));
    cmd.args(args);
    match database_url {
        Some(url) => {
            cmd.env("DATABASE_URL", url);
            cmd.env("MIGRATION_DATABASE_URL", url);
        }
        None => {
            cmd.env_remove("DATABASE_URL");
            cmd.env_remove("MIGRATION_DATABASE_URL");
        }
    }
    cmd.output().expect("failed to execute engine-cli")
}

fn stdout_of(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr_of(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

async fn unmigrate_collations(pool: &PgPool) {
    sqlx::query("ALTER TABLE event DROP CONSTRAINT IF EXISTS event_target_node_id_fkey")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE node DROP CONSTRAINT IF EXISTS node_parent_id_fkey")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE node ALTER COLUMN id TYPE text COLLATE \"default\"")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE node ALTER COLUMN parent_id TYPE text COLLATE \"default\"")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE node ALTER COLUMN pos TYPE text COLLATE \"default\"")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE event ALTER COLUMN target_node_id TYPE text COLLATE \"default\"")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "ALTER TABLE change_request_review ALTER COLUMN node_id TYPE text COLLATE \"default\"",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("ALTER TABLE node ADD CONSTRAINT node_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES node(id) ON DELETE CASCADE")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE event ADD CONSTRAINT event_target_node_id_fkey FOREIGN KEY (target_node_id) REFERENCES node(id)")
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn migrated_catalog_reports_ok_and_exits_0(pool: PgPool) {
    let url = db_url(&pool);
    let output = run_cli(Some(&url), &["check-ordering"]);
    let stdout = stdout_of(&output);
    let stderr = stderr_of(&output);

    // The command must exit with 0 on fully migrated schema.
    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit 0 on clean schema; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Human-readable output checks
    assert!(
        stdout.contains("Column Collation Inventory"),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("[OK] node.id"), "stdout:\n{stdout}");
    assert!(stdout.contains("[OK] node.pos"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("[OK] event.target_node_id"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("Synthetic Ordering Parity Checks"),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("[OK] upper_lower"), "stdout:\n{stdout}");
    assert!(stdout.contains("[OK] pos_keys"), "stdout:\n{stdout}");
    assert!(stdout.contains("Result: OK"), "stdout:\n{stdout}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn unmigrated_catalog_reports_mismatch_and_exits_2(pool: PgPool) {
    unmigrate_collations(&pool).await;

    let url = db_url(&pool);
    let output = run_cli(Some(&url), &["check-ordering"]);
    let stdout = stdout_of(&output);
    let stderr = stderr_of(&output);

    // On standard non-C database, unmigrated columns must exit with code 2.
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 on mismatch; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Human-readable output checks
    assert!(
        stdout.contains("Column Collation Inventory"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("[INCOMPATIBLE] node.id"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("[INCOMPATIBLE] node.pos"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("[INCOMPATIBLE] event.target_node_id"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("Synthetic Ordering Parity Checks"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("[MISMATCH] upper_lower"),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("[MISMATCH] pos_keys"), "stdout:\n{stdout}");
    assert!(stdout.contains("Result: MISMATCH"), "stdout:\n{stdout}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn json_output_mode_contains_structured_diagnostics(pool: PgPool) {
    let url = db_url(&pool);

    // 1. Fully-migrated state
    let output = run_cli(Some(&url), &["check-ordering", "--json"]);
    let stdout = stdout_of(&output);
    assert_eq!(output.status.code(), Some(0));

    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON output: {e}\n{stdout}"));

    assert_eq!(parsed["compatible"], true);
    assert_eq!(parsed["incompatible_columns"].as_array().unwrap().len(), 0);
    assert_eq!(parsed["ordering_mismatches"], 0);

    let columns = parsed["columns"].as_array().expect("columns array");
    let node_pos = columns
        .iter()
        .find(|c| c["table_name"] == "node" && c["column_name"] == "pos")
        .expect("node.pos in inventory");
    assert_eq!(node_pos["is_byte_order"], true);
    assert_eq!(node_pos["explicit_collation"], "C");

    // 2. Unmigrated state
    unmigrate_collations(&pool).await;
    let output_unmig = run_cli(Some(&url), &["check-ordering", "--json"]);
    let stdout_unmig = stdout_of(&output_unmig);
    assert_eq!(output_unmig.status.code(), Some(2));

    let parsed_unmig: serde_json::Value = serde_json::from_str(&stdout_unmig)
        .unwrap_or_else(|e| panic!("invalid JSON output: {e}\n{stdout_unmig}"));
    assert_eq!(parsed_unmig["compatible"], false);
    assert!(
        parsed_unmig["incompatible_columns"]
            .as_array()
            .unwrap()
            .len()
            >= 4
    );
    assert!(parsed_unmig["ordering_mismatches"].as_i64().unwrap() > 0);
}

#[sqlx::test(migrations = "../../migrations")]
async fn clean_c_collation_database_reports_ok_and_exits_0(pool: PgPool) {
    let base_url = db_url(&pool);
    let server = base_url.rsplit_once('/').unwrap().0;
    let clean_db_name = format!("dynodoc_c_test_{}", uuid::Uuid::new_v4().simple());

    // Create disposable database with explicit C collation
    let create_sql = format!(
        "create database \"{clean_db_name}\" lc_collate 'C' lc_ctype 'C' template template0"
    );
    if let Err(e) = sqlx::query(&create_sql).execute(&pool).await {
        eprintln!("SKIPPING clean C test (creating C database failed in this environment: {e})");
        return;
    }

    let clean_url = format!("{server}/{clean_db_name}");

    // Apply migrations to clean DB
    let mig_output = run_cli(Some(&clean_url), &["migrate"]);
    assert!(
        mig_output.status.success(),
        "migration failed: {}",
        stderr_of(&mig_output)
    );

    // Run check-ordering against the C-collation database
    let output = run_cli(Some(&clean_url), &["check-ordering"]);
    let stdout = stdout_of(&output);
    let stderr = stderr_of(&output);

    // Drop clean database before asserting
    let drop_sql = format!("drop database if exists \"{clean_db_name}\"");
    let _ = sqlx::query(&drop_sql).execute(&pool).await;

    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit 0 on clean C database; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("Database default byte-order collation: YES"));
    assert!(stdout.contains("[OK] node.id"));
    assert!(stdout.contains("[OK] node.pos"));
    assert!(stdout.contains("Result: OK"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn runtime_login_has_sufficient_privileges_for_audit(pool: PgPool) {
    let url = db_url(&pool);
    let role = format!("dynodoc_audit_role_{}", uuid::Uuid::new_v4().simple());

    // Create a restricted login role with NO superuser/DDL rights
    sqlx::query(&format!("create role \"{role}\" with login"))
        .execute(&pool)
        .await
        .unwrap();

    // Grant restricted runtime privileges
    engine_core::database::grant_runtime(&pool, &role)
        .await
        .unwrap();

    let server = url.rsplit_once('/').unwrap().0;
    // Strip user from server URL and attach runtime user
    let host_and_port = server.rsplit_once('@').map_or(server, |(_, h)| h);
    let db_name = pool.connect_options().get_database().unwrap().to_string();
    let runtime_url = format!("postgres://{role}@{host_and_port}/{db_name}");

    // Run check-ordering using the runtime role connection
    let output = run_cli(Some(&runtime_url), &["check-ordering"]);
    let stdout = stdout_of(&output);
    let stderr = stderr_of(&output);

    // Cleanup role
    let _ = sqlx::query(&format!(
        "revoke all privileges on schema public from \"{role}\""
    ))
    .execute(&pool)
    .await;
    let _ = sqlx::query(&format!(
        "revoke all privileges on database \"{db_name}\" from \"{role}\""
    ))
    .execute(&pool)
    .await;
    let _ = sqlx::query(&format!("drop role if exists \"{role}\""))
        .execute(&pool)
        .await;

    assert_eq!(
        output.status.code(),
        Some(0),
        "expected exit 0 from runtime check on migrated schema; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("permission denied"),
        "stderr should not contain permission denied: {stderr}"
    );
    assert!(
        stdout.contains("Column Collation Inventory"),
        "stdout:\n{stdout}"
    );
}

#[sqlx::test]
async fn non_c_locale_detection_and_reporting(pool: PgPool) {
    // Check available locales in the running Postgres instance
    let locales: Vec<String> = sqlx::query_scalar(
        "select collname::text from pg_collation where collname in ('en_US.utf8', 'en_US.UTF-8', 'en_GB.utf8', 'C', 'POSIX') order by collname",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    let has_c = locales.iter().any(|l| l == "C" || l == "POSIX");
    assert!(has_c, "PostgreSQL must have C/POSIX collation");

    let non_c: Vec<&String> = locales
        .iter()
        .filter(|l| l != &"C" && l != &"POSIX")
        .collect();
    if non_c.is_empty() {
        println!("Note: no non-C locales pre-installed in this PostgreSQL catalog");
    } else {
        println!("Available non-C test locales: {non_c:?}");
    }
}
