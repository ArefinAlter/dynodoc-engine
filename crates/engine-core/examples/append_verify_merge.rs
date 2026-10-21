//! Append, verify, and merge using synthetic data in a temporary PostgreSQL database.
//!
//! Set DATABASE_URL to a local disposable PostgreSQL 16 owner with CREATE DATABASE,
//! and DYNODOC_EXAMPLE_DATABASE=disposable. The example creates/migrates its own
//! randomly named database and drops it afterwards, including after an error.
//! cargo run --locked -p engine-core --example append_verify_merge
//! This shows core log primitives, not the API's authorization/projection workflow.

use anyhow::{ensure, Context};
use engine_core::{
    log::{append, verify_chain},
    materializer::apply_payload,
    ops::validate_op,
    snapshot::read_state_at,
    workspace_merge,
};
use engine_shared::{DocumentId, EventPayload, IdentityId, NodeId, NodeType};
use serde_json::json;
use sqlx::{postgres::PgConnectOptions, postgres::PgPoolOptions, PgPool};
use std::{collections::BTreeMap, str::FromStr};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    ensure!(
        std::env::var("DYNODOC_EXAMPLE_DATABASE").as_deref() == Ok("disposable"),
        "set DYNODOC_EXAMPLE_DATABASE=disposable for this synthetic example"
    );
    let url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL must name a local disposable PostgreSQL owner")?;
    let options = PgConnectOptions::from_str(&url)?;
    ensure!(
        matches!(options.get_host(), "127.0.0.1" | "localhost" | "::1"),
        "the example accepts only a loopback PostgreSQL server"
    );
    let owner = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await?;
    let database = format!("dynodoc_example_{}", uuid::Uuid::new_v4().simple());
    // This identifier is generated locally from a UUID, never supplied by a client.
    sqlx::query(&format!("create database {database}"))
        .execute(&owner)
        .await?;
    let result = async {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options.database(&database))
            .await?;
        let result = demonstrate(&pool).await;
        pool.close().await;
        result
    }
    .await;
    let cleanup = sqlx::query(&format!("drop database {database}"))
        .execute(&owner)
        .await;
    owner.close().await;
    if let Err(error) = cleanup {
        return Err(error).context(format!(
            "could not remove synthetic database {database}; example result: {result:?}"
        ));
    }
    result?;
    println!(
        "Verified 3 events; merged 1 independent draft operation; temporary database removed."
    );
    Ok(())
}

async fn demonstrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!("../../migrations").run(pool).await?;
    let actor = IdentityId(
        sqlx::query_scalar("insert into identity(email,display_name) values ('example@example.test','Synthetic example') returning id")
            .fetch_one(pool)
            .await?,
    );
    let document = DocumentId(
        sqlx::query_scalar(
            "insert into document(title,created_by) values ('Synthetic example',$1) returning id",
        )
        .bind(actor.0)
        .fetch_one(pool)
        .await?,
    );
    let root = NodeId(ulid::Ulid::generate().to_string());
    // The event target FK requires a node row. The application normally maintains
    // projections in its write transaction; this example exercises the log only.
    sqlx::query("insert into node(id,document_id,type,pos,current_fields) values ($1,$2,'form','a0','{}'::jsonb)")
        .bind(&root.0)
        .bind(document.0)
        .execute(pool)
        .await?;
    let operations = [
        EventPayload::NodeCreated {
            node_id: root.clone(),
            node_type: NodeType::Form,
            parent_id: None,
            pos: "a0".into(),
            fields: json!({"title":"Original","description":"Original","note":"Base"}),
            var_name: None,
        },
        EventPayload::FieldEdited {
            node_id: root.clone(),
            field: "title".into(),
            value: json!("Team title"),
        },
        EventPayload::FieldEdited {
            node_id: root.clone(),
            field: "description".into(),
            value: json!("Team description"),
        },
    ];
    let mut state = engine_core::materializer::DocumentState::default();
    for (index, operation) in operations.iter().enumerate() {
        validate_op(&state, operation)?;
        let event = append(pool, document, operation, actor).await?;
        ensure!(event.seq == index as i64 + 1, "unexpected event sequence");
        apply_payload(&mut state, operation)?;
    }
    verify_chain(pool, document).await?;
    let mut connection = pool.acquire().await?;
    let base = read_state_at(&mut connection, document, 1).await?.state;
    let team = read_state_at(&mut connection, document, 3).await?.state;
    ensure!(team == state, "verified history did not replay as expected");
    let mut draft = base.clone();
    apply_payload(
        &mut draft,
        &EventPayload::FieldEdited {
            node_id: root.clone(),
            field: "note".into(),
            value: json!("Draft note"),
        },
    )?;
    let plan = workspace_merge::merge(&base, &team, &draft, &BTreeMap::new());
    ensure!(plan.conflicts.is_empty(), "unexpected merge conflict");
    ensure!(plan.ops.len() == 1, "expected exactly one draft operation");
    let mut merged = team;
    for operation in &plan.ops {
        validate_op(&merged, operation)?;
        apply_payload(&mut merged, operation)?;
    }
    ensure!(
        merged.nodes[&root].current_fields
            == json!({"title":"Team title","description":"Team description","note":"Draft note"}),
        "merge failed to retain both sides' independent changes"
    );
    Ok(())
}
