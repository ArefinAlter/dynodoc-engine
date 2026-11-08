//! At-rest envelopes in PgStore (decision 041): with a data key, the stored bytes hold no
//! plaintext and read back as the object; existing rows are sealed by the resumable backfill;
//! another project's data key does not open them. Its own test binary: the configuration is
//! process-wide.
use engine_core::at_rest::{store, Dek, KeyProvider, Purpose, TestKeyProvider, WrapContext, MAGIC};
use engine_core::shared_checkpoint::{
    content, postgres::PgStore, Address, Limits, MemoryStore, ObjectStore,
};
use engine_shared::DocumentId;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

const MARK: &[u8] = b"PLAINTEXT-CANARY-at-rest";

async fn project(pool: &PgPool, who: Uuid, name: &str) -> anyhow::Result<(Uuid, Uuid)> {
    let space: Uuid = sqlx::query_scalar(
        "insert into access_space(name,kind,created_by) values($1,'project',$2) returning id",
    )
    .bind(name)
    .bind(who)
    .fetch_one(pool)
    .await?;
    sqlx::query("insert into project_settings(space_id,description) values($1,'')")
        .bind(space)
        .execute(pool)
        .await?;
    let doc: Uuid = sqlx::query_scalar(
        "insert into document(title,created_by,space_id) values('At rest',$1,$2) returning id",
    )
    .bind(who)
    .bind(space)
    .fetch_one(pool)
    .await?;
    Ok((space, doc))
}

/// A content chunk: the object format whose bytes carry the text as written.
async fn object(text: &[u8]) -> (Address, Vec<u8>) {
    let mut memory = MemoryStore::default();
    let (root, _) = content::write(
        &mut memory,
        DocumentId(Uuid::nil()),
        &mut &text[..],
        Limits::default(),
    )
    .await
    .expect("chunk");
    let bytes = memory
        .objects()
        .find(|(a, _)| **a == root)
        .expect("root")
        .1
        .to_vec();
    (root, bytes)
}

#[sqlx::test(migrations = "../../migrations")]
async fn objects_are_sealed_at_rest_backfilled_and_bound_to_their_project(
    pool: PgPool,
) -> anyhow::Result<()> {
    let installation: Uuid = sqlx::query_scalar("select id from device_authority where singleton")
        .fetch_one(&pool)
        .await?;
    let who: Uuid = sqlx::query_scalar(
        "insert into identity(email,display_name) values('at-rest@example.test','At rest') returning id",
    )
    .fetch_one(&pool)
    .await?;
    let (p1, d1) = project(&pool, who, "One").await?;
    let (_p2, d2) = project(&pool, who, "Two").await?;

    // A row written before at-rest encryption: plaintext.
    let (old_addr, old_bytes) = object(&[MARK, b" old"].concat()).await;
    {
        let mut tx = pool.begin().await?;
        PgStore::new(&mut tx)
            .put(DocumentId(d1), &old_addr, &old_bytes)
            .await?;
        tx.commit().await?;
    }

    let provider: Arc<dyn KeyProvider> = Arc::new(TestKeyProvider::new([(1, [9; 32])]));
    let kms: Uuid = sqlx::query_scalar(
        "insert into kms_key(provider,key_ref,purpose) values('file','test','data') returning id",
    )
    .fetch_one(&pool)
    .await?;
    let wrapped = provider.wrap(
        &Dek::from_bytes([5; 32]),
        &WrapContext::new(installation, Some(p1), Purpose::Data),
    )?;
    sqlx::query(
        "insert into data_key(project_id,kms_key_id,kek_version,wrapped) values($1,$2,$3,$4)",
    )
    .bind(p1)
    .bind(kms)
    .bind(wrapped.kek_version() as i32)
    .bind(wrapped.as_bytes())
    .execute(&pool)
    .await?;
    assert!(
        store::install(store::AtRest::new(installation, provider)),
        "installed once"
    );

    // New writes are envelopes; reads give the object back; dedup still holds.
    let (addr, bytes) = object(&[MARK, b" new"].concat()).await;
    let mut tx = pool.begin().await?;
    let mut s = PgStore::new(&mut tx);
    assert!(s.put(DocumentId(d1), &addr, &bytes).await?);
    assert!(
        !s.put(DocumentId(d1), &addr, &bytes).await?,
        "same object, same envelope"
    );
    assert_eq!(
        s.put_batch(
            DocumentId(d1),
            &[
                (addr.clone(), bytes.clone()),
                (old_addr.clone(), old_bytes.clone())
            ]
        )
        .await?,
        vec![false, false]
    );
    assert_eq!(s.get(DocumentId(d1), &addr).await?, bytes);
    assert_eq!(
        s.get(DocumentId(d1), &old_addr).await?,
        old_bytes,
        "legacy rows still read"
    );
    tx.commit().await?;

    // The backfill seals the legacy row, resumably: a second run finds nothing to do.
    let mut db = pool.acquire().await?;
    let (sealed, next) = store::backfill_step(&mut db, p1, None, 1).await?;
    let (more, _) = store::backfill_step(&mut db, p1, next, 100).await?;
    assert_eq!(sealed + more, 1);
    assert_eq!(store::backfill_step(&mut db, p1, None, 100).await?.0, 0);
    let mut tx = pool.begin().await?;
    assert_eq!(
        PgStore::new(&mut tx).get(DocumentId(d1), &old_addr).await?,
        old_bytes
    );
    tx.rollback().await?;

    // Storage scan: no row of the keyed project holds the marker; every row is an envelope.
    let rows: Vec<Vec<u8>> =
        sqlx::query_scalar("select bytes from checkpoint_object where document_id=$1")
            .bind(d1)
            .fetch_all(&pool)
            .await?;
    assert_eq!(rows.len(), 2);
    for r in &rows {
        assert!(r.starts_with(&MAGIC));
        assert!(!r.windows(MARK.len()).any(|w| w == MARK));
    }

    // A project without a data key keeps plaintext.
    let mut tx = pool.begin().await?;
    PgStore::new(&mut tx)
        .put(DocumentId(d2), &addr, &bytes)
        .await?;
    tx.commit().await?;
    let plain: Vec<u8> =
        sqlx::query_scalar("select bytes from checkpoint_object where document_id=$1")
            .bind(d2)
            .fetch_one(&pool)
            .await?;
    assert_eq!(plain, bytes);

    // An envelope moved to another project's document does not open there.
    sqlx::query("delete from checkpoint_object where document_id=$1")
        .bind(d2)
        .execute(&pool)
        .await
        .ok();
    let envelope = rows[0].clone();
    let address: String = sqlx::query_scalar(
        "select address from checkpoint_object where document_id=$1 and bytes=$2",
    )
    .bind(d1)
    .bind(&envelope)
    .fetch_one(&pool)
    .await?;
    let mut db = pool.acquire().await?;
    assert!(store::open_object(&mut db, d2, &address, envelope)
        .await
        .is_err());

    // The table allows only plaintext to envelope, never back.
    let back = sqlx::query("update checkpoint_object set bytes=$2 where document_id=$1")
        .bind(d1)
        .bind(&bytes)
        .execute(&pool)
        .await;
    assert!(back.is_err(), "an envelope never turns back into plaintext");
    Ok(())
}
