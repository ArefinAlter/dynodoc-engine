//! Read-only database collation and SQL ordering diagnostic.
//!
//! Inspects actual PostgreSQL catalog collations for all relational node ID,
//! parent ID, and position (`pos`) columns and references. Compares SQL sorting
//! against native Rust byte order across fixed synthetic test strings without
//! touching or printing any user or document contents.

use anyhow::{Context, Result};
use sqlx::{PgConnection, PgPool};

/// Database-level collation and locale configuration from `pg_database`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DatabaseCollationInfo {
    pub datname: String,
    pub datcollate: String,
    pub datctype: String,
    pub datlocprovider: String,
    pub daticulocale: String,
    pub is_byte_order_default: bool,
}

/// Collation metadata for a specific column in the relational schema.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ColumnCollationInfo {
    pub table_name: String,
    pub column_name: String,
    pub data_type: String,
    pub explicit_collation: Option<String>,
    pub effective_collation: String,
    pub is_byte_order: bool,
}

/// A foreign key constraint reference to `node(id)` or related identifiers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ForeignKeyReference {
    pub constraint_name: String,
    pub source_table: String,
    pub source_column: String,
    pub target_table: String,
    pub target_column: String,
}

/// Diagnostic comparison of SQL ordering vs Rust byte order on a fixed synthetic corpus.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SyntheticOrderingComparison {
    pub category: String,
    pub count: usize,
    pub sql_order: Vec<String>,
    pub rust_byte_order: Vec<String>,
    pub matches: bool,
    pub first_mismatch: Option<(String, String)>,
}

/// Complete diagnostic report of database and column collation ordering parity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OrderingAuditReport {
    pub database: DatabaseCollationInfo,
    pub columns: Vec<ColumnCollationInfo>,
    pub foreign_keys: Vec<ForeignKeyReference>,
    pub comparisons: Vec<SyntheticOrderingComparison>,
    pub compatible: bool,
    pub incompatible_columns: Vec<String>,
    pub ordering_mismatches: usize,
}

/// Known relational columns storing or referencing node IDs or fractional pos keys.
pub const TARGET_COLUMNS: &[(&str, &str)] = &[
    ("node", "id"),
    ("node", "parent_id"),
    ("node", "pos"),
    ("event", "target_node_id"),
    ("change_request_review", "node_id"),
    ("export_node_token", "node_id"),
];

/// Returns true if a PostgreSQL collation name denotes deterministic binary byte order.
pub fn is_byte_order_collation(name: &str) -> bool {
    let norm = name.trim().to_ascii_uppercase();
    matches!(
        norm.as_str(),
        "C" | "\"C\"" | "POSIX" | "\"POSIX\"" | "C.UTF-8" | "C.UTF8" | "UCS_BASIC"
    )
}

/// Fixed synthetic string corpora representing various character classes and boundary keys.
///
/// Under no circumstances do these queries read or output node contents.
pub fn synthetic_test_categories() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "upper_lower",
            vec!["A", "B", "Z", "a", "b", "z", "AA", "Aa", "aA", "aa"],
        ),
        (
            "digits_punctuation",
            vec!["!", "-", ".", "/", "0", "1", "9", ":", "_", "~"],
        ),
        (
            "pos_keys",
            vec![
                "O", "f", "r", "x", "{", "|", "a0", "a0V", "a1", "aO", "ab", "z9",
            ],
        ),
        (
            "legacy_and_node_ids",
            vec![
                "01HABCDEF",
                "01Habcdef",
                "block-1",
                "block-10",
                "block-2",
                "node-01",
                "node:1",
                "node_01",
            ],
        ),
        (
            "mixed_boundary",
            vec![
                "0", "1", "10", "2", "@", "Draft", "_draft", "draft", "~", "\u{007F}",
            ],
        ),
    ]
}

/// Execute read-only ordering audit against the database connection.
pub async fn audit_ordering(pool: &PgPool) -> Result<OrderingAuditReport> {
    let mut conn = pool
        .acquire()
        .await
        .context("acquiring connection for ordering audit failed")?;
    audit_ordering_connection(&mut conn).await
}

/// Execute read-only ordering audit using an explicit connection (compatible with runtime login).
pub async fn audit_ordering_connection(conn: &mut PgConnection) -> Result<OrderingAuditReport> {
    // 1. Inspect database-level collation
    let (datname, datcollate, datctype, datlocprovider, daticulocale): (
        String,
        String,
        String,
        String,
        Option<String>,
    ) = sqlx::query_as(
        "select datname::text, datcollate::text, datctype::text,
                datlocprovider::text, daticulocale::text
         from pg_database
         where datname = current_database()",
    )
    .fetch_one(&mut *conn)
    .await
    .context("querying pg_database collation failed")?;

    let is_c_default = is_byte_order_collation(&datcollate);
    let db_info = DatabaseCollationInfo {
        datname,
        datcollate: datcollate.clone(),
        datctype,
        datlocprovider,
        daticulocale: daticulocale.unwrap_or_default(),
        is_byte_order_default: is_c_default,
    };

    // 2. Discover foreign key references pointing to node(id) or related tables
    let fks_raw: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "select
             con.conname::text as constraint_name,
             src_rel.relname::text as source_table,
             src_att.attname::text as source_column,
             dst_rel.relname::text as target_table,
             dst_att.attname::text as target_column
         from pg_constraint con
         join pg_class src_rel on src_rel.oid = con.conrelid
         join pg_class dst_rel on dst_rel.oid = con.confrelid
         join pg_namespace ns on ns.oid = src_rel.relnamespace
         join lateral unnest(con.conkey) with ordinality as k(attnum, ord) on true
         join lateral unnest(con.confkey) with ordinality as fk(attnum, ord) on k.ord = fk.ord
         join pg_attribute src_att on src_att.attrelid = src_rel.oid and src_att.attnum = k.attnum
         join pg_attribute dst_att on dst_att.attrelid = dst_rel.oid and dst_att.attnum = fk.attnum
         where con.contype = 'f'
           and ns.nspname = 'public'
           and (
             dst_rel.relname = 'node'
             or src_rel.relname in ('node', 'event', 'change_request_review', 'export_node_token')
           )
         order by src_rel.relname, src_att.attname",
    )
    .fetch_all(&mut *conn)
    .await
    .context("querying foreign key references failed")?;

    let mut foreign_keys = Vec::with_capacity(fks_raw.len());
    let mut inventory: Vec<(String, String)> = TARGET_COLUMNS
        .iter()
        .map(|(t, c)| (t.to_string(), c.to_string()))
        .collect();

    for (cname, stable, scol, ttable, tcol) in fks_raw {
        if !inventory.iter().any(|(t, c)| t == &stable && c == &scol) {
            inventory.push((stable.clone(), scol.clone()));
        }
        foreign_keys.push(ForeignKeyReference {
            constraint_name: cname,
            source_table: stable,
            source_column: scol,
            target_table: ttable,
            target_column: tcol,
        });
    }

    // 3. Inspect actual column collations
    let mut columns = Vec::new();
    let mut incompatible_columns = Vec::new();

    for (tbl, col) in &inventory {
        let col_info: Option<(String, String, String, Option<String>)> = sqlx::query_as(
            "select
                 cl.relname::text,
                 att.attname::text,
                 format_type(att.atttypid, att.atttypmod)::text,
                 coll.collname::text
             from pg_attribute att
             join pg_class cl on cl.oid = att.attrelid
             join pg_namespace ns on ns.oid = cl.relnamespace
             left join pg_collation coll on coll.oid = att.attcollation
             where ns.nspname = 'public'
               and cl.relname = $1
               and att.attname = $2
               and att.attnum > 0
               and not att.attisdropped",
        )
        .bind(tbl)
        .bind(col)
        .fetch_optional(&mut *conn)
        .await
        .with_context(|| format!("querying column collation for {tbl}.{col} failed"))?;

        if let Some((_t, _c, data_type, explicit_coll)) = col_info {
            // Only text and character string types are subject to collation and ordering semantics
            let dt_lower = data_type.to_ascii_lowercase();
            if !dt_lower.contains("text")
                && !dt_lower.contains("char")
                && !dt_lower.contains("varchar")
            {
                continue;
            }

            let (effective_coll, is_byte_order) = match explicit_coll.as_deref() {
                Some("default") | None => {
                    (format!("database default ({datcollate})"), is_c_default)
                }
                Some(ec) => (ec.to_string(), is_byte_order_collation(ec)),
            };
            if !is_byte_order {
                incompatible_columns.push(format!("{tbl}.{col} (effective: {effective_coll})"));
            }
            columns.push(ColumnCollationInfo {
                table_name: tbl.clone(),
                column_name: col.clone(),
                data_type,
                explicit_collation: explicit_coll,
                effective_collation: effective_coll,
                is_byte_order,
            });
        }
    }

    // 4. Compare SQL default ordering vs native Rust byte order on synthetic test cases
    let mut comparisons = Vec::new();
    let mut ordering_mismatches = 0;

    for (category, items) in synthetic_test_categories() {
        let mut rust_sorted = items.clone();
        rust_sorted.sort_unstable();

        let rows: Vec<String> =
            sqlx::query_scalar("select s::text from unnest($1::text[]) as s order by s")
                .bind(&items)
                .fetch_all(&mut *conn)
                .await
                .with_context(|| format!("testing ordering for category {category} failed"))?;

        let matches = rows == rust_sorted;
        let mut first_mismatch = None;
        if !matches {
            ordering_mismatches += 1;
            for i in 0..rows.len().min(rust_sorted.len()) {
                if rows[i] != rust_sorted[i] {
                    first_mismatch = Some((rows[i].clone(), rust_sorted[i].to_string()));
                    break;
                }
            }
        }

        comparisons.push(SyntheticOrderingComparison {
            category: category.to_string(),
            count: items.len(),
            sql_order: rows,
            rust_byte_order: rust_sorted.into_iter().map(|s| s.to_string()).collect(),
            matches,
            first_mismatch,
        });
    }

    let compatible = incompatible_columns.is_empty() && ordering_mismatches == 0;

    Ok(OrderingAuditReport {
        database: db_info,
        columns,
        foreign_keys,
        comparisons,
        compatible,
        incompatible_columns,
        ordering_mismatches,
    })
}
