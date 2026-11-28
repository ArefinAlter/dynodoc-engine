//! Wire DTOs and constants for the document export-token endpoints.
//!
//! Kept in `engine-shared` so both `engine-api` and standalone clients (`dynodoc-cli`)
//! share the exact request/response schema without pulling Axum or Postgres into clients.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CARRIER_FORMAT: &str = "dynodoc.export-node-tokens";
pub const CARRIER_VERSION: u32 = 1;
pub const MAX_EXPORT_MAPPINGS: usize = 10_000;

#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CreateExportTokensRequest {
    /// Checked revision (sequence number) in document history. Omitted means current head.
    #[serde(default)]
    pub revision: Option<i64>,
    /// Specific node IDs to map. Omitted means all live (non-deleted) nodes at this revision.
    #[serde(default)]
    pub node_ids: Option<Vec<String>>,
    /// Creator-scoped idempotency key if not sent via Idempotency-Key header.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ExportTokenMapping {
    pub node_id: String,
    pub token: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ExportTokensResponse {
    pub format: String,
    pub version: u32,
    pub export_id: Uuid,
    pub document_id: Uuid,
    pub revision: i64,
    pub created_at: DateTime<Utc>,
    pub mappings: Vec<ExportTokenMapping>,
}

#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ResolveExportTokensRequest {
    /// Versioned carrier format ("dynodoc.export-node-tokens").
    #[serde(default)]
    pub format: Option<String>,
    /// Carrier format version (1).
    #[serde(default)]
    pub version: Option<u32>,
    /// Export ID under which tokens were minted. Required when resolving export tokens.
    #[serde(default)]
    pub export_id: Option<Uuid>,
    /// Export tokens to resolve to node IDs.
    #[serde(default)]
    pub tokens: Vec<String>,
    /// Legacy node IDs to resolve directly, preserving spelling.
    #[serde(default)]
    pub legacy_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ResolvedNodeTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_id: Option<String>,
    pub node_id: Option<String>,
    pub deleted: bool,
    pub resolved: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ResolveExportTokensResponse {
    pub document_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_id: Option<Uuid>,
    pub items: Vec<ResolvedNodeTarget>,
}

#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RevokeExportResponse {
    pub revoked: bool,
    pub export_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ExportDetailsResponse {
    pub export_id: Uuid,
    pub document_id: Uuid,
    pub revision: i64,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub token_count: i64,
}
