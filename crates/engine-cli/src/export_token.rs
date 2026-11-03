//! Private export-carrier CLI: account-authenticated mint, status, resolve and revoke.
//!
//! Tokens are identity carriers, not bearer permissions. Raw tokens are generated
//! securely on the server and only stored as SHA-256 hashes in `export_node_token`.
//! The server's idempotency cache stores replayed responses during its cache window.
//! Carrier files are written with exclusive owner-only permissions (mode 0600 on Unix).
//! Raw tokens are never printed to standard output by default, and carriers are redacted
//! from diagnostics.

use anyhow::{anyhow, ensure, Context};
use clap::{Args, Subcommand};
use engine_api::{
    auth::token,
    export_tokens::{
        CreateExportTokensRequest, ExportDetailsResponse, ExportTokensResponse,
        ResolveExportTokensRequest, ResolveExportTokensResponse, RevokeExportResponse,
        CARRIER_FORMAT, CARRIER_VERSION, MAX_EXPORT_MAPPINGS,
    },
};
use reqwest::{header, Method, Url};
use serde_json::Value;
use std::{
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

#[cfg(test)]
mod tests;

const MAX_CARRIER_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Args, Debug, Clone)]
pub struct Options {
    /// API server URL (e.g. `https://api.dynodoc.com` or `http://127.0.0.1:5548`).
    #[arg(long)]
    pub url: Option<String>,
    /// Path to remote configuration JSON file (with url field).
    #[arg(long, conflicts_with = "url")]
    pub remote: Option<PathBuf>,
    /// Private file containing the account access token.
    #[arg(long, value_name = "PATH", conflicts_with = "token")]
    pub token_file: Option<PathBuf>,
    /// Account access token string (never pass credentials in shared shells).
    #[arg(long, value_name = "TOKEN", conflicts_with = "token_file")]
    pub token: Option<String>,
    /// Device key file: rejected explicitly because export token endpoints require account authentication.
    #[arg(long, value_name = "PATH")]
    pub device_key: Option<PathBuf>,
    /// Synthetic local tests only. HTTPS is required for non-loopback addresses.
    #[arg(long)]
    pub allow_loopback_http: bool,
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Action {
    /// Mint random per-export tokens mapped to nodes and write private carrier.
    Mint {
        /// Document ID (UUID).
        document: Uuid,
        /// Path to write the private versioned carrier JSON (exclusively created, mode 0600).
        #[arg(long)]
        out: PathBuf,
        /// Explicit checked revision in document history (defaults to current head).
        #[arg(long)]
        revision: Option<i64>,
        /// Explicit node ID to map (repeatable; if omitted, maps live nodes at revision).
        #[arg(long = "node", value_name = "NODE_ID")]
        nodes: Vec<String>,
        /// Explicit idempotency key for retries. Never auto-mint after a lost response.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Inspect status and metadata of an export.
    Status {
        /// Document ID (UUID).
        document: Uuid,
        /// Export ID (UUID).
        export_id: Uuid,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Resolve export tokens and/or legacy block IDs to stable node targets.
    Resolve {
        /// Document ID (UUID).
        document: Uuid,
        /// Path to a versioned carrier JSON file to resolve.
        #[arg(long)]
        carrier: Option<PathBuf>,
        /// Export ID (UUID), required if resolving individual tokens without a carrier file.
        #[arg(long)]
        export_id: Option<Uuid>,
        /// Individual export token to resolve (repeatable).
        #[arg(long = "token", value_name = "TOKEN")]
        tokens: Vec<String>,
        /// Legacy node ID to resolve directly (repeatable), preserving spelling.
        #[arg(long = "legacy-id", value_name = "ID")]
        legacy_ids: Vec<String>,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Revoke an export, permanently preventing further token resolution.
    Revoke {
        /// Document ID (UUID).
        document: Uuid,
        /// Explicit export ID (UUID) to revoke.
        export_id: Uuid,
        /// Format output as JSON.
        #[arg(long)]
        json: bool,
    },
}

pub struct Client {
    http: reqwest::Client,
    base: Url,
    authorization: header::HeaderValue,
}

impl Client {
    pub fn new(url_str: &str, token_raw: &str, loopback_ok: bool) -> anyhow::Result<Self> {
        let base = Url::parse(url_str).context("invalid API base URL")?;
        let is_loopback = base.host_str().is_some_and(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        });
        ensure!(
            base.scheme() == "https" || (loopback_ok && is_loopback && base.scheme() == "http"),
            "HTTPS is required (HTTP requires a loopback address and --allow-loopback-http)"
        );
        ensure!(
            base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none(),
            "API URL must not contain credentials, query or fragment"
        );
        ensure!(
            base.path().ends_with('/'),
            "API base URL path must end with a trailing slash"
        );

        let clean_token = token_raw.trim();
        ensure!(
            !clean_token.is_empty()
                && clean_token.len() <= 16384
                && !clean_token.chars().any(char::is_whitespace),
            "invalid bearer token"
        );
        ensure!(
            !token::is_project_device_token(clean_token),
            "export token endpoints require account authentication; project-device tokens are rejected"
        );

        let mut auth_header = header::HeaderValue::from_str(&format!("Bearer {clean_token}"))
            .map_err(|_| anyhow!("invalid bearer token characters"))?;
        auth_header.set_sensitive(true);

        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .user_agent("dynodoc-engine-cli/0.1")
            .build()?;

        Ok(Self {
            http,
            base,
            authorization: auth_header,
        })
    }

    async fn send_json<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<T> {
        let url = self.base.join(path.trim_start_matches('/'))?;
        let mut req = self
            .http
            .request(method, url)
            .header(header::AUTHORIZATION, &self.authorization);

        if let Some(key) = idempotency_key {
            req = req.header("Idempotency-Key", key);
        }

        if let Some(body_val) = body {
            let encoded = serde_json::to_vec(body_val)?;
            req = req
                .header(header::CONTENT_TYPE, "application/json")
                .body(encoded);
        }

        let response = req
            .send()
            .await
            .map_err(|_| anyhow!("remote request failed or timed out at {path}"))?;

        let status = response.status();
        ensure!(
            status.is_success(),
            "remote HTTP {} at {path}; no response body logged",
            status.as_u16()
        );

        let bytes = response
            .bytes()
            .await
            .map_err(|_| anyhow!("failed to read response body from {path}"))?;
        ensure!(
            bytes.len() <= MAX_RESPONSE_BYTES,
            "response exceeds byte limit"
        );

        serde_json::from_slice(&bytes)
            .map_err(|e| anyhow!("failed to parse server JSON response: {e}"))
    }
}

fn read_bounded(path: &Path, cap: usize) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= cap, "input file exceeds byte limit");
    Ok(bytes)
}

fn resolve_api_url(options: &Options) -> anyhow::Result<String> {
    if let Some(ref url) = options.url {
        let mut u = url.clone();
        if !u.ends_with('/') {
            u.push('/');
        }
        return Ok(u);
    }
    if let Some(ref remote_path) = options.remote {
        let bytes = read_bounded(remote_path, 8192)?;
        let val: Value = serde_json::from_slice(&bytes)?;
        let mut u = val
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("remote file missing 'url' field"))?
            .to_string();
        if !u.ends_with('/') {
            u.push('/');
        }
        return Ok(u);
    }
    anyhow::bail!("provide API URL via --url or --remote (or DYNODOC_API_URL environment variable)")
}

fn resolve_account_token(options: &Options) -> anyhow::Result<String> {
    ensure!(
        options.device_key.is_none(),
        "export token endpoints require account authentication; device-only credentials are not accepted"
    );
    if let Some(ref path) = options.token_file {
        let bytes = read_bounded(path, 16384)?;
        let s = String::from_utf8(bytes).context("token file must contain valid UTF-8")?;
        return Ok(s.trim().to_owned());
    }
    if let Some(ref token) = options.token {
        return Ok(token.trim().to_owned());
    }
    anyhow::bail!("provide account credential via --token-file or --token")
}

pub async fn run(options: Options) -> anyhow::Result<()> {
    let url = resolve_api_url(&options)?;
    let token = resolve_account_token(&options)?;
    let client = Client::new(&url, &token, options.allow_loopback_http)?;

    match options.action {
        Action::Mint {
            document,
            out,
            revision,
            nodes,
            idempotency_key,
        } => {
            mint(
                &client,
                document,
                &out,
                revision,
                &nodes,
                idempotency_key.as_deref(),
            )
            .await
        }
        Action::Status {
            document,
            export_id,
            json,
        } => status(&client, document, export_id, json).await,
        Action::Resolve {
            document,
            carrier,
            export_id,
            tokens,
            legacy_ids,
            json,
        } => {
            resolve(
                &client,
                document,
                carrier.as_deref(),
                export_id,
                tokens,
                legacy_ids,
                json,
            )
            .await
        }
        Action::Revoke {
            document,
            export_id,
            json,
        } => revoke(&client, document, export_id, json).await,
    }
}

async fn mint(
    client: &Client,
    document: Uuid,
    out: &Path,
    revision: Option<i64>,
    nodes: &[String],
    idempotency_key: Option<&str>,
) -> anyhow::Result<()> {
    ensure!(
        !out.exists(),
        "output file already exists; will not overwrite: {}",
        out.display()
    );

    let req = CreateExportTokensRequest {
        revision,
        node_ids: if nodes.is_empty() {
            None
        } else {
            Some(nodes.to_vec())
        },
        idempotency_key: idempotency_key.map(|k| k.to_string()),
    };

    let path = format!("documents/{document}/export-tokens");
    let resp: ExportTokensResponse = client
        .send_json(
            Method::POST,
            &path,
            Some(&serde_json::to_value(&req)?),
            idempotency_key,
        )
        .await?;

    // Validate carrier contract on response
    ensure!(
        resp.format == CARRIER_FORMAT,
        "contract failure: server returned unsupported carrier format '{}'",
        resp.format
    );
    ensure!(
        resp.version == CARRIER_VERSION,
        "contract failure: server returned unsupported carrier version {}",
        resp.version
    );
    ensure!(
        resp.document_id == document,
        "contract failure: document mismatch: requested {document}, got {}",
        resp.document_id
    );
    if let Some(rev) = revision {
        ensure!(
            resp.revision == rev,
            "contract failure: revision mismatch: requested {rev}, got {}",
            resp.revision
        );
    }
    if !nodes.is_empty() {
        let mapped_nodes: std::collections::HashSet<&str> =
            resp.mappings.iter().map(|m| m.node_id.as_str()).collect();
        for req_node in nodes {
            ensure!(
                mapped_nodes.contains(req_node.as_str()),
                "contract failure: requested node '{req_node}' not present in export mappings"
            );
        }
    }

    let carrier_bytes = serde_json::to_vec_pretty(&resp)?;
    ensure!(
        carrier_bytes.len() <= MAX_CARRIER_FILE_BYTES,
        "carrier JSON exceeds byte limit"
    );

    crate::private_file::write_new(out, &carrier_bytes)
        .with_context(|| format!("failed to write private carrier file at {}", out.display()))?;

    // Safe stdout: print safe IDs and counts only, never token maps
    println!("Minted export carrier:");
    println!("  Export ID:   {}", resp.export_id);
    println!("  Document ID: {}", resp.document_id);
    println!("  Revision:    {}", resp.revision);
    println!("  Mappings:    {}", resp.mappings.len());
    println!("  Created at:  {}", resp.created_at);
    println!("  Carrier:     {}", out.display());
    println!("Notice: Raw tokens are stored as hashes in document history; carrier written exclusively with private owner-only permissions.");

    Ok(())
}

async fn status(
    client: &Client,
    document: Uuid,
    export_id: Uuid,
    json: bool,
) -> anyhow::Result<()> {
    let path = format!("documents/{document}/export-tokens/{export_id}");
    let details: ExportDetailsResponse = client.send_json(Method::GET, &path, None, None).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&details)?);
    } else {
        println!("Export status:");
        println!("  Export ID:    {}", details.export_id);
        println!("  Document ID:  {}", details.document_id);
        println!("  Revision:     {}", details.revision);
        println!("  Creator:      {}", details.created_by);
        println!("  Created at:   {}", details.created_at);
        if let Some(revoked) = details.revoked_at {
            println!("  Revoked at:   {revoked}");
            println!("  Status:       REVOKED");
        } else {
            println!("  Status:       ACTIVE");
        }
        println!("  Token count:  {}", details.token_count);
    }
    Ok(())
}

async fn resolve(
    client: &Client,
    document: Uuid,
    carrier: Option<&Path>,
    export_id: Option<Uuid>,
    mut tokens: Vec<String>,
    legacy_ids: Vec<String>,
    json: bool,
) -> anyhow::Result<()> {
    let mut resolved_export_id = export_id;

    if let Some(carrier_path) = carrier {
        let bytes = read_bounded(carrier_path, MAX_CARRIER_FILE_BYTES)?;
        let parsed_carrier: ExportTokensResponse = serde_json::from_slice(&bytes)
            .context("failed to parse carrier file as versioned ExportTokensResponse")?;

        ensure!(
            parsed_carrier.format == CARRIER_FORMAT,
            "carrier file has unsupported format '{}'",
            parsed_carrier.format
        );
        ensure!(
            parsed_carrier.version == CARRIER_VERSION,
            "carrier file has unsupported version {}",
            parsed_carrier.version
        );
        ensure!(
            parsed_carrier.document_id == document,
            "carrier document ID mismatch: carrier is for {}, but document is {document}",
            parsed_carrier.document_id
        );

        if let Some(exp_id) = resolved_export_id {
            ensure!(
                exp_id == parsed_carrier.export_id,
                "explicit export ID mismatch with carrier file: {exp_id} != {}",
                parsed_carrier.export_id
            );
        } else {
            resolved_export_id = Some(parsed_carrier.export_id);
        }

        for m in parsed_carrier.mappings {
            tokens.push(m.token);
        }
    }

    let total_count = tokens.len() + legacy_ids.len();
    ensure!(
        total_count <= MAX_EXPORT_MAPPINGS,
        "resolve request exceeds maximum limit of {MAX_EXPORT_MAPPINGS} identifiers"
    );

    if !tokens.is_empty() {
        ensure!(
            resolved_export_id.is_some(),
            "export_id is required to resolve export tokens (provide via --carrier or --export-id)"
        );
    }

    let req = ResolveExportTokensRequest {
        format: Some(CARRIER_FORMAT.to_string()),
        version: Some(CARRIER_VERSION),
        export_id: resolved_export_id,
        tokens,
        legacy_ids,
    };

    let path = format!("documents/{document}/export-tokens/resolve");
    let resp: ResolveExportTokensResponse = client
        .send_json(
            Method::POST,
            &path,
            Some(&serde_json::to_value(&req)?),
            None,
        )
        .await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        println!("Resolved targets ({}):", resp.items.len());
        for item in &resp.items {
            if let Some(ref legacy) = item.legacy_id {
                let status_str = if item.resolved {
                    if item.deleted {
                        "DELETED"
                    } else {
                        "LIVE"
                    }
                } else {
                    "UNRESOLVED"
                };
                let target = item.node_id.as_deref().unwrap_or("<none>");
                println!("  legacy:{legacy} -> {target} [{status_str}]");
            } else {
                let status_str = if item.resolved {
                    if item.deleted {
                        "DELETED"
                    } else {
                        "LIVE"
                    }
                } else {
                    "UNRESOLVED"
                };
                let target = item.node_id.as_deref().unwrap_or("<none>");
                println!("  token:<redacted> -> {target} [{status_str}]");
            }
        }
    }

    Ok(())
}

async fn revoke(
    client: &Client,
    document: Uuid,
    export_id: Uuid,
    json: bool,
) -> anyhow::Result<()> {
    let path = format!("documents/{document}/export-tokens/{export_id}/revoke");
    let resp: RevokeExportResponse = client.send_json(Method::POST, &path, None, None).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        println!("Export revocation:");
        println!("  Export ID: {}", resp.export_id);
        println!("  Revoked:   {}", resp.revoked);
        println!("Notice: Export tokens under this export can no longer be resolved.");
    }
    Ok(())
}
