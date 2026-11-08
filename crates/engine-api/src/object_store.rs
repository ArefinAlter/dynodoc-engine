//! Where the bytes of original files (`document_upload`) and editor images (`connector_media`)
//! live (roadmap Q16 default: S3-compatible with a local filesystem driver; decision 037).
//!
//! `DYNODOC_OBJECT_STORE`:
//!
//! - `database` (the default): in the row, as before. Nothing else changes.
//! - `filesystem`: files under `DYNODOC_OBJECT_DIR` (must exist). Back it up with the database.
//! - `s3`: an S3-compatible bucket (`S3_ENDPOINT`, `S3_BUCKET`, `S3_REGION`, `S3_PREFIX`,
//!   `S3_PATH_STYLE`, `S3_ACCESS_KEY_ID(_FILE)`, `S3_SECRET_ACCESS_KEY(_FILE)`), signed with AWS
//!   Signature Version 4 over the payload's SHA-256 (never `UNSIGNED-PAYLOAD`).
//!
//! Keys are made only here, from ids and digests ([`original_key`], [`media_key`]), and every
//! driver refuses any other shape ([`valid_key`]), so no key can name a path outside its prefix.
//! The database also ties each key to its row (migration 0113). Rows written before a switch
//! keep their bytes in the database and are still read from there. A row's SHA-256 is checked on
//! every read from a store: bytes that do not match are never served.

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use ring::hmac;
use uuid::Uuid;

use crate::secrets::{self, Lookup, Secret};

/// What can go wrong with a stored object. Messages name no key, path or credential.
#[derive(Debug, thiserror::Error)]
pub enum ObjectError {
    #[error("object key refused")]
    InvalidKey,
    #[error("object path is not a plain directory under the store root")]
    UnsafePath,
    #[error("object not found")]
    NotFound,
    #[error("object does not match its digest")]
    Integrity,
    #[error("object store input/output failed: {0}")]
    Io(std::io::ErrorKind),
    #[error("object store answered {0}")]
    Status(u16),
    #[error("object store unreachable")]
    Unreachable,
}

/// The configured store.
#[derive(Default)]
pub enum ObjectStore {
    #[default]
    Database,
    Filesystem {
        /// Canonical, existing directory.
        root: PathBuf,
    },
    S3(Box<S3>),
}

/// An S3-compatible bucket.
pub struct S3 {
    /// `scheme://host[:port]`, no path.
    pub endpoint: reqwest::Url,
    pub bucket: String,
    pub region: String,
    /// Empty, or ends with `/`.
    pub prefix: String,
    pub path_style: bool,
    pub access_key: Secret,
    pub secret: Secret,
    client: reqwest::Client,
}

/// The key of an original file: `originals/<document>/<upload id without dashes>`.
pub fn original_key(document: Uuid, upload: Uuid) -> String {
    format!("originals/{document}/{}", upload.simple())
}

/// The key of an editor image: `media/<document>/<sha256 hex>`.
pub fn media_key(document: Uuid, sha256: &[u8]) -> String {
    format!("media/{document}/{}", hex::encode(sha256))
}

/// Exactly the shapes [`original_key`] and [`media_key`] make: lower-case, three segments, a
/// hyphenated document id, 32 or 64 hexadecimal digits. Nothing else, so no `..`, separator,
/// encoding trick or absolute path survives.
pub fn valid_key(key: &str) -> bool {
    let mut parts = key.split('/');
    let (Some(kind), Some(document), Some(name), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let hex = |s: &str, n: usize| {
        s.len() == n
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let document_ok = Uuid::parse_str(document).is_ok_and(|u| u.to_string() == document);
    document_ok
        && match kind {
            "originals" => hex(name, 32),
            "media" => hex(name, 64),
            _ => false,
        }
}

/// SHA-256 of `bytes`.
pub fn digest(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

impl ObjectStore {
    /// Whether bytes go to the row (`database`) rather than to a store.
    pub fn in_database(&self) -> bool {
        matches!(self, Self::Database)
    }

    /// Load the configuration; every problem goes to `problems`. No message holds a secret.
    pub fn load(lookup: Lookup, problems: &mut Vec<String>) -> Self {
        let text = |name: &str| {
            lookup(name)
                .and_then(|v| v.into_string().ok())
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        match text("DYNODOC_OBJECT_STORE").as_deref() {
            None | Some("database") => Self::Database,
            Some("filesystem") => match text("DYNODOC_OBJECT_DIR")
                .map(|d| std::fs::canonicalize(&d))
            {
                Some(Ok(root)) if root.is_dir() => Self::Filesystem { root },
                Some(_) => {
                    problems.push("DYNODOC_OBJECT_DIR must be an existing directory".into());
                    Self::Database
                }
                None => {
                    problems
                        .push("DYNODOC_OBJECT_STORE=filesystem needs DYNODOC_OBJECT_DIR".into());
                    Self::Database
                }
            },
            Some("s3") => match S3::load(lookup, &text, problems) {
                Some(s3) => Self::S3(Box::new(s3)),
                None => Self::Database,
            },
            Some(_) => {
                problems.push("DYNODOC_OBJECT_STORE must be database, filesystem or s3".into());
                Self::Database
            }
        }
    }

    /// Store `bytes` under `key` (whole or not at all).
    pub async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), ObjectError> {
        if !valid_key(key) {
            return Err(ObjectError::InvalidKey);
        }
        match self {
            Self::Database => Err(ObjectError::InvalidKey),
            Self::Filesystem { root } => {
                let (root, key, bytes) = (root.clone(), key.to_owned(), bytes.to_vec());
                blocking(move || fs_put(&root, &key, &bytes)).await
            }
            Self::S3(s3) => s3.send(reqwest::Method::PUT, key, bytes).await.map(drop),
        }
    }

    /// The bytes under `key`, checked against `sha256`.
    pub async fn get(&self, key: &str, sha256: &[u8]) -> Result<Vec<u8>, ObjectError> {
        if !valid_key(key) {
            return Err(ObjectError::InvalidKey);
        }
        let bytes = match self {
            Self::Database => return Err(ObjectError::NotFound),
            Self::Filesystem { root } => {
                let (root, key) = (root.clone(), key.to_owned());
                blocking(move || fs_get(&root, &key)).await?
            }
            Self::S3(s3) => s3.send(reqwest::Method::GET, key, &[]).await?,
        };
        if digest(&bytes) != sha256 {
            tracing::error!("a stored object does not match its digest; it is not served");
            return Err(ObjectError::Integrity);
        }
        Ok(bytes)
    }

    /// Remove `key`; a missing object is not an error.
    pub async fn delete(&self, key: &str) -> Result<(), ObjectError> {
        if !valid_key(key) {
            return Err(ObjectError::InvalidKey);
        }
        match self {
            Self::Database => Ok(()),
            Self::Filesystem { root } => {
                let (root, key) = (root.clone(), key.to_owned());
                blocking(move || fs_delete(&root, &key)).await
            }
            Self::S3(s3) => match s3.send(reqwest::Method::DELETE, key, &[]).await {
                Ok(_) | Err(ObjectError::NotFound) => Ok(()),
                Err(e) => Err(e),
            },
        }
    }
}

/// Delete up to `batch` queued objects an erasure left behind (migration 0140) and drop their
/// rows; a failure is retried later, with a backoff of up to a day. Returns how many it deleted.
pub async fn sweep(
    pool: &sqlx::PgPool,
    store: &ObjectStore,
    batch: i64,
) -> Result<u64, sqlx::Error> {
    // Claimed with a ten-minute lease, so no transaction stays open across store requests and
    // another replica skips what this one works on.
    let due: Vec<String> = sqlx::query_scalar("update object_deletion set next_attempt_at=now()+interval '10 minutes' where storage_key in (select storage_key from object_deletion where next_attempt_at<=now() order by next_attempt_at limit $1 for update skip locked) returning storage_key")
        .bind(batch)
        .fetch_all(pool)
        .await?;
    let mut deleted = 0;
    for key in &due {
        let done = match store.delete(key).await {
            Ok(()) | Err(ObjectError::InvalidKey) => true,
            Err(error) => {
                tracing::warn!(%error, "a queued object could not be deleted; retried later");
                false
            }
        };
        let sql = if done {
            deleted += 1;
            "delete from object_deletion where storage_key=$1"
        } else {
            "update object_deletion set attempts=attempts+1,next_attempt_at=now()+least(interval '1 day',interval '1 minute'*power(2,least(attempts,11))) where storage_key=$1"
        };
        sqlx::query(sql).bind(key).execute(pool).await?;
    }
    Ok(deleted)
}

/// Run [`sweep`] every ten minutes beside the request path, when objects live in a store.
pub fn spawn_sweep(state: crate::AppState) -> Option<tokio::task::JoinHandle<()>> {
    if state.objects.in_database() {
        return None;
    }
    Some(tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
            match sweep(&state.pool, &state.objects, 200).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(objects = n, "erased documents' leftover objects deleted"),
                Err(error) => tracing::warn!(%error, "object deletion sweep failed"),
            }
        }
    }))
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, ObjectError> + Send + 'static,
) -> Result<T, ObjectError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| ObjectError::Io(std::io::ErrorKind::Other))?
}

fn io(error: std::io::Error) -> ObjectError {
    match error.kind() {
        std::io::ErrorKind::NotFound => ObjectError::NotFound,
        kind => ObjectError::Io(kind),
    }
}

/// The path of a valid `key` under `root`, refusing a symbolic link (or anything but a
/// directory) at any level that exists, so nothing outside `root` is ever reached.
fn fs_path(root: &Path, key: &str) -> Result<PathBuf, ObjectError> {
    if !valid_key(key) {
        return Err(ObjectError::InvalidKey);
    }
    let segments: Vec<&str> = key.split('/').collect();
    let mut path = root.to_path_buf();
    for (i, segment) in segments.iter().enumerate() {
        path.push(segment);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(ObjectError::UnsafePath),
            Ok(meta) if i + 1 < segments.len() && !meta.is_dir() => {
                return Err(ObjectError::UnsafePath)
            }
            Ok(meta) if i + 1 == segments.len() && !meta.is_file() => {
                return Err(ObjectError::UnsafePath)
            }
            _ => {}
        }
    }
    Ok(path)
}

fn fs_put(root: &Path, key: &str, bytes: &[u8]) -> Result<(), ObjectError> {
    let path = fs_path(root, key)?;
    let dir = path.parent().ok_or(ObjectError::UnsafePath)?;
    std::fs::create_dir_all(dir).map_err(io)?;
    // Checked again after creating: a link planted meanwhile is refused.
    fs_path(root, key)?;
    let temp = dir.join(format!(".tmp-{}", Uuid::new_v4().simple()));
    let written = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, &path)
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(io(error));
    }
    Ok(())
}

fn fs_get(root: &Path, key: &str) -> Result<Vec<u8>, ObjectError> {
    std::fs::read(fs_path(root, key)?).map_err(io)
}

fn fs_delete(root: &Path, key: &str) -> Result<(), ObjectError> {
    match std::fs::remove_file(fs_path(root, key)?) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(io(e)),
        _ => Ok(()),
    }
}

// --- S3 ------------------------------------------------------------------------------------------

/// Whether a plain-HTTP endpoint is acceptable: a loopback or private address, `localhost`, or a
/// one-label name (a container service such as `minio`). Anything else needs HTTPS.
fn plain_http_ok(url: &reqwest::Url) -> bool {
    let host = url.host_str().unwrap_or_default();
    match host.trim_start_matches('[').trim_end_matches(']').parse() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private(),
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
        Err(_) => host == "localhost" || (!host.is_empty() && !host.contains('.')),
    }
}

impl S3 {
    fn load(
        lookup: Lookup,
        text: &dyn Fn(&str) -> Option<String>,
        problems: &mut Vec<String>,
    ) -> Option<Self> {
        let before = problems.len();
        let endpoint = match text("S3_ENDPOINT").map(|e| reqwest::Url::parse(&e)) {
            Some(Ok(url))
                if (url.scheme() == "https" || (url.scheme() == "http" && plain_http_ok(&url)))
                    && url.host().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.path() == "/"
                    && url.query().is_none() =>
            {
                Some(url)
            }
            Some(_) => {
                problems.push("S3_ENDPOINT must be https://host[:port] (http only to a loopback, private or single-label host)".into());
                None
            }
            None => {
                problems.push("DYNODOC_OBJECT_STORE=s3 needs S3_ENDPOINT".into());
                None
            }
        };
        let bucket = text("S3_BUCKET").unwrap_or_default();
        if !(3..=63).contains(&bucket.len())
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        {
            problems.push(
                "S3_BUCKET must be 3 to 63 lower-case letters, digits, dots and dashes".into(),
            );
        }
        let region = text("S3_REGION").unwrap_or_else(|| "us-east-1".into());
        if region.len() > 32
            || !region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            problems.push("S3_REGION must be lower-case letters, digits and dashes".into());
        }
        let mut prefix = text("S3_PREFIX").unwrap_or_default();
        if prefix.len() > 200
            || prefix.starts_with('/')
            || prefix.contains("//")
            || prefix.split('/').any(|s| s == "." || s == "..")
            || !prefix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_./".contains(&b))
        {
            problems.push("S3_PREFIX must be lower-case letters, digits, dashes, underscores, dots and slashes, without a leading slash or empty or dot segments".into());
        }
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }
        let path_style = match text("S3_PATH_STYLE").as_deref() {
            None | Some("true") => true,
            Some("false") => false,
            Some(_) => {
                problems.push("S3_PATH_STYLE must be true or false".into());
                true
            }
        };
        let mut secret = |name: &str| match secrets::read(lookup, name) {
            Ok(Some(value)) if !value.expose().trim().is_empty() => Some(value),
            Ok(_) => {
                problems.push(format!(
                    "DYNODOC_OBJECT_STORE=s3 needs {name} (or {name}_FILE)"
                ));
                None
            }
            Err(error) => {
                problems.push(error.to_string());
                None
            }
        };
        let access_key = secret("S3_ACCESS_KEY_ID");
        let secret_key = secret("S3_SECRET_ACCESS_KEY");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build();
        match (endpoint, access_key, secret_key, client) {
            (Some(endpoint), Some(access_key), Some(secret), Ok(client))
                if problems.len() == before =>
            {
                Some(Self {
                    endpoint,
                    bucket,
                    region,
                    prefix,
                    path_style,
                    access_key,
                    secret,
                    client,
                })
            }
            _ => None,
        }
    }

    /// Host header and request path for `key`.
    fn locate(&self, key: &str) -> (String, String) {
        let host = self.endpoint.host_str().unwrap_or_default();
        let host = match self.endpoint.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        let object = uri_encode(&format!("{}{key}", self.prefix));
        if self.path_style {
            (host, format!("/{}/{object}", self.bucket))
        } else {
            (format!("{}.{host}", self.bucket), format!("/{object}"))
        }
    }

    async fn send(
        &self,
        method: reqwest::Method,
        key: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, ObjectError> {
        let (host, path) = self.locate(key);
        let payload = hex::encode(digest(body));
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let headers = [
            ("host", host.clone()),
            ("x-amz-content-sha256", payload.clone()),
            ("x-amz-date", amz_date.clone()),
        ];
        let authorization = sign(
            method.as_str(),
            &path,
            &headers,
            &payload,
            &amz_date,
            &self.region,
            self.access_key.expose(),
            self.secret.expose(),
        );
        let url = format!("{}://{host}{path}", self.endpoint.scheme());
        let response = self
            .client
            .request(method, url)
            .header("x-amz-content-sha256", payload)
            .header("x-amz-date", amz_date)
            .header("authorization", authorization)
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| ObjectError::Unreachable)?;
        let status = response.status().as_u16();
        if status == 404 {
            return Err(ObjectError::NotFound);
        }
        if !response.status().is_success() {
            return Err(ObjectError::Status(status));
        }
        Ok(response
            .bytes()
            .await
            .map_err(|_| ObjectError::Unreachable)?
            .to_vec())
    }
}

/// S3's URI encoding of a path: every byte but unreserved characters and `/` is `%XX`.
fn uri_encode(path: &str) -> String {
    path.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
        .as_ref()
        .to_vec()
}

/// The `Authorization` header of AWS Signature Version 4 for S3: `headers` are the signed headers
/// (lower-case names), `uri` is already encoded, the query is empty.
#[allow(clippy::too_many_arguments)]
fn sign(
    method: &str,
    uri: &str,
    headers: &[(&str, String)],
    payload_sha256: &str,
    amz_date: &str,
    region: &str,
    access_key: &str,
    secret_key: &str,
) -> String {
    let mut headers: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| (n.to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    headers.sort();
    let canonical_headers: String = headers.iter().map(|(n, v)| format!("{n}:{v}\n")).collect();
    let signed: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
    let signed = signed.join(";");
    let canonical = format!("{method}\n{uri}\n\n{canonical_headers}\n{signed}\n{payload_sha256}");
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(digest(canonical.as_bytes()))
    );
    let mut key = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    for part in [region, "s3", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = hex::encode(hmac_sha256(&key, to_sign.as_bytes()));
    format!("AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "0b6a1d6e-6c0a-4a64-9a43-1f2b7d0a0001";

    #[test]
    fn only_the_server_made_key_shapes_are_accepted() {
        let doc = Uuid::parse_str(DOC).unwrap();
        let upload = Uuid::new_v4();
        assert!(valid_key(&original_key(doc, upload)));
        assert!(valid_key(&media_key(doc, &[0xab; 32])));
        let sha = "ab".repeat(32);
        for bad in [
            format!("originals/{DOC}/../../etc/passwd"),
            format!("../originals/{DOC}/{}", "a".repeat(32)),
            format!("/originals/{DOC}/{}", "a".repeat(32)),
            format!("originals\\{DOC}\\{}", "a".repeat(32)),
            format!("originals/{DOC}/%2e%2e{}", "a".repeat(26)),
            format!("thumbnails/{DOC}/{}", "a".repeat(32)),
            format!("originals/{}/{}", DOC.to_uppercase(), "a".repeat(32)),
            format!("originals/{DOC}/{}", "A".repeat(32)),
            format!("originals/{DOC}/{sha}"),
            format!("media/{DOC}/{}", "a".repeat(32)),
            format!("media/{DOC}/{sha}a"),
            format!("media/{DOC}/{sha}/x"),
            format!("media/{DOC}/{}\0", &sha[..63]),
            format!("media/{}/{sha}", DOC.replace('-', "")),
            format!("media//{sha}"),
            String::new(),
        ] {
            assert!(!valid_key(&bad), "{bad:?}");
        }
    }

    #[test]
    fn the_filesystem_driver_stays_under_its_root() {
        let base = std::env::temp_dir().join(format!("dynodoc-objects-{}", Uuid::new_v4()));
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        let key = media_key(Uuid::parse_str(DOC).unwrap(), &[1; 32]);
        fs_put(&root, &key, b"bytes").unwrap();
        assert_eq!(fs_get(&root, &key).unwrap(), b"bytes");
        assert!(matches!(
            fs_put(&root, "media/../../x", b"x"),
            Err(ObjectError::InvalidKey)
        ));
        // A link planted inside the root that points outside is refused, for read and write.
        let doc2 = "0b6a1d6e-6c0a-4a64-9a43-1f2b7d0a0002";
        let link = root.join("media").join(doc2);
        #[cfg(unix)]
        let planted = std::os::unix::fs::symlink(&outside, &link).is_ok();
        // Without the symbolic-link privilege, a directory junction (also a name surrogate).
        #[cfg(windows)]
        let planted = std::os::windows::fs::symlink_dir(&outside, &link).is_ok()
            || std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&link)
                .arg(&outside)
                .output()
                .is_ok_and(|o| o.status.success());
        if planted {
            let via = format!("media/{doc2}/{}", "cd".repeat(32));
            assert!(matches!(
                fs_put(&root, &via, b"x"),
                Err(ObjectError::UnsafePath)
            ));
            assert!(matches!(fs_get(&root, &via), Err(ObjectError::UnsafePath)));
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        } else {
            eprintln!("symbolic links are not permitted here; the link case did not run");
        }
        fs_delete(&root, &key).unwrap();
        assert!(matches!(fs_get(&root, &key), Err(ObjectError::NotFound)));
        fs_delete(&root, &key).unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The "GET Object" example of the AWS Signature Version 4 documentation for S3
    /// (header-based authentication, example credentials of the documentation).
    #[test]
    fn signature_v4_matches_the_aws_documented_example() {
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let authorization = sign(
            "GET",
            "/test.txt",
            &[
                ("Host", "examplebucket.s3.amazonaws.com".into()),
                ("Range", "bytes=0-9".into()),
                ("x-amz-content-sha256", empty.into()),
                ("x-amz-date", "20130524T000000Z".into()),
            ],
            empty,
            "20130524T000000Z",
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        assert_eq!(uri_encode("a b/c+d"), "a%20b/c%2Bd");
    }

    #[test]
    fn settings_are_checked_and_secrets_never_echoed() {
        use std::{collections::HashMap, ffi::OsString};
        let env = |pairs: &[(&str, &str)]| {
            let map: HashMap<String, OsString> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), OsString::from(v)))
                .collect();
            move |name: &str| map.get(name).cloned()
        };
        let mut problems = Vec::new();
        assert!(ObjectStore::load(&env(&[]), &mut problems).in_database());
        assert!(problems.is_empty());
        let lookup = env(&[
            ("DYNODOC_OBJECT_STORE", "s3"),
            ("S3_ENDPOINT", "http://storage.example.com"),
            ("S3_BUCKET", "Bad_Bucket"),
            ("S3_PREFIX", "../x"),
            ("S3_ACCESS_KEY_ID", "AKIA-DO-NOT-LEAK"),
        ]);
        let store = ObjectStore::load(&lookup, &mut problems);
        assert!(store.in_database());
        let all = problems.join("\n");
        for wanted in [
            "S3_ENDPOINT",
            "S3_BUCKET",
            "S3_PREFIX",
            "S3_SECRET_ACCESS_KEY",
        ] {
            assert!(all.contains(wanted), "{all}");
        }
        assert!(!all.contains("DO-NOT-LEAK"));
        let mut problems = Vec::new();
        let lookup = env(&[
            ("DYNODOC_OBJECT_STORE", "s3"),
            ("S3_ENDPOINT", "http://minio:9000"),
            ("S3_BUCKET", "dynodoc"),
            ("S3_PREFIX", "site-a"),
            ("S3_ACCESS_KEY_ID", "key"),
            ("S3_SECRET_ACCESS_KEY", "secret"),
        ]);
        match ObjectStore::load(&lookup, &mut problems) {
            ObjectStore::S3(s3) => {
                assert_eq!(s3.prefix, "site-a/");
                let doc = Uuid::parse_str(DOC).unwrap();
                let (host, path) = s3.locate(&media_key(doc, &[0; 32]));
                assert_eq!(host, "minio:9000");
                assert_eq!(
                    path,
                    format!("/dynodoc/site-a/media/{DOC}/{}", "00".repeat(32))
                );
            }
            _ => panic!("{problems:?}"),
        }
    }
}
