//! Network key providers (feature `kms`, decision 041): HashiCorp Vault Transit (moved from
//! `engine-cli`), AWS KMS, Google Cloud KMS and Azure Key Vault, each over its REST API with a
//! blocking client (call them off async workers, as [`super::store`] does).
//!
//! Every wrap binds [`WrapContext::to_bytes`]: as Vault's derived-key `context`, as the AWS
//! `EncryptionContext`, as Google's `additionalAuthenticatedData`, and for Azure (whose key
//! wrap has no associated data) as a SHA-256 prefix inside the wrapped value that unwrap checks.
//!
//! Credentials come from the environment or the cloud's instance metadata service and are held
//! in [`Zeroizing`] strings. No credential, token or key byte is in an error, `Debug` or log
//! text: errors name the call and the provider's status only.
use super::{Dek, KeyProvider, ProviderError, ProviderInfo, WrapContext, Wrapped};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

type Lookup<'a> = &'a dyn Fn(&str) -> Option<String>;

fn http() -> Result<reqwest::blocking::Client, ProviderError> {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| ProviderError::Unavailable("HTTP client".into()))
}

/// HTTPS, or HTTP to a loopback address when explicitly allowed (tests, local proxies).
fn checked_url(url: &str, allow_loopback_http: bool) -> Result<reqwest::Url, ProviderError> {
    let parsed =
        reqwest::Url::parse(url).map_err(|_| ProviderError::Corrupt("provider address".into()))?;
    let loopback = parsed
        .host_str()
        .is_some_and(|h| h == "127.0.0.1" || h == "[::1]" || h == "localhost");
    if parsed.scheme() == "https" || (allow_loopback_http && loopback && parsed.scheme() == "http")
    {
        Ok(parsed)
    } else {
        Err(ProviderError::Denied(
            "the key provider must be reached over HTTPS".into(),
        ))
    }
}

fn status_error(status: u16, what: &str, kind: Option<&str>) -> ProviderError {
    let kind = kind.unwrap_or("");
    if kind.contains("InvalidCiphertext") || kind.contains("IncorrectKey") || status == 400 {
        ProviderError::Corrupt(format!(
            "{what}: refused (wrong context or damaged ciphertext)"
        ))
    } else if kind.contains("NotFound") || status == 404 {
        ProviderError::NotFound(format!("{what}: no such key"))
    } else if kind.contains("AccessDenied") || status == 401 || status == 403 {
        ProviderError::Denied(format!("{what}: the provider denied the credentials"))
    } else {
        ProviderError::Unavailable(format!("{what}: the provider answered {status}"))
    }
}

fn send(request: reqwest::blocking::RequestBuilder, what: &str) -> Result<Value, ProviderError> {
    let response = request
        .send()
        .map_err(|_| ProviderError::Unavailable(format!("{what}: provider unreachable")))?;
    let status = response.status().as_u16();
    let body: Value = response.json().unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        let kind = body["__type"]
            .as_str()
            .or_else(|| body["error"]["code"].as_str())
            .or_else(|| body["error"]["status"].as_str());
        return Err(status_error(status, what, kind));
    }
    Ok(body)
}

fn b64(value: &Value, what: &str) -> Result<Vec<u8>, ProviderError> {
    STANDARD
        .decode(value.as_str().unwrap_or_default())
        .map_err(|_| ProviderError::Corrupt(format!("{what}: provider answer")))
}

fn dek(bytes: &[u8]) -> Result<Dek, ProviderError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ProviderError::Corrupt("unwrapped key length".into()))?;
    Ok(Dek::from_bytes(bytes))
}

// ---- HashiCorp Vault Transit ------------------------------------------------------------

/// Vault Transit with a derived key (`derived=true`), so the wrap context binds every call.
pub struct VaultTransit {
    http: reqwest::blocking::Client,
    base: String,
    mount: String,
    key: String,
    token: Zeroizing<String>,
    latest: u32,
}

impl std::fmt::Debug for VaultTransit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultTransit")
            .field("base", &self.base)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl VaultTransit {
    /// `base` is the Vault address (`https://vault:8200`); the token is never logged. Reads
    /// the key's latest version once.
    pub fn connect(
        base: &str,
        mount: &str,
        key: &str,
        token: String,
        allow_loopback_http: bool,
    ) -> Result<Self, ProviderError> {
        checked_url(base, allow_loopback_http)?;
        let mut v = Self {
            http: http()?,
            base: base.trim_end_matches('/').into(),
            mount: mount.into(),
            key: key.into(),
            token: Zeroizing::new(token),
            latest: 0,
        };
        let info = v.call(
            reqwest::Method::GET,
            &format!("keys/{}", v.key),
            None,
            "read key",
        )?;
        v.latest = info["data"]["latest_version"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n >= 1)
            .ok_or_else(|| ProviderError::Corrupt("Vault key version".into()))?;
        if info["data"]["derived"] != json!(true) {
            return Err(ProviderError::Denied(
                "the Vault key must be created with derived=true so the context binds".into(),
            ));
        }
        Ok(v)
    }
    fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        what: &str,
    ) -> Result<Value, ProviderError> {
        let mut request = self
            .http
            .request(method, format!("{}/v1/{}/{path}", self.base, self.mount))
            .header("X-Vault-Token", self.token.as_str());
        if let Some(body) = body {
            request = request.json(&body);
        }
        send(request, what)
    }
    fn version_of(ciphertext: &str) -> Result<u32, ProviderError> {
        ciphertext
            .strip_prefix("vault:v")
            .and_then(|r| r.split(':').next())
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| ProviderError::Corrupt("Vault ciphertext".into()))
    }
    fn wrapped(&self, value: Value) -> Result<Wrapped, ProviderError> {
        let ct = value["data"]["ciphertext"]
            .as_str()
            .ok_or_else(|| ProviderError::Corrupt("Vault answer".into()))?;
        Wrapped::new(Self::version_of(ct)?, ct.as_bytes().to_vec())
    }
}

impl KeyProvider for VaultTransit {
    fn wrap(&self, dek: &Dek, ctx: &WrapContext) -> Result<Wrapped, ProviderError> {
        let body = json!({"plaintext": STANDARD.encode(dek.as_bytes()), "context": STANDARD.encode(ctx.to_bytes())});
        self.wrapped(self.call(
            reqwest::Method::POST,
            &format!("encrypt/{}", self.key),
            Some(body),
            "wrap",
        )?)
    }
    fn unwrap(&self, wrapped: &Wrapped, ctx: &WrapContext) -> Result<Dek, ProviderError> {
        let ct = std::str::from_utf8(wrapped.as_bytes())
            .map_err(|_| ProviderError::Corrupt("wrapped key".into()))?;
        let body = json!({"ciphertext": ct, "context": STANDARD.encode(ctx.to_bytes())});
        let answer = self.call(
            reqwest::Method::POST,
            &format!("decrypt/{}", self.key),
            Some(body),
            "unwrap",
        )?;
        dek(&Zeroizing::new(b64(
            &answer["data"]["plaintext"],
            "unwrap",
        )?))
    }
    fn rewrap(&self, wrapped: &Wrapped, ctx: &WrapContext) -> Result<Wrapped, ProviderError> {
        let ct = std::str::from_utf8(wrapped.as_bytes())
            .map_err(|_| ProviderError::Corrupt("wrapped key".into()))?;
        let body = json!({"ciphertext": ct, "context": STANDARD.encode(ctx.to_bytes())});
        self.wrapped(self.call(
            reqwest::Method::POST,
            &format!("rewrap/{}", self.key),
            Some(body),
            "rewrap",
        )?)
    }
    fn describe(&self) -> ProviderInfo {
        ProviderInfo {
            provider: "vault-transit",
            key_ref: format!("{}/v1/{}/keys/{}", self.base, self.mount, self.key),
            kek_version: self.latest,
        }
    }
}

// ---- AWS KMS (JSON 1.1 API, Signature Version 4) ----------------------------------------

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key), data)
        .as_ref()
        .to_vec()
}
fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex_of(&sha2::Sha256::digest(data))
}
fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// AWS Signature Version 4 of one request: `headers` are lowercase names with trimmed values
/// and must include `host` and `x-amz-date`; returns the `Authorization` header value.
#[allow(clippy::too_many_arguments)]
pub fn sigv4(
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    payload: &[u8],
) -> String {
    let mut headers: Vec<(&str, &str)> = headers.to_vec();
    headers.sort();
    let amz_date = headers
        .iter()
        .find(|(k, _)| *k == "x-amz-date")
        .map_or("", |(_, v)| *v);
    let date = &amz_date[..amz_date.len().min(8)];
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed: Vec<&str> = headers.iter().map(|(k, _)| *k).collect();
    let signed = signed.join(";");
    let canonical = format!(
        "{method}\n{path}\n\n{canonical_headers}\n{signed}\n{}",
        sha256_hex(payload)
    );
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );
    let k_secret = Zeroizing::new(format!("AWS4{secret_key}"));
    let k = Zeroizing::new(hmac(k_secret.as_bytes(), date.as_bytes()));
    let k = Zeroizing::new(hmac(&k, region.as_bytes()));
    let k = Zeroizing::new(hmac(&k, service.as_bytes()));
    let k = Zeroizing::new(hmac(&k, b"aws4_request"));
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={}",
        hex_of(&hmac(&k, to_sign.as_bytes()))
    )
}

/// AWS KMS: `Encrypt`, `Decrypt` and `ReEncrypt` with the wrap context as the encryption
/// context. Key rotation is AWS's (transparent to ciphertexts), so the KEK version is 1.
pub struct AwsKms {
    http: reqwest::blocking::Client,
    endpoint: reqwest::Url,
    region: String,
    key_id: String,
    access_key: Zeroizing<String>,
    secret_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for AwsKms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKms")
            .field("region", &self.region)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl AwsKms {
    /// `key_id` is a key ARN (its region is used) or an alias ARN. Credentials:
    /// `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`;
    /// `endpoint` overrides `https://kms.<region>.amazonaws.com/` (VPC endpoints, tests).
    pub fn from_env(
        key_id: &str,
        endpoint: Option<&str>,
        allow_loopback_http: bool,
        env: Lookup<'_>,
    ) -> Result<Self, ProviderError> {
        let region = key_id
            .split(':')
            .nth(3)
            .filter(|r| !r.is_empty() && key_id.starts_with("arn:"))
            .map(str::to_owned)
            .or_else(|| env("AWS_REGION"))
            .ok_or_else(|| ProviderError::Corrupt("use a key ARN or set AWS_REGION".into()))?;
        let need = |name: &str| {
            env(name)
                .filter(|v| !v.is_empty())
                .map(Zeroizing::new)
                .ok_or_else(|| ProviderError::Denied(format!("{name} is not set")))
        };
        let endpoint = endpoint
            .map(str::to_owned)
            .unwrap_or_else(|| format!("https://kms.{region}.amazonaws.com/"));
        Ok(Self {
            http: http()?,
            endpoint: checked_url(&endpoint, allow_loopback_http)?,
            region,
            key_id: key_id.into(),
            access_key: need("AWS_ACCESS_KEY_ID")?,
            secret_key: need("AWS_SECRET_ACCESS_KEY")?,
            session_token: env("AWS_SESSION_TOKEN")
                .filter(|v| !v.is_empty())
                .map(Zeroizing::new),
        })
    }
    fn context(ctx: &WrapContext) -> Value {
        json!({"dynodoc": STANDARD.encode(ctx.to_bytes())})
    }
    fn call(&self, target: &str, body: Value, what: &str) -> Result<Value, ProviderError> {
        let payload = serde_json::to_vec(&body)
            .map_err(|_| ProviderError::Corrupt(format!("{what}: request")))?;
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let host = match (self.endpoint.host_str(), self.endpoint.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_owned(),
            _ => return Err(ProviderError::Corrupt("provider address".into())),
        };
        let target = format!("TrentService.{target}");
        let mut headers = vec![
            ("content-type", "application/x-amz-json-1.1"),
            ("host", host.as_str()),
            ("x-amz-date", amz_date.as_str()),
            ("x-amz-target", target.as_str()),
        ];
        if let Some(t) = &self.session_token {
            headers.push(("x-amz-security-token", t.as_str()));
        }
        let auth = sigv4(
            &self.access_key,
            &self.secret_key,
            &self.region,
            "kms",
            "POST",
            self.endpoint.path(),
            &headers,
            &payload,
        );
        let mut request = self
            .http
            .post(self.endpoint.clone())
            .header("authorization", auth)
            .body(payload);
        for (k, v) in headers.iter().filter(|(k, _)| *k != "host") {
            request = request.header(*k, *v);
        }
        send(request, what)
    }
}

impl KeyProvider for AwsKms {
    fn wrap(&self, dek: &Dek, ctx: &WrapContext) -> Result<Wrapped, ProviderError> {
        let answer = self.call(
            "Encrypt",
            json!({"KeyId": self.key_id, "Plaintext": STANDARD.encode(dek.as_bytes()), "EncryptionContext": Self::context(ctx)}),
            "wrap",
        )?;
        Wrapped::new(1, b64(&answer["CiphertextBlob"], "wrap")?)
    }
    fn unwrap(&self, wrapped: &Wrapped, ctx: &WrapContext) -> Result<Dek, ProviderError> {
        let answer = self.call(
            "Decrypt",
            json!({"KeyId": self.key_id, "CiphertextBlob": STANDARD.encode(wrapped.as_bytes()), "EncryptionContext": Self::context(ctx)}),
            "unwrap",
        )?;
        dek(&Zeroizing::new(b64(&answer["Plaintext"], "unwrap")?))
    }
    fn rewrap(&self, wrapped: &Wrapped, ctx: &WrapContext) -> Result<Wrapped, ProviderError> {
        let answer = self.call(
            "ReEncrypt",
            json!({"CiphertextBlob": STANDARD.encode(wrapped.as_bytes()), "SourceEncryptionContext": Self::context(ctx), "DestinationKeyId": self.key_id, "DestinationEncryptionContext": Self::context(ctx)}),
            "rewrap",
        )?;
        Wrapped::new(1, b64(&answer["CiphertextBlob"], "rewrap")?)
    }
    fn describe(&self) -> ProviderInfo {
        ProviderInfo {
            provider: "aws-kms",
            key_ref: self.key_id.clone(),
            kek_version: 1,
        }
    }
}

// ---- Bearer tokens for Google Cloud and Azure ---------------------------------------------

/// A bearer token: fixed from the environment, or fetched from the instance metadata service
/// for each call (data keys are cached, so calls are rare).
enum Token {
    Fixed(Zeroizing<String>),
    Metadata {
        url: &'static str,
        header: (&'static str, &'static str),
    },
}

impl Token {
    fn get(&self, http: &reqwest::blocking::Client) -> Result<Zeroizing<String>, ProviderError> {
        match self {
            Self::Fixed(t) => Ok(t.clone()),
            Self::Metadata { url, header } => {
                let answer = send(http.get(*url).header(header.0, header.1), "access token")?;
                answer["access_token"]
                    .as_str()
                    .map(|t| Zeroizing::new(t.to_owned()))
                    .ok_or_else(|| ProviderError::Denied("no access token".into()))
            }
        }
    }
}

// ---- Google Cloud KMS ------------------------------------------------------------------------

/// Google Cloud KMS symmetric `encrypt`/`decrypt` with the wrap context as additional
/// authenticated data. `key_ref` is `projects/P/locations/L/keyRings/R/cryptoKeys/K`.
/// Token: `GOOGLE_OAUTH_ACCESS_TOKEN`, else the metadata server's service account.
pub struct GcpKms {
    http: reqwest::blocking::Client,
    base: String,
    name: String,
    token: Token,
}

impl std::fmt::Debug for GcpKms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKms")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl GcpKms {
    pub fn from_env(
        name: &str,
        endpoint: Option<&str>,
        allow_loopback_http: bool,
        env: Lookup<'_>,
    ) -> Result<Self, ProviderError> {
        if !name.starts_with("projects/") || !name.contains("/cryptoKeys/") || name.contains("..") {
            return Err(ProviderError::Corrupt(
                "use projects/P/locations/L/keyRings/R/cryptoKeys/K".into(),
            ));
        }
        let base = endpoint.unwrap_or("https://cloudkms.googleapis.com");
        checked_url(base, allow_loopback_http)?;
        Ok(Self {
            http: http()?,
            base: base.trim_end_matches('/').into(),
            name: name.into(),
            token: match env("GOOGLE_OAUTH_ACCESS_TOKEN").filter(|t| !t.is_empty()) {
                Some(t) => Token::Fixed(Zeroizing::new(t)),
                None => Token::Metadata {
                    url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                    header: ("Metadata-Flavor", "Google"),
                },
            },
        })
    }
    fn call(&self, verb: &str, body: Value, what: &str) -> Result<Value, ProviderError> {
        let token = self.token.get(&self.http)?;
        send(
            self.http
                .post(format!("{}/v1/{}:{verb}", self.base, self.name))
                .bearer_auth(token.as_str())
                .json(&body),
            what,
        )
    }
}

impl KeyProvider for GcpKms {
    fn wrap(&self, dek: &Dek, ctx: &WrapContext) -> Result<Wrapped, ProviderError> {
        let answer = self.call(
            "encrypt",
            json!({"plaintext": STANDARD.encode(dek.as_bytes()), "additionalAuthenticatedData": STANDARD.encode(ctx.to_bytes())}),
            "wrap",
        )?;
        let version = answer["name"]
            .as_str()
            .and_then(|n| n.rsplit_once("/cryptoKeyVersions/"))
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(1);
        Wrapped::new(version, b64(&answer["ciphertext"], "wrap")?)
    }
    fn unwrap(&self, wrapped: &Wrapped, ctx: &WrapContext) -> Result<Dek, ProviderError> {
        let answer = self.call(
            "decrypt",
            json!({"ciphertext": STANDARD.encode(wrapped.as_bytes()), "additionalAuthenticatedData": STANDARD.encode(ctx.to_bytes())}),
            "unwrap",
        )?;
        dek(&Zeroizing::new(b64(&answer["plaintext"], "unwrap")?))
    }
    fn describe(&self) -> ProviderInfo {
        ProviderInfo {
            provider: "gcp-kms",
            key_ref: self.name.clone(),
            kek_version: 1,
        }
    }
}

// ---- Azure Key Vault ------------------------------------------------------------------------

const AZURE_API: &str = "api-version=7.4";
const AZURE_ALG: &str = "RSA-OAEP-256";

/// Azure Key Vault `wrapkey`/`unwrapkey` with an RSA key (`RSA-OAEP-256`). The wrapped value is
/// `SHA-256(context) || DEK`, checked on unwrap, because key wrap takes no associated data.
/// `key_ref` is `https://<vault>.vault.azure.net/keys/<name>`. Token: `AZURE_ACCESS_TOKEN`
/// (resource `https://vault.azure.net`), else the managed identity endpoint.
///
/// The stored form is `version length (1 byte) || key version || ciphertext`, so unwrap uses the
/// key version that wrapped it after a rotation. The KEK version number is not Azure's (a hex
/// string) and is recorded as 1.
pub struct AzureKeyVault {
    http: reqwest::blocking::Client,
    key: String,
    token: Token,
}

impl std::fmt::Debug for AzureKeyVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureKeyVault")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl AzureKeyVault {
    pub fn from_env(
        key: &str,
        allow_loopback_http: bool,
        env: Lookup<'_>,
    ) -> Result<Self, ProviderError> {
        let url = checked_url(key, allow_loopback_http)?;
        let segments: Vec<&str> = url.path().trim_matches('/').split('/').collect();
        if segments.len() != 2 || segments[0] != "keys" || segments[1].is_empty() {
            return Err(ProviderError::Corrupt(
                "use https://<vault>.vault.azure.net/keys/<name>".into(),
            ));
        }
        Ok(Self {
            http: http()?,
            key: key.trim_end_matches('/').into(),
            token: match env("AZURE_ACCESS_TOKEN").filter(|t| !t.is_empty()) {
                Some(t) => Token::Fixed(Zeroizing::new(t)),
                None => Token::Metadata {
                    url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net",
                    header: ("Metadata", "true"),
                },
            },
        })
    }
    fn bound(ctx: &WrapContext) -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha256::digest(ctx.to_bytes()).to_vec()
    }
    fn call(&self, url: &str, value: &[u8], what: &str) -> Result<Value, ProviderError> {
        let token = self.token.get(&self.http)?;
        send(
            self.http
                .post(format!("{url}?{AZURE_API}"))
                .bearer_auth(token.as_str())
                .json(&json!({"alg": AZURE_ALG, "value": URL_SAFE_NO_PAD.encode(value)})),
            what,
        )
    }
}

impl KeyProvider for AzureKeyVault {
    fn wrap(&self, dek: &Dek, ctx: &WrapContext) -> Result<Wrapped, ProviderError> {
        let value = Zeroizing::new([Self::bound(ctx).as_slice(), dek.as_bytes()].concat());
        let answer = self.call(&format!("{}/wrapkey", self.key), &value, "wrap")?;
        let version = answer["kid"]
            .as_str()
            .and_then(|k| k.strip_prefix(&format!("{}/", self.key)))
            .filter(|v| {
                !v.is_empty() && v.len() <= 64 && v.bytes().all(|b| b.is_ascii_alphanumeric())
            })
            .ok_or_else(|| ProviderError::Corrupt("wrap: provider answer".into()))?;
        let ct = URL_SAFE_NO_PAD
            .decode(answer["value"].as_str().unwrap_or_default())
            .map_err(|_| ProviderError::Corrupt("wrap: provider answer".into()))?;
        Wrapped::new(
            1,
            [&[version.len() as u8][..], version.as_bytes(), &ct].concat(),
        )
    }
    fn unwrap(&self, wrapped: &Wrapped, ctx: &WrapContext) -> Result<Dek, ProviderError> {
        let bytes = wrapped.as_bytes();
        let n = usize::from(bytes[0]);
        let version = bytes
            .get(1..1 + n)
            .and_then(|v| std::str::from_utf8(v).ok())
            .filter(|v| v.bytes().all(|b| b.is_ascii_alphanumeric()))
            .ok_or_else(|| ProviderError::Corrupt("wrapped key".into()))?;
        let answer = self.call(
            &format!("{}/{version}/unwrapkey", self.key),
            &bytes[1 + n..],
            "unwrap",
        )?;
        let plain = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(answer["value"].as_str().unwrap_or_default())
                .map_err(|_| ProviderError::Corrupt("unwrap: provider answer".into()))?,
        );
        let bound = Self::bound(ctx);
        if plain.len() != 64 || !bool::from(subtle::ConstantTimeEq::ct_eq(&plain[..32], &bound[..]))
        {
            return Err(ProviderError::Corrupt(
                "unwrap: the wrapped key belongs to another context".into(),
            ));
        }
        dek(&plain[32..])
    }
    fn describe(&self) -> ProviderInfo {
        ProviderInfo {
            provider: "azure-keyvault",
            key_ref: self.key.clone(),
            kek_version: 1,
        }
    }
}

/// A provider by its `kms_key.provider` name. `key_ref` is the directory, Vault address, key
/// ARN, Google key name or Azure key URL. Settings beyond it come from `env`:
/// `DYNODOC_KMS_ENDPOINT` (AWS and Google endpoint override), `DYNODOC_VAULT_TOKEN`
/// (or the file named by `DYNODOC_VAULT_TOKEN_FILE`), `DYNODOC_VAULT_KEY` and
/// `DYNODOC_VAULT_MOUNT`, and each cloud's own credential variables.
pub fn provider(
    kind: &str,
    key_ref: &str,
    allow_loopback_http: bool,
    env: Lookup<'_>,
) -> Result<Box<dyn KeyProvider>, ProviderError> {
    let endpoint = env("DYNODOC_KMS_ENDPOINT");
    Ok(match kind {
        "file" => Box::new(super::FileKeyProvider::from_dir(std::path::Path::new(
            key_ref,
        ))?),
        "vault-transit" => {
            let token = match env("DYNODOC_VAULT_TOKEN") {
                Some(t) => t,
                None => {
                    let path = env("DYNODOC_VAULT_TOKEN_FILE").ok_or_else(|| {
                        ProviderError::Denied("set DYNODOC_VAULT_TOKEN_FILE".into())
                    })?;
                    std::fs::read_to_string(path)
                        .map_err(|_| ProviderError::Denied("cannot read the Vault token file".into()))?
                        .trim()
                        .to_owned()
                }
            };
            Box::new(VaultTransit::connect(
                key_ref,
                &env("DYNODOC_VAULT_MOUNT").unwrap_or_else(|| "transit".into()),
                &env("DYNODOC_VAULT_KEY").unwrap_or_else(|| "dynodoc-data".into()),
                token,
                allow_loopback_http,
            )?)
        }
        "aws-kms" => Box::new(AwsKms::from_env(
            key_ref,
            endpoint.as_deref(),
            allow_loopback_http,
            env,
        )?),
        "gcp-kms" => Box::new(GcpKms::from_env(
            key_ref,
            endpoint.as_deref(),
            allow_loopback_http,
            env,
        )?),
        "azure-keyvault" => Box::new(AzureKeyVault::from_env(key_ref, allow_loopback_http, env)?),
        _ => {
            return Err(ProviderError::Corrupt(
                "unknown key provider (file, vault-transit, aws-kms, gcp-kms, azure-keyvault; PKCS#11 is not built)".into(),
            ))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use uuid::Uuid;

    /// One loopback stand-in for the four contracts: a ciphertext is `plain|context`, opened
    /// only under the same context (Vault `context`, AWS `EncryptionContext`, Google AAD);
    /// Azure's key wrap ignores context, as the real one does.
    fn mock() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let (mut line, mut length, mut auth) = (String::new(), 0usize, String::new());
                reader.read_line(&mut line).unwrap();
                let path = line.split(' ').nth(1).unwrap_or("").to_owned();
                let mut target = String::new();
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    let lower = h.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap();
                    }
                    if lower.starts_with("x-vault-token:") || lower.starts_with("authorization:") {
                        auth = h.split_once(':').unwrap().1.trim().into();
                    }
                    if let Some(v) = lower.strip_prefix("x-amz-target:") {
                        target = v.trim().into();
                    }
                    if h == "\r\n" {
                        break;
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let seal = |plain: &str, ctx: &str| STANDARD.encode(format!("{plain}|{ctx}"));
                let open = |ct: &str, ctx: &str| -> Option<String> {
                    let text = String::from_utf8(STANDARD.decode(ct).ok()?).ok()?;
                    let (plain, bound) = text.split_once('|')?;
                    (bound == ctx).then(|| plain.to_owned())
                };
                let ok = auth == "test-token"
                    || auth == "Bearer test-token"
                    || auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDTEST/");
                let (status, answer) = if !ok {
                    (403, json!({"__type": "AccessDeniedException"}))
                } else if path.ends_with("/keys/k") {
                    (200, json!({"data": {"latest_version": 2, "derived": true}}))
                } else if path.contains("/encrypt/") || path.contains("/rewrap/") {
                    let ctx = req["context"].as_str().unwrap();
                    let plain = req["plaintext"]
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| {
                            let ct = req["ciphertext"]
                                .as_str()
                                .unwrap()
                                .trim_start_matches("vault:v2:");
                            open(ct, ctx).unwrap()
                        });
                    (
                        200,
                        json!({"data": {"ciphertext": format!("vault:v2:{}", seal(&plain, ctx))}}),
                    )
                } else if path.contains("/decrypt/") {
                    let ct = req["ciphertext"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("vault:v2:");
                    match open(ct, req["context"].as_str().unwrap()) {
                        Some(p) => (200, json!({"data": {"plaintext": p}})),
                        None => (400, json!({})),
                    }
                } else if target == "trentservice.encrypt" {
                    let ctx = req["EncryptionContext"].to_string();
                    (
                        200,
                        json!({"CiphertextBlob": seal(req["Plaintext"].as_str().unwrap(), &ctx)}),
                    )
                } else if target == "trentservice.decrypt" {
                    let ctx = req["EncryptionContext"].to_string();
                    match open(req["CiphertextBlob"].as_str().unwrap(), &ctx) {
                        Some(p) => (200, json!({"Plaintext": p})),
                        None => (400, json!({"__type": "InvalidCiphertextException"})),
                    }
                } else if target == "trentservice.reencrypt" {
                    let from = req["SourceEncryptionContext"].to_string();
                    let to = req["DestinationEncryptionContext"].to_string();
                    match open(req["CiphertextBlob"].as_str().unwrap(), &from) {
                        Some(p) => (200, json!({"CiphertextBlob": seal(&p, &to)})),
                        None => (400, json!({"__type": "InvalidCiphertextException"})),
                    }
                } else if path.ends_with(":encrypt") {
                    let aad = req["additionalAuthenticatedData"].as_str().unwrap();
                    (
                        200,
                        json!({"name": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/3", "ciphertext": seal(req["plaintext"].as_str().unwrap(), aad)}),
                    )
                } else if path.ends_with(":decrypt") {
                    let aad = req["additionalAuthenticatedData"].as_str().unwrap();
                    match open(req["ciphertext"].as_str().unwrap(), aad) {
                        Some(p) => (200, json!({"plaintext": p})),
                        None => (400, json!({"error": {"status": "INVALID_ARGUMENT"}})),
                    }
                } else if path.contains("/wrapkey") {
                    (
                        200,
                        json!({"kid": format!("http://{addr}/keys/a/v7"), "value": req["value"]}),
                    )
                } else if path.contains("/v7/unwrapkey") {
                    (200, json!({"value": req["value"]}))
                } else {
                    (404, json!({}))
                };
                let text = answer.to_string();
                let mut s = stream;
                let _ = write!(s, "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}", text.len());
            }
        });
        format!("http://{addr}")
    }

    fn lookup(base: String) -> impl Fn(&str) -> Option<String> {
        move |name| match name {
            "AWS_ACCESS_KEY_ID" => Some("AKIDTEST".into()),
            "AWS_SECRET_ACCESS_KEY" => Some("ZEUS-CANARY-aws-secret".into()),
            "GOOGLE_OAUTH_ACCESS_TOKEN" | "AZURE_ACCESS_TOKEN" | "DYNODOC_VAULT_TOKEN" => {
                Some("test-token".into())
            }
            "DYNODOC_KMS_ENDPOINT" => Some(format!("{base}/")),
            "DYNODOC_VAULT_KEY" => Some("k".into()),
            _ => None,
        }
    }

    #[test]
    fn every_provider_binds_the_wrap_context_and_hides_its_credentials() {
        use super::super::Purpose;
        let base = mock();
        let env = lookup(base.clone());
        let ctx = WrapContext::new(Uuid::from_u128(1), Some(Uuid::from_u128(2)), Purpose::Data);
        let other = WrapContext::new(Uuid::from_u128(1), Some(Uuid::from_u128(3)), Purpose::Data);
        let key = Dek::from_bytes([7; 32]);
        for (kind, key_ref) in [
            ("vault-transit", base.clone()),
            (
                "aws-kms",
                "arn:aws:kms:eu-west-1:111122223333:key/k".to_owned(),
            ),
            (
                "gcp-kms",
                "projects/p/locations/l/keyRings/r/cryptoKeys/k".to_owned(),
            ),
            ("azure-keyvault", format!("{base}/keys/a")),
        ] {
            assert!(
                matches!(
                    provider(kind, &key_ref, false, &env),
                    Err(ProviderError::Denied(_))
                ),
                "{kind}: plain HTTP needs the loopback switch"
            );
            let p = provider(kind, &key_ref, true, &env).unwrap();
            let w = p.wrap(&key, &ctx).unwrap();
            assert_eq!(
                p.unwrap(&w, &ctx).unwrap().as_bytes(),
                key.as_bytes(),
                "{kind}"
            );
            assert!(
                matches!(p.unwrap(&w, &other), Err(ProviderError::Corrupt(_))),
                "{kind}: another project's context must not unwrap"
            );
            let r = p.rewrap(&w, &ctx).unwrap();
            assert_eq!(
                p.unwrap(&r, &ctx).unwrap().as_bytes(),
                key.as_bytes(),
                "{kind} rewrap"
            );
        }
        // Credentials never print, and a refused call names no secret.
        let endpoint = format!("{base}/");
        let arn = "arn:aws:kms:eu-west-1:1:key/k";
        let aws = AwsKms::from_env(arn, Some(&endpoint), true, &env).unwrap();
        assert!(!format!("{aws:?}").contains("CANARY"));
        let wrong = |name: &str| match name {
            "AWS_ACCESS_KEY_ID" => Some("WRONG".into()),
            "AWS_SECRET_ACCESS_KEY" => Some("ZEUS-CANARY-aws-secret".into()),
            _ => None,
        };
        let refused = AwsKms::from_env(arn, Some(&endpoint), true, &wrong)
            .unwrap()
            .wrap(&key, &ctx)
            .unwrap_err();
        assert!(matches!(refused, ProviderError::Denied(_)));
        assert!(!refused.to_string().contains("CANARY"));
        assert!(matches!(
            AwsKms::from_env(arn, None, false, &|_| None),
            Err(ProviderError::Denied(_))
        ));
    }

    #[test]
    fn sigv4_matches_the_published_aws_examples() {
        // AWS documentation, "Examples of how to derive a signing key for Signature Version 4".
        let k = hmac(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", b"20120215");
        let k = hmac(&hmac(&hmac(&k, b"us-east-1"), b"iam"), b"aws4_request");
        assert_eq!(
            hex_of(&k),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
        // The Signature Version 4 test suite, `get-vanilla`.
        let auth = sigv4(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "service",
            "GET",
            "/",
            &[
                ("host", "example.amazonaws.com"),
                ("x-amz-date", "20150830T123600Z"),
            ],
            b"",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }
}
