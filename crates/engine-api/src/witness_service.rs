//! HTTP face of a transparency witness (design sections 4.2 and 4.8, phase W3,
//! decision 032), served by the separate `dynodoc-witness` binary on its own host and
//! key. `POST /add-checkpoint` follows C2SP `tlog-witness` (editor's copy); `GET
//! /{sha256_hex(origin)}/checkpoint` returns the checkpoint it last cosigned, so
//! monitors can compare the witness's view with the log's. The witness holds no
//! content, no project data and no database credential: only its key and its state.
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use engine_core::transparency::witness::{
    AddCheckpoint, Refusal, Witness, WitnessState, MAX_REQUEST_BYTES,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct WitnessApp {
    pub witness: Arc<Witness>,
    pub state: WitnessState,
    /// Hex SHA-256 of each configured origin, with the origin.
    pub origins: Arc<Vec<(String, String)>>,
}

pub fn router(app: WitnessApp) -> Router {
    Router::new()
        .route("/add-checkpoint", post(add_checkpoint))
        .route("/{origin}/checkpoint", get(latest))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(app)
}

fn refusal(error: Refusal) -> Response {
    let status = StatusCode::from_u16(error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    match error {
        // The log retries with a proof from this size.
        Refusal::Conflict { size } => (
            status,
            [(header::CONTENT_TYPE, "text/x.tlog.size")],
            format!("{size}\n"),
        )
            .into_response(),
        Refusal::Storage(message) => {
            tracing::error!(error = %message, "witness state failure");
            (status, "witness state failure\n").into_response()
        }
        other => (status, format!("{other}\n")).into_response(),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

async fn add_checkpoint(State(app): State<WitnessApp>, body: Bytes) -> Response {
    let request = match AddCheckpoint::parse(&body) {
        Ok(request) => request,
        Err(error) => return refusal(error),
    };
    match app
        .state
        .add_checkpoint(&app.witness, &request, now())
        .await
    {
        Ok(line) => {
            tracing::info!(old = request.old_size, "witness cosigned a checkpoint");
            ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], line).into_response()
        }
        Err(error) => {
            tracing::warn!(status = error.status(), "witness refused a checkpoint");
            refusal(error)
        }
    }
}

async fn latest(State(app): State<WitnessApp>, Path(hash): Path<String>) -> Response {
    let Some((_, origin)) = app.origins.iter().find(|(h, _)| *h == hash) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match app.state.latest(origin).await {
        Ok(Some(note)) => {
            ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], note).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => refusal(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use engine_core::transparency::{KeyKind, Leaf, Log, MemoryTileStore, Origin, Signer};
    use tower::ServiceExt;

    const ORIGIN: &str = "log.example/dynodoc/v1/transparency";

    #[tokio::test]
    async fn protocol_status_codes_follow_the_witness_state() {
        let log_key = Signer::from_seed(ORIGIN, KeyKind::Log, &[1; 32]).unwrap();
        let witness = Witness::new(
            Signer::from_seed("w.example/w", KeyKind::Cosigner, &[2; 32]).unwrap(),
            vec![log_key.verifier_key()],
        )
        .unwrap();
        let path = std::env::temp_dir().join(format!(
            "dynodoc-witness-http-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let state = WitnessState::open(&path).await.unwrap();
        let hash = hex::encode(ring::digest::digest(
            &ring::digest::SHA256,
            ORIGIN.as_bytes(),
        ));
        let app = router(WitnessApp {
            witness: Arc::new(witness),
            state: state.clone(),
            origins: Arc::new(vec![(hash.clone(), ORIGIN.into())]),
        });
        let mut log = Log::open(Origin::new(ORIGIN).unwrap(), MemoryTileStore::new()).unwrap();
        for i in 0..5u64 {
            log.append(&Leaf::EventHeads {
                root: [1; 32],
                count: 1,
                interval: i,
            })
            .unwrap();
        }
        let send = |body: String| {
            let app = app.clone();
            async move {
                let response = app
                    .oneshot(
                        axum::http::Request::post("/add-checkpoint")
                            .body(Body::from(body))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = response.status();
                let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
                (status, String::from_utf8(bytes.to_vec()).unwrap())
            }
        };
        let request = |old: u64| AddCheckpoint {
            old_size: old,
            proof: vec![],
            note: log.signed_checkpoint(&log_key).unwrap(),
        };
        let (status, line) = send(request(0).encode()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(line.starts_with("\u{2014} w.example/w "));
        let (status, body) = send(request(2).encode()).await;
        assert_eq!((status, body.as_str()), (StatusCode::CONFLICT, "5\n"));
        assert_eq!(send("garbage".into()).await.0, StatusCode::BAD_REQUEST);
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::get(format!("/{hash}/checkpoint"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        state.close().await;
        let _ = std::fs::remove_file(&path);
    }
}
