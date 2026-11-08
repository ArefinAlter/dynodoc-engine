//! Error responses counted since this API process started, for the admin overview.
//! Each process counts its own; these are not fleet-wide totals.
use crate::error::ErrorCode;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use serde_json::{Map, Value};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

const CODES: [&str; 5] = [
    "internal",
    "replay_failed",
    "conflict",
    "rate_limited",
    "busy",
];

/// Status classes of every response, for the local metrics endpoint ([`crate::metrics`]).
pub const CLASSES: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];

#[derive(Clone, Default)]
pub struct Counters(Arc<Inner>);

#[derive(Default)]
struct Inner {
    codes: [AtomicU64; CODES.len()],
    classes: [AtomicU64; CLASSES.len()],
}

impl Counters {
    pub fn snapshot(&self) -> Value {
        let counts: Map<String, Value> = CODES
            .iter()
            .zip(self.0.codes.iter())
            .map(|(code, n)| (code.to_string(), n.load(Ordering::Relaxed).into()))
            .collect();
        Value::Object(counts)
    }

    /// Responses by status class since start, in [`CLASSES`] order.
    pub fn classes(&self) -> [u64; CLASSES.len()] {
        std::array::from_fn(|i| self.0.classes[i].load(Ordering::Relaxed))
    }
}

pub async fn count(State(counters): State<Counters>, request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if let Some(ErrorCode(code)) = response.extensions().get::<ErrorCode>() {
        if let Some(i) = CODES.iter().position(|c| c == code) {
            counters.0.codes[i].fetch_add(1, Ordering::Relaxed);
        }
    }
    let class = (response.status().as_u16() / 100).clamp(1, 5) as usize - 1;
    counters.0.classes[class].fetch_add(1, Ordering::Relaxed);
    response
}
