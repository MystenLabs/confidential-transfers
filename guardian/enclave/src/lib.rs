// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian enclave, which generates keys at boot, serves its attestation, and signs
//! responses for requests sealed to its `enc_pk`.

mod attestation;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use contra_guardian_core::sealing::{SealedRequest, SEALED_REQUEST_VERSION};
use contra_guardian_core::{EnclaveKeyPair, GuardianError};
use fastcrypto::encoding::{Base64, Encoding};
use serde::Serialize;

pub struct AppState {
    pub keys: EnclaveKeyPair,
    /// Set once the operator has registered this instance's key on chain,
    /// used by proxy to decide whether to route requests to.
    pub registered: AtomicBool,
}

/// Base64 of the attestation document, whose `user_data` is the BCS `EnclaveKeys` — or,
/// in a dev build, that `user_data` alone.
#[derive(Serialize)]
struct AttestationResponse {
    attestation: String,
}

/// The HTTP surface, served directly by tests and wrapped in a listener by the binary.
pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/attestation", get(attestation_handler))
        .route(
            "/registered",
            get(registered_handler).post(set_registered_handler),
        )
        .route("/process_request", post(process_request_handler))
        .with_state(state)
}

/// 200 once registered, 503 before — the proxy's readiness gate.
async fn registered_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.registered.load(Ordering::Relaxed) {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not registered")
    }
}

/// Marks this instance's key as registered on chain, called by the parent once it has seen
/// the key in the token's `guardian_enclave_keys`.
async fn set_registered_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.registered.store(true, Ordering::Relaxed);
    (StatusCode::OK, "registered")
}

async fn attestation_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let keys = state.keys.keys();
    match attestation::attestation_document(keys) {
        Ok(doc) => Json(AttestationResponse {
            attestation: Base64::encode(doc),
        })
        .into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// Unseal, check, and sign. Returns the signature and the signing pk, or error.
async fn process_request_handler(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let Ok(req) = bcs::from_bytes::<SealedRequest>(&body) else {
        return error(StatusCode::BAD_REQUEST, "malformed request");
    };
    if req.version != SEALED_REQUEST_VERSION {
        return error(
            StatusCode::BAD_REQUEST,
            format!("unsupported version {}", req.version),
        );
    }
    let req = match state.keys.unseal(&req.sealed) {
        Ok(req) => req,
        // 422 means it can be retried on other instances.
        Err(e @ GuardianError::NotARecipient) => {
            tracing::debug!(error = %e, "not a recipient");
            return error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string());
        }
        Err(e) => {
            tracing::info!(error = %e, "request rejected");
            return error(StatusCode::BAD_REQUEST, e.to_string());
        }
    };
    match state.keys.verify_and_sign(&req) {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => {
            tracing::info!(error = %e, "request rejected");
            error(StatusCode::BAD_REQUEST, e.to_string())
        }
    }
}

fn error(code: StatusCode, message: impl Into<String>) -> axum::response::Response {
    (code, Json(serde_json::json!({ "error": message.into() }))).into_response()
}
