// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Guardian enclave HTTP service.
//!
//! The service exposes its attestation, gates readiness on on-chain registration, and delegates
//! sealed-request decryption, plaintext validation, and signing to `contra-guardian-core`.

mod attestation;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use contra_guardian_core::types::SealedRequest;
use contra_guardian_core::{EnclaveKeyPair, GuardianError};
use fastcrypto::encoding::{Base64, Encoding};
use serde::Serialize;

/// Covers a maximum-size transfer request while bounding request-body allocation.
const MAX_REQUEST_BODY_BYTES: usize = 128 * 1024;

struct AppState {
    keys: EnclaveKeyPair,
    registered: AtomicBool,
}

/// Base64-encoded Nitro attestation document whose `user_data` is the BCS `EnclaveKeys`.
#[derive(Serialize)]
struct AttestationResponse {
    attestation: String,
}

/// Build the HTTP service around an unregistered enclave key pair.
pub fn app(keys: EnclaveKeyPair) -> Router {
    let state = Arc::new(AppState {
        keys,
        registered: AtomicBool::new(false),
    });
    Router::new()
        .route("/attestation", get(attestation_handler))
        .route(
            "/registered",
            get(registered_handler).post(set_registered_handler),
        )
        .route("/process_request", post(process_request_handler))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state)
}

/// Return the register status: 200 if ready, 503 if not.
async fn registered_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.registered.load(Ordering::Relaxed) {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not registered")
    }
}

/// Called by the parent after this instance's enclave key has been registered on chain and
/// observed in the token's `guardian_enclave_keys` claim.
async fn set_registered_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.registered.store(true, Ordering::Relaxed);
    (StatusCode::OK, "registered")
}

async fn attestation_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let keys = state.keys.enclave_keys();
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
    let req = match state.keys.unseal(&req) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use contra_guardian_core::test_utils::{seal_to_all, transfer_request};
    use contra_guardian_core::types::{EnclaveResponse, UnsealedRequest};
    use serde_json::Value;
    use tower::ServiceExt;

    fn test_app() -> Router {
        app(EnclaveKeyPair::generate())
    }

    async fn post_process(app: Router, body: impl Into<Body>) -> axum::response::Response {
        app.oneshot(Request::post("/process_request").body(body.into()).unwrap())
            .await
            .unwrap()
    }

    async fn error_message(response: axum::response::Response) -> Value {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice::<Value>(&body).unwrap()["error"].clone()
    }

    #[tokio::test]
    async fn set_and_get_registered_status() {
        let app = test_app();
        let response = app
            .clone()
            .oneshot(Request::get("/registered").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let response = app
            .clone()
            .oneshot(Request::post("/registered").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(Request::get("/registered").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn valid_request_returns_signed_response() {
        let keys = EnclaveKeyPair::generate();
        let signing_pk = keys.enclave_keys().signing_pk.clone();
        let enc_pk = keys.enclave_keys().enc_pk.clone();
        let sealed = seal_to_all(&[enc_pk], &transfer_request()).unwrap();
        let response = post_process(app(keys), bcs::to_bytes(&sealed).unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response: EnclaveResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(response.signing_pk, signing_pk);
    }

    #[tokio::test]
    async fn attestation_requires_nsm() {
        let response = test_app()
            .oneshot(Request::get("/attestation").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["error"],
            "Nitro attestation requires a Linux enclave with NSM"
        );
    }

    #[tokio::test]
    async fn malformed_request_is_rejected() {
        let response = post_process(test_app(), "not bcs").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_message(response).await, "malformed request");
    }

    #[tokio::test]
    async fn request_for_another_enclave_returns_retryable_status() {
        let keys = EnclaveKeyPair::generate();
        let other_keys = EnclaveKeyPair::generate();
        let sealed = seal_to_all(
            &[other_keys.enclave_keys().enc_pk.clone()],
            &transfer_request(),
        )
        .unwrap();
        let response = post_process(app(keys), bcs::to_bytes(&sealed).unwrap()).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(error_message(response).await, "not a recipient");
    }

    #[tokio::test]
    async fn invalid_operation_returns_bad_request() {
        let keys = EnclaveKeyPair::generate();
        let enc_pk = keys.enclave_keys().enc_pk.clone();
        let mut request = transfer_request();
        let UnsealedRequest::TransferRequest { old_balance, .. } = &mut request else {
            unreachable!()
        };
        *old_balance += 1;
        let sealed = seal_to_all(&[enc_pk], &request).unwrap();
        let response = post_process(app(keys), bcs::to_bytes(&sealed).unwrap()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            error_message(response).await,
            "balance does not open to the expected value"
        );
    }

    #[tokio::test]
    async fn oversized_request_is_rejected() {
        let response = post_process(test_app(), vec![0; MAX_REQUEST_BODY_BYTES + 1]).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
