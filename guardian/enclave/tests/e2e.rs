// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end test, wallet sealing a request to the enclave's `enc_pk` and checking the
//! response verifies over the signed payload.

use std::sync::Arc;

use contra_guardian_core::sealing::{self, SealedRequest, SEALED_REQUEST_VERSION};
use contra_guardian_core::testing::{transfer_payload, transfer_request};
use contra_guardian_core::types::{EnclaveKeys, UnsealedRequest};
use contra_guardian_core::EnclaveKeyPair;
use contra_guardian_enclave::{app, AppState};
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::traits::{ToFromBytes, VerifyingKey};

/// Serve a guardian on an ephemeral port and return its base URL.
async fn serve() -> String {
    let state = Arc::new(AppState {
        keys: EnclaveKeyPair::from_seed_for_testing(),
        registered: std::sync::atomic::AtomicBool::new(true),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
    format!("http://{addr}")
}

/// Serve a guardian and return its base URL alongside the keys it publishes.
async fn serve_with_keys() -> (String, EnclaveKeys) {
    let base = serve().await;
    let info = get_json(format!("{base}/attestation")).await;
    let user_data = Base64::decode(info["attestation"].as_str().unwrap()).unwrap();
    (base, bcs::from_bytes(&user_data).unwrap())
}

/// A dev build serves the `user_data` alone: the two keys, in the order
/// `guardian::parse_user_data` slices them.
async fn get_json(url: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || ureq::get(&url).call().unwrap().into_json().unwrap())
        .await
        .unwrap()
}

/// Returns `(status, body)` so rejection paths can assert on the status.
async fn post_sealed(url: String, req: SealedRequest) -> (u16, serde_json::Value) {
    post_bytes(url, bcs::to_bytes(&req).unwrap()).await
}

/// Returns `(status, body)` so rejection paths can assert on the status.
async fn post_bytes(url: String, body: Vec<u8>) -> (u16, serde_json::Value) {
    tokio::task::spawn_blocking(move || match ureq::post(&url).send_bytes(&body) {
        Ok(r) => (r.status(), r.into_json().unwrap()),
        Err(ureq::Error::Status(code, r)) => {
            (code, r.into_json().unwrap_or(serde_json::Value::Null))
        }
        Err(e) => panic!("request failed: {e}"),
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn attestation_carries_the_enclave_keys() {
    let base = serve().await;
    let info = get_json(format!("{base}/attestation")).await;
    let user_data = Base64::decode(info["attestation"].as_str().unwrap()).unwrap();

    let expected = EnclaveKeyPair::from_seed_for_testing();
    let keys: EnclaveKeys = bcs::from_bytes(&user_data).unwrap();
    assert_eq!(keys.signing_pk, expected.keys().signing_pk);
    assert_eq!(keys.enc_pk, expected.keys().enc_pk);
}

#[tokio::test]
async fn rejects_an_inflated_balance() {
    let (base, keys) = serve_with_keys().await;
    let mut req = transfer_request();
    if let UnsealedRequest::TransferRequest { old_balance, .. } = &mut req {
        *old_balance = 500; // claims more than the ciphertext opens to
    }
    let sealed = sealing::seal_to_all(&[keys.enc_pk], &req).unwrap();
    let (status, resp) = post_sealed(format!("{base}/process_request"), sealed).await;
    assert_eq!(status, 400);
    assert_eq!(
        resp["error"].as_str().unwrap(),
        "old balance does not open to the claimed value"
    );
}

#[tokio::test]
async fn rejects_request_sealed_to_another_instance() {
    let base = serve().await;
    let other = EnclaveKeyPair::generate();
    let other_enc_pk = other.keys().enc_pk;

    let req = transfer_request();
    let sealed = sealing::seal_to_all(&[other_enc_pk], &req).unwrap();
    let (status, _) = post_sealed(format!("{base}/process_request"), sealed).await;
    assert_eq!(status, 422);
}

#[tokio::test]
async fn rejects_unknown_version() {
    let (base, keys) = serve_with_keys().await;
    let req = transfer_request();
    let mut sealed = sealing::seal_to_all(&[keys.enc_pk], &req).unwrap();
    sealed.version = 2;
    let (status, resp) = post_sealed(format!("{base}/process_request"), sealed).await;
    assert_eq!(status, 400);
    assert_eq!(resp["error"].as_str().unwrap(), "unsupported version 2");
}

#[tokio::test]
async fn rejects_a_malformed_body() {
    let (base, _) = serve_with_keys().await;
    let (status, resp) = post_bytes(format!("{base}/process_request"), b"not bcs".to_vec()).await;
    assert_eq!(status, 400);
    assert_eq!(resp["error"].as_str().unwrap(), "malformed request");
}

#[tokio::test]
async fn rejects_undecodable_plaintext() {
    let (base, keys) = serve_with_keys().await;
    let sealed = SealedRequest {
        version: SEALED_REQUEST_VERSION,
        sealed: vec![sealing::seal(&keys.enc_pk, b"not a bcs request").unwrap()],
    };
    let (status, resp) = post_sealed(format!("{base}/process_request"), sealed).await;
    assert_eq!(status, 400);
    assert_eq!(
        resp["error"].as_str().unwrap(),
        "sealed body is not a BCS UnsealedRequest"
    );
}

#[tokio::test]
async fn health_gates_on_registration() {
    let state = Arc::new(AppState {
        keys: EnclaveKeyPair::generate(),
        registered: std::sync::atomic::AtomicBool::new(false),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });

    let status = |url: String, post: bool| {
        tokio::task::spawn_blocking(move || {
            let req = if post {
                ureq::post(&url).call()
            } else {
                ureq::get(&url).call()
            };
            match req {
                Ok(r) => r.status(),
                Err(ureq::Error::Status(code, _)) => code,
                Err(e) => panic!("request failed: {e}"),
            }
        })
    };

    assert_eq!(
        status(format!("{base}/registered"), false).await.unwrap(),
        503
    );
    assert_eq!(
        status(format!("{base}/registered"), true).await.unwrap(),
        200
    );
    assert_eq!(
        status(format!("{base}/registered"), false).await.unwrap(),
        200
    );
}

#[tokio::test]
async fn multi_recipients_envelope_accepts() {
    let (base, keys) = serve_with_keys().await;
    let mine = keys.enc_pk;
    let sibling_a = EnclaveKeyPair::generate().keys().enc_pk;
    let sibling_b = EnclaveKeyPair::generate().keys().enc_pk;

    let req = transfer_request();
    for fleet in [
        vec![mine, sibling_a, sibling_b],
        vec![sibling_a, mine, sibling_b],
        vec![sibling_a, sibling_b, mine],
    ] {
        let sealed = sealing::seal_to_all(&fleet, &req).unwrap();
        assert_eq!(sealed.sealed.len(), 3);
        let (status, resp) = post_sealed(format!("{base}/process_request"), sealed).await;
        assert_eq!(status, 200);

        let signature = Base64::decode(resp["signature"].as_str().unwrap()).unwrap();
        Ed25519PublicKey::from_bytes(keys.signing_pk.as_ref())
            .unwrap()
            .verify(
                &bcs::to_bytes(&transfer_payload(&req)).unwrap(),
                &Ed25519Signature::from_bytes(&signature).unwrap(),
            )
            .expect("response must verify under the enclave's key");
    }
}
