// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use contra_guardian_core::EnclaveKeyPair;
use contra_guardian_enclave::{app, AppState};
use fastcrypto::encoding::{Base64, Encoding};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let state = Arc::new(AppState {
        keys: EnclaveKeyPair::generate(),
        registered: std::sync::atomic::AtomicBool::new(false),
    });

    let addr = std::env::var("GUARDIAN_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".into());
    let keys = state.keys.keys();
    tracing::info!(
        signing_pk = %Base64::encode(keys.signing_pk.0),
        enc_pk = %Base64::encode(keys.enc_pk),
        %addr,
        "guardian ready"
    );
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app(state)).await?;
    Ok(())
}
