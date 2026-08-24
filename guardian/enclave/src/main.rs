// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use contra_guardian_core::EnclaveKeyPair;
use contra_guardian_enclave::app;
use fastcrypto::encoding::{Base64, Encoding};
use hpke::Serializable;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let keys = EnclaveKeyPair::generate();
    let public_keys = keys.enclave_keys();

    let addr = std::env::var("GUARDIAN_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".into());
    tracing::info!(
        signing_pk = %Base64::encode(public_keys.signing_pk.as_ref()),
        enc_pk = %Base64::encode(public_keys.enc_pk.to_bytes()),
        %addr,
        "guardian ready"
    );
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app(keys)).await?;
    Ok(())
}
