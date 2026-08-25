// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use sui_crypto::simple::SimpleKeypair;
use sui_sdk_types::Address;

#[derive(Deserialize)]
struct WalletConfig {
    keystore: KeystoreConfig,
    envs: Vec<Environment>,
    active_env: String,
    active_address: Address,
}

#[derive(Deserialize)]
struct KeystoreConfig {
    #[serde(rename = "File")]
    file: PathBuf,
}

#[derive(Deserialize)]
struct Environment {
    alias: String,
    rpc: String,
}

/// Operator signing material and its selected Sui RPC endpoint.
pub(crate) struct Wallet {
    pub(crate) keypair: SimpleKeypair,
    pub(crate) address: Address,
    pub(crate) rpc_url: String,
}

/// Load the active operator and matching keypair from a Sui client config.
pub(crate) fn load_wallet(wallet_path: Option<PathBuf>, rpc_url: Option<&str>) -> Result<Wallet> {
    let wallet_path = wallet_path.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".sui/sui_config/client.yaml")
    });
    let config: WalletConfig = serde_yaml::from_str(
        &fs::read_to_string(&wallet_path)
            .with_context(|| format!("failed to read {}", wallet_path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", wallet_path.display()))?;
    let address = config.active_address;
    let keystore_path = config.keystore.file;
    let keys: Vec<String> = serde_json::from_str(
        &fs::read_to_string(&keystore_path)
            .with_context(|| format!("failed to read {}", keystore_path.display()))?,
    )?;
    let keypair = keys
        .iter()
        .filter_map(|key| {
            if key.starts_with("suiprivkey") {
                SimpleKeypair::from_suiprivkey(key).ok()
            } else {
                SimpleKeypair::from_base64(key).ok()
            }
        })
        .find(|key| key.verifying_key().derive_address() == address)
        .ok_or_else(|| {
            anyhow!(
                "address {address} is not present in {}",
                keystore_path.display()
            )
        })?;
    let configured_rpc = config
        .envs
        .iter()
        .find(|environment| environment.alias == config.active_env)
        .map(|environment| environment.rpc.as_str())
        .ok_or_else(|| {
            anyhow!(
                "active environment {} is missing from wallet",
                config.active_env
            )
        })?;
    Ok(Wallet {
        keypair,
        address,
        rpc_url: rpc_url.unwrap_or(configured_rpc).to_owned(),
    })
}
