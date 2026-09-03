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
}

#[derive(Deserialize)]
struct KeystoreConfig {
    #[serde(rename = "File")]
    file: PathBuf,
}

/// Operator signing material loaded from a Sui keystore.
pub(crate) struct Wallet {
    keypairs: Vec<SimpleKeypair>,
}

/// Load operator keys directly or from the keystore referenced by a Sui client config.
pub(crate) fn load_wallet(
    wallet_path: Option<PathBuf>,
    keystore_json: Option<&str>,
) -> Result<Wallet> {
    let keystore = match keystore_json {
        Some(keystore) => keystore.to_owned(),
        None => {
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
            fs::read_to_string(&config.keystore.file)
                .with_context(|| format!("failed to read {}", config.keystore.file.display()))?
        }
    };
    let keys: Vec<String> = serde_json::from_str(&keystore).context("failed to parse keystore")?;
    let keypairs = keys
        .iter()
        .map(|key| {
            if key.starts_with("suiprivkey") {
                SimpleKeypair::from_suiprivkey(key)
            } else {
                SimpleKeypair::from_base64(key)
            }
            .context("keystore contains an invalid key")
        })
        .collect::<Result<Vec<_>>>()?;
    if keypairs.is_empty() {
        return Err(anyhow!("keystore contains no keys"));
    }
    Ok(Wallet { keypairs })
}

impl Wallet {
    /// Return the keypair for the Guardian's designated operator.
    pub(crate) fn keypair(&self, operator: Address) -> Result<&SimpleKeypair> {
        self.keypairs
            .iter()
            .find(|key| key.verifying_key().derive_address() == operator)
            .ok_or_else(|| anyhow!("designated operator {operator} is not present in the keystore"))
    }
}
