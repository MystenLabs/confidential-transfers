// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

mod transaction;
mod wallet;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use sui_sdk_types::{Address, TypeTag};

use wallet::load_wallet;

/// Default gas budget for Guardian programmable transactions.
const DEFAULT_GAS_BUDGET: u64 = 100_000_000;

/// Contra Guardian command-line arguments.
#[derive(Parser)]
#[command(about = "Operate a Contra Guardian without the Sui CLI")]
struct Cli {
    /// Sui client configuration containing the active environment and keystore path.
    #[arg(long, env = "SUI_WALLET")]
    wallet: Option<PathBuf>,
    /// Override the RPC URL from the wallet's active environment.
    #[arg(long, env = "SUI_RPC_URL")]
    rpc_url: Option<String>,
    #[arg(long, env = "SUI_GAS_BUDGET", default_value_t = DEFAULT_GAS_BUDGET)]
    gas_budget: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage a Guardian as the confidential token issuer.
    Issuer {
        /// Address of the offline issuer that will sign the transaction.
        #[arg(long, env = "SUI_SENDER")]
        sender: Address,
        #[command(subcommand)]
        command: IssuerCommand,
    },
    /// Operate a Guardian's enclave fleet.
    Operator {
        #[command(subcommand)]
        command: OperatorCommand,
    },
}

/// Identifies an existing `Guardian<T>` and its package/type context.
#[derive(Args)]
struct GuardianObjectArgs {
    #[arg(long, env = "GUARDIAN_PACKAGE_ID")]
    guardian_package: Address,
    #[arg(long, env = "GUARDIAN_ID")]
    guardian: Address,
    #[arg(long, env = "TOKEN_TYPE")]
    token_type: TypeTag,
}

/// Existing Guardian arguments plus the issuer's management capability.
#[derive(Args)]
struct IssuerGuardianArgs {
    #[command(flatten)]
    guardian: GuardianObjectArgs,
    #[arg(long, env = "MANAGEMENT_CAP_ID")]
    management_cap: Address,
}

/// PCR values used when creating or updating a Guardian policy.
#[derive(Args)]
struct PcrInput {
    #[arg(long)]
    pcr0: String,
    #[arg(long)]
    pcr1: String,
    #[arg(long)]
    pcr2: String,
}

#[derive(Subcommand)]
enum IssuerCommand {
    /// Create a Guardian for a confidential token.
    CreateGuardian {
        #[arg(long, env = "GUARDIAN_PACKAGE_ID")]
        guardian_package: Address,
        #[arg(long, env = "MANAGEMENT_CAP_ID")]
        management_cap: Address,
        #[arg(long, env = "TOKEN_TYPE")]
        token_type: TypeTag,
        #[command(flatten)]
        pcrs: PcrInput,
        #[arg(long, env = "GUARDIAN_OPERATOR")]
        operator: Address,
    },
    /// Remove an enclave with issuer authority.
    RemoveEnclave {
        #[command(flatten)]
        issuer: IssuerGuardianArgs,
        #[arg(long)]
        key_index: u8,
    },
    /// Update Guardian security settings and assign its operator.
    UpdateGuardian {
        #[command(flatten)]
        issuer: IssuerGuardianArgs,
        #[command(flatten)]
        pcrs: PcrInput,
        /// Override min_version for a breaking release; routine releases preserve it from chain.
        #[arg(long)]
        min_version: Option<u16>,
        #[arg(long, env = "GUARDIAN_OPERATOR")]
        operator: Address,
    },
    /// Enable the Guardian as the confidential token's authority.
    EnableGuardian {
        #[command(flatten)]
        issuer: IssuerGuardianArgs,
        #[arg(long, env = "CONFIDENTIAL_TOKEN_ID")]
        confidential_token: Address,
    },
    /// Disable the confidential token's external authority.
    DisableGuardian {
        #[arg(long, env = "CONTRA_PACKAGE_ID")]
        contra_package: Address,
        #[arg(long, env = "CONFIDENTIAL_TOKEN_ID")]
        confidential_token: Address,
        #[arg(long, env = "MANAGEMENT_CAP_ID")]
        management_cap: Address,
        #[arg(long, env = "TOKEN_TYPE")]
        token_type: TypeTag,
    },
}

#[derive(Subcommand)]
enum OperatorCommand {
    /// Register an attested enclave.
    RegisterEnclave {
        #[command(flatten)]
        guardian: GuardianObjectArgs,
        /// Base64-encoded Nitro attestation document.
        #[arg(long)]
        attestation_base64: String,
    },
    /// Remove an enclave with operator authority.
    RemoveEnclave {
        #[command(flatten)]
        guardian: GuardianObjectArgs,
        #[arg(long)]
        key_index: u8,
    },
    /// Set the Guardian service URL.
    SetServiceUrl {
        #[command(flatten)]
        guardian: GuardianObjectArgs,
        #[arg(long)]
        url: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let issuer_command = matches!(&cli.command, Command::Issuer { .. });
    let wallet = if issuer_command {
        None
    } else {
        Some(load_wallet(cli.wallet, cli.rpc_url.as_deref())?)
    };
    let rpc_url = cli
        .rpc_url
        .as_deref()
        .or_else(|| wallet.as_ref().map(|wallet| wallet.rpc_url.as_str()))
        .context("--rpc-url is required when no wallet is loaded")?;
    transaction::execute(cli.command, wallet.as_ref(), rpc_url, cli.gas_budget).await
}
