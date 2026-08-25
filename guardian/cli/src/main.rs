// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{Parser, Subcommand, ValueEnum};
use move_package_alt_compilation::build_config::BuildConfig as MoveBuildConfig;
use prost_types::{value::Kind, Value};
use serde::{Deserialize, Serialize};
use sui_crypto::{simple::SimpleKeypair, SuiSigner};
use sui_move_build::BuildConfig;
use sui_package_alt::{mainnet_environment, testnet_environment, SuiFlavor};
use sui_rpc::{
    field::{FieldMask, FieldMaskUtil},
    proto::sui::rpc::v2::{ExecuteTransactionRequest, ExecutedTransaction},
    Client,
};
use sui_sdk_types::{Address, Identifier, TypeTag};
use sui_transaction_builder::{Function, ObjectInput, TransactionBuilder};

const DEFAULT_GAS_BUDGET: u64 = 100_000_000;
const EXECUTION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Parser)]
#[command(about = "Operate a Contra Guardian without the Sui CLI")]
struct Cli {
    /// Sui client configuration containing the active environment and keystore path.
    #[arg(long)]
    wallet: Option<PathBuf>,
    /// Override the wallet's active address.
    #[arg(long)]
    active_address: Option<Address>,
    /// Override the RPC URL from the wallet's active environment.
    #[arg(long)]
    rpc_url: Option<String>,
    #[arg(long, default_value_t = DEFAULT_GAS_BUDGET)]
    gas_budget: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Publish {
        package_path: PathBuf,
        #[arg(long)]
        build_env: Option<BuildEnvironment>,
    },
    Create {
        #[arg(long)]
        guardian_package: Address,
        #[arg(long)]
        management_cap: Address,
        #[arg(long)]
        token_type: TypeTag,
        #[arg(long, value_parser = parse_hex)]
        pcr0: Vec<u8>,
        #[arg(long, value_parser = parse_hex)]
        pcr1: Vec<u8>,
        #[arg(long, value_parser = parse_hex)]
        pcr2: Vec<u8>,
        #[arg(long)]
        operator: Address,
    },
    RegisterEnclave {
        #[arg(long)]
        guardian_package: Address,
        #[arg(long)]
        guardian: Address,
        #[arg(long)]
        token_type: TypeTag,
        #[arg(long)]
        attestation_base64: String,
    },
    RemoveEnclave {
        #[arg(long)]
        guardian_package: Address,
        #[arg(long)]
        guardian: Address,
        #[arg(long)]
        token_type: TypeTag,
        #[arg(long)]
        key_index: u8,
    },
    SetUrl {
        #[arg(long)]
        guardian_package: Address,
        #[arg(long)]
        guardian: Address,
        #[arg(long)]
        token_type: TypeTag,
        #[arg(long)]
        url: String,
    },
    Update {
        #[arg(long)]
        guardian_package: Address,
        #[arg(long)]
        guardian: Address,
        #[arg(long)]
        management_cap: Address,
        #[arg(long)]
        token_type: TypeTag,
        #[arg(long, value_parser = parse_hex)]
        pcr0: Vec<u8>,
        #[arg(long, value_parser = parse_hex)]
        pcr1: Vec<u8>,
        #[arg(long, value_parser = parse_hex)]
        pcr2: Vec<u8>,
        #[arg(long)]
        min_version: u16,
        #[arg(long)]
        operator: Address,
    },
    Enable {
        #[arg(long)]
        guardian_package: Address,
        #[arg(long)]
        guardian: Address,
        #[arg(long)]
        confidential_token: Address,
        #[arg(long)]
        management_cap: Address,
        #[arg(long)]
        token_type: TypeTag,
    },
    Disable {
        #[arg(long)]
        contra_package: Address,
        #[arg(long)]
        confidential_token: Address,
        #[arg(long)]
        management_cap: Address,
        #[arg(long)]
        token_type: TypeTag,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum BuildEnvironment {
    Mainnet,
    Testnet,
}

#[derive(Deserialize)]
struct WalletConfig {
    keystore: KeystoreConfig,
    envs: Vec<Environment>,
    active_env: String,
    active_address: Address,
}

#[derive(Deserialize)]
enum KeystoreConfig {
    File(PathBuf),
}

#[derive(Deserialize)]
struct Environment {
    alias: String,
    rpc: String,
}

struct Wallet {
    keypair: SimpleKeypair,
    address: Address,
    rpc_url: String,
    active_env: String,
}

#[derive(Serialize)]
struct Output<'a> {
    digest: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guardian_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_index: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let wallet = load_wallet(cli.wallet, cli.active_address, cli.rpc_url.as_deref())?;
    let mut client = Client::new(&wallet.rpc_url).context("invalid Sui RPC URL")?;
    let mut tx = TransactionBuilder::new();
    tx.set_sender(wallet.address);
    tx.set_gas_budget(cli.gas_budget);

    let output_kind = match cli.command {
        Command::Publish {
            package_path,
            build_env,
        } => {
            let environment =
                build_env.unwrap_or_else(|| infer_build_environment(&wallet.active_env));
            let package = build_package(&package_path, environment)?;
            let modules = package.get_package_bytes(false);
            let dependencies = package
                .dependency_ids
                .published
                .into_values()
                .map(|dependency| dependency.published_at.to_string().parse())
                .collect::<Result<Vec<Address>, _>>()?;
            let cap = tx.publish(modules, dependencies);
            let recipient = tx.pure(&wallet.address);
            tx.transfer_objects(vec![cap], recipient);
            OutputKind::Package
        }
        Command::Create {
            guardian_package,
            management_cap,
            token_type,
            pcr0,
            pcr1,
            pcr2,
            operator,
        } => {
            let pcr0 = tx.pure(&pcr0);
            let pcr1 = tx.pure(&pcr1);
            let pcr2 = tx.pure(&pcr2);
            let pcrs = tx.move_call(
                function(guardian_package, "guardian", "new_pcrs", vec![]),
                vec![pcr0, pcr1, pcr2],
            );
            let cap = tx.object(ObjectInput::new(management_cap));
            let operator = tx.pure(&operator);
            tx.move_call(
                function(
                    guardian_package,
                    "guardian",
                    "new_guardian",
                    vec![token_type],
                ),
                vec![cap, pcrs, operator],
            );
            OutputKind::Guardian
        }
        Command::RegisterEnclave {
            guardian_package,
            guardian,
            token_type,
            attestation_base64,
        } => {
            let bytes = BASE64
                .decode(attestation_base64)
                .context("invalid attestation base64")?;
            let bytes = tx.pure(&bytes);
            let randomness = tx.object(ObjectInput::new(Address::from_static("0x6")));
            let document = tx.move_call(
                function(
                    Address::TWO,
                    "nitro_attestation",
                    "load_nitro_attestation",
                    vec![],
                ),
                vec![bytes, randomness],
            );
            let guardian = tx.object(ObjectInput::new(guardian).with_mutable(true));
            tx.move_call(
                function(
                    guardian_package,
                    "guardian",
                    "register_enclave",
                    vec![token_type],
                ),
                vec![guardian, document],
            );
            OutputKind::KeyIndex
        }
        Command::RemoveEnclave {
            guardian_package,
            guardian,
            token_type,
            key_index,
        } => {
            let guardian = tx.object(ObjectInput::new(guardian).with_mutable(true));
            let key_index = tx.pure(&key_index);
            tx.move_call(
                function(
                    guardian_package,
                    "guardian",
                    "remove_enclave",
                    vec![token_type],
                ),
                vec![guardian, key_index],
            );
            OutputKind::Plain
        }
        Command::SetUrl {
            guardian_package,
            guardian,
            token_type,
            url,
        } => {
            let guardian = tx.object(ObjectInput::new(guardian).with_mutable(true));
            let url = tx.pure(&url);
            tx.move_call(
                function(guardian_package, "guardian", "set_url", vec![token_type]),
                vec![guardian, url],
            );
            OutputKind::Plain
        }
        Command::Update {
            guardian_package,
            guardian,
            management_cap,
            token_type,
            pcr0,
            pcr1,
            pcr2,
            min_version,
            operator,
        } => {
            let pcr0 = tx.pure(&pcr0);
            let pcr1 = tx.pure(&pcr1);
            let pcr2 = tx.pure(&pcr2);
            let pcrs = tx.move_call(
                function(guardian_package, "guardian", "new_pcrs", vec![]),
                vec![pcr0, pcr1, pcr2],
            );
            let guardian = tx.object(ObjectInput::new(guardian).with_mutable(true));
            let cap = tx.object(ObjectInput::new(management_cap));
            let min_version = tx.pure(&min_version);
            let operator = tx.pure(&operator);
            tx.move_call(
                function(guardian_package, "guardian", "update", vec![token_type]),
                vec![guardian, cap, pcrs, min_version, operator],
            );
            OutputKind::Plain
        }
        Command::Enable {
            guardian_package,
            guardian,
            confidential_token,
            management_cap,
            token_type,
        } => {
            let token = tx.object(ObjectInput::new(confidential_token).with_mutable(true));
            let guardian = tx.object(ObjectInput::new(guardian));
            let cap = tx.object(ObjectInput::new(management_cap));
            tx.move_call(
                function(
                    guardian_package,
                    "guardian",
                    "set_authority",
                    vec![token_type],
                ),
                vec![token, guardian, cap],
            );
            OutputKind::Plain
        }
        Command::Disable {
            contra_package,
            confidential_token,
            management_cap,
            token_type,
        } => {
            let token = tx.object(ObjectInput::new(confidential_token).with_mutable(true));
            let cap = tx.object(ObjectInput::new(management_cap));
            tx.move_call(
                function(
                    contra_package,
                    "contra",
                    "unset_authority_ref",
                    vec![token_type],
                ),
                vec![token, cap],
            );
            OutputKind::Plain
        }
    };

    let executed = execute(&mut client, &wallet.keypair, tx).await?;
    print_output(&executed, output_kind)
}

#[derive(Clone, Copy)]
enum OutputKind {
    Plain,
    Package,
    Guardian,
    KeyIndex,
}

fn function(package: Address, module: &str, name: &str, type_args: Vec<TypeTag>) -> Function {
    Function::new(
        package,
        Identifier::from_str(module).expect("static module name is valid"),
        Identifier::from_str(name).expect("static function name is valid"),
    )
    .with_type_args(type_args)
}

async fn execute(
    client: &mut Client,
    keypair: &SimpleKeypair,
    tx: TransactionBuilder,
) -> Result<ExecutedTransaction> {
    let transaction = tx
        .build(client)
        .await
        .context("failed to build transaction")?;
    let signature = keypair.sign_transaction(&transaction)?;
    let response = client
        .execute_transaction_and_wait_for_checkpoint(
            ExecuteTransactionRequest::new(transaction.into())
                .with_signatures(vec![signature.into()])
                .with_read_mask(FieldMask::from_str("*")),
            EXECUTION_TIMEOUT,
        )
        .await?
        .into_inner();
    let executed = response
        .transaction
        .ok_or_else(|| anyhow!("RPC response omitted transaction"))?;
    let status = executed.effects().status();
    if !status.success() {
        bail!(
            "transaction failed: {}",
            status
                .error()
                .description
                .as_deref()
                .unwrap_or("unknown execution error")
        );
    }
    Ok(executed)
}

fn print_output(executed: &ExecutedTransaction, kind: OutputKind) -> Result<()> {
    let digest = executed
        .digest
        .as_deref()
        .ok_or_else(|| anyhow!("RPC response omitted transaction digest"))?;
    let mut output = Output {
        digest,
        package_id: None,
        guardian_id: None,
        key_index: None,
    };
    match kind {
        OutputKind::Plain => {}
        OutputKind::Package => {
            output.package_id = Some(find_created_object(executed, |kind| kind == "package")?);
        }
        OutputKind::Guardian => {
            output.guardian_id = Some(find_created_object(executed, |kind| {
                kind.contains("::guardian::Guardian<")
            })?);
        }
        OutputKind::KeyIndex => {
            output.key_index = Some(find_event_index(executed)?);
        }
    }
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn find_created_object<F>(executed: &ExecutedTransaction, predicate: F) -> Result<&str>
where
    F: Fn(&str) -> bool,
{
    let created_ids = executed
        .effects()
        .changed_objects()
        .iter()
        .filter(|object| {
            object.id_operation()
                == sui_rpc::proto::sui::rpc::v2::changed_object::IdOperation::Created
        })
        .filter_map(|object| object.object_id.as_deref())
        .collect::<Vec<_>>();
    executed
        .objects()
        .objects()
        .iter()
        .find(|object| {
            object
                .object_id
                .as_deref()
                .is_some_and(|id| created_ids.contains(&id))
                && object.object_type.as_deref().is_some_and(&predicate)
        })
        .and_then(|object| object.object_id.as_deref())
        .ok_or_else(|| anyhow!("created object not found in transaction response"))
}

fn find_event_index(executed: &ExecutedTransaction) -> Result<u64> {
    executed
        .events()
        .events()
        .iter()
        .filter(|event| {
            event
                .event_type
                .as_deref()
                .is_some_and(|kind| kind.contains("::guardian::EnclaveRegisteredEvent<"))
        })
        .find_map(|event| {
            event
                .json
                .as_deref()
                .and_then(|json| find_json_u64(json, "index"))
        })
        .ok_or_else(|| anyhow!("Guardian key index not found in transaction events"))
}

fn find_json_u64(value: &Value, field: &str) -> Option<u64> {
    match value.kind.as_ref()? {
        Kind::StructValue(object) => {
            object.fields.get(field).and_then(value_as_u64).or_else(|| {
                object
                    .fields
                    .values()
                    .find_map(|value| find_json_u64(value, field))
            })
        }
        Kind::ListValue(list) => list
            .values
            .iter()
            .find_map(|value| find_json_u64(value, field)),
        _ => None,
    }
}

fn value_as_u64(value: &Value) -> Option<u64> {
    match value.kind.as_ref()? {
        Kind::NumberValue(number) if number.fract() == 0.0 && *number >= 0.0 => {
            Some(*number as u64)
        }
        Kind::StringValue(number) => number.parse().ok(),
        _ => None,
    }
}

fn load_wallet(
    wallet_path: Option<PathBuf>,
    address: Option<Address>,
    rpc_url: Option<&str>,
) -> Result<Wallet> {
    let wallet_path = wallet_path.unwrap_or_else(default_wallet_path);
    let config: WalletConfig = serde_yaml::from_str(
        &fs::read_to_string(&wallet_path)
            .with_context(|| format!("failed to read {}", wallet_path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", wallet_path.display()))?;
    let address = address.unwrap_or(config.active_address);
    let KeystoreConfig::File(keystore_path) = config.keystore;
    let keys: Vec<String> = serde_json::from_str(
        &fs::read_to_string(&keystore_path)
            .with_context(|| format!("failed to read {}", keystore_path.display()))?,
    )?;
    let keypair = keys
        .iter()
        .filter_map(|key| parse_keypair(key).ok())
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
        active_env: config.active_env,
    })
}

fn parse_keypair(value: &str) -> Result<SimpleKeypair> {
    if value.starts_with("suiprivkey") {
        Ok(SimpleKeypair::from_suiprivkey(value)?)
    } else {
        Ok(SimpleKeypair::from_base64(value)?)
    }
}

fn default_wallet_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sui/sui_config/client.yaml")
}

fn infer_build_environment(active_env: &str) -> BuildEnvironment {
    if active_env == "mainnet" {
        BuildEnvironment::Mainnet
    } else {
        BuildEnvironment::Testnet
    }
}

fn build_package(
    path: &Path,
    environment: BuildEnvironment,
) -> Result<sui_move_build::CompiledPackage> {
    let environment = match environment {
        BuildEnvironment::Mainnet => mainnet_environment(),
        BuildEnvironment::Testnet => testnet_environment(),
    };
    BuildConfig {
        config: MoveBuildConfig {
            root_as_zero: true,
            ..Default::default()
        },
        run_bytecode_verifier: true,
        print_diags_to_stderr: true,
        environment,
        flavor: SuiFlavor::new(),
    }
    .build(path)
    .with_context(|| format!("failed to build Move package at {}", path.display()))
}

fn parse_hex(value: &str) -> Result<Vec<u8>, String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err("must be non-empty, even-length hexadecimal".to_owned());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).map_err(|error| error.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prefixed_and_unprefixed_hex() {
        assert_eq!(parse_hex("0x00aF").unwrap(), vec![0, 175]);
        assert_eq!(parse_hex("cafe").unwrap(), vec![202, 254]);
    }

    #[test]
    fn finds_nested_numeric_and_string_indices() {
        let numeric = object([("key", object([("index", scalar(Kind::NumberValue(3.0)))]))]);
        let string = object([("index", scalar(Kind::StringValue("12".to_owned())))]);
        assert_eq!(find_json_u64(&numeric, "index"), Some(3));
        assert_eq!(find_json_u64(&string, "index"), Some(12));
    }

    #[test]
    fn rejects_invalid_hex() {
        assert!(parse_hex("").is_err());
        assert!(parse_hex("abc").is_err());
        assert!(parse_hex("zz").is_err());
    }

    fn scalar(kind: Kind) -> Value {
        Value { kind: Some(kind) }
    }

    fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
        scalar(Kind::StructValue(prost_types::Struct {
            fields: fields
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value))
                .collect(),
        }))
    }
}
