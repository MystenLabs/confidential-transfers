// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use fastcrypto::encoding::{Base64, Encoding, Hex};
use prost_types::value::Kind;
use sui_crypto::SuiSigner;
use sui_rpc::{
    field::{FieldMask, FieldMaskUtil},
    proto::sui::rpc::v2::{ExecuteTransactionRequest, GetObjectRequest},
    Client,
};
use sui_sdk_types::{Address, Identifier, TypeTag};
use sui_transaction_builder::{Function, ObjectInput, TransactionBuilder};

use crate::{wallet::Wallet, Command, GuardianObjectArgs, IssuerCommand, OperatorCommand};

/// Transaction execute call timeout.
const EXECUTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Build an unsigned issuer transaction or execute a signed operator transaction.
pub(crate) async fn execute(
    command: Command,
    wallet: Option<&Wallet>,
    rpc_url: &str,
    gas_budget: u64,
) -> Result<()> {
    let mut client = Client::new(rpc_url).context("invalid Sui RPC URL")?;
    let mut tx = TransactionBuilder::new();
    tx.set_gas_budget(gas_budget);
    let issuer_command = matches!(&command, Command::Issuer { .. });
    let register_enclave = matches!(
        &command,
        Command::Operator {
            command: OperatorCommand::RegisterEnclave { .. }
        }
    );

    match command {
        Command::Issuer { sender, command } => {
            tx.set_sender(sender);
            match command {
                IssuerCommand::CreateGuardian {
                    guardian_package,
                    management_cap,
                    token_type,
                    pcrs,
                    operator,
                } => {
                    let pcr0 = tx.pure(&Hex::try_from(pcrs.pcr0)?.to_vec()?);
                    let pcr1 = tx.pure(&Hex::try_from(pcrs.pcr1)?.to_vec()?);
                    let pcr2 = tx.pure(&Hex::try_from(pcrs.pcr2)?.to_vec()?);
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
                }
                IssuerCommand::RemoveEnclave { issuer, key_index } => {
                    let GuardianObjectArgs {
                        guardian_package,
                        guardian,
                        token_type,
                    } = issuer.guardian;
                    let guardian = tx.object(ObjectInput::new(guardian).with_mutable(true));
                    let cap = tx.object(ObjectInput::new(issuer.management_cap));
                    let key_index = tx.pure(&key_index);
                    tx.move_call(
                        function(
                            guardian_package,
                            "guardian",
                            "remove_enclave_as_issuer",
                            vec![token_type],
                        ),
                        vec![guardian, cap, key_index],
                    );
                }
                IssuerCommand::UpdateGuardian {
                    issuer,
                    pcrs,
                    min_version,
                    operator,
                } => {
                    let GuardianObjectArgs {
                        guardian_package,
                        guardian,
                        token_type,
                    } = issuer.guardian;
                    let min_version = match min_version {
                        Some(min_version) => min_version,
                        None => current_min_version(&mut client, guardian).await?,
                    };
                    let pcr0 = tx.pure(&Hex::try_from(pcrs.pcr0)?.to_vec()?);
                    let pcr1 = tx.pure(&Hex::try_from(pcrs.pcr1)?.to_vec()?);
                    let pcr2 = tx.pure(&Hex::try_from(pcrs.pcr2)?.to_vec()?);
                    let pcrs = tx.move_call(
                        function(guardian_package, "guardian", "new_pcrs", vec![]),
                        vec![pcr0, pcr1, pcr2],
                    );
                    let guardian = tx.object(ObjectInput::new(guardian).with_mutable(true));
                    let cap = tx.object(ObjectInput::new(issuer.management_cap));
                    let min_version = tx.pure(&min_version);
                    let operator = tx.pure(&operator);
                    tx.move_call(
                        function(guardian_package, "guardian", "update", vec![token_type]),
                        vec![guardian, cap, pcrs, min_version, operator],
                    );
                }
                IssuerCommand::EnableGuardian {
                    issuer,
                    confidential_token,
                } => {
                    let GuardianObjectArgs {
                        guardian_package,
                        guardian,
                        token_type,
                    } = issuer.guardian;
                    let token = tx.object(ObjectInput::new(confidential_token).with_mutable(true));
                    let guardian = tx.object(ObjectInput::new(guardian));
                    let cap = tx.object(ObjectInput::new(issuer.management_cap));
                    tx.move_call(
                        function(
                            guardian_package,
                            "guardian",
                            "set_authority",
                            vec![token_type],
                        ),
                        vec![token, guardian, cap],
                    );
                }
                IssuerCommand::DisableGuardian {
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
                }
            }
        }
        Command::Operator { command } => {
            tx.set_sender(
                wallet
                    .context("operator commands require a wallet")?
                    .address,
            );
            match command {
                OperatorCommand::RegisterEnclave {
                    guardian,
                    attestation_base64,
                } => {
                    let GuardianObjectArgs {
                        guardian_package,
                        guardian,
                        token_type,
                    } = guardian;
                    let bytes = Base64::decode(&attestation_base64)
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
                }
                OperatorCommand::RemoveEnclave {
                    guardian,
                    key_index,
                } => {
                    let GuardianObjectArgs {
                        guardian_package,
                        guardian,
                        token_type,
                    } = guardian;
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
                }
                OperatorCommand::SetServiceUrl { guardian, url } => {
                    let GuardianObjectArgs {
                        guardian_package,
                        guardian,
                        token_type,
                    } = guardian;
                    let guardian = tx.object(ObjectInput::new(guardian).with_mutable(true));
                    let url = tx.pure(&url);
                    tx.move_call(
                        function(guardian_package, "guardian", "set_url", vec![token_type]),
                        vec![guardian, url],
                    );
                }
            }
        }
    }

    let transaction = tx
        .build(&mut client)
        .await
        .context("failed to build transaction")?;
    if issuer_command {
        let tx_bytes = Base64::encode(bcs::to_bytes(&transaction)?);
        println!("{}", serde_json::json!({ "tx_bytes": tx_bytes }));
        return Ok(());
    }
    let wallet = wallet.context("a wallet is required to sign and execute the transaction")?;
    let signature = wallet.keypair.sign_transaction(&transaction)?;
    let response = client
        .execute_transaction_and_wait_for_checkpoint(
            ExecuteTransactionRequest::new(transaction.into())
                .with_signatures(vec![signature.into()])
                .with_read_mask(FieldMask::from_paths([
                    "digest",
                    "effects.status",
                    "events.events.event_type",
                    "events.events.json",
                ])),
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
    let digest = executed
        .digest
        .as_deref()
        .ok_or_else(|| anyhow!("RPC response omitted transaction digest"))?;
    if !register_enclave {
        println!("{}", serde_json::json!({ "digest": digest }));
        return Ok(());
    }
    let key_index = executed
        .events()
        .events()
        .iter()
        .find(|event| {
            event
                .event_type
                .as_deref()
                .is_some_and(|kind| kind.contains("::guardian::EnclaveRegisteredEvent<"))
        })
        .and_then(|event| match event.json.as_deref()?.kind.as_ref()? {
            Kind::StructValue(event) => event.fields.get("pos0"),
            _ => None,
        })
        .and_then(|key| match key.kind.as_ref()? {
            Kind::StructValue(key) => key.fields.get("index"),
            _ => None,
        })
        .and_then(|index| match index.kind.as_ref()? {
            Kind::NumberValue(number) if number.fract() == 0.0 && *number >= 0.0 => {
                Some(*number as u64)
            }
            Kind::StringValue(number) => number.parse().ok(),
            _ => None,
        })
        .ok_or_else(|| anyhow!("Guardian key index not found in transaction events"))?;
    println!(
        "{}",
        serde_json::json!({ "digest": digest, "key_index": key_index })
    );
    Ok(())
}

/// Reads the Guardian's current minimum enclave version through Sui gRPC.
async fn current_min_version(client: &mut Client, guardian: Address) -> Result<u16> {
    let object = client
        .ledger_client()
        .get_object(GetObjectRequest::new(&guardian).with_read_mask(FieldMask::from_str("json")))
        .await?
        .into_inner()
        .object
        .context("Guardian object was not returned")?;
    let fields = match object.json.context("Guardian JSON was not returned")?.kind {
        Some(Kind::StructValue(value)) => value.fields,
        _ => bail!("Guardian JSON is not an object"),
    };
    match fields
        .get("min_version")
        .context("Guardian min_version was not returned")?
        .kind
        .as_ref()
    {
        Some(Kind::NumberValue(value))
            if value.fract() == 0.0 && *value >= 0.0 && *value <= u16::MAX.into() =>
        {
            Ok(*value as u16)
        }
        Some(Kind::StringValue(value)) => value
            .parse()
            .context("Guardian min_version is not a valid u16"),
        _ => bail!("Guardian min_version is not a valid u16"),
    }
}

/// Constructs a Move function reference from compile-time module and function names.
fn function(
    package: Address,
    module: &'static str,
    name: &'static str,
    type_args: Vec<TypeTag>,
) -> Function {
    Function::new(
        package,
        Identifier::from_static(module),
        Identifier::from_static(name),
    )
    .with_type_args(type_args)
}
