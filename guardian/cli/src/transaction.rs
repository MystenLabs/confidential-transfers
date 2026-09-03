// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use fastcrypto::encoding::{Base64, Encoding, Hex};
use prost_types::value::Kind;
use sui_crypto::SuiSigner;
use sui_rpc::{
    field::{FieldMask, FieldMaskUtil},
    proto::sui::rpc::v2::{Event, ExecuteTransactionRequest, GetObjectRequest},
    Client,
};
use sui_sdk_types::{Address, Identifier, StructTag, Transaction, TypeTag};
use sui_transaction_builder::{Argument, Function, ObjectInput, TransactionBuilder};

use crate::{
    wallet::Wallet, Command, GuardianObjectArgs, IssuerCommand, OperatorCommand, PcrInput,
};

/// Transaction execute call timeout.
const EXECUTION_TIMEOUT: Duration = Duration::from_secs(60);

enum Output {
    Digest,
    Guardian,
    Enclave,
}

/// Build an unsigned issuer transaction or execute a signed transaction.
pub(crate) async fn execute(
    command: Command,
    wallet: Option<&Wallet>,
    rpc_url: &str,
    gas_budget: u64,
) -> Result<()> {
    let mut client = Client::new(rpc_url).context("invalid Sui RPC URL")?;
    let mut tx = TransactionBuilder::new();
    tx.set_gas_budget(gas_budget);
    let (signer, output) = match command {
        Command::Issuer {
            sender,
            execute,
            command,
        } => {
            tx.set_sender(sender);
            let output = match command.as_ref() {
                IssuerCommand::CreateGuardian { .. } => Output::Guardian,
                _ => Output::Digest,
            };
            match *command {
                IssuerCommand::CreateGuardian {
                    guardian_package,
                    guardian_registry,
                    management_cap,
                    confidential_token,
                    token_type,
                    pcrs,
                    operator,
                } => {
                    let pcrs = new_pcrs(&mut tx, guardian_package, pcrs)?;
                    let registry =
                        tx.object(ObjectInput::new(guardian_registry).with_mutable(true));
                    let cap = tx.object(ObjectInput::new(management_cap));
                    let token = tx.object(ObjectInput::new(confidential_token).with_mutable(true));
                    let operator = tx.pure(&operator);
                    let guardian = tx.move_call(
                        function(
                            guardian_package,
                            "guardian",
                            "new_guardian",
                            vec![token_type.clone()],
                        ),
                        vec![registry, cap, pcrs, operator],
                    );
                    tx.move_call(
                        function(
                            guardian_package,
                            "guardian",
                            "enable_authority",
                            vec![token_type.clone()],
                        ),
                        vec![token, guardian, cap],
                    );
                    tx.move_call(
                        function(guardian_package, "guardian", "share", vec![token_type]),
                        vec![guardian],
                    );
                }
                IssuerCommand::RemoveEnclave { issuer, key_index } => {
                    let GuardianObjectArgs { guardian } = issuer.guardian;
                    let (guardian_package, token_type) =
                        guardian_type(&mut client, guardian).await?;
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
                    let GuardianObjectArgs { guardian } = issuer.guardian;
                    let (guardian_package, token_type, current_min_version, current_operator) =
                        guardian_info(&mut client, guardian).await?;
                    let min_version = min_version.unwrap_or(current_min_version);
                    let operator = operator.unwrap_or(current_operator);
                    let pcrs = new_pcrs(&mut tx, guardian_package, pcrs)?;
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
                    let GuardianObjectArgs { guardian } = issuer.guardian;
                    let (guardian_package, token_type) =
                        guardian_type(&mut client, guardian).await?;
                    let token = tx.object(ObjectInput::new(confidential_token).with_mutable(true));
                    let guardian = tx.object(ObjectInput::new(guardian));
                    let cap = tx.object(ObjectInput::new(issuer.management_cap));
                    tx.move_call(
                        function(
                            guardian_package,
                            "guardian",
                            "enable_authority",
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
                            "disable_authority",
                            vec![token_type],
                        ),
                        vec![token, cap],
                    );
                }
            }
            if !execute {
                let transaction = build_transaction(tx, &mut client).await?;
                let tx_bytes = Base64::encode(bcs::to_bytes(&transaction)?);
                println!("{}", serde_json::json!({ "tx_bytes": tx_bytes }));
                return Ok(());
            }
            (sender, output)
        }
        Command::Operator { command } => {
            let register_enclave = matches!(&command, OperatorCommand::RegisterEnclave { .. });
            let guardian = match &command {
                OperatorCommand::RegisterEnclave { guardian, .. }
                | OperatorCommand::RemoveEnclave { guardian, .. }
                | OperatorCommand::SetServiceUrl { guardian, .. } => guardian.guardian,
            };
            let (guardian_package, token_type, _, operator) =
                guardian_info(&mut client, guardian).await?;
            tx.set_sender(operator);
            match command {
                OperatorCommand::RegisterEnclave {
                    guardian: _,
                    attestation_base64,
                } => {
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
                    guardian: _,
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
                }
                OperatorCommand::SetServiceUrl { guardian: _, url } => {
                    let guardian = tx.object(ObjectInput::new(guardian).with_mutable(true));
                    let url = tx.pure(&url);
                    tx.move_call(
                        function(guardian_package, "guardian", "set_url", vec![token_type]),
                        vec![guardian, url],
                    );
                }
            }
            (
                operator,
                if register_enclave {
                    Output::Enclave
                } else {
                    Output::Digest
                },
            )
        }
    };

    let transaction = build_transaction(tx, &mut client).await?;
    let wallet = wallet.context("a wallet is required to sign and execute the transaction")?;
    let signature = wallet.keypair(signer)?.sign_transaction(&transaction)?;
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
    let events = executed.events().events();
    let output = match output {
        Output::Digest => serde_json::json!({ "digest": digest }),
        Output::Guardian => {
            let guardian_id = event_struct(events, "GuardianUpdatedEvent<")
                .and_then(|event| event.fields.get("guardian_id"))
                .and_then(|id| match id.kind.as_ref()? {
                    Kind::StringValue(id) => Some(id),
                    _ => None,
                })
                .ok_or_else(|| anyhow!("Guardian ID not found in transaction events"))?;
            serde_json::json!({ "digest": digest, "guardian_id": guardian_id })
        }
        Output::Enclave => {
            let key_index = event_struct(events, "EnclaveRegisteredEvent<")
                .and_then(|event| event.fields.get("pos0"))
                .and_then(|key| match key.kind.as_ref()? {
                    Kind::StructValue(key) => key.fields.get("index"),
                    _ => None,
                })
                .and_then(|index| match index.kind.as_ref()? {
                    Kind::NumberValue(index) => Some(*index as u8),
                    _ => None,
                })
                .ok_or_else(|| anyhow!("Guardian key index not found in transaction events"))?;
            serde_json::json!({ "digest": digest, "key_index": key_index })
        }
    };
    println!("{output}");
    Ok(())
}

fn event_struct<'a>(events: &'a [Event], name: &str) -> Option<&'a prost_types::Struct> {
    events
        .iter()
        .find(|event| {
            event
                .event_type
                .as_deref()
                .is_some_and(|kind| kind.contains("::guardian::") && kind.contains(name))
        })
        .and_then(|event| match event.json.as_deref()?.kind.as_ref()? {
            Kind::StructValue(event) => Some(event),
            _ => None,
        })
}

/// Resolves transaction inputs and builds the final transaction data.
async fn build_transaction(tx: TransactionBuilder, client: &mut Client) -> Result<Transaction> {
    tx.build(client)
        .await
        .context("failed to build transaction")
}

/// Adds the Move call that constructs Guardian PCR values.
fn new_pcrs(
    tx: &mut TransactionBuilder,
    guardian_package: Address,
    pcrs: PcrInput,
) -> Result<Argument> {
    let pcr0 = tx.pure(&Hex::try_from(pcrs.pcr0)?.to_vec()?);
    let pcr1 = tx.pure(&Hex::try_from(pcrs.pcr1)?.to_vec()?);
    let pcr2 = tx.pure(&Hex::try_from(pcrs.pcr2)?.to_vec()?);
    Ok(tx.move_call(
        function(guardian_package, "guardian", "new_pcrs", vec![]),
        vec![pcr0, pcr1, pcr2],
    ))
}

/// Reads a Guardian's package and token type through Sui gRPC.
async fn guardian_type(client: &mut Client, guardian: Address) -> Result<(Address, TypeTag)> {
    let object = client
        .ledger_client()
        .get_object(
            GetObjectRequest::new(&guardian).with_read_mask(FieldMask::from_str("object_type")),
        )
        .await?
        .into_inner()
        .object
        .context("Guardian object was not returned")?;
    parse_guardian_type(
        object
            .object_type
            .as_deref()
            .context("Guardian object type was not returned")?,
    )
}

/// Reads the Guardian's type, minimum version, and operator through Sui gRPC.
async fn guardian_info(
    client: &mut Client,
    guardian: Address,
) -> Result<(Address, TypeTag, u16, Address)> {
    let object = client
        .ledger_client()
        .get_object(
            GetObjectRequest::new(&guardian)
                .with_read_mask(FieldMask::from_str("object_type,json")),
        )
        .await?
        .into_inner()
        .object
        .context("Guardian object was not returned")?;
    let (guardian_package, token_type) = parse_guardian_type(
        object
            .object_type
            .as_deref()
            .context("Guardian object type was not returned")?,
    )?;
    let fields = match object.json.context("Guardian JSON was not returned")?.kind {
        Some(Kind::StructValue(value)) => value.fields,
        _ => bail!("Guardian JSON is not an object"),
    };
    let min_version = match fields
        .get("min_version")
        .context("Guardian min_version was not returned")?
        .kind
        .as_ref()
    {
        Some(Kind::NumberValue(value))
            if value.fract() == 0.0 && *value >= 0.0 && *value <= u16::MAX.into() =>
        {
            *value as u16
        }
        Some(Kind::StringValue(value)) => value
            .parse()
            .context("Guardian min_version is not a valid u16")?,
        _ => bail!("Guardian min_version is not a valid u16"),
    };
    let operator = match fields
        .get("operator")
        .context("Guardian operator was not returned")?
        .kind
        .as_ref()
    {
        Some(Kind::StringValue(value)) => value
            .parse()
            .context("Guardian operator is not a valid address")?,
        _ => bail!("Guardian operator is not a valid address"),
    };
    Ok((guardian_package, token_type, min_version, operator))
}

/// Parses and validates the type of a `guardian::guardian::Guardian<T>` object.
fn parse_guardian_type(object_type: &str) -> Result<(Address, TypeTag)> {
    let guardian: StructTag = object_type
        .parse()
        .context("invalid Guardian object type")?;
    if guardian.module() != "guardian" || guardian.name() != "Guardian" {
        bail!("object is not a guardian::guardian::Guardian");
    }
    let [token_type] = guardian.type_params() else {
        bail!("Guardian object type must have one token type argument");
    };
    Ok((*guardian.address(), token_type.clone()))
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
