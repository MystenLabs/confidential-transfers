// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Seal a self-consistent transfer to the local fleet's keys, POST it through the proxy,
//! and verify the returned signature onchain via `contra::verify_transfer_approval_for_dev`
//!
//!   # reads PACKAGE_ID, TOKEN_ID and TOKEN_TYPE from the environment; the serving
//!   # url and the fleet's enc_pks come from the token's onchain guardian policy:
//!   source guardian/.fleet/issuer.env
//!   cargo run -p contra-guardian-enclave --example process_request \
//!       --no-default-features --features non-enclave-dev

use anyhow::Context;
use contra_guardian_core::sealing::seal_to_all;
use contra_guardian_core::testing::transfer_request;
use contra_guardian_core::types::UnsealedRequest;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::twisted_elgamal::{Ciphertext, PublicKey};
use serde::Deserialize;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_crypto::SuiSigner;
use sui_rpc::field::{FieldMask, FieldMaskUtil};
use sui_rpc::proto::sui::rpc::v2::{ExecuteTransactionRequest, GetObjectRequest};
use sui_rpc::Client;
use sui_sdk_types::{Address, Identifier, TypeTag};
use sui_transaction_builder::{Function, ObjectInput, TransactionBuilder};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let rpc = std::env::var("SUI_RPC").unwrap_or_else(|_| "http://127.0.0.1:9000".into());
    let mut client = Client::new(rpc)?;
    let (url, enc_pks) = guardian_policy(&mut client).await?;
    println!("policy: {} registered keys at {url}", enc_pks.len());

    let req = transfer_request();
    let sealed = seal_to_all(&enc_pks, &req)?;
    println!(
        "sealed 1 request into {} envelopes; POST {url}/process_request",
        sealed.sealed.len()
    );
    let resp: serde_json::Value = ureq::post(&format!("{url}/process_request"))
        .send_bytes(&bcs::to_bytes(&sealed)?)?
        .into_json()?;
    let b64 = |name: &str| -> anyhow::Result<Vec<u8>> {
        Base64::decode(
            resp[name]
                .as_str()
                .with_context(|| format!("missing {name}"))?,
        )
        .map_err(|e| anyhow::anyhow!("bad base64 in {name}: {e}"))
    };
    let (signing_pk, signature) = (b64("signing_pk")?, b64("signature")?);

    println!("signed by 0x{}", Hex::encode(&signing_pk));
    submit_onchain(&mut client, &req, &signing_pk, &signature).await
}

/// Submits payload and guardian approval onchain.
async fn submit_onchain(
    client: &mut Client,
    req: &UnsealedRequest,
    signing_pk: &[u8],
    signature: &[u8],
) -> anyhow::Result<()> {
    let package: Address = std::env::var("PACKAGE_ID")?.parse()?;
    let token: Address = std::env::var("TOKEN_ID")?.parse()?;
    let token_type: TypeTag = std::env::var("TOKEN_TYPE")?.parse()?;

    let UnsealedRequest::TransferRequest {
        old_encrypted_balance,
        new_encrypted_balance,
        recipients,
        x_a,
        ..
    } = req
    else {
        unreachable!()
    };

    let signer = active_address_key()?;

    let mut tx = TransactionBuilder::new();
    tx.set_sender(signer.public_key().derive_address());
    let point_bytes = |p: &RistrettoPoint| p.to_byte_array().to_vec();
    let call = |module: &str, name: &str| {
        Function::new(
            package,
            Identifier::new(module).expect("valid module"),
            Identifier::new(name).expect("valid function"),
        )
    };
    // Build each with `contra::decode` and collect the amounts.
    let sender_arg = tx.pure(&point_bytes(PublicKey::from(x_a).as_point()));
    let sender_pk = tx.move_call(
        Function::new(
            Address::TWO,
            Identifier::new("ristretto255")?,
            Identifier::new("g_from_bytes")?,
        ),
        vec![sender_arg],
    );
    let receivers: Vec<Vec<u8>> = recipients
        .iter()
        .map(|r| point_bytes(r.receiver_pk.as_point()))
        .collect();
    let receivers_arg = tx.pure(&receivers);
    let receiver_pks = tx.move_call(call("decode", "g_vector"), vec![receivers_arg]);

    let encryption = |c: &Ciphertext, tx: &mut TransactionBuilder| {
        let parts = vec![
            point_bytes(&c.commitment().0),
            point_bytes(c.decryption_handle()),
        ];
        let arg = tx.pure(&parts);
        tx.move_call(call("decode", "encryption"), vec![arg])
    };
    let old_balance = encryption(old_encrypted_balance, &mut tx);
    let new_balance = encryption(new_encrypted_balance, &mut tx);
    let amount_args: Vec<_> = recipients
        .iter()
        .map(|r| encryption(&r.encrypted_amount, &mut tx))
        .collect();
    let encryption_type: TypeTag = format!("{package}::twisted_elgamal::Encryption").parse()?;
    let amounts = tx.make_move_vec(Some(encryption_type), amount_args);

    let signing_pk_arg = tx.pure(&signing_pk.to_vec());
    let signature_arg = tx.pure(&signature.to_vec());
    let approval = tx.move_call(
        call("guardian", "new_guardian_approval"),
        vec![signing_pk_arg, signature_arg],
    );
    let token_arg = tx.object(ObjectInput::shared(token, 0, false));
    tx.move_call(
        call("contra", "verify_transfer_approval_for_dev").with_type_args(vec![token_type]),
        vec![
            token_arg,
            sender_pk,
            receiver_pks,
            old_balance,
            new_balance,
            amounts,
            approval,
        ],
    );

    let tx = tx.build(client).await?;
    let signature = signer.sign_transaction(&tx)?;
    let response = client
        .execute_transaction_and_wait_for_checkpoint(
            ExecuteTransactionRequest::new(tx.into())
                .with_signatures(vec![signature.into()])
                .with_read_mask(FieldMask::from_str("*")),
            std::time::Duration::from_secs(20),
        )
        .await?
        .into_inner();
    anyhow::ensure!(
        response.transaction().effects().status().success(),
        "onchain verification failed: {:?}",
        response.transaction().effects().status()
    );
    println!(
        "onchain verify_transfer_approval_for_dev succeeded in tx {}",
        response.transaction().digest()
    );
    Ok(())
}

/// The JSON rendering of a Move newtype over `vector<u8>`, whose single positional field
/// is named `pos0` and carries the bytes as base64.
#[derive(Deserialize)]
struct MoveBytes {
    pos0: String,
}

/// Read the serving url and all registered `enc_pks` from the token's onchain policy.
async fn guardian_policy(client: &mut Client) -> anyhow::Result<(String, Vec<[u8; 32]>)> {
    let token: Address = std::env::var("TOKEN_ID")?.parse()?;
    let object = client
        .ledger_client()
        .get_object(GetObjectRequest::new(&token).with_read_mask(FieldMask::from_str("json")))
        .await?
        .into_inner();
    let json = serde_json::to_value(sui_rpc::_serde::ValueSerializer(
        object.object().json.as_ref().context("no json rendering")?,
    ))?;
    let policy = json
        .pointer("/guardian")
        .context("token has no guardian policy; run bootstrap.sh")?;
    let url = policy["url"]
        .as_str()
        .context("policy has no url")?
        .to_string();
    let enc_pks = policy["guardian_enclave_keys"]["contents"]
        .as_array()
        .context("policy has no registered keys")?
        .iter()
        .map(|entry| {
            let enc_pk: MoveBytes = serde_json::from_value(entry["value"]["enc_pk"].clone())
                .context("key entry has no enc_pk")?;
            Base64::decode(&enc_pk.pos0)
                .map_err(|e| anyhow::anyhow!("enc_pk is not base64: {e}"))?
                .try_into()
                .map_err(|_| anyhow::anyhow!("enc_pk is not 32 bytes"))
        })
        .collect::<anyhow::Result<Vec<[u8; 32]>>>()?;
    Ok((url, enc_pks))
}

/// Locate the private key for the CLI wallet's active address.
fn active_address_key() -> anyhow::Result<Ed25519PrivateKey> {
    let config = std::path::PathBuf::from(std::env::var("HOME")?).join(".sui/sui_config");
    let active = std::fs::read_to_string(config.join("client.yaml"))?
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("active_address:")
                .map(str::trim)
                .map(str::to_string)
        })
        .context("no active_address in client.yaml")?
        .trim_matches('"')
        .to_string();
    let keys: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(config.join("sui.keystore"))?)?;
    keys.iter()
        .filter_map(|k| Ed25519PrivateKey::from_base64(k).ok())
        .find(|k| k.public_key().derive_address().to_string() == active)
        .with_context(|| format!("no ed25519 key for active address {active}"))
}
