// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Guardian module (design: `guardian/README.md`).
///
/// When a `GuardianPolicy` is set on a `ConfidentialToken<T>`, every transfer and
/// unwrap must carry a `GuardianApproval` signed by a registered enclave.
///
/// The issuer (`ManagementCap`) owns the policy and can set and update `pcrs`,
/// `min_version`, and the operator address.
///
/// The operator runs a proxy at endpoint (`url`) that points to multiple enclave
/// instances offchain. Each registers onchain with `{ signing_pk, enc_pk }`. The
/// operator can update url, register or remove enclave keys.
module contra::guardian;

use contra::twisted_elgamal::{Encryption, PublicKey};
use std::{bcs, string::String};
use sui::{ed25519, nitro_attestation::NitroAttestationDocument, vec_map::{Self, VecMap}};

// === Errors ===

const ENotOperator: u64 = 0;
const EPcrMismatch: u64 = 1;
const EInvalidUserData: u64 = 2;
const ETooManyGuardianEnclaveKeys: u64 = 3;
const EInvalidMinVersion: u64 = 4;
const EInvalidKeyLength: u64 = 5;

/// The approval's signing key is not registered in `guardian_enclave_keys`.
const EApprovalKeyNotRegistered: u64 = 6;
/// The signature does not verify over the BCS payload.
const EApprovalSignatureMismatch: u64 = 7;

// === Constants ===

/// Maximum number of enclave keys a policy may hold.
const MAX_GUARDIAN_ENCLAVE_KEYS: u64 = 10;

const KEY_LENGTH: u64 = 32;
const SIGNATURE_LENGTH: u64 = 64;

// === Types ===

/// PCRs: reproducible image binary.
public struct Pcrs(vector<u8>, vector<u8>, vector<u8>) has copy, drop, store;

/// 32-byte ed25519 public key.
public struct Ed25519PublicKey(vector<u8>) has copy, drop, store;

/// 64-byte ed25519 signature.
public struct Ed25519Signature(vector<u8>) has copy, drop, store;

/// 32-byte X25519 public key for sealing requests.
public struct X25519PublicKey(vector<u8>) has copy, drop, store;

/// Guardian configuration for one confidential token, set as
/// `Option<GuardianPolicy>` on the `ConfidentialToken`.
public struct GuardianPolicy has copy, drop, store {
    /// The designed operator. Can be updated by the issuer.
    operator: address,
    /// The url that fronts the fleet of enclaves. Can be updated by the operator.
    url: String,
    /// Incremented per PCR change.
    version: u16,
    /// Min version of registered. If bumped the old enclave keys are pruned.
    min_version: u16,
    /// The expected enclave image measurements.
    pcrs: Pcrs,
    /// A list enclave keys for the fleet, keyed by `signing_pk`.
    guardian_enclave_keys: VecMap<Ed25519PublicKey, GuardianEnclaveKey>,
}

/// Registered enclave keys.
public struct GuardianEnclaveKey has copy, drop, store {
    signing_pk: Ed25519PublicKey,
    enc_pk: X25519PublicKey,
    /// Policy version at registration. If `min_version` is
    /// bumped greater than this, this enclave will be removed.
    version: u16,
}

/// An enclave's ed25519 signature over the BCS `RequestPayload` and the
/// `signing_pk` that produced it.
public struct GuardianApproval has copy, drop {
    signing_pk: Ed25519PublicKey,
    signature: Ed25519Signature,
}

/// The request payload that the enclave signature is verified against.
public enum RequestPayload has copy, drop {
    Transfer {
        sender_pk: PublicKey,
        receiver_pks: vector<PublicKey>,
        old_encrypted_balance: Encryption,
        new_encrypted_balance: Encryption,
        encrypted_amounts: vector<Encryption>,
    },
    Unwrap {
        sender_pk: PublicKey,
        old_encrypted_balance: Encryption,
        new_encrypted_balance: Encryption,
        amount: u64,
    },
}

// === Public Functions ===

public fun new_guardian_approval(signing_pk: vector<u8>, signature: vector<u8>): GuardianApproval {
    GuardianApproval {
        signing_pk: new_ed25519_public_key(signing_pk),
        signature: new_ed25519_signature(signature),
    }
}

public fun new_pcrs(pcr0: vector<u8>, pcr1: vector<u8>, pcr2: vector<u8>): Pcrs {
    Pcrs(pcr0, pcr1, pcr2)
}

// === Package Functions ===

public(package) fun new(pcrs: Pcrs, operator: address): GuardianPolicy {
    GuardianPolicy {
        operator,
        url: b"".to_string(), // set by operator later.
        version: 0,
        min_version: 0,
        pcrs,
        guardian_enclave_keys: vec_map::empty(),
    }
}

/// Called by the issuer in `contra.move`.
/// Update `pcrs`, `min_version`, or `operator` address on the policy.
/// If pcrs are updated, `version` is bumped. If `min_version` is bumped,
/// all keys of older versions are pruned.
public(package) fun update(
    self: &mut GuardianPolicy,
    pcrs: Pcrs,
    min_version: u16,
    operator: address,
): vector<GuardianEnclaveKey> {
    if (pcrs != self.pcrs) {
        self.pcrs = pcrs;
        self.version = self.version + 1;
    };

    assert!(min_version <= self.version, EInvalidMinVersion);
    self.min_version = min_version;

    self.operator = operator;

    let mut pruned = vector[];
    self.guardian_enclave_keys.keys().do!(|pk| {
        if (self.guardian_enclave_keys.get(&pk).version < min_version) {
            let (_, key) = self.guardian_enclave_keys.remove(&pk);
            pruned.push_back(key);
        };
    });
    pruned
}

/// Called by the operator in `contra.move`.
/// Load the valid attestation document. Check pcrs against the policy,
/// parse and insert the keys.
public(package) fun register_enclave(
    self: &mut GuardianPolicy,
    document: NitroAttestationDocument,
    ctx: &TxContext,
): GuardianEnclaveKey {
    assert!(ctx.sender() == self.operator, ENotOperator);

    let entries = document.pcrs();
    assert!(
        entries[0].index() == 0 && *entries[0].value() == self.pcrs.0 &&
        entries[1].index() == 1 && *entries[1].value() == self.pcrs.1 &&
        entries[2].index() == 2 && *entries[2].value() == self.pcrs.2,
        EPcrMismatch,
    );
    let (signing_pk, enc_pk) = parse_user_data((*document.user_data()).destroy_some());
    self.insert_key(signing_pk, enc_pk)
}

/// Called by the operator in `contra.move`.
/// Remove the enclave key at `signing_pk` and return it.
public(package) fun remove_enclave(
    self: &mut GuardianPolicy,
    signing_pk: vector<u8>,
    ctx: &TxContext,
): GuardianEnclaveKey {
    assert!(ctx.sender() == self.operator, ENotOperator);
    let (_, key) = self.guardian_enclave_keys.remove(&new_ed25519_public_key(signing_pk));
    key
}

/// Called by the operator in `contra.move`.
/// Update the url for the enclave fleet.
public(package) fun set_url(self: &mut GuardianPolicy, url: String, ctx: &TxContext) {
    assert!(ctx.sender() == self.operator, ENotOperator);
    self.url = url;
}

/// Assert the guardian approval signed this transfer. Verifies the signature against payload.
public(package) fun assert_transfer_approval(
    self: &GuardianPolicy,
    approval: &GuardianApproval,
    sender_pk: PublicKey,
    receiver_pks: vector<PublicKey>,
    old_encrypted_balance: Encryption,
    new_encrypted_balance: Encryption,
    encrypted_amounts: vector<Encryption>,
) {
    self.assert_approval(
        approval,
        &RequestPayload::Transfer {
            sender_pk,
            receiver_pks,
            old_encrypted_balance,
            new_encrypted_balance,
            encrypted_amounts,
        },
    )
}

/// Assert `approval` signs this unwrap. Verifies the signature against payload.
public(package) fun assert_unwrap_approval(
    self: &GuardianPolicy,
    approval: &GuardianApproval,
    sender_pk: PublicKey,
    old_encrypted_balance: Encryption,
    new_encrypted_balance: Encryption,
    amount: u64,
) {
    self.assert_approval(
        approval,
        &RequestPayload::Unwrap { sender_pk, old_encrypted_balance, new_encrypted_balance, amount },
    )
}

/// Parse `user_data`: `signing_pk || enc_pk`, 32 bytes each.
public(package) fun parse_user_data(user_data: vector<u8>): (Ed25519PublicKey, X25519PublicKey) {
    assert!(user_data.length() == 2 * KEY_LENGTH, EInvalidUserData);
    (
        new_ed25519_public_key(user_data.take(KEY_LENGTH)),
        new_x25519_public_key(user_data.skip(KEY_LENGTH)),
    )
}

// === Dev Helpers ===

/// TODO: DEV ONLY CONVENIENCE TESTING FUNCTION. REMOVE FOR PRODUCTION.
/// Register an enclave key without an attestation document.
public(package) fun register_guardian_enclave_key_for_dev(
    self: &mut GuardianPolicy,
    signing_pk: vector<u8>,
    enc_pk: vector<u8>,
    ctx: &TxContext,
): GuardianEnclaveKey {
    assert!(ctx.sender() == self.operator, ENotOperator);
    self.insert_key(new_ed25519_public_key(signing_pk), new_x25519_public_key(enc_pk))
}

// === Internal Functions ===

fun new_ed25519_public_key(bytes: vector<u8>): Ed25519PublicKey {
    assert!(bytes.length() == KEY_LENGTH, EInvalidKeyLength);
    Ed25519PublicKey(bytes)
}

fun new_ed25519_signature(bytes: vector<u8>): Ed25519Signature {
    assert!(bytes.length() == SIGNATURE_LENGTH, EInvalidKeyLength);
    Ed25519Signature(bytes)
}

fun new_x25519_public_key(bytes: vector<u8>): X25519PublicKey {
    assert!(bytes.length() == KEY_LENGTH, EInvalidKeyLength);
    X25519PublicKey(bytes)
}

/// Helper function to assert approval on payload (transfer or unwrap).
fun assert_approval(self: &GuardianPolicy, approval: &GuardianApproval, payload: &RequestPayload) {
    assert!(self.guardian_enclave_keys.contains(&approval.signing_pk), EApprovalKeyNotRegistered);
    assert!(
        ed25519::ed25519_verify(
            &approval.signature.0,
            &approval.signing_pk.0,
            &bcs::to_bytes(payload),
        ),
        EApprovalSignatureMismatch,
    );
}

/// Insert the enclave keys with current policy version.
fun insert_key(
    self: &mut GuardianPolicy,
    signing_pk: Ed25519PublicKey,
    enc_pk: X25519PublicKey,
): GuardianEnclaveKey {
    assert!(
        self.guardian_enclave_keys.length() < MAX_GUARDIAN_ENCLAVE_KEYS,
        ETooManyGuardianEnclaveKeys,
    );
    let key = GuardianEnclaveKey { signing_pk, enc_pk, version: self.version };
    self.guardian_enclave_keys.insert(signing_pk, key);
    key
}

// === Test Helpers ===

#[test_only]
public fun operator(self: &GuardianPolicy): address { self.operator }

#[test_only]
public fun url(self: &GuardianPolicy): &String { &self.url }

#[test_only]
public fun version(self: &GuardianPolicy): u16 { self.version }

#[test_only]
public fun min_version(self: &GuardianPolicy): u16 { self.min_version }

#[test_only]
public fun pcrs(self: &GuardianPolicy): &Pcrs { &self.pcrs }

#[test_only]
public fun ed25519_public_key_bytes(pk: &Ed25519PublicKey): &vector<u8> { &pk.0 }

#[test_only]
public fun x25519_public_key_bytes(pk: &X25519PublicKey): &vector<u8> { &pk.0 }

#[test_only]
public use fun ed25519_public_key_bytes as Ed25519PublicKey.bytes;
#[test_only]
public use fun x25519_public_key_bytes as X25519PublicKey.bytes;

#[test_only]
public fun contains_guardian_enclave_key(self: &GuardianPolicy, signing_pk: vector<u8>): bool {
    self.guardian_enclave_keys.contains(&new_ed25519_public_key(signing_pk))
}

/// Register the enclave without the attestation document.
#[test_only]
public fun register_guardian_enclave_key_for_testing(
    self: &mut GuardianPolicy,
    signing_pk: vector<u8>,
    enc_pk: vector<u8>,
) {
    self.insert_key(new_ed25519_public_key(signing_pk), new_x25519_public_key(enc_pk));
}

// Constructors: `RequestPayload` can only be packed in its defining module, so
// the serde pin tests in `guardian_tests` build payloads through these.

#[test_only]
public fun new_transfer_request_payload(
    sender_pk: PublicKey,
    receiver_pks: vector<PublicKey>,
    old_encrypted_balance: Encryption,
    new_encrypted_balance: Encryption,
    encrypted_amounts: vector<Encryption>,
): RequestPayload {
    RequestPayload::Transfer {
        sender_pk,
        receiver_pks,
        old_encrypted_balance,
        new_encrypted_balance,
        encrypted_amounts,
    }
}

#[test_only]
public fun new_unwrap_request_payload(
    sender_pk: PublicKey,
    old_encrypted_balance: Encryption,
    new_encrypted_balance: Encryption,
    amount: u64,
): RequestPayload {
    RequestPayload::Unwrap { sender_pk, old_encrypted_balance, new_encrypted_balance, amount }
}
