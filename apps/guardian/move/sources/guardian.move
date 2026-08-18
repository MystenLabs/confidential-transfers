// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// The issuer may deploy an additional guardian to a `ConfidentialToken`.
/// The issuer runs `contra::set_policy<T, GuardianWitness>([TRANSFER, UNWRAP])`
/// to enable or disable it. Client may pass a guardian approval to
/// `guardian::authorize_transfer` / `authorize_unwrap`, which verify an enclave
/// signature over the operation and mint an `Auth` bound to its digest.
///
/// The issuer creates the `GuardianRegistry<T>` and can update `pcrs`,
/// `min_version` and the operator; the operator sets `url` and can
/// register/remove enclave keys.
module guardian::guardian;

use contra::{
    contra::{Self, Account, Binding, ConfidentialToken, ManagementCap},
    encrypted_amount::EncryptedAmount,
    policy::Auth,
    twisted_elgamal::{Encryption, PublicKey, public_key}
};
use std::{bcs, string::String};
use sui::{
    ed25519,
    hash::blake2b256,
    nitro_attestation::NitroAttestationDocument,
    vec_map::{Self, VecMap}
};

// === Errors ===

const ENotOperator: u64 = 0;
const EPcrMismatch: u64 = 1;
const EInvalidUserData: u64 = 2;
const ETooManyGuardianEnclaveKeys: u64 = 3;
const EInvalidMinVersion: u64 = 4;
const EInvalidKeyLength: u64 = 5;
/// The approval's `key_index` has no registered enclave.
const EApprovalKeyNotRegistered: u64 = 6;
/// The signature does not verify over the BCS `GuardianRequest`.
const EApprovalSignatureMismatch: u64 = 7;

// === Constants ===

const MAX_GUARDIAN_ENCLAVE_KEYS: u8 = 10;
const KEY_LENGTH: u64 = 32;
const SIGNATURE_LENGTH: u64 = 64;
const REQUEST_VERSION: u16 = 1;

/// Maps to `contra`'s operation indices.
const PERMISSIONED_UNWRAP: u8 = 2;
const PERMISSIONED_TRANSFER: u8 = 3;

// === Types ===

public struct GuardianWitness has drop {}

/// PCRs: reproducible image binary.
public struct Pcrs(vector<u8>, vector<u8>, vector<u8>) has copy, drop, store;

/// 32-byte ed25519 public key.
public struct Ed25519PublicKey(vector<u8>) has copy, drop, store;

/// 64-byte ed25519 signature.
public struct Ed25519Signature(vector<u8>) has copy, drop, store;

/// 32-byte X25519 public key for sealing requests.
public struct X25519PublicKey(vector<u8>) has copy, drop, store;

/// The guardian fleet configuration for a confidential token, a shared object created by
/// the token's issuer.
public struct GuardianRegistry<phantom T> has key {
    id: UID,
    /// The designated operator. Can be updated by the issuer (`ManagementCap<T>` holder).
    operator: address,
    /// The url that fronts the fleet of enclaves. Can be updated by the operator.
    url: String,
    /// Incremented per PCR change.
    version: u16,
    /// Keys registered below this version are pruned.
    min_version: u16,
    /// The expected enclave image measurements.
    pcrs: Pcrs,
    /// The fleet's enclave keys, keyed by a slot index.
    guardian_enclave_keys: VecMap<u8, GuardianEnclaveKey>,
}

/// Registered enclave keys.
public struct GuardianEnclaveKey has copy, drop, store {
    index: u8,
    signing_pk: Ed25519PublicKey,
    enc_pk: X25519PublicKey,
    /// Registry version at registration; pruned once `min_version` is higher.
    version: u16,
}

/// The message an enclave signs: version and the digest of a given payload.
public struct GuardianRequest has copy, drop {
    version: u16,
    digest: vector<u8>,
}

/// An enclave's ed25519 signature over the BCS `GuardianRequest`, and the
/// slot index of the key that produced it.
public struct GuardianApproval has copy, drop {
    key_index: u8,
    signature: Ed25519Signature,
}

// === Events ===

public struct RegistryUpdatedEvent<phantom T> has copy, drop {
    operator: address,
    url: String,
    version: u16,
    min_version: u16,
    pcrs: Pcrs,
}
public struct EnclaveRegisteredEvent<phantom T>(GuardianEnclaveKey) has copy, drop;
public struct EnclaveRemovedEvent<phantom T>(GuardianEnclaveKey) has copy, drop;

// === Public Functions: constructors ===

public fun new_guardian_approval(key_index: u8, signature: vector<u8>): GuardianApproval {
    GuardianApproval { key_index, signature: new_ed25519_signature(signature) }
}

public fun new_pcrs(pcr0: vector<u8>, pcr1: vector<u8>, pcr2: vector<u8>): Pcrs {
    Pcrs(pcr0, pcr1, pcr2)
}

/// The digest `contra` binds the auth to: blake2b256 of the BCS payload.
fun digest(binding: &Binding): vector<u8> {
    blake2b256(&bcs::to_bytes(binding))
}

use fun digest as Binding.digest;

/// The message an enclave must sign to approve `payload`.
public fun new_guardian_request(binding: &Binding): GuardianRequest {
    GuardianRequest { version: REQUEST_VERSION, digest: binding.digest() }
}

// === Public Functions: authorization called by client ===

/// Verify that a registered enclave approved exactly this transfer and mint the `Auth<T>`
/// that binds to the digest. The receiver keys, amounts and new balance must be the ones
/// then passed to `batched_transfer`.
public fun authorize_transfer<T>(
    self: &GuardianRegistry<T>,
    ct: &ConfidentialToken<T>,
    sender: &Account,
    receiver_pks: vector<PublicKey>,
    receiver_amounts: vector<EncryptedAmount>,
    new_balance: EncryptedAmount,
    approval: GuardianApproval,
): Auth<T> {
    let binding = contra::transfer_binding(
        public_key(sender.token_public_key<T>()),
        receiver_pks,
        sender.balance<T>(),
        &new_balance,
        &receiver_amounts,
    );
    self.assert_approval(&approval, &binding);
    ct.authorize_with_witness_bound<T, GuardianWitness>(
        PERMISSIONED_TRANSFER,
        sender.owner(),
        binding.digest(),
        GuardianWitness {},
    )
}

/// Verify that a registered enclave approved exactly this unwrap and mint the `Auth<T>`
/// that binds to the digest.
public fun authorize_unwrap<T>(
    self: &GuardianRegistry<T>,
    ct: &ConfidentialToken<T>,
    account: &Account,
    new_balance: EncryptedAmount,
    amount: u64,
    approval: GuardianApproval,
): Auth<T> {
    let binding = contra::unwrap_binding(
        public_key(account.token_public_key<T>()),
        account.balance<T>(),
        &new_balance,
        amount,
    );
    self.assert_approval(&approval, &binding);
    ct.authorize_with_witness_bound<T, GuardianWitness>(
        PERMISSIONED_UNWRAP,
        account.owner(),
        binding.digest(),
        GuardianWitness {},
    )
}

// === Public Functions: issuer ===

/// Create and share the registry for token `T`. Enforcement starts once the issuer runs
/// `contra::set_policy<T, GuardianWitness>`.
public fun new_registry<T>(
    _cap: &ManagementCap<T>,
    pcrs: Pcrs,
    operator: address,
    ctx: &mut TxContext,
) {
    let registry = GuardianRegistry<T> {
        id: object::new(ctx),
        operator,
        url: b"".to_string(), // set by operator later.
        version: 0,
        min_version: 0,
        pcrs,
        guardian_enclave_keys: vec_map::empty(),
    };
    registry.emit_updated();
    transfer::share_object(registry);
}

/// A changed `pcrs` bumps `version`; raising `min_version` prunes every key
/// stamped below it.
public fun update<T>(
    self: &mut GuardianRegistry<T>,
    _cap: &ManagementCap<T>,
    pcrs: Pcrs,
    min_version: u16,
    operator: address,
) {
    if (pcrs != self.pcrs) {
        self.pcrs = pcrs;
        self.version = self.version + 1;
    };
    assert!(min_version <= self.version, EInvalidMinVersion);
    self.min_version = min_version;
    self.operator = operator;

    self.guardian_enclave_keys.keys().do!(|index| {
        if (self.guardian_enclave_keys.get(&index).version < min_version) {
            let (_, key) = self.guardian_enclave_keys.remove(&index);
            sui::event::emit(EnclaveRemovedEvent<T>(key));
        };
    });
    self.emit_updated();
}

// === Public Functions: operator ===

/// Operator-only. Verify the attestation document's PCRs against the registry, parse
/// `{ signing_pk, enc_pk }` from its `user_data`, and register the key at the lowest free slot.
public fun register_enclave<T>(
    self: &mut GuardianRegistry<T>,
    document: NitroAttestationDocument,
    ctx: &TxContext,
) {
    assert!(ctx.sender() == self.operator, ENotOperator);
    let entries = document.pcrs();
    assert!(
        entries[0].index() == 0 && *entries[0].value() == self.pcrs.0 &&
        entries[1].index() == 1 && *entries[1].value() == self.pcrs.1 &&
        entries[2].index() == 2 && *entries[2].value() == self.pcrs.2,
        EPcrMismatch,
    );
    let user_data = document.user_data();
    assert!(user_data.is_some(), EInvalidUserData);
    let (signing_pk, enc_pk) = parse_user_data(*user_data.borrow());
    let key = self.insert_key(signing_pk, enc_pk);
    sui::event::emit(EnclaveRegisteredEvent<T>(key));
}

/// Operator-only. Remove the enclave key at slot `key_index`.
public fun remove_enclave<T>(self: &mut GuardianRegistry<T>, key_index: u8, ctx: &TxContext) {
    assert!(ctx.sender() == self.operator, ENotOperator);
    let (_, key) = self.guardian_enclave_keys.remove(&key_index);
    sui::event::emit(EnclaveRemovedEvent<T>(key));
}

/// Operator-only. Update the url for the enclave fleet.
public fun set_url<T>(self: &mut GuardianRegistry<T>, url: String, ctx: &TxContext) {
    assert!(ctx.sender() == self.operator, ENotOperator);
    self.url = url;
    self.emit_updated();
}

// === Dev Helpers ===

/// TODO: DEV ONLY CONVENIENCE TESTING FUNCTION. REMOVE FOR PRODUCTION.
/// Operator-only. Register an enclave key without an attestation document.
public fun register_enclave_for_dev<T>(
    self: &mut GuardianRegistry<T>,
    signing_pk: vector<u8>,
    enc_pk: vector<u8>,
    ctx: &TxContext,
) {
    assert!(ctx.sender() == self.operator, ENotOperator);
    let key = self.insert_key(new_ed25519_public_key(signing_pk), new_x25519_public_key(enc_pk));
    sui::event::emit(EnclaveRegisteredEvent<T>(key));
}

// === Package Functions ===

/// Parse `user_data`: `signing_pk || enc_pk`, 32 bytes each.
fun parse_user_data(user_data: vector<u8>): (Ed25519PublicKey, X25519PublicKey) {
    assert!(user_data.length() == 2 * KEY_LENGTH, EInvalidUserData);
    (
        new_ed25519_public_key(user_data.take(KEY_LENGTH)),
        new_x25519_public_key(user_data.skip(KEY_LENGTH)),
    )
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

/// The approval's key must be registered and its signature must verify over the BCS
/// `GuardianRequest` for `payload`.
fun assert_approval<T>(self: &GuardianRegistry<T>, approval: &GuardianApproval, binding: &Binding) {
    assert!(self.guardian_enclave_keys.contains(&approval.key_index), EApprovalKeyNotRegistered);
    let key = &self.guardian_enclave_keys[&approval.key_index];
    let message = bcs::to_bytes(&new_guardian_request(binding));
    assert!(
        ed25519::ed25519_verify(&approval.signature.0, &key.signing_pk.0, &message),
        EApprovalSignatureMismatch,
    );
}

/// Insert at the lowest free slot, stamped with the current version. Aborts when all slots till
/// MAX_GUARDIAN_ENCLAVE_KEYS are taken.
fun insert_key<T>(
    self: &mut GuardianRegistry<T>,
    signing_pk: Ed25519PublicKey,
    enc_pk: X25519PublicKey,
): GuardianEnclaveKey {
    let mut free = option::none();
    MAX_GUARDIAN_ENCLAVE_KEYS.do!(|i| {
        if (free.is_none() && !self.guardian_enclave_keys.contains(&i)) free.fill(i);
    });
    assert!(free.is_some(), ETooManyGuardianEnclaveKeys);
    let index = free.extract();
    let key = GuardianEnclaveKey { index, signing_pk, enc_pk, version: self.version };
    self.guardian_enclave_keys.insert(index, key);
    key
}

fun emit_updated<T>(self: &GuardianRegistry<T>) {
    sui::event::emit(RegistryUpdatedEvent<T> {
        operator: self.operator,
        url: self.url,
        version: self.version,
        min_version: self.min_version,
        pcrs: self.pcrs,
    });
}

// === Test Helpers ===

#[test_only]
public fun parse_user_data_for_testing(user_data: vector<u8>): (vector<u8>, vector<u8>) {
    let (signing_pk, enc_pk) = parse_user_data(user_data);
    (signing_pk.0, enc_pk.0)
}

#[test_only]
public fun new_registry_for_testing<T>(
    pcrs: Pcrs,
    operator: address,
    ctx: &mut TxContext,
): GuardianRegistry<T> {
    GuardianRegistry<T> {
        id: object::new(ctx),
        operator,
        url: b"".to_string(),
        version: 0,
        min_version: 0,
        pcrs,
        guardian_enclave_keys: vec_map::empty(),
    }
}

#[test_only]
public fun operator<T>(self: &GuardianRegistry<T>): address { self.operator }

#[test_only]
public fun url<T>(self: &GuardianRegistry<T>): &String { &self.url }

#[test_only]
public fun version<T>(self: &GuardianRegistry<T>): u16 { self.version }

#[test_only]
public fun min_version<T>(self: &GuardianRegistry<T>): u16 { self.min_version }

#[test_only]
public fun pcrs<T>(self: &GuardianRegistry<T>): &Pcrs { &self.pcrs }

#[test_only]
public fun contains_guardian_enclave_key<T>(self: &GuardianRegistry<T>, key_index: u8): bool {
    self.guardian_enclave_keys.contains(&key_index)
}

/// Register the enclave without the attestation document or operator gate; returns its slot.
#[test_only]
public fun register_guardian_enclave_key_for_testing<T>(
    self: &mut GuardianRegistry<T>,
    signing_pk: vector<u8>,
    enc_pk: vector<u8>,
): u8 {
    self.insert_key(new_ed25519_public_key(signing_pk), new_x25519_public_key(enc_pk)).index
}

/// Verify `approval` over `payload` directly (the transfer/unwrap authorizers' inner check).
#[test_only]
public fun assert_approval_for_testing<T>(
    self: &GuardianRegistry<T>,
    approval: &GuardianApproval,
    binding: &Binding,
) {
    self.assert_approval(approval, binding)
}
