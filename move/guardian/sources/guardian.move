// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// The canonical Guardian package, deployed separately from Contra and enabled as its authority. It
/// provides an AWS Nitro enclave second factor for a `ConfidentialToken`'s protected operations. The
/// issuer creates its Guardian with `new_guardian`, which privately stores an `AuthorityCap<T>` bound
/// to its derived ID. The issuer enables it with `guardian::enable` and can disable its checks with
/// `guardian::disable`. If enabled, the client must present an enclave-signed operation digest to
/// `guardian::new_approval` to mint an approval, then pass the returned `Approval<T>` to the
/// protected operation in the same PTB.
///
/// The issuer can update PCRs, minimum version, and the operator. Only the operator can register
/// attested enclave keys; both the issuer and operator can remove them. The operator also sets the
/// service URL. During planned key rotation, old and new enclave keys should overlap for at least as
/// long as pending signatures may remain valid before the keys are removed. Raising `min_version`
/// with `update` immediately prunes every older-version key.
module guardian::guardian;

use contra::{
    authority::{Self, Approval, AuthorityCap},
    contra::{Self, ConfidentialToken, ManagementCap}
};
use std::{bcs, string::String};
use sui::{derived_object, ed25519, nitro_attestation::NitroAttestationDocument};

// === Errors ===

const ENotOperator: u64 = 0;
const EPcrMismatch: u64 = 1;
const EInvalidUserData: u64 = 2;
const ETooManyGuardianEnclaveKeys: u64 = 3;
const EInvalidMinVersion: u64 = 4;
const EEnclaveKeyNotRegistered: u64 = 5;
const EApprovalSignatureMismatch: u64 = 6;

// === Constants ===

const MAX_GUARDIAN_ENCLAVE_KEYS: u64 = 64;
const KEY_LENGTH: u64 = 32;
const REQUEST_VERSION: u16 = 1;

// === Types ===

/// The expected PCR measurements of a reproducibly built enclave image.
public struct Pcrs(vector<u8>, vector<u8>, vector<u8>) has copy, drop, store;

/// 32-byte ed25519 public key.
public struct Ed25519PublicKey(vector<u8>) has copy, drop, store;

/// 32-byte X25519 public key for sealing requests.
public struct X25519PublicKey(vector<u8>) has copy, drop, store;

/// Key used to derive this package's canonical singleton Guardian from its confidential token.
public struct GuardianKey() has copy, drop, store;

/// This separate package's canonical Guardian authority derived from a confidential token.
public struct Guardian<phantom T> has key {
    id: UID,
    /// Capability bound to this Guardian's UID using the issuer's management capability.
    /// Privately stored in the guardian object.
    authority_cap: AuthorityCap<T>,
    /// The designated operator. The issuer can replace it using `ManagementCap<T>`.
    operator: address,
    /// The URL that fronts the enclave fleet. Set and updated by the operator.
    url: String,
    /// Incremented per PCR change.
    version: u16,
    /// Keys registered below this version are pruned.
    min_version: u16,
    /// The expected enclave image measurements.
    pcrs: Pcrs,
    /// The fleet's enclave keys in `MAX_GUARDIAN_ENCLAVE_KEYS` fixed slots.
    guardian_enclave_keys: vector<Option<GuardianEnclaveKey>>,
}

/// A registered enclave key pair.
public struct GuardianEnclaveKey has copy, drop, store {
    /// Registered public key used to verify Guardian signatures.
    signing_pk: Ed25519PublicKey,
    /// Registered encryption public key for clients to seal requests to the enclave.
    enc_pk: X25519PublicKey,
    /// Guardian version at registration; pruned once `min_version` is higher.
    version: u16,
}

/// The message an enclave signs: protocol version and the digest of the checked operation.
public struct GuardianRequest has copy, drop {
    version: u16,
    digest: vector<u8>,
}

// === Events ===

/// The canonical `Guardian<T>` core configuration, emitted on creation and after `update` or
/// `set_url`.
public struct GuardianUpdatedEvent<phantom T> has copy, drop {
    guardian_id: ID,
    operator: address,
    url: String,
    version: u16,
    min_version: u16,
    pcrs: Pcrs,
}

/// An enclave key was registered for the canonical `Guardian<T>`.
public struct EnclaveRegisteredEvent<phantom T> has copy, drop {
    key_index: u8,
    key: GuardianEnclaveKey,
}

/// An enclave key was removed or pruned from the canonical `Guardian<T>`.
public struct EnclaveRemovedEvent<phantom T> has copy, drop {
    key_index: u8,
    key: GuardianEnclaveKey,
}

// === Public Functions: called by client ===

/// Given an enclave-signed operation `digest`, return `none` without checking the key or signature
/// when authority checks are disabled. Otherwise verify the signature with the selected enclave key
/// and return an `Approval<T>`. Contra reconstructs the same digest from the protected operation
/// when it consumes the approval later in the PTB. Called by the client before that operation in the
/// same PTB.
public fun new_approval<T>(
    self: &Guardian<T>,
    ct: &ConfidentialToken<T>,
    digest: vector<u8>,
    key_index: u8,
    signature: vector<u8>,
): Option<Approval<T>> {
    ct.mint_approval(&self.authority_cap, &digest).map!(|approval| {
        let key_index = key_index as u64;
        assert!(key_index < MAX_GUARDIAN_ENCLAVE_KEYS, EEnclaveKeyNotRegistered);
        let key = self
            .guardian_enclave_keys[key_index]
            .fold_ref!(abort EEnclaveKeyNotRegistered, |key| key);
        let message = bcs::to_bytes(&GuardianRequest { version: REQUEST_VERSION, digest });
        assert!(
            ed25519::ed25519_verify(&signature, &key.signing_pk.0, &message),
            EApprovalSignatureMismatch,
        );
        approval
    })
}

// === Public Functions: called by issuer ===

/// Called by the issuer to create the confidential token's canonical Guardian with the expected
/// PCRs and an operator. The `GuardianKey` derived-object slot under `ct` is claimed to ensure the
/// Guardian is created once per confidential token by this package. The Guardian privately stores
/// an `AuthorityCap<T>` bound to its derived ID. To create and enable it atomically, call `enable`
/// before `share`; otherwise share it and enable it later.
public fun new_guardian<T>(
    ct: &mut ConfidentialToken<T>,
    management_cap: &ManagementCap<T>,
    pcr0: vector<u8>,
    pcr1: vector<u8>,
    pcr2: vector<u8>,
    operator: address,
): Guardian<T> {
    let id = derived_object::claim(ct.authority_parent(management_cap), GuardianKey());
    let authority_cap = contra::new_authority_cap(&id, management_cap);
    let guardian = Guardian<T> {
        id,
        authority_cap,
        operator,
        url: b"".to_string(),
        version: 0,
        min_version: 0,
        pcrs: Pcrs(pcr0, pcr1, pcr2),
        guardian_enclave_keys: vector::tabulate!(MAX_GUARDIAN_ENCLAVE_KEYS, |_| option::none()),
    };
    guardian.emit_updated();
    guardian
}

/// Called by the issuer after `new_guardian`, optionally after enabling it in the same PTB.
public fun share<T>(guardian: Guardian<T>) {
    transfer::share_object(guardian);
}

/// Called by the issuer to enable this canonical Guardian. Only this module can borrow the
/// `AuthorityCap<T>` stored in the Guardian's private field. Enabling it replaces any other
/// authority currently enabled by Contra.
public fun enable<T>(
    ct: &mut ConfidentialToken<T>,
    guardian: &Guardian<T>,
    management_cap: &ManagementCap<T>,
) {
    ct.enable_authority(management_cap, &guardian.authority_cap);
}

/// Called by the issuer to disable this canonical Guardian without removing its ID or capability.
/// It can be enabled again later with `enable`.
public fun disable<T>(
    ct: &mut ConfidentialToken<T>,
    guardian: &Guardian<T>,
    management_cap: &ManagementCap<T>,
) {
    ct.disable_authority(management_cap, &guardian.authority_cap);
}

/// Called by the issuer to update the expected PCRs, minimum accepted version, and operator.
/// Changing the PCRs increments `version`; raising `min_version` immediately removes every key
/// registered at an older version.
public fun update<T>(
    self: &mut Guardian<T>,
    _management_cap: &ManagementCap<T>,
    pcr0: vector<u8>,
    pcr1: vector<u8>,
    pcr2: vector<u8>,
    min_version: u16,
    operator: address,
) {
    let pcrs = Pcrs(pcr0, pcr1, pcr2);
    let prune_keys = min_version > self.min_version;
    if (pcrs != self.pcrs) {
        self.pcrs = pcrs;
        self.version = self.version + 1;
    };
    assert!(min_version <= self.version, EInvalidMinVersion);
    self.min_version = min_version;
    self.operator = operator;

    if (prune_keys) {
        MAX_GUARDIAN_ENCLAVE_KEYS.do!(|index| {
            let slot = &mut self.guardian_enclave_keys[index];
            if (slot.is_some() && slot.borrow().version < min_version) {
                let key = slot.extract();
                emit_enclave_removed<T>(index as u8, key);
            };
        });
    };
    self.emit_updated();
}

/// Called by the issuer to remove the enclave key at `key_index` using its management capability.
/// During planned rotation, keep the old key through the grace period before calling this function;
/// compromised keys should be removed immediately.
public fun remove_enclave_as_issuer<T>(
    self: &mut Guardian<T>,
    _management_cap: &ManagementCap<T>,
    key_index: u8,
) {
    self.remove_enclave_key(key_index)
}

// === Public Functions: called by operator ===

/// Called by the operator to register an enclave whose attestation document matches the Guardian's
/// PCRs. The function parses `signing_pk || enc_pk` from `user_data` and stores the key pair in the
/// lowest free slot.
public fun register_enclave<T>(
    self: &mut Guardian<T>,
    document: NitroAttestationDocument,
    ctx: &mut TxContext,
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
    let (key_index, key) = self.insert_key(signing_pk, enc_pk);
    sui::event::emit(EnclaveRegisteredEvent<T> { key_index, key });
}

/// Called by the operator to remove the enclave key at `key_index`. During planned rotation, keep
/// the old key through the grace period before calling this function; compromised keys should be
/// removed immediately.
public fun remove_enclave<T>(self: &mut Guardian<T>, key_index: u8, ctx: &mut TxContext) {
    assert!(ctx.sender() == self.operator, ENotOperator);
    self.remove_enclave_key(key_index)
}

/// Called by the operator to update the enclave fleet URL.
public fun set_url<T>(self: &mut Guardian<T>, url: String, ctx: &mut TxContext) {
    assert!(ctx.sender() == self.operator, ENotOperator);
    self.url = url;
    self.emit_updated();
}

// === Internal Functions ===

fun remove_enclave_key<T>(self: &mut Guardian<T>, key_index: u8) {
    let key_index = key_index as u64;
    assert!(key_index < MAX_GUARDIAN_ENCLAVE_KEYS, EEnclaveKeyNotRegistered);
    let slot = &mut self.guardian_enclave_keys[key_index];
    assert!(slot.is_some(), EEnclaveKeyNotRegistered);
    let key = slot.extract();
    emit_enclave_removed<T>(key_index as u8, key);
}

/// Parse `user_data`: `signing_pk || enc_pk`, 32 bytes each.
fun parse_user_data(user_data: vector<u8>): (Ed25519PublicKey, X25519PublicKey) {
    assert!(user_data.length() == 2 * KEY_LENGTH, EInvalidUserData);
    (Ed25519PublicKey(user_data.take(KEY_LENGTH)), X25519PublicKey(user_data.skip(KEY_LENGTH)))
}

/// Insert at the lowest free slot and stamp the key with the current version. Abort when all
/// `MAX_GUARDIAN_ENCLAVE_KEYS` slots are occupied.
fun insert_key<T>(
    self: &mut Guardian<T>,
    signing_pk: Ed25519PublicKey,
    enc_pk: X25519PublicKey,
): (u8, GuardianEnclaveKey) {
    let index = self
        .guardian_enclave_keys
        .find_index!(|slot| slot.is_none())
        .destroy_or!(abort ETooManyGuardianEnclaveKeys);
    let key = GuardianEnclaveKey { signing_pk, enc_pk, version: self.version };
    self.guardian_enclave_keys[index].fill(key);
    (index as u8, key)
}

fun emit_enclave_removed<T>(key_index: u8, key: GuardianEnclaveKey) {
    sui::event::emit(EnclaveRemovedEvent<T> { key_index, key });
}

fun emit_updated<T>(self: &Guardian<T>) {
    sui::event::emit(GuardianUpdatedEvent<T> {
        guardian_id: self.id.to_inner(),
        operator: self.operator,
        url: self.url,
        version: self.version,
        min_version: self.min_version,
        pcrs: self.pcrs,
    });
}

// === Test Helpers ===

#[test_only]
public(package) fun new_guardian_request_for_testing(digest: vector<u8>): GuardianRequest {
    GuardianRequest { version: REQUEST_VERSION, digest }
}

#[test_only]
public(package) fun parse_user_data_for_testing(user_data: vector<u8>): (vector<u8>, vector<u8>) {
    let (signing_pk, enc_pk) = parse_user_data(user_data);
    (signing_pk.0, enc_pk.0)
}

#[test_only]
public(package) fun new_guardian_for_testing<T>(
    pcr0: vector<u8>,
    pcr1: vector<u8>,
    pcr2: vector<u8>,
    operator: address,
    ctx: &mut TxContext,
): Guardian<T> {
    let id = object::new(ctx);
    let authority_cap = authority::new_authority_cap_for_testing(id.to_inner());
    let guardian = Guardian<T> {
        id,
        authority_cap,
        operator,
        url: b"".to_string(),
        version: 0,
        min_version: 0,
        pcrs: Pcrs(pcr0, pcr1, pcr2),
        guardian_enclave_keys: vector::tabulate!(MAX_GUARDIAN_ENCLAVE_KEYS, |_| option::none()),
    };
    guardian.emit_updated();
    guardian
}

#[test_only]
public(package) fun operator<T>(self: &Guardian<T>): address { self.operator }

#[test_only]
public(package) fun url<T>(self: &Guardian<T>): &String { &self.url }

#[test_only]
public(package) fun version<T>(self: &Guardian<T>): u16 { self.version }

#[test_only]
public(package) fun min_version<T>(self: &Guardian<T>): u16 { self.min_version }

#[test_only]
public(package) fun pcrs<T>(self: &Guardian<T>): (vector<u8>, vector<u8>, vector<u8>) {
    (self.pcrs.0, self.pcrs.1, self.pcrs.2)
}

#[test_only]
public(package) fun contains_guardian_enclave_key<T>(self: &Guardian<T>, key_index: u8): bool {
    let key_index = key_index as u64;
    key_index < MAX_GUARDIAN_ENCLAVE_KEYS && self.guardian_enclave_keys[key_index].is_some()
}

/// Register the enclave without the attestation document or operator gate; returns its slot.
#[test_only]
public(package) fun register_guardian_enclave_key_for_testing<T>(
    self: &mut Guardian<T>,
    signing_pk: vector<u8>,
    enc_pk: vector<u8>,
): u8 {
    assert!(signing_pk.length() == KEY_LENGTH && enc_pk.length() == KEY_LENGTH, EInvalidUserData);
    let (key_index, _) = self.insert_key(Ed25519PublicKey(signing_pk), X25519PublicKey(enc_pk));
    key_index
}
