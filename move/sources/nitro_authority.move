// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Contra's canonical AWS Nitro enclave authority, providing an optional approval factor in
/// addition to the zero-knowledge proofs required by a `ConfidentialToken`'s protected operations.
/// The issuer creates its `NitroAuthority<T>` with `new`, enables it by calling
/// `contra::enable_authority` with `AuthorityKind::Nitro`, and can disable its checks with
/// `contra::disable_authority`. If enabled, the client must present an enclave-signed operation
/// digest to `nitro_authority::new_approval` to mint an approval, then pass the returned
/// `Option<Approval<T>>` to the protected operation in the same PTB.
///
/// The issuer can update PCRs, minimum version, and the operator. Only the operator can register
/// attested enclave keys; both the issuer and operator can remove them. The operator also sets the
/// service URL. During planned key rotation, old and new enclave keys should overlap for at least as
/// long as pending signatures may remain valid before the keys are removed. Raising `min_version`
/// with `update` immediately prunes every older-version key.
module contra::nitro_authority;

use contra::{authority::Approval, contra::{Self, ConfidentialToken, ManagementCap}};
use std::{bcs, string::String};
use sui::{derived_object, ed25519, nitro_attestation::NitroAttestationDocument};

// === Errors ===

const ENotOperator: u64 = 0;
const EPcrMismatch: u64 = 1;
const EInvalidUserData: u64 = 2;
const ETooManyNitroAuthorityEnclaveKeys: u64 = 3;
const EInvalidMinVersion: u64 = 4;
const EEnclaveKeyNotRegistered: u64 = 5;
const EApprovalSignatureMismatch: u64 = 6;

// === Constants ===

const MAX_NITRO_AUTHORITY_ENCLAVE_KEYS: u64 = 64;
const KEY_LENGTH: u64 = 32;

// === Types ===

/// The expected PCR measurements of a reproducibly built enclave image.
public struct Pcrs(vector<u8>, vector<u8>, vector<u8>) has copy, drop, store;

/// 32-byte ed25519 public key.
public struct Ed25519PublicKey(vector<u8>) has copy, drop, store;

/// 32-byte X25519 public key for sealing requests.
public struct X25519PublicKey(vector<u8>) has copy, drop, store;

/// Key used to derive the canonical singleton `NitroAuthority<T>` from its confidential token.
public struct NitroAuthorityKey() has copy, drop, store;

/// Contra's canonical AWS Nitro enclave authority derived from a confidential token.
public struct NitroAuthority<phantom T> has key {
    id: UID,
    /// The designated operator. The issuer can replace it using `ManagementCap<T>`.
    operator: address,
    /// The URL that fronts the enclave fleet. Set and updated by the operator.
    url: String,
    /// Incremented per PCR change.
    version: u16,
    /// Enclaves registered below this version are pruned on PCRs update.
    min_version: u16,
    /// The expected enclave image measurements.
    pcrs: Pcrs,
    /// The fleet's enclave keys in `MAX_NITRO_AUTHORITY_ENCLAVE_KEYS` fixed slots.
    nitro_authority_enclave_keys: vector<Option<NitroAuthorityEnclaveKey>>,
}

/// A registered enclave key pair.
public struct NitroAuthorityEnclaveKey has copy, drop, store {
    /// Registered public key used to verify Nitro authority signatures.
    signing_pk: Ed25519PublicKey,
    /// Registered encryption public key for clients to seal requests to the enclave.
    enc_pk: X25519PublicKey,
    /// Nitro authority version at registration; pruned once `min_version` is higher.
    version: u16,
}

/// The versioned message an enclave signs. Add a new variant when the signed payload changes.
public enum NitroAuthorityRequest has copy, drop {
    V1 { digest: vector<u8> },
}

// === Events ===

/// The canonical `NitroAuthority<T>` core configuration, emitted on creation and after `update` or
/// `set_url`.
public struct NitroAuthorityUpdatedEvent<phantom T> has copy, drop {
    nitro_authority_id: ID,
    operator: address,
    url: String,
    version: u16,
    min_version: u16,
    pcrs: Pcrs,
}

/// An enclave key was registered for the canonical `NitroAuthority<T>`.
public struct EnclaveRegisteredEvent<phantom T> has copy, drop {
    key_index: u8,
    key: NitroAuthorityEnclaveKey,
}

/// An enclave key was removed or pruned from the canonical `NitroAuthority<T>`.
public struct EnclaveRemovedEvent<phantom T> has copy, drop {
    key_index: u8,
    key: NitroAuthorityEnclaveKey,
}

// === Public Functions: called by issuer ===

/// Create the confidential token's canonical `NitroAuthority<T>` with the expected PCRs and an
/// operator. The issuer calls this public function using its `ManagementCap<T>`, which restricts
/// creation to the issuer. Contra claims a derived-object slot under `ct` to ensure this package can
/// create the authority only once per confidential token. The issuer may call
/// `contra::enable_authority` with `AuthorityKind::Nitro` in the same PTB before `share`, or enable
/// it later.
public fun new<T>(
    ct: &mut ConfidentialToken<T>,
    management_cap: &ManagementCap<T>,
    pcr0: vector<u8>,
    pcr1: vector<u8>,
    pcr2: vector<u8>,
    operator: address,
): NitroAuthority<T> {
    let id = derived_object::claim(ct.authority_parent(management_cap), NitroAuthorityKey());
    let nitro_authority = NitroAuthority<T> {
        id,
        operator,
        url: b"".to_string(), // Set by operator later.
        version: 0,
        min_version: 0,
        pcrs: Pcrs(pcr0, pcr1, pcr2),
        nitro_authority_enclave_keys: vector::tabulate!(
            MAX_NITRO_AUTHORITY_ENCLAVE_KEYS,
            |_| option::none(),
        ),
    };
    nitro_authority.emit_updated();
    nitro_authority
}

// === Public Functions: called by client ===

/// Create an approval for an enclave-signed operation `digest`. The client calls this public
/// function before the protected operation in the same PTB. It returns `none` without checking
/// the key or signature when no authority is enabled. Otherwise it requires the Nitro authority
/// to be enabled, verifies the signature with the selected enclave key, and returns an `Approval<T>`.
/// Contra reconstructs the same digest when consuming the approval.
public fun new_approval<T>(
    self: &NitroAuthority<T>,
    ct: &ConfidentialToken<T>,
    digest: vector<u8>,
    key_index: u8,
    signature: vector<u8>,
): Option<Approval<T>> {
    ct.mint_nitro_authority_approval(&digest).map!(|approval| {
        let key_index = key_index as u64;
        let key = self
            .nitro_authority_enclave_keys[key_index]
            .fold_ref!(abort EEnclaveKeyNotRegistered, |key| key);
        let message = bcs::to_bytes(&NitroAuthorityRequest::V1 { digest });
        assert!(
            ed25519::ed25519_verify(&signature, &key.signing_pk.0, &message),
            EApprovalSignatureMismatch,
        );
        approval
    })
}

// === Entry Functions: called by issuer ===

/// Share a newly created `NitroAuthority<T>`. The issuer calls this entry function after `new`,
/// optionally after enabling Nitro in the same PTB; ownership of the unshared object authorizes the
/// call.
entry fun share<T>(nitro_authority: NitroAuthority<T>) {
    transfer::share_object(nitro_authority);
}

/// Update the expected PCRs, minimum accepted version, and operator. The issuer calls this entry
/// function using its `ManagementCap<T>`, which restricts the update to the issuer. Changing the
/// PCRs increments `version`; raising `min_version` immediately removes every key registered at an
/// older version.
entry fun update<T>(
    self: &mut NitroAuthority<T>,
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
        MAX_NITRO_AUTHORITY_ENCLAVE_KEYS.do!(|index| {
            let slot = &mut self.nitro_authority_enclave_keys[index];
            if (slot.is_some() && slot.borrow().version < min_version) {
                let key = slot.extract();
                emit_enclave_removed<T>(index as u8, key);
            };
        });
    };
    self.emit_updated();
}

/// Remove the enclave key at `key_index`. The issuer calls this entry function using its
/// `ManagementCap<T>`, which restricts this path to the issuer. During planned rotation, keep the
/// old key through the grace period before calling this function; compromised keys should be
/// removed immediately.
entry fun remove_enclave_as_issuer<T>(
    self: &mut NitroAuthority<T>,
    _management_cap: &ManagementCap<T>,
    key_index: u8,
) {
    self.remove_enclave_key(key_index)
}

// === Entry Functions: called by operator ===

/// Register an enclave whose attestation document matches the Nitro authority's PCRs. The operator
/// calls this entry function, and `TxContext.sender` must equal the configured operator; no
/// capability is required. The function parses `signing_pk || enc_pk` from `user_data` and stores
/// the key pair in the lowest free slot.
entry fun register_enclave<T>(
    self: &mut NitroAuthority<T>,
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
    let mut user_data = *user_data.borrow();
    assert!(user_data.length() == 2 * KEY_LENGTH, EInvalidUserData);
    let signing_pk = Ed25519PublicKey(user_data.take(KEY_LENGTH));
    let enc_pk = X25519PublicKey(user_data);
    let (key_index, key) = self.insert_key(signing_pk, enc_pk);
    sui::event::emit(EnclaveRegisteredEvent<T> { key_index, key });
}

/// Remove the enclave key at `key_index`. The operator calls this entry function, and `TxContext.sender`
/// must equal the configured operator. During planned rotation, keep the old key through the grace period
/// before calling this function; compromised keys should be removed immediately.
entry fun remove_enclave<T>(self: &mut NitroAuthority<T>, key_index: u8, ctx: &mut TxContext) {
    assert!(ctx.sender() == self.operator, ENotOperator);
    self.remove_enclave_key(key_index)
}

/// Update the enclave fleet URL. The operator calls this entry function, and `TxContext.sender` must
/// equal the configured operator.
entry fun set_url<T>(self: &mut NitroAuthority<T>, url: String, ctx: &mut TxContext) {
    assert!(ctx.sender() == self.operator, ENotOperator);
    self.url = url;
    self.emit_updated();
}

// === Internal Functions ===

/// Insert a key in the lowest free slot and stamp it with the current version. Called by
/// `register_enclave` and its test helper; module-private visibility prevents external calls, and
/// the production caller performs the operator check. Aborts when all
/// `MAX_NITRO_AUTHORITY_ENCLAVE_KEYS` slots are occupied.
fun insert_key<T>(
    self: &mut NitroAuthority<T>,
    signing_pk: Ed25519PublicKey,
    enc_pk: X25519PublicKey,
): (u8, NitroAuthorityEnclaveKey) {
    let index = self
        .nitro_authority_enclave_keys
        .find_index!(|slot| slot.is_none())
        .destroy_or!(abort ETooManyNitroAuthorityEnclaveKeys);
    let key = NitroAuthorityEnclaveKey { signing_pk, enc_pk, version: self.version };
    self.nitro_authority_enclave_keys[index].fill(key);
    (index as u8, key)
}

/// Remove the registered enclave key at `key_index`. Called by the issuer and operator removal entry
/// functions after their respective authorization checks; module-private visibility prevents
/// external calls. Aborts if the index is out of range or the slot is empty.
fun remove_enclave_key<T>(self: &mut NitroAuthority<T>, key_index: u8) {
    let key_index = key_index as u64;
    assert!(key_index < MAX_NITRO_AUTHORITY_ENCLAVE_KEYS, EEnclaveKeyNotRegistered);
    let slot = &mut self.nitro_authority_enclave_keys[key_index];
    assert!(slot.is_some(), EEnclaveKeyNotRegistered);
    let key = slot.extract();
    emit_enclave_removed<T>(key_index as u8, key);
}

fun emit_enclave_removed<T>(key_index: u8, key: NitroAuthorityEnclaveKey) {
    sui::event::emit(EnclaveRemovedEvent<T> { key_index, key });
}

fun emit_updated<T>(self: &NitroAuthority<T>) {
    sui::event::emit(NitroAuthorityUpdatedEvent<T> {
        nitro_authority_id: self.id.to_inner(),
        operator: self.operator,
        url: self.url,
        version: self.version,
        min_version: self.min_version,
        pcrs: self.pcrs,
    });
}

// === Test Helpers ===

#[test_only]
public(package) fun new_for_testing<T>(
    pcr0: vector<u8>,
    pcr1: vector<u8>,
    pcr2: vector<u8>,
    operator: address,
    ctx: &mut TxContext,
): NitroAuthority<T> {
    let id = object::new(ctx);
    let nitro_authority = NitroAuthority<T> {
        id,
        operator,
        url: b"".to_string(),
        version: 0,
        min_version: 0,
        pcrs: Pcrs(pcr0, pcr1, pcr2),
        nitro_authority_enclave_keys: vector::tabulate!(
            MAX_NITRO_AUTHORITY_ENCLAVE_KEYS,
            |_| option::none(),
        ),
    };
    nitro_authority.emit_updated();
    nitro_authority
}

#[test_only]
public(package) fun new_nitro_authority_request_for_testing(
    digest: vector<u8>,
): NitroAuthorityRequest {
    NitroAuthorityRequest::V1 { digest }
}

#[test_only]
public(package) fun register_enclave_for_testing<T>(
    self: &mut NitroAuthority<T>,
    signing_pk: vector<u8>,
    enc_pk: vector<u8>,
): u8 {
    let (key_index, _) = self.insert_key(Ed25519PublicKey(signing_pk), X25519PublicKey(enc_pk));
    key_index
}

#[test_only]
public(package) fun operator<T>(self: &NitroAuthority<T>): address { self.operator }

#[test_only]
public(package) fun url<T>(self: &NitroAuthority<T>): &String { &self.url }

#[test_only]
public(package) fun version<T>(self: &NitroAuthority<T>): u16 { self.version }

#[test_only]
public(package) fun min_version<T>(self: &NitroAuthority<T>): u16 { self.min_version }

#[test_only]
public(package) fun pcrs<T>(self: &NitroAuthority<T>): (vector<u8>, vector<u8>, vector<u8>) {
    (self.pcrs.0, self.pcrs.1, self.pcrs.2)
}

#[test_only]
public(package) fun contains_nitro_authority_enclave_key<T>(
    self: &NitroAuthority<T>,
    key_index: u8,
): bool {
    let key_index = key_index as u64;
    key_index < MAX_NITRO_AUTHORITY_ENCLAVE_KEYS && self.nitro_authority_enclave_keys[key_index].is_some()
}
