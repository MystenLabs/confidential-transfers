// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Guardian module (design: `guardian/README.md`).
///
/// When a `GuardianPolicy` is set on a `ConfidentialToken<T>`, every transfer and
/// unwrap must carry an approval signed by a registered enclave.
///
/// The issuer (`ManagementCap`) owns the policy, its `pcrs`, `min_version`, and the
/// operator address. The operator runs one serving endpoint (`url`) backed by
/// multiple enclave instances — each holds its own `{ signing_pk, enc_pk }` — and
/// registers/removes those keys.
module contra::guardian;

use contra::twisted_elgamal::Encryption;
use std::{bcs, string::String};
use sui::{
    ed25519,
    group_ops::Element,
    nitro_attestation::NitroAttestationDocument,
    ristretto255::G,
    vec_map::{Self, VecMap}
};

// === Errors ===

const ENotOperator: u64 = 0;
const EPcrMismatch: u64 = 1;
const EInvalidUserData: u64 = 2;
const ETooManyGuardianEnclaveKeys: u64 = 3;
const EInvalidMinVersion: u64 = 4;
const EInvalidKeyLength: u64 = 5;

// === Constants ===

/// Maximum number of enclave keys a policy may hold.
const MAX_GUARDIAN_ENCLAVE_KEYS: u64 = 10;

const KEY_LENGTH: u64 = 32;
const SIGNATURE_LENGTH: u64 = 64;

// === Types ===

/// PCR0 (enclave image), PCR1 (kernel), PCR2 (application).
public struct Pcrs(vector<u8>, vector<u8>, vector<u8>) has copy, drop, store;

/// 32-byte ed25519 public key (the framework's `sui::ed25519` is untyped).
public struct Ed25519PublicKey(vector<u8>) has copy, drop, store;

/// 64-byte ed25519 signature.
public struct Ed25519Signature(vector<u8>) has copy, drop, store;

/// 32-byte X25519 public key clients seal requests to.
public struct X25519PublicKey(vector<u8>) has copy, drop, store;

/// Guardian configuration for one confidential token, held as an
/// `Option<GuardianPolicy>` on the `ConfidentialToken`: `Some` enables the guardian,
/// `None` disables it.
public struct GuardianPolicy has drop, store {
    /// The address allowed to add/remove enclave keys and update `url`;
    /// replaceable by the issuer.
    operator: address,
    /// The single endpoint fronting the operator's enclave fleet.
    url: String,
    /// Incremented per PCR change.
    version: u16,
    /// A key is valid iff `key.version >= min_version`; raising this invalidates
    /// old-image keys.
    min_version: u16,
    /// The expected enclave image measurements.
    pcrs: Pcrs,
    /// The fleet's registered keys — one per enclave instance, keyed by `signing_pk`.
    guardian_enclave_keys: VecMap<Ed25519PublicKey, GuardianEnclaveKey>,
}

/// A registered enclave.
public struct GuardianEnclaveKey has copy, drop, store {
    signing_pk: Ed25519PublicKey,
    enc_pk: X25519PublicKey,
    /// Policy version at registration; valid while `>= min_version`.
    version: u16,
}

/// An enclave's ed25519 signature over the BCS `ApprovalPayload`, together with the
/// `signing_pk` that produced it.
public struct GuardianApproval has copy, drop {
    signing_pk: Ed25519PublicKey,
    signature: Ed25519Signature,
}

/// The approval payload that the enclave signature is verified against.
public enum ApprovalPayload has copy, drop {
    Transfer {
        sender_pk: Element<G>,
        receiver_pks: vector<Element<G>>,
        old_balance: Encryption,
        new_balance: Encryption,
        amounts: vector<Encryption>,
    },
    Unwrap {
        sender_pk: Element<G>,
        old_balance: Encryption,
        new_balance: Encryption,
        amount: u64,
    },
}

// === Public Functions ===

public fun new_guardian_approval(signing_pk: vector<u8>, signature: vector<u8>): GuardianApproval {
    assert!(
        signing_pk.length() == KEY_LENGTH && signature.length() == SIGNATURE_LENGTH,
        EInvalidKeyLength,
    );
    GuardianApproval {
        signing_pk: Ed25519PublicKey(signing_pk),
        signature: Ed25519Signature(signature),
    }
}

public fun new_pcrs(pcr0: vector<u8>, pcr1: vector<u8>, pcr2: vector<u8>): Pcrs {
    Pcrs(pcr0, pcr1, pcr2)
}

public fun operator(self: &GuardianPolicy): address { self.operator }

public fun url(self: &GuardianPolicy): &String { &self.url }

public fun version(self: &GuardianPolicy): u16 { self.version }

public fun min_version(self: &GuardianPolicy): u16 { self.min_version }

public fun pcrs(self: &GuardianPolicy): &Pcrs { &self.pcrs }

/// The registered key pairs whose version is still supported — the set clients seal
/// transfer requests to.
public fun live_guardian_enclave_keys(self: &GuardianPolicy): vector<GuardianEnclaveKey> {
    let mut live = vector[];
    self.guardian_enclave_keys.length().do!(|i| {
        let (_, key) = self.guardian_enclave_keys.get_entry_by_idx(i);
        if (key.version >= self.min_version) {
            live.push_back(*key);
        };
    });
    live
}

public fun key_signing_pk(key: &GuardianEnclaveKey): &Ed25519PublicKey { &key.signing_pk }

public fun key_enc_pk(key: &GuardianEnclaveKey): &X25519PublicKey { &key.enc_pk }

public fun key_version(key: &GuardianEnclaveKey): u16 { key.version }

public fun ed25519_public_key_bytes(pk: &Ed25519PublicKey): &vector<u8> { &pk.0 }

public fun x25519_public_key_bytes(pk: &X25519PublicKey): &vector<u8> { &pk.0 }

public use fun key_signing_pk as GuardianEnclaveKey.signing_pk;
public use fun key_enc_pk as GuardianEnclaveKey.enc_pk;
public use fun ed25519_public_key_bytes as Ed25519PublicKey.bytes;
public use fun x25519_public_key_bytes as X25519PublicKey.bytes;

// === Package Functions ===

public(package) fun new(pcrs: Pcrs, operator: address, url: String): GuardianPolicy {
    GuardianPolicy {
        operator,
        url,
        version: 0,
        min_version: 0,
        pcrs,
        guardian_enclave_keys: vec_map::empty(),
    }
}

public(package) fun new_transfer_approval_payload(
    sender_pk: Element<G>,
    receiver_pks: vector<Element<G>>,
    old_balance: Encryption,
    new_balance: Encryption,
    amounts: vector<Encryption>,
): ApprovalPayload {
    ApprovalPayload::Transfer {
        sender_pk,
        receiver_pks,
        old_balance,
        new_balance,
        amounts,
    }
}

public(package) fun new_unwrap_approval_payload(
    sender_pk: Element<G>,
    old_balance: Encryption,
    new_balance: Encryption,
    amount: u64,
): ApprovalPayload {
    ApprovalPayload::Unwrap { sender_pk, old_balance, new_balance, amount }
}

// Issuer operations (ManagementCap-gated by the wrappers in contra.move).

/// Each `Some` field is applied, `None` is a no-op; `pcrs` applies first, bumping
/// `version` without invalidating existing keys. Raising `min_version` revokes every
/// key stamped below it.
public(package) fun update(
    self: &mut GuardianPolicy,
    pcrs: Option<Pcrs>,
    min_version: Option<u16>,
    operator: Option<address>,
) {
    pcrs.do!(|pcrs| {
        self.pcrs = pcrs;
        self.version = self.version + 1;
    });
    min_version.do!(|min_version| {
        assert!(min_version <= self.version, EInvalidMinVersion);
        self.min_version = min_version;
    });
    operator.do!(|operator| self.operator = operator);
}

// Operator operations.

/// Operator-only: each `Some` field is applied, `remove` before `register`. Returns
/// the registered pk and the removed key for the caller's events.
public(package) fun update_enclaves(
    self: &mut GuardianPolicy,
    register: Option<NitroAttestationDocument>,
    remove: Option<vector<u8>>,
    url: Option<String>,
    ctx: &TxContext,
): (Option<Ed25519PublicKey>, Option<GuardianEnclaveKey>) {
    assert!(ctx.sender() == self.operator, ENotOperator);
    let removed = remove.map!(|signing_pk| {
        let (_, key) = self.guardian_enclave_keys.remove(&Ed25519PublicKey(signing_pk));
        key
    });
    let registered = register.map!(|document| self.register_key(&document));
    url.do!(|url| self.url = url);
    (registered, removed)
}

/// The signing key must be registered with `version >= min_version` and `signature`
/// valid over the BCS payload. Returns `false` rather than aborting so the caller
/// owns the error surface.
public(package) fun verify_approval<P: drop>(
    self: &GuardianPolicy,
    approval: &GuardianApproval,
    payload: &P,
): bool {
    if (!self.guardian_enclave_keys.contains(&approval.signing_pk)) return false;
    let key = self.guardian_enclave_keys.get(&approval.signing_pk);
    if (key.version < self.min_version) return false;
    ed25519::ed25519_verify(
        &approval.signature.0,
        &approval.signing_pk.0,
        &bcs::to_bytes(payload),
    )
}

// === Internal Functions ===

/// Register an enclave from its attestation document: the PCRs must match the
/// policy, and both keys come from the attested `user_data`. Stamped with the
/// current `version`.
fun register_key(self: &mut GuardianPolicy, document: &NitroAttestationDocument): Ed25519PublicKey {
    assert!(
        self.guardian_enclave_keys.length() < MAX_GUARDIAN_ENCLAVE_KEYS,
        ETooManyGuardianEnclaveKeys,
    );
    // Parse exactly pcr0, 1, 2.
    let entries = document.pcrs();
    assert!(
        entries[0].index() == 0 && *entries[0].value() == self.pcrs.0 &&
        entries[1].index() == 1 && *entries[1].value() == self.pcrs.1 &&
        entries[2].index() == 2 && *entries[2].value() == self.pcrs.2,
        EPcrMismatch,
    );

    let (signing_pk, enc_pk) = parse_user_data((*document.user_data()).destroy_some());

    // `insert` aborts on a duplicate signing_pk.
    self
        .guardian_enclave_keys
        .insert(signing_pk, GuardianEnclaveKey { signing_pk, enc_pk, version: self.version });
    signing_pk
}

/// `user_data`: `signing_pk || enc_pk`, 32 bytes each.
fun parse_user_data(user_data: vector<u8>): (Ed25519PublicKey, X25519PublicKey) {
    assert!(user_data.length() == 2 * KEY_LENGTH, EInvalidUserData);
    (Ed25519PublicKey(user_data.take(KEY_LENGTH)), X25519PublicKey(user_data.skip(KEY_LENGTH)))
}

// === Dev Helpers ===

/// Register an enclave key without an attestation document, for localnet dev runs
/// against a `non-enclave-dev` guardian (whose mock document cannot verify). Gated on
/// the operator like the real path. NOT for production.
public fun register_guardian_enclave_key_for_dev(
    self: &mut GuardianPolicy,
    signing_pk: vector<u8>,
    enc_pk: vector<u8>,
    ctx: &TxContext,
): Ed25519PublicKey {
    assert!(ctx.sender() == self.operator, ENotOperator);
    assert!(
        self.guardian_enclave_keys.length() < MAX_GUARDIAN_ENCLAVE_KEYS,
        ETooManyGuardianEnclaveKeys,
    );
    assert!(signing_pk.length() == KEY_LENGTH && enc_pk.length() == KEY_LENGTH, EInvalidKeyLength);
    let signing_pk = Ed25519PublicKey(signing_pk);
    self
        .guardian_enclave_keys
        .insert(
            signing_pk,
            GuardianEnclaveKey {
                signing_pk,
                enc_pk: X25519PublicKey(enc_pk),
                version: self.version,
            },
        );
    signing_pk
}

// === Test Helpers ===

#[test_only]
public fun contains_guardian_enclave_key(self: &GuardianPolicy, signing_pk: vector<u8>): bool {
    self.guardian_enclave_keys.contains(&Ed25519PublicKey(signing_pk))
}

/// Register the enclave without the attestation document.
#[test_only]
public fun register_guardian_enclave_key_for_testing(
    self: &mut GuardianPolicy,
    signing_pk: vector<u8>,
    enc_pk: vector<u8>,
) {
    let ctx = tx_context::dummy();
    let operator = self.operator;
    self.operator = ctx.sender();
    self.register_guardian_enclave_key_for_dev(signing_pk, enc_pk, &ctx);
    self.operator = operator;
}

#[test_only]
public fun new_for_testing(pcrs: Pcrs, operator: address): GuardianPolicy {
    new(pcrs, operator, b"".to_string())
}

#[test_only]
public fun parse_user_data_for_testing(user_data: vector<u8>): (Ed25519PublicKey, X25519PublicKey) {
    parse_user_data(user_data)
}

#[test_only]
public fun guardian_enclave_key_version_for_testing(
    self: &GuardianPolicy,
    signing_pk: vector<u8>,
): u16 {
    self.guardian_enclave_keys.get(&Ed25519PublicKey(signing_pk)).version
}

#[test_only]
public fun verify_approval_for_testing<P: drop>(
    self: &GuardianPolicy,
    approval: &GuardianApproval,
    payload: &P,
): bool {
    self.verify_approval(approval, payload)
}

#[test_only]
public fun set_min_version_for_testing(self: &mut GuardianPolicy, min_version: u16) {
    self.update(option::none(), option::some(min_version), option::none())
}

#[test_only]
public fun update_pcrs_for_testing(self: &mut GuardianPolicy, pcrs: Pcrs) {
    self.update(option::some(pcrs), option::none(), option::none())
}

#[test_only]
public fun set_operator_for_testing(self: &mut GuardianPolicy, operator: address) {
    self.update(option::none(), option::none(), option::some(operator))
}

#[test_only]
public fun new_unwrap_approval_payload_for_testing(
    sender_pk: Element<G>,
    old_balance: Encryption,
    new_balance: Encryption,
    amount: u64,
): ApprovalPayload {
    new_unwrap_approval_payload(sender_pk, old_balance, new_balance, amount)
}

#[test_only]
public fun new_transfer_approval_payload_for_testing(
    sender_pk: Element<G>,
    receiver_pks: vector<Element<G>>,
    old_balance: Encryption,
    new_balance: Encryption,
    amounts: vector<Encryption>,
): ApprovalPayload {
    new_transfer_approval_payload(sender_pk, receiver_pks, old_balance, new_balance, amounts)
}
