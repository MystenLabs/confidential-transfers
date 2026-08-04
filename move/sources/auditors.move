// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::auditors;

use contra::{nizk::{ElGamalProof, verify_elgamal}, twisted_elgamal::Encryption};
use sui::{group_ops::Element, ristretto255::{G, g_identity}};

// === Errors ===

const EIdentityAuditorPublicKey: u64 = 0;

// === Main Type ===

/// The auditor configuration for a confidential token under the per-transfer auditing model: a
/// single auditor public key, plus a grace window on rotation.
///
/// Auditing is per-transfer — every transfer carries auditor-readable ciphertexts of the amount
/// (see `verify_transfer`) — so the auditor never learns the user's viewing key and balances are
/// encrypted only under the user's own key.
///
/// `current_pk == none` means auditing is disabled: transfers must carry no auditor data. On
/// `update`, the outgoing key is retained as `previous_pk` and stays valid for transfers through
/// `previous_expiration_epoch` (inclusive), so transfers built against the old key just before a
/// rotation still verify.
public struct Auditor has store {
    current_pk: Option<Element<G>>,
    previous_pk: Option<Element<G>>,
    previous_expiration_epoch: u64,
}

// === Functions ===

public(package) fun new(pk: Option<Element<G>>): Auditor {
    assert_non_identity(&pk);
    Auditor { current_pk: pk, previous_pk: option::none(), previous_expiration_epoch: 0 }
}

/// Rotate the auditor key. The old `current_pk` (if any) becomes `previous_pk` and remains valid for
/// transfers through `expiration_epoch`. Passing `new_pk = none` disables auditing going forward,
/// though the previous key still audits in-flight transfers until it expires.
public(package) fun update(
    auditor: &mut Auditor,
    new_pk: Option<Element<G>>,
    expiration_epoch: u64,
) {
    assert_non_identity(&new_pk);
    auditor.previous_pk = auditor.current_pk;
    auditor.previous_expiration_epoch = expiration_epoch;
    auditor.current_pk = new_pk;
}

/// Whether auditing is currently enabled (a current key is set). A transfer MUST attach auditor data
/// when this is true.
public(package) fun is_enabled(auditor: &Auditor): bool {
    auditor.current_pk.is_some()
}

/// Whether a transfer's auditor data can be verified at `epoch`: either a current key is set, or the
/// previous key is still within its grace window. When a token is disabled (`current_pk == none`) but
/// the previous key is still in grace, auditor data is OPTIONAL — a transfer may still attach it (so
/// in-flight transfers built against the old key remain auditable), but need not. When this is false,
/// a transfer must carry no auditor data.
public(package) fun accepts_at(auditor: &Auditor, epoch: u64): bool {
    auditor.current_pk.is_some() ||
        (epoch <= auditor.previous_expiration_epoch && auditor.previous_pk.is_some())
}

/// Verify a batched per-transfer auditor `ElGamalProof` over `encryptions` — the derived u32-limb
/// `(commitment, handle)` pairs for the whole transfer batch, all encrypted under one auditor key.
/// Accepts the proof if it verifies under the current key, or under the previous key while
/// `epoch <= previous_expiration_epoch` (the rotation grace window). Returns the auditor key that
/// verified it (so callers can record which key a transfer used), or `none` if neither verifies or
/// auditing is disabled.
public(package) fun verify_transfer(
    auditor: &Auditor,
    epoch: u64,
    encryptions: &vector<Encryption>,
    proof: &ElGamalProof,
    dst: vector<u8>,
): Option<Element<G>> {
    if (auditor.current_pk.is_some_and!(|pk| proof.verify_elgamal(dst, pk, encryptions))) {
        return auditor.current_pk
    };
    if (
        epoch <= auditor.previous_expiration_epoch &&
            auditor.previous_pk.is_some_and!(|pk| proof.verify_elgamal(dst, pk, encryptions))
    ) {
        return auditor.previous_pk
    };
    option::none()
}

public(package) fun current_pk(auditor: &Auditor): Option<Element<G>> {
    auditor.current_pk
}

public(package) fun previous_pk(auditor: &Auditor): Option<Element<G>> {
    auditor.previous_pk
}

public(package) fun previous_expiration_epoch(auditor: &Auditor): u64 {
    auditor.previous_expiration_epoch
}

/// Abort with `EIdentityAuditorPublicKey` if `pk` is set to the group identity.
fun assert_non_identity(pk: &Option<Element<G>>) {
    pk.do_ref!(|k| assert!(*k != g_identity(), EIdentityAuditorPublicKey));
}
