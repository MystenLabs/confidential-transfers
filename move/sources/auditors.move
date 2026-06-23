// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::auditors;

use contra::{
    nizk::{KeyConsistencyProof, verify_key_consistency},
    twisted_elgamal::MultiRecipientEncryption
};
use sui::{group_ops::Element, rangeproofs, ristretto255::{G, g_identity}};

/// Bulletproof construction version (Bünz et al., 2018).
const BULLETPROOFS_VERSION: u8 = 0;

/// Bit-length of each private-key limb committed in the viewing-key encryption.
const LIMB_BITS: u8 = 32;

// === Errors ===

const EInvalidEncryptedViewingKey: u64 = 0;
const EMissingEncryptedViewingKeyArguments: u64 = 1;
const ETooManyEncryptedViewingKeyArguments: u64 = 2;
const EIdentityAuditorPublicKey: u64 = 3;

// === Main Type(s) ===

/// Holds the set of auditor `public_keys` registered for a token. Auditors can decrypt the
/// viewing-key ciphertexts attached to each transfer, giving them read access to transaction
/// amounts without being able to move funds.
///
/// The `version` number is incremented on every `update` so that `VerifiedKeyEncryption` values
/// stored on user accounts can be checked for staleness. `recommended_min_version` is the issuer's
/// advertised minimum `VerifiedKeyEncryption.version`; it is not enforced on chain. Wallets and
/// other clients should treat any account whose `VerifiedKeyEncryption.version` is below it as
/// stale and prompt the user to rotate before transferring.
public struct Auditors has store {
    pks: vector<Element<G>>,
    version: u32,
    recommended_min_version: u32,
}

/// A user's viewing key encrypted to each auditor's public key, stored on their account after
/// passing a `KeyConsistencyProof` check. The `version` records which auditor key set it was
/// produced against, so callers can compare it against `Auditors.recommended_min_version` to
/// detect encryptions that the issuer considers stale.
///
/// An empty `ciphertext` means the user's account was registered while the token had no
/// auditors set.
public struct VerifiedKeyEncryption has copy, drop, store {
    ciphertext: vector<MultiRecipientEncryption>,
    version: u32,
}

/// A user's viewing key encrypted to each auditor's public key, bundled with the
/// proofs needed to register it on-chain:
/// - `proof` is the `KeyConsistencyProof` showing each limb of `ciphertext` correctly
///   encrypts the matching 32-bit limb of the user's private key under every auditor's
///   public key, and that the limbs sum to `sender_public_key`'s discrete log.
/// - `range_proof` is an aggregate Bulletproof showing every limb's plaintext lies
///   in `[0, 2^32)` so that auditors can recover each limb via baby-step giant-step.
public struct KeyEncryption has drop {
    ciphertext: vector<MultiRecipientEncryption>,
    proof: KeyConsistencyProof,
    range_proof: vector<u8>,
}

// === Functions ===

public(package) fun new(pks: vector<Element<G>>): Auditors {
    assert_no_identity_pk(&pks);
    let auditors = Auditors {
        pks,
        version: 0,
        recommended_min_version: 0,
    };
    auditors
}

/// Rotate the auditor key set. The `version` is bumped on every call. When
/// `bump_recommended_min` is true, `recommended_min_version` is raised to the new `version`,
/// signalling that the issuer would like every user to refresh keys.
public(package) fun update(
    auditors: &mut Auditors,
    new_pks: vector<Element<G>>,
    bump_recommended_min: bool,
) {
    assert_no_identity_pk(&new_pks);
    auditors.pks = new_pks;
    auditors.version = auditors.version + 1;
    if (bump_recommended_min) {
        auditors.recommended_min_version = auditors.version;
    };
}

/// Abort with `EIdentityAuditorPublicKey` if any entry of `pks` is the group identity.
fun assert_no_identity_pk(pks: &vector<Element<G>>) {
    let identity = g_identity();
    pks.do_ref!(|pk| assert!(*pk != identity, EIdentityAuditorPublicKey));
}

public(package) fun pks(auditors: &Auditors): &vector<Element<G>> {
    &auditors.pks
}

public(package) fun is_empty(auditors: &Auditors): bool {
    auditors.pks.is_empty()
}

public(package) fun version(auditors: &Auditors): u32 {
    auditors.version
}

public(package) fun recommended_min_version(auditors: &Auditors): u32 {
    auditors.recommended_min_version
}

public(package) fun ciphertext(
    verified_key_encryption: &VerifiedKeyEncryption,
): &vector<MultiRecipientEncryption> {
    &verified_key_encryption.ciphertext
}

public(package) fun key_version(verified_key_encryption: &VerifiedKeyEncryption): u32 {
    verified_key_encryption.version
}

/// True iff this `VerifiedKeyEncryption` was produced from a non-empty `Auditors` set.
public(package) fun is_set(verified_key_encryption: &VerifiedKeyEncryption): bool {
    !verified_key_encryption.ciphertext.is_empty()
}

public fun new_key_encryption(
    ciphertext: vector<MultiRecipientEncryption>,
    proof: KeyConsistencyProof,
    range_proof: vector<u8>,
): KeyEncryption {
    KeyEncryption { ciphertext, proof, range_proof }
}

/// Placeholder `VerifiedKeyEncryption` for accounts registered while the token has no
/// auditors configured. The `ciphertext` is empty.
fun new_empty_verified_key_encryption(auditors: &Auditors): VerifiedKeyEncryption {
    VerifiedKeyEncryption { ciphertext: vector[], version: auditors.version }
}

/// Resolve an `Option<KeyEncryption>` against the configured `auditors` and produce a
/// `VerifiedKeyEncryption`. When auditors are set, a `KeyEncryption` must be provided; the
/// sigma proof (bound to `key_consistency_dst`) and the aggregate Bulletproof over the limb
/// commitments (bound to the distinct `range_dst`) are both checked before returning. When
/// auditors are not set, no
/// `KeyEncryption` may be provided and an empty placeholder is returned. Aborts with
/// `EMissingEncryptedViewingKeyArguments` / `ETooManyEncryptedViewingKeyArguments` on mismatch.
public(package) fun verify_key_encryption(
    auditors: &Auditors,
    sender_public_key: &Element<G>,
    key_encryption: Option<KeyEncryption>,
    key_consistency_dst: vector<u8>,
    range_dst: vector<u8>,
): VerifiedKeyEncryption {
    if (auditors.is_empty()) {
        assert!(key_encryption.is_none(), ETooManyEncryptedViewingKeyArguments);
        auditors.new_empty_verified_key_encryption()
    } else {
        assert!(key_encryption.is_some(), EMissingEncryptedViewingKeyArguments);
        let KeyEncryption { ciphertext, proof, range_proof } = key_encryption.destroy_some();
        assert!(
            proof.verify_key_consistency(
                key_consistency_dst,
                sender_public_key,
                auditors.pks(),
                &ciphertext,
            ) &&
                rangeproofs::verify_bulletproofs_with_dst_ristretto255(
                    &range_proof,
                    LIMB_BITS,
                    &vector::tabulate!(
                        ciphertext.length(),
                        |i| *ciphertext[i].multi_recipient_ciphertext(),
                    ),
                    &range_dst,
                    BULLETPROOFS_VERSION,
                ),
            EInvalidEncryptedViewingKey,
        );
        VerifiedKeyEncryption { ciphertext, version: auditors.version }
    }
}

// === Test-only ===

/// Test-only version of `verify_key_encryption` that skips the Bulletproof range check on
/// the limb commitments. Move tests cannot generate real Bulletproof bytes, so they assert
/// each limb is a u32 out of band and only verify the sigma protocol on-chain.
#[test_only]
public(package) fun verify_key_encryption_for_testing(
    auditors: &Auditors,
    sender_public_key: &Element<G>,
    key_encryption: Option<KeyEncryption>,
    dst: vector<u8>,
): VerifiedKeyEncryption {
    if (auditors.is_empty()) {
        assert!(key_encryption.is_none(), ETooManyEncryptedViewingKeyArguments);
        auditors.new_empty_verified_key_encryption()
    } else {
        assert!(key_encryption.is_some(), EMissingEncryptedViewingKeyArguments);
        let KeyEncryption { ciphertext, proof, range_proof: _ } = key_encryption.destroy_some();
        assert!(
            proof.verify_key_consistency(
                dst,
                sender_public_key,
                auditors.pks(),
                &ciphertext,
            ),
            EInvalidEncryptedViewingKey,
        );
        VerifiedKeyEncryption { ciphertext, version: auditors.version }
    }
}
