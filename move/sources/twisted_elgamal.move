// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::twisted_elgamal;

use sui::{
    group_ops::Element,
    ristretto255::{Self, G, g_identity, g_add, g_mul, g_sub, scalar_from_u64, g_from_bytes}
};

/// Twisted ElGamal encryption with message in the exponent, over Ristretto255.
///
/// Uses two generators with unknown discrete log relationship:
/// - `g`: the standard Ristretto255 generator
/// - `h`: derived via `hash_to_curve("fastcrypto-blinding-gen-01")`, ensuring no one knows `log_g(h)`
///
/// Encryption of message `m` with public key `pk = x * g` and randomness `r`:
///   - ciphertext:        `c = r * g + m * h`
///   - decryption handle: `d = r * pk`
///
/// Decryption with secret key `x`:
///   - Compute `c - d/x = c - r*g = m * h`
///   - Solve the discrete log `m = log_h(m * h)` via brute force
///
/// Homomorphic properties: Encryptions can be added and subtracted component-wise,
/// yielding an encryption of the sum or difference of the plaintexts.
///
/// Values up to at least ~2^32 can be decrypted.
public struct Encryption has copy, drop, store {
    ciphertext: Element<G>,
    decryption_handle: Element<G>,
}

/// Create a new Twisted ElGamal encryption from a given `ciphertext` and `decryption_handle`.
public fun new(ciphertext: Element<G>, decryption_handle: Element<G>): Encryption {
    Encryption {
        ciphertext,
        decryption_handle,
    }
}

// === Public key ===

const EIdentityPublicKey: u64 = 0;

/// A twisted ElGamal public key `pk = x * g`, guaranteed non-identity by construction.
public struct PublicKey has copy, drop, store {
    element: Element<G>,
}

/// Wrap `element` as a `PublicKey`, aborting with `EIdentityPublicKey` if it is the group identity.
public fun public_key(element: Element<G>): PublicKey {
    assert!(element != g_identity(), EIdentityPublicKey);
    PublicKey { element }
}

/// The underlying group element.
public fun as_element(pk: &PublicKey): &Element<G> {
    &pk.element
}

/// The standard Ristretto255 generator `g`, used for randomness blinding in ciphertexts.
public(package) fun g(): Element<G> {
    ristretto255::g_generator()
}

/// The blinding generator `h`, derived via `hash_to_curve("fastcrypto-blinding-gen-01")`.
/// The discrete log relationship between `g` and `h` is unknown.
public(package) fun h(): Element<G> {
    g_from_bytes(
        &x"34ce1477c14558178089500a39c864e0f607b3c1f41ab398400e4a9de6d2c446",
    )
}

/// Returns the ciphertext of a Twisted ElGamal encryption `c = r * g + m * h`.
public(package) fun ciphertext(e: &Encryption): &Element<G> {
    &e.ciphertext
}

/// Returns the decryption handle of a Twisted ElGamal encryption `d = r * pk`.
public(package) fun decryption_handle(e: &Encryption): &Element<G> {
    &e.decryption_handle
}

/// Homomorphically add two Twisted ElGamal encryptions. The result is an encryption of the sum of the plaintexts
/// in the scalar field.
public(package) fun add(e1: &Encryption, e2: &Encryption): Encryption {
    Encryption {
        ciphertext: g_add(&e1.ciphertext, &e2.ciphertext),
        decryption_handle: g_add(&e1.decryption_handle, &e2.decryption_handle),
    }
}

/// Homomorphically subtract two Twisted ElGamal encryptions. The result is an encryption of the difference of the
/// plaintexts in the scalar field.
public(package) fun sub(e1: &Encryption, e2: &Encryption): Encryption {
    Encryption {
        ciphertext: g_sub(&e1.ciphertext, &e2.ciphertext),
        decryption_handle: g_sub(&e1.decryption_handle, &e2.decryption_handle),
    }
}

/// Add a known public `amount` to the ciphertext.
public(package) fun add_assign_u64(e: &mut Encryption, amount: u64) {
    if (amount == 0) return;
    e.ciphertext = g_add(&e.ciphertext, &g_mul(&scalar_from_u64(amount), &h()));
}

#[test_only]
public(package) fun sub_assign(e1: &mut Encryption, e2: &Encryption) {
    e1.ciphertext = g_sub(&e1.ciphertext, &e2.ciphertext);
    e1.decryption_handle = g_sub(&e1.decryption_handle, &e2.decryption_handle);
}

/// Trivial encryption of zero without randomness.
public(package) fun encrypt_zero(): Encryption {
    // TODO: consider changing to (pk, g)
    Encryption {
        ciphertext: g_identity(),
        decryption_handle: g_identity(),
    }
}

#[test_only]
public fun encrypt_zero_for_testing(): Encryption {
    encrypt_zero()
}

#[test_only]
public fun decryption_handle_for_testing(e: &Encryption): Element<G> {
    *e.decryption_handle()
}

#[test_only]
public fun encrypt_trivial_for_testing(amount: u64, pk: &Element<G>, r: u64): Encryption {
    let r = scalar_from_u64(r);
    Encryption {
        ciphertext: g_add(
            &g_mul(&r, &g()),
            &g_mul(&scalar_from_u64(amount as u64), &h()),
        ),
        decryption_handle: g_mul(&r, pk),
    }
}
