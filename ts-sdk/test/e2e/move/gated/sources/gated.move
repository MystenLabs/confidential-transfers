// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Test-only witness/object adapter used by the e2e tests to exercise the
/// permissioned (`authorize_with_witness`) and object-bound (`authorize_as_object`) auth paths
/// in `contra::contra`. The wrappers just build an `Auth<T>` and forward to
/// the contra entrypoint -- no extra access control is performed.
module gated::gated;

use contra::{
    contra::{Self, ConfidentialToken, Account, AccountRegistry, Pool},
    twisted_elgamal::public_key
};
use sui::{coin::Coin, deny_list::DenyList, group_ops::Element, ristretto255::G};

// Operation indices, mirroring private constants in `contra::contra`.
const REGISTER_OP: u8 = 0;
const WRAP_OP: u8 = 1;

/// Witness type for permissioned ops. Only this module can construct it,
/// which is the property `authorize_with_witness` relies on.
public struct GatedWitness has drop {}

/// A shared object whose UID's address self-authenticates via `authorize_as_object`.
public struct Vault has key {
    id: UID,
}

public fun new_vault(ctx: &mut TxContext): Vault {
    Vault { id: object::new(ctx) }
}

#[allow(lint(share_owned))]
public fun share_vault(vault: Vault) {
    transfer::share_object(vault);
}

/// The address that `authorize_as_object(&mut vault.id)` authenticates as.
public fun vault_address(vault: &Vault): address {
    vault.id.to_inner().to_address()
}

// === Permissioned ops (`authorize_with_witness`) ===

public fun gated_register<T>(ct: &ConfidentialToken<T>, account: &mut Account, pk: Element<G>) {
    let auth = ct.authorize_with_witness(REGISTER_OP, account.owner(), GatedWitness {});
    contra::register(account, &auth, public_key(pk));
}

public fun gated_wrap<T>(
    receiver: &mut Account,
    ct: &ConfidentialToken<T>,
    deny_list: &DenyList,
    pool: &Pool<T>,
    coin: Coin<T>,
    memo: vector<u8>,
) {
    let auth = ct.authorize_with_witness(WRAP_OP, receiver.owner(), GatedWitness {});
    contra::wrap(receiver, &auth, ct, deny_list, pool, coin, memo);
}

// === Object-bound ops (`authorize_as_object`) ===

/// Create the contra `Account` owned by `vault`'s address. `new_account` is permissionless, so this
/// is a thin wrapper; the vault's token account is keyed explicitly at `vault_register`.
public fun vault_new_account(vault: &Vault, registry: &mut AccountRegistry): Account {
    contra::new_account(registry, vault.id.to_inner().to_address())
}

public fun vault_register<T>(
    vault: &mut Vault,
    ct: &ConfidentialToken<T>,
    account: &mut Account,
    pk: Element<G>,
) {
    let auth = ct.authorize_as_object(&mut vault.id);
    contra::register(account, &auth, public_key(pk));
}

public fun vault_wrap<T>(
    vault: &mut Vault,
    receiver: &mut Account,
    ct: &ConfidentialToken<T>,
    deny_list: &DenyList,
    pool: &Pool<T>,
    coin: Coin<T>,
    memo: vector<u8>,
) {
    let auth = ct.authorize_as_object(&mut vault.id);
    contra::wrap(receiver, &auth, ct, deny_list, pool, coin, memo);
}
