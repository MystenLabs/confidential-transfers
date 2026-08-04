// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Confidential variant of pBU.
///
/// Registration of a confidential pBU `TokenAccount` is gated by a shared
/// `Whitelist`: only addresses added by a `WhitelistAdminCap` holder may call
/// `register`, but once allowed they can register a `TokenAccount` on any
/// `Account` (e.g. an issuer-controlled operator registering on behalf of
/// KYCed users).
///
/// All other flows (wrap, unwrap, transfer, ...) are inherited from
/// `contra::contra` and remain permissionless.
module closed_loop::confidential_pbu;

use closed_loop::pbu::{Self, PbuAdminCap, Pool, PBU};
use contra::{
    contra::{Self, Account, ConfidentialToken, ManagementCap, TokenRegistry},
    nizk::DdhProof
};
use sui::{group_ops::Element, ristretto255::G, vec_set::{Self, VecSet}};

// === Errors ===

const ENotWhitelisted: u64 = 0;

// === Constants ===

/// Bitmap index for the `register` operation in `contra::contra`. Must stay in
/// sync with `contra::contra::REGISTER = 0`.
const REGISTER_OP: u8 = 0;

// === Types ===

/// Witness for the permissioned `register` operation. Only this module can
/// construct it, which is what lets us enforce the whitelist check here.
public struct PbuWitness has drop {}

/// Shared object holding the set of addresses allowed to call `register`.
public struct Whitelist has key {
    id: UID,
    addresses: VecSet<address>,
}

/// Capability for managing the `Whitelist`. Issued once at setup and given
/// to the deployer/issuer.
public struct WhitelistAdminCap has key, store { id: UID }

// === Setup ===

/// Create the `ConfidentialToken<PBU>`, install a policy that makes `register`
/// permissioned with this module's `PbuWitness`, share the confidential token,
/// share the `Whitelist`, and return the `ManagementCap<PBU>` and
/// `WhitelistAdminCap` to the caller.
///
/// Requires `&PbuAdminCap` so only the pBU deployer can perform setup.
public fun setup(
    _admin: &PbuAdminCap,
    pool: &mut Pool,
    registry: &mut TokenRegistry,
    ctx: &mut TxContext,
): (ManagementCap<PBU>, WhitelistAdminCap) {
    let (mut ct, management_cap) = contra::new_confidential_token<PBU>(
        registry,
        pbu::treasury_mut(pool),
        option::none(),
        ctx,
    );
    ct.set_policy<PBU, PbuWitness>(pbu::treasury_mut(pool), vector[REGISTER_OP]);
    contra::share_confidential_token(ct);

    transfer::share_object(Whitelist {
        id: object::new(ctx),
        addresses: vec_set::empty(),
    });

    (management_cap, WhitelistAdminCap { id: object::new(ctx) })
}

// === Whitelist management ===

public fun add_to_whitelist(_cap: &WhitelistAdminCap, whitelist: &mut Whitelist, addr: address) {
    whitelist.addresses.insert(addr);
}

public fun remove_from_whitelist(
    _cap: &WhitelistAdminCap,
    whitelist: &mut Whitelist,
    addr: address,
) {
    whitelist.addresses.remove(&addr);
}

public fun is_whitelisted(whitelist: &Whitelist, addr: address): bool {
    whitelist.addresses.contains(&addr)
}

// === Gated register ===

/// Register a confidential pBU `TokenAccount` on `account`, keyed under the
/// current `account.pk`. Callable only by addresses on the `Whitelist`; the
/// caller does not need to own `account`.
public fun register(
    ct: &ConfidentialToken<PBU>,
    whitelist: &Whitelist,
    account: &mut Account,
    ctx: &mut TxContext,
) {
    assert!(whitelist.addresses.contains(&ctx.sender()), ENotWhitelisted);
    // Auth is only used internally.
    let auth = ct.authorize_with_witness(REGISTER_OP, account.owner(), PbuWitness {});
    // Key the token account under the account's default key (set at account creation).
    let pk = *contra::account_public_key(account).borrow();
    contra::register(account, &auth, pk);
}

/// Rotate `account`'s key to `new_pk` and re-key its confidential pBU balance.
/// Callable only by addresses on the `Whitelist`; like `register`, the caller
/// does not need to own `account` (key rotation reuses the `REGISTER`
/// operation slot in the policy, so it is gated by the same whitelist).
public fun set_public_key(
    ct: &ConfidentialToken<PBU>,
    whitelist: &Whitelist,
    account: &mut Account,
    new_pk: Element<G>,
    new_handles: vector<Element<G>>,
    rekey_proof: DdhProof,
    ctx: &mut TxContext,
) {
    assert!(whitelist.addresses.contains(&ctx.sender()), ENotWhitelisted);
    let auth = ct.authorize_with_witness(REGISTER_OP, account.owner(), PbuWitness {});
    contra::set_account_key(account, &auth, option::some(new_pk));
    contra::rekey_token(account, &auth, new_pk, new_handles, rekey_proof);
}
