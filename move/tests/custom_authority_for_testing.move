// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Minimal custom authority used to test Contra's public authority integration surface.
#[test_only]
module contra::custom_authority_for_testing;

use contra::{authority::{Approval, AuthorityCap}, contra::{Self, ConfidentialToken, ManagementCap}};

public struct CustomAuthority<phantom T> has key {
    id: UID,
    authority_cap: AuthorityCap<T>,
}

public(package) fun new<T>(
    management_cap: &ManagementCap<T>,
    ctx: &mut TxContext,
): CustomAuthority<T> {
    let id = object::new(ctx);
    let authority_cap = contra::new_authority_cap(&id, management_cap);
    CustomAuthority { id, authority_cap }
}

public(package) fun mint_approval<T>(
    self: &CustomAuthority<T>,
    ct: &ConfidentialToken<T>,
    digest: &vector<u8>,
): Option<Approval<T>> {
    ct.mint_custom_authority_approval(&self.authority_cap, digest)
}
