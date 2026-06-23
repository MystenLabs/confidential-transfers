// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Access policies for `ConfidentialToken<T>`. A `Policy` records the set of operations that
/// require a witness of a specific type, used to gate permissioned versions of those operations.
module contra::policy;

use std::type_name::{Self, TypeName};

// === Errors ===

const EInvalidOperation: u64 = 0;
const EDuplicateOperation: u64 = 1;
const EAuthorizationError: u64 = 2;

// === Constants ===

/// Permissioned operations are stored as a 32 bit bitmap.
const MAX_OPERATION_INDEX: u8 = 31;

// === Types ===

/// Access policies for a confidential token.
/// If set, some operations, as defined in the policy, must be called using their permissioned
/// version with a witness.
public struct Policy has drop, store {
    // Only the contract that owns this type can produce a witness, preventing other callers from
    // authorizing permissioned operations.
    witness_type: TypeName,
    permissioned_operations_bitmap: u32,
}

/// A capability authorizing a set of operations on behalf of `owner`. The phantom `T` tags the
/// auth with the consuming domain so an auth minted for one context cannot be used in another.
public struct Auth<phantom T> has drop {
    /// Bitmap with bit `o` set iff operation `o` is allowed.
    operations: u32,
    owner: address,
}

// === Constructor ===

/// Create a new `Policy` for witness type `W` covering the given operations. Aborts if any
/// operation index exceeds `MAX_OPERATION_INDEX` or if `permissioned_operations` contains
/// duplicates.
fun new<W>(permissioned_operations: vector<u8>): Policy {
    assert!(permissioned_operations.all!(|o| *o <= MAX_OPERATION_INDEX), EInvalidOperation);
    assert!(is_unique(&permissioned_operations), EDuplicateOperation);
    Policy {
        witness_type: type_name::with_defining_ids<W>(),
        permissioned_operations_bitmap: create_bitmap(permissioned_operations),
    }
}

/// A fully permissionless policy slot: every operation is allowed without a witness.
public(package) fun permissionless(): Option<Policy> {
    option::none()
}

/// Update `policy` to gate `permissioned_operations` behind witness `W`. An empty
/// `permissioned_operations` clears the policy entirely (every operation becomes permissionless
/// again). Aborts if any operation index exceeds `MAX_OPERATION_INDEX` or if
/// `permissioned_operations` contains duplicates.
public(package) fun set<W>(policy: &mut Option<Policy>, permissioned_operations: vector<u8>) {
    if (permissioned_operations.is_empty()) {
        *policy = permissionless();
    } else {
        policy.swap_or_fill(new<W>(permissioned_operations));
    }
}

// === Auth constructors ===

/// Create an `Auth<T>` for `ctx.sender()` covering every operation the policy leaves
/// permissionless (i.e. every operation NOT listed in the policy's permissioned bitmap). When
/// `policy` is empty, all operations are permissionless.
public(package) fun as_sender<T>(policy: &Option<Policy>, ctx: &TxContext): Auth<T> {
    Auth { operations: permissionless_bitmap(policy), owner: ctx.sender() }
}

#[allow(unused_mut_parameter)]
/// Create an `Auth<T>` on behalf of the object identified by `uid` covering every operation the
/// policy leaves permissionless. Holding `&mut UID` proves custody of the object, so the object
/// self-authenticates as its own `owner`. Owner address is the inner value of the `UID`.
public(package) fun as_object<T>(policy: &Option<Policy>, uid: &mut UID): Auth<T> {
    Auth { operations: permissionless_bitmap(policy), owner: uid.to_inner().to_address() }
}

/// Create an `Auth<T>` on behalf of `owner` covering the requested `operation`, authorized by
/// witness `W`. Aborts unless `policy` is set, its witness type is `W`, and `operation` is
/// permissioned in `policy`. The witness-holding contract is fully responsible for authenticating
/// `owner`.
public(package) fun with_witness<T, W: drop>(
    policy: &Option<Policy>,
    operation: u8,
    owner: address,
    _witness: W,
): Auth<T> {
    assert!(operation <= MAX_OPERATION_INDEX, EInvalidOperation);
    assert!(
        policy.is_some_and!(|p| p.witness_type == type_name::with_defining_ids<W>()),
        EAuthorizationError,
    );
    // TODO: consider limiting it to permissioned operations only (defense in depth)
    Auth { operations: 1u32 << operation, owner }
}

/// True if `auth` authorizes `operation`. Aborts if `operation > MAX_OPERATION_INDEX`.
public(package) fun is_allowed<T>(auth: &Auth<T>, operation: u8): bool {
    assert!(operation <= MAX_OPERATION_INDEX, EInvalidOperation);
    auth.operations & (1 << operation) != 0
}

/// True if `auth` authenticates `owner`.
public(package) fun is_authenticated<T>(auth: &Auth<T>, owner: address): bool {
    auth.owner == owner
}

// === Helpers ===

/// Return `true` iff `v` contains no duplicates.
fun is_unique<T: copy + drop>(v: &vector<T>): bool {
    let mut seen = vector[];
    v.all!(|item| {
        if (seen.contains(item)) false
        else { seen.push_back(*item); true }
    })
}

/// Build a `u32` bitmap with bit `o` set for each `o` in `operations`. Caller must ensure each
/// `o <= MAX_OPERATION_INDEX`.
fun create_bitmap(operations: vector<u8>): u32 {
    operations.fold!(0, |acc, operation| acc | (1 << operation))
}

/// The bitmap of operations that `policy` leaves permissionless. When `policy` is `None`, every
/// operation is permissionless (`u32::MAX`); otherwise it's the bitwise complement of the
/// policy's permissioned bitmap.
fun permissionless_bitmap(policy: &Option<Policy>): u32 {
    policy.map_ref!(|p| p.permissioned_operations_bitmap ^ 0xFFFFFFFFu32).destroy_or!(0xFFFFFFFFu32)
}
