// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Access policies for `ConfidentialToken<T>`: a `Policy` maps each permissioned operation to a list of required
/// witness types (up to `MAX_WITNESSES_PER_OPERATION`). All of the witness are required for the operation. Each
/// witness mints its own `Auth<T>`; `join` combines them, and an `Auth` may be *bound* to a digest of the operation's
/// arguments, which the gated entry point recomputes and must match.
module contra::policy;

use std::type_name::{Self, TypeName};
use sui::vec_map::{Self, VecMap};

// === Errors ===

const EInvalidOperation: u64 = 0;
const EDuplicateOperation: u64 = 1;
const EAuthorizationError: u64 = 2;
const ETooManyWitnesses: u64 = 3;

// === Constants ===

/// Permissioned operations are indexed into a 32 bit bitmap.
const MAX_OPERATION_INDEX: u8 = 31;
/// Most witness types one operation may require.
const MAX_WITNESSES_PER_OPERATION: u64 = 3;

// === Types ===

/// Access policy for a confidential token: operation index -> the witness types that must all
/// authorize it; an operation with no entry is permissionless. Only the module defining a
/// witness type can produce it, so only that module can authorize the operations listing it.
public struct Policy has drop, store {
    witnesses: VecMap<u8, vector<TypeName>>,
}

/// A witness's stamp on an `Auth`: `witness_type` approved the operation it is filed under for
/// the auth's owner, bound to the argument digest `binding` if set (`None` = any arguments).
public struct Endorsement has copy, drop {
    witness_type: TypeName,
    binding: Option<vector<u8>>,
}

/// A capability authorizing operations on behalf of `owner`. The phantom `T` tags the auth with
/// the consuming domain so an auth minted for one context cannot be used in another.
public struct Auth<phantom T> has drop {
    /// Bitmap with bit `o` set iff operation `o` is allowed: every permissionless operation for
    /// a sender/object auth; for a witness auth, each operation every required witness endorsed.
    operations: u32,
    owner: address,
    /// Operation -> the witnesses that endorsed it, mirroring `Policy.witnesses`.
    endorsements: VecMap<u8, vector<Endorsement>>,
}

// === Policy mutation ===

/// A fully permissionless policy: every operation is allowed without a witness.
public(package) fun permissionless(): Policy {
    Policy { witnesses: vec_map::empty() }
}

/// Require witness `W` for each of `operations`, in addition to any witnesses already required.
/// Aborts on an operation index above `MAX_OPERATION_INDEX`, a duplicate, or a fourth witness.
public(package) fun add<W>(policy: &mut Policy, operations: vector<u8>) {
    assert!(operations.all!(|o| *o <= MAX_OPERATION_INDEX), EInvalidOperation);
    let witness = type_name::with_defining_ids<W>();
    operations.do!(|operation| {
        if (!policy.witnesses.contains(&operation)) {
            policy.witnesses.insert(operation, vector[]);
        };
        let required = &mut policy.witnesses[&operation];
        assert!(!required.contains(&witness), EDuplicateOperation);
        assert!(required.length() < MAX_WITNESSES_PER_OPERATION, ETooManyWitnesses);
        required.push_back(witness);
    });
}

/// Stop requiring witness `W` for each of `operations`; an operation becomes permissionless once
/// no witness is required for it. A no-op where `W` was not required.
public(package) fun remove<W>(policy: &mut Policy, operations: vector<u8>) {
    let witness = type_name::with_defining_ids<W>();
    operations.do!(|operation| {
        assert!(operation <= MAX_OPERATION_INDEX, EInvalidOperation);
        if (!policy.witnesses.contains(&operation)) return;
        let required = &mut policy.witnesses[&operation];
        required.find_index!(|w| w == witness).do!(|i| { required.remove(i); });
        if (required.is_empty()) {
            policy.witnesses.remove(&operation);
        }
    });
}

// === Auth constructors ===

/// Create an `Auth<T>` for `ctx.sender()` covering every permissionless operation.
public(package) fun as_sender<T>(policy: &Policy, ctx: &TxContext): Auth<T> {
    Auth {
        operations: permissionless_bitmap(policy),
        owner: ctx.sender(),
        endorsements: vec_map::empty(),
    }
}

#[allow(unused_mut_parameter)]
/// Create an `Auth<T>` on behalf of the object identified by `uid` covering every permissionless
/// operation. Holding `&mut UID` proves custody of the object, so the object self-authenticates
/// as its own `owner`. Owner address is the inner value of the `UID`.
public(package) fun as_object<T>(policy: &Policy, uid: &mut UID): Auth<T> {
    Auth {
        operations: permissionless_bitmap(policy),
        owner: uid.to_inner().to_address(),
        endorsements: vec_map::empty(),
    }
}

/// Create an `Auth<T>` on behalf of `owner` for `operation`, endorsed by witness `W`; aborts
/// unless `W` is required for `operation`, and the witness-holding module must authenticate
/// `owner`. The auth allows `operation` immediately if `W` is its only required witness;
/// otherwise `join` it with the other witnesses' auths.
public(package) fun with_witness<T, W: drop>(
    policy: &Policy,
    operation: u8,
    owner: address,
    _witness: W,
): Auth<T> {
    endorsed(policy, operation, owner, option::none(), type_name::with_defining_ids<W>())
}

/// Like `with_witness`, but the endorsement is bound to `binding`: the resulting `Auth` is
/// spendable only on the operation whose recomputed argument digest equals `binding`.
public(package) fun with_witness_bound<T, W: drop>(
    policy: &Policy,
    operation: u8,
    owner: address,
    binding: vector<u8>,
    _witness: W,
): Auth<T> {
    endorsed(policy, operation, owner, option::some(binding), type_name::with_defining_ids<W>())
}

/// Combine two auths for the same owner: the endorsements are concatenated, and an operation is
/// allowed if either auth allowed it or every witness it requires has now endorsed it.
public(package) fun join<T>(policy: &Policy, a: Auth<T>, b: Auth<T>): Auth<T> {
    assert!(a.owner == b.owner, EAuthorizationError);
    let mut endorsements = a.endorsements;
    b.endorsements.keys().do!(|op| {
        if (!endorsements.contains(&op)) endorsements.insert(op, vector[]);
        endorsements[&op].append(b.endorsements[&op]);
    });
    Auth {
        operations: a.operations | b.operations | endorsed_bitmap(policy, &endorsements),
        owner: a.owner,
        endorsements,
    }
}

// === Checks ===

/// True iff `operation` is not gated by any witness. Aborts if `operation > MAX_OPERATION_INDEX`.
public(package) fun is_permissionless(policy: &Policy, operation: u8): bool {
    assert!(operation <= MAX_OPERATION_INDEX, EInvalidOperation);
    !policy.witnesses.contains(&operation)
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

/// Every bound endorsement on `auth` must have committed to `digest`, i.e. the caller is
/// executing exactly the operation each binding witness approved. A no-op if none is bound.
public(package) fun assert_binding<T>(auth: &Auth<T>, digest: vector<u8>) {
    auth.endorsements.keys().do!(|op| {
        auth.endorsements[&op].do_ref!(|e| {
            e.binding.do_ref!(|b| assert!(*b == digest, EAuthorizationError))
        })
    });
}

// === Helpers ===

/// A one-endorsement auth for `operation` by `witness_type`; aborts unless the policy requires
/// that witness for the operation.
fun endorsed<T>(
    policy: &Policy,
    operation: u8,
    owner: address,
    binding: Option<vector<u8>>,
    witness_type: TypeName,
): Auth<T> {
    assert!(operation <= MAX_OPERATION_INDEX, EInvalidOperation);
    assert!(
        policy.witnesses.contains(&operation) && policy.witnesses[&operation].contains(&witness_type),
        EAuthorizationError,
    );
    let mut endorsements = vec_map::empty();
    endorsements.insert(operation, vector[Endorsement { witness_type, binding }]);
    Auth { operations: endorsed_bitmap(policy, &endorsements), owner, endorsements }
}

/// The bitmap of gated operations for which every required witness has an endorsement.
fun endorsed_bitmap(policy: &Policy, endorsements: &VecMap<u8, vector<Endorsement>>): u32 {
    endorsements.keys().fold!(0u32, |acc, op| {
        let endorsed = &endorsements[&op];
        let all =
            policy.witnesses.contains(&op) &&
            policy.witnesses[&op].all!(|w| endorsed.any!(|e| e.witness_type == *w));
        if (all) acc | (1u32 << op) else acc
    })
}

/// The bitmap of operations no witness gates: every index absent from `witnesses`.
fun permissionless_bitmap(policy: &Policy): u32 {
    policy.witnesses.keys().fold!(0xFFFFFFFFu32, |acc, op| acc & (0xFFFFFFFFu32 ^ (1 << op)))
}
