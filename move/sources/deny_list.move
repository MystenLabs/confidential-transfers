// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::deny_list;

use sui::{
    coin::{deny_list_v2_contains_next_epoch, deny_list_v2_is_global_pause_enabled_next_epoch},
    deny_list::DenyList
};

/// Check if the given address is on the deny list for token type `T`.
public(package) fun is_receiver_denied<T>(deny_list: &DenyList, receiver: address): bool {
    deny_list_v2_contains_next_epoch<T>(deny_list, receiver)
}

/// Check if all transfers for token type `T` are globally paused.
public(package) fun is_frozen<T>(deny_list: &DenyList): bool {
    deny_list_v2_is_global_pause_enabled_next_epoch<T>(deny_list)
}

/// Check if the given sender address is on the deny list for token type `T`.
public(package) fun is_sender_denied<T>(deny_list: &DenyList, sender: address): bool {
    // Denied addresses in the next epoch will immediately be unable to use objects of this coin type as inputs.
    deny_list_v2_contains_next_epoch<T>(deny_list, sender)
}
