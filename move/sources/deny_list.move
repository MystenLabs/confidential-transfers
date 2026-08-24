// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::deny_list;

use sui::{
    coin::{deny_list_v2_contains_next_epoch, deny_list_v2_is_global_pause_enabled_next_epoch},
    deny_list::DenyList
};

// The `_next_epoch` variants are used because addresses denied for the next epoch are already
// unable to use objects of this coin type as inputs.

public(package) fun is_receiver_denied<T>(deny_list: &DenyList, receiver: address): bool {
    deny_list_v2_contains_next_epoch<T>(deny_list, receiver)
}

public(package) fun is_frozen<T>(deny_list: &DenyList): bool {
    deny_list_v2_is_global_pause_enabled_next_epoch<T>(deny_list)
}

public(package) fun is_sender_denied<T>(deny_list: &DenyList, sender: address): bool {
    deny_list_v2_contains_next_epoch<T>(deny_list, sender)
}
