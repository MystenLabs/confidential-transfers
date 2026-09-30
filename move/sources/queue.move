// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module contra::queue;

/// FIFO over a vector: reversed once on construction, so `pop_front` is an O(1) `pop_back`.
public struct Queue<T> has store { reversed: vector<T> }

public(package) fun from_vector<T>(mut v: vector<T>): Queue<T> {
    v.reverse();
    Queue { reversed: v }
}

public(package) fun pop_front<T>(q: &mut Queue<T>): T { q.reversed.pop_back() }

public(package) fun is_empty<T>(q: &Queue<T>): bool { q.reversed.is_empty() }

public(package) fun destroy_empty<T>(q: Queue<T>) {
    let Queue { reversed } = q;
    reversed.destroy_empty();
}

#[test]
fun test_fifo_order() {
    let mut q = from_vector(vector[1u64, 2, 3]);
    assert!(q.pop_front() == 1);
    assert!(q.pop_front() == 2);
    assert!(q.pop_front() == 3);
    assert!(q.is_empty());
    q.destroy_empty();
}
