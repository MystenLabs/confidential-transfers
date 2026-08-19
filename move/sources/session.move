// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// The Fiat-Shamir transcript of one token account: the session it is bound to, and the domain
/// separator of each protocol proven against it.
module contra::session;

/// A domain separator unique to one account's holdings of one token.
public struct Session has copy, drop, store {
    id: vector<u8>,
}

public(package) fun new(id: vector<u8>): Session {
    Session { id }
}

// The Fiat-Shamir DST binding a proof of each protocol to `self`. The tags are shared with the
// ts-sdk, which reserves `100` for `PROTOCOL_VERIFIED_DEC`.

public(package) fun ddh(self: &Session): vector<u8> { self.dst(0x01) }

public(package) fun elgamal(self: &Session): vector<u8> { self.dst(0x02) }

public(package) fun range_proof_16(self: &Session): vector<u8> { self.dst(0x04) }

public(package) fun batch_ddh(self: &Session): vector<u8> { self.dst(0x06) }

public(package) fun auditor_elgamal(self: &Session): vector<u8> { self.dst(0x07) }

fun dst(self: &Session, tag: u8): vector<u8> {
    let mut bytes = self.id;
    bytes.push_back(tag);
    bytes
}

// === Test Helpers ===

#[test_only]
public(package) fun protocol_id_ddh(): u8 { 0x01 }

#[test_only]
public(package) fun protocol_id_elgamal(): u8 { 0x02 }

#[test_only]
public(package) fun protocol_id_batch_ddh(): u8 { 0x06 }

#[test_only]
public(package) fun protocol_id_auditor_elgamal(): u8 { 0x07 }

#[test_only]
public(package) fun dst_with_tag(self: &Session, tag: u8): vector<u8> {
    let mut bytes = self.id;
    bytes.push_back(tag);
    bytes
}
