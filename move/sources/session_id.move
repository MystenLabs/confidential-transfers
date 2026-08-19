// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// The Fiat-Shamir transcript of one token account: the session it is bound to, and the domain
/// separator of each protocol proven against it.
module contra::session_id;

// === Constants ===

// Protocol tags, shared with the ts-sdk, which reserves `100` for `PROTOCOL_VERIFIED_DEC`.
const DST_DDH: u8 = 0x01;
const DST_ELGAMAL: u8 = 0x02;
const DST_RANGE_PROOF_16: u8 = 0x04;
const DST_BATCH_DDH: u8 = 0x06;
const DST_AUDITOR_ELGAMAL: u8 = 0x07;

// === Structs ===

/// A domain separator unique to one account's holdings of one token.
public struct SessionId has copy, drop, store {
    id: vector<u8>,
}

public(package) fun new(id: vector<u8>): SessionId {
    SessionId { id }
}

// The Fiat-Shamir DST binding a proof of each protocol to `self`.

public(package) fun ddh(self: &SessionId): vector<u8> { self.dst(DST_DDH) }

public(package) fun elgamal(self: &SessionId): vector<u8> { self.dst(DST_ELGAMAL) }

public(package) fun range_proof_16(self: &SessionId): vector<u8> { self.dst(DST_RANGE_PROOF_16) }

public(package) fun batch_ddh(self: &SessionId): vector<u8> { self.dst(DST_BATCH_DDH) }

public(package) fun auditor_elgamal(self: &SessionId): vector<u8> { self.dst(DST_AUDITOR_ELGAMAL) }

fun dst(self: &SessionId, tag: u8): vector<u8> {
    let mut bytes = self.id;
    bytes.push_back(tag);
    bytes
}
