/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/**
 * An account's confidential holdings of one token, all under one key: the
 * spendable `active` balance, the `pending` deposits, and the plaintext
 * `public_balance` of wrapped-but-unmerged coins — deposits land aside and are
 * folded in by `merge_deposits`, so they never mutate the balance a concurrent
 * transfer is proving against. The module is closed over its own key and
 * transcript: every amount is checked against `pk`, every proof against a DST it
 * derives itself.
 */

import { bcs } from '@mysten/sui/bcs';

import { MoveStruct } from '../utils/index.js';
import * as encrypted_amount from './encrypted_amount.js';
import * as twisted_elgamal from './twisted_elgamal.js';

const $moduleName = '@local-pkg/contra::balance';
export const BoundedEncryptedAmount = new MoveStruct({
	name: `${$moduleName}::BoundedEncryptedAmount`,
	fields: {
		amount: encrypted_amount.EncryptedAmount,
		upper_bound: bcs.u16(),
	},
});
export const EncryptedBalance = new MoveStruct({
	name: `${$moduleName}::EncryptedBalance<phantom T>`,
	fields: {
		pk: twisted_elgamal.PublicKey,
		active: BoundedEncryptedAmount,
		pending: BoundedEncryptedAmount,
		public_balance: bcs.u64(),
	},
});
export const PublicCoin = new MoveStruct({
	name: `${$moduleName}::PublicCoin<phantom T>`,
	fields: {
		value: bcs.u64(),
	},
});
export const EncryptedCoin = new MoveStruct({
	name: `${$moduleName}::EncryptedCoin<phantom T>`,
	fields: {
		amount: encrypted_amount.InRangeVerifiedEncryptedAmount,
	},
});
export const VerifiedTransfer = new MoveStruct({
	name: `${$moduleName}::VerifiedTransfer<phantom T>`,
	fields: {
		receiver_amounts: bcs.vector(encrypted_amount.InRangeVerifiedEncryptedAmount),
		new_balance: encrypted_amount.InRangeVerifiedEncryptedAmount,
		total_sender: encrypted_amount.VerifiedEncryption,
	},
});
