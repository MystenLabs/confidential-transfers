/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/**
 * An account's confidential holdings of one token, all under one key: the
 * spendable `active` balance, the `pending` deposits, and the `public_balance` of
 * wrapped-but-unmerged coins — deposits land aside and are folded in by
 * `merge_deposits`, so they never mutate the balance a concurrent transfer is
 * proving against.
 */

import { bcs } from '@mysten/sui/bcs';

import { MoveStruct } from '../utils/index.js';
import * as encrypted_amount from './encrypted_amount.js';
import * as twisted_elgamal from './twisted_elgamal.js';

const $moduleName = '@local-pkg/contra::balance';
export const AccumulatedAmount = new MoveStruct({
	name: `${$moduleName}::AccumulatedAmount`,
	fields: {
		amount: encrypted_amount.EncryptedAmount,
		terms: bcs.u16(),
	},
});
export const Balances = new MoveStruct({
	name: `${$moduleName}::Balances<phantom T>`,
	fields: {
		pk: twisted_elgamal.PublicKey,
		active: AccumulatedAmount,
		pending: AccumulatedAmount,
		public_balance: bcs.u64(),
	},
});
export const EncryptedCoin = new MoveStruct({
	name: `${$moduleName}::EncryptedCoin<phantom T>`,
	fields: {
		amount: encrypted_amount.RangeVerifiedAmount,
	},
});
