/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/**
 * An account's confidential holdings of one token, under one key.
 *
 * `EncryptedBalance<T>` bundles the public key an account's amounts for token `T`
 * are encrypted under with the three places its value sits: the spendable `active`
 * balance, the `pending` encrypted deposits received from other accounts, and
 * `public_balance`, the wrapped but not yet merged public deposits. Deposits land
 * in `pending` / `public_balance` and are folded into `active` by
 * `merge_deposits`, so an incoming deposit never mutates the balance a concurrent
 * transfer is proving against.
 *
 * The module is closed over its own key and transcript: every amount is verified
 * and checked against `EncryptedBalance.pk` — one encrypted under any other key is
 * rejected, whether it arrives as a deposit or as a replacement balance — and
 * every proof is checked against a Fiat-Shamir domain separator the module derives
 * itself from the caller's session id, so a caller can supply neither a mismatched
 * key nor the wrong transcript. What stays with the caller is everything that is
 * not value: authorization, freezing, and events.
 *
 * Amounts are verified in their own step (`verify_amount` /
 * `verify_transfer_amounts`) and the resulting `InRangeVerifiedEncryptedAmount` is
 * what the withdrawal and re-statement entry points take. The split is what lets a
 * transfer's auditor data be checked against the verified receiver amounts before
 * any balance moves.
 *
 * Encrypted value leaves a balance as an `EncryptedCoin<T>`: a linear,
 * receiver-keyed amount split off a sender's balance and handed back for the
 * caller to credit to the receiver. Public value crosses straight to and from the
 * token's pool, tracked here only by the plaintext `public_balance`.
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
export const EncryptedCoin = new MoveStruct({
	name: `${$moduleName}::EncryptedCoin<phantom T>`,
	fields: {
		amount: encrypted_amount.InRangeVerifiedEncryptedAmount,
	},
});
