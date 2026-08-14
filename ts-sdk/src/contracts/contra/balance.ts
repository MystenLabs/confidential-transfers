/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/**
 * Confidential value: `EncryptedBalance<T>` (a single encrypted amount with a
 * count of merged u16-bounded values that bounds limb growth), plus the linear
 * coin types `PublicCoin<T>` and `EncryptedCoin<T>` that move value in and out.
 */

import { bcs } from '@mysten/sui/bcs';

import { MoveStruct } from '../utils/index.js';
import * as encrypted_amount from './encrypted_amount.js';

const $moduleName = '@local-pkg/contra::balance';
export const EncryptedBalance = new MoveStruct({
	name: `${$moduleName}::EncryptedBalance<phantom T>`,
	fields: {
		amount: encrypted_amount.EncryptedAmount,
		upper_bound: bcs.u16(),
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
