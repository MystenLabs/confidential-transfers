/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { bcs } from '@mysten/sui/bcs';
import { type Transaction, type TransactionArgument } from '@mysten/sui/transactions';

import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import * as group_ops from './deps/sui/group_ops.js';
import * as nizk from './nizk.js';
import * as twisted_elgamal from './twisted_elgamal.js';

const $moduleName = '@local-pkg/contra::auditors';
export const Auditors = new MoveStruct({
	name: `${$moduleName}::Auditors`,
	fields: {
		pks: bcs.vector(group_ops.Element),
		version: bcs.u32(),
		recommended_min_version: bcs.u32(),
	},
});
export const VerifiedKeyEncryption = new MoveStruct({
	name: `${$moduleName}::VerifiedKeyEncryption`,
	fields: {
		ciphertext: bcs.vector(twisted_elgamal.MultiRecipientEncryption),
		version: bcs.u32(),
	},
});
export const KeyEncryption = new MoveStruct({
	name: `${$moduleName}::KeyEncryption`,
	fields: {
		ciphertext: bcs.vector(twisted_elgamal.MultiRecipientEncryption),
		proof: nizk.KeyConsistencyProof,
		range_proof: bcs.vector(bcs.u8()),
	},
});
export interface NewKeyEncryptionArguments {
	ciphertext: TransactionArgument;
	proof: TransactionArgument;
	rangeProof: RawTransactionArgument<Array<number>>;
}
export interface NewKeyEncryptionOptions {
	package?: string;
	arguments:
		| NewKeyEncryptionArguments
		| [
				ciphertext: TransactionArgument,
				proof: TransactionArgument,
				rangeProof: RawTransactionArgument<Array<number>>,
		  ];
}
export function newKeyEncryption(options: NewKeyEncryptionOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<null>', null, 'vector<u8>'] satisfies (string | null)[];
	const parameterNames = ['ciphertext', 'proof', 'rangeProof'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'auditors',
			function: 'new_key_encryption',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
