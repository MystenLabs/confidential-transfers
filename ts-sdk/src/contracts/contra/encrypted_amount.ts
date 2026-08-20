/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { bcs } from '@mysten/sui/bcs';
import { type Transaction, type TransactionArgument } from '@mysten/sui/transactions';

import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import * as twisted_elgamal from './twisted_elgamal.js';

const $moduleName = '@local-pkg/contra::encrypted_amount';
export const EncryptedAmount = new MoveStruct({
	name: `${$moduleName}::EncryptedAmount`,
	fields: {
		l0: twisted_elgamal.Encryption,
		l1: twisted_elgamal.Encryption,
		l2: twisted_elgamal.Encryption,
		l3: twisted_elgamal.Encryption,
	},
});
export const RangeVerifiedAmount = new MoveStruct({
	name: `${$moduleName}::RangeVerifiedAmount`,
	fields: {
		amount: EncryptedAmount,
		pk: twisted_elgamal.PublicKey,
	},
});
export const VerifiedEncryption = new MoveStruct({
	name: `${$moduleName}::VerifiedEncryption`,
	fields: {
		encryption: twisted_elgamal.Encryption,
		pk: twisted_elgamal.PublicKey,
	},
});
export const VerifiedAmount = new MoveStruct({
	name: `${$moduleName}::VerifiedAmount`,
	fields: {
		amount: EncryptedAmount,
		pk: twisted_elgamal.PublicKey,
	},
});
export const RangeProofs = new MoveStruct({
	name: `${$moduleName}::RangeProofs`,
	fields: {
		proofs: bcs.vector(bcs.vector(bcs.u8())),
	},
});
export interface NewRangeProofsArguments {
	proofs: RawTransactionArgument<Array<Array<number>>>;
}
export interface NewRangeProofsOptions {
	package?: string;
	arguments: NewRangeProofsArguments | [proofs: RawTransactionArgument<Array<Array<number>>>];
}
/**
 * Wrap `proofs` into `RangeProofs`; rejects an empty set so the range check can't
 * be skipped on chain.
 */
export function newRangeProofs(options: NewRangeProofsOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<u8>>'] satisfies (string | null)[];
	const parameterNames = ['proofs'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'encrypted_amount',
			function: 'new_range_proofs',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface NewEncryptedAmountArguments {
	l0: TransactionArgument;
	l1: TransactionArgument;
	l2: TransactionArgument;
	l3: TransactionArgument;
}
export interface NewEncryptedAmountOptions {
	package?: string;
	arguments:
		| NewEncryptedAmountArguments
		| [
				l0: TransactionArgument,
				l1: TransactionArgument,
				l2: TransactionArgument,
				l3: TransactionArgument,
		  ];
}
export function newEncryptedAmount(options: NewEncryptedAmountOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, null, null] satisfies (string | null)[];
	const parameterNames = ['l0', 'l1', 'l2', 'l3'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'encrypted_amount',
			function: 'new_encrypted_amount',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
