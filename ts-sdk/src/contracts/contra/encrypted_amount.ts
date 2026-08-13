/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { bcs } from '@mysten/sui/bcs';
import { type Transaction, type TransactionArgument } from '@mysten/sui/transactions';

import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import * as nizk from './nizk.js';
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
export const WellFormedEncryptedAmount = new MoveStruct({
	name: `${$moduleName}::WellFormedEncryptedAmount`,
	fields: {
		amount: EncryptedAmount,
		pk: twisted_elgamal.PublicKey,
	},
});
export const WellFormedProof = new MoveStruct({
	name: `${$moduleName}::WellFormedProof`,
	fields: {
		range_proofs: bcs.vector(bcs.vector(bcs.u8())),
		consistency_proofs: bcs.vector(nizk.ElGamalProof),
	},
});
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
export interface NewWellFormedProofArguments {
	rangeProofs: RawTransactionArgument<Array<Array<number>>>;
	consistencyProofs: TransactionArgument;
}
export interface NewWellFormedProofOptions {
	package?: string;
	arguments:
		| NewWellFormedProofArguments
		| [
				rangeProofs: RawTransactionArgument<Array<Array<number>>>,
				consistencyProofs: TransactionArgument,
		  ];
}
/**
 * Bundle range proofs and consistency proofs into a `WellFormedProof`. Pass one
 * consistency proof per amount and one range proof per
 * `batch_sizes(consistency_proofs.length())` chunk, where each chunk's range proof
 * covers that chunk's amounts (4 limbs each). Aborts on length mismatch or empty
 * `range_proofs[i]`; proofs are not verified here — callers must call `verify`.
 */
export function newWellFormedProof(options: NewWellFormedProofOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<u8>>', 'vector<null>'] satisfies (string | null)[];
	const parameterNames = ['rangeProofs', 'consistencyProofs'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'encrypted_amount',
			function: 'new_well_formed_proof',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
