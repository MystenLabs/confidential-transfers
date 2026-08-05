/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { bcs } from '@mysten/sui/bcs';
import { type Transaction, type TransactionArgument } from '@mysten/sui/transactions';

import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';
import * as group_ops from './deps/sui/group_ops.js';
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
		pk: group_ops.Element,
	},
});
export const ConsistencyProof = new MoveStruct({
	name: `${$moduleName}::ConsistencyProof`,
	fields: {
		proof: nizk.ElGamalProof,
	},
});
export const WellFormedProof = new MoveStruct({
	name: `${$moduleName}::WellFormedProof`,
	fields: {
		range_proofs: bcs.vector(bcs.vector(bcs.u8())),
		consistency_proofs: bcs.vector(ConsistencyProof),
	},
});
export const U32LimbHandles = new MoveStruct({
	name: `${$moduleName}::U32LimbHandles`,
	fields: {
		handles: bcs.vector(group_ops.Element),
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
export interface NewConsistencyProofArguments {
	proof: TransactionArgument;
}
export interface NewConsistencyProofOptions {
	package?: string;
	arguments: NewConsistencyProofArguments | [proof: TransactionArgument];
}
export function newConsistencyProof(options: NewConsistencyProofOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null] satisfies (string | null)[];
	const parameterNames = ['proof'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'encrypted_amount',
			function: 'new_consistency_proof',
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
export interface NewU32LimbHandlesArguments {
	handles: TransactionArgument;
}
export interface NewU32LimbHandlesOptions {
	package?: string;
	arguments: NewU32LimbHandlesArguments | [handles: TransactionArgument];
}
export function newU32LimbHandles(options: NewU32LimbHandlesOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<null>'] satisfies (string | null)[];
	const parameterNames = ['handles'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'encrypted_amount',
			function: 'new_u32_limb_handles',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
