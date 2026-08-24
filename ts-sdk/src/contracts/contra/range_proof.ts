/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/**
 * Batched Bulletproof range checks over Pedersen commitments.
 *
 * A batch of any size is covered by one `RangeProofs`: the commitments are
 * partitioned into power-of-two chunks (`batch_sizes`), each proven by its own
 * aggregated Bulletproof, because Sui's verifier caps one proof at
 * `MAX_BATCH_SIZE` commitments.
 */

import { bcs } from '@mysten/sui/bcs';
import { type Transaction } from '@mysten/sui/transactions';

import { MoveStruct, normalizeMoveArguments, type RawTransactionArgument } from '../utils/index.js';

const $moduleName = '@local-pkg/contra::range_proof';
export const RangeProofs = new MoveStruct({
	name: `${$moduleName}::RangeProofs`,
	fields: {
		version: bcs.u8(),
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
 * Wrap `proofs` into a `RangeProofs` to be checked as aggregated 16-bit
 * Bulletproofs; rejects an empty set, which would verify vacuously over an empty
 * batch.
 */
export function newRangeProofs(options: NewRangeProofsOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<u8>>'] satisfies (string | null)[];
	const parameterNames = ['proofs'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'range_proof',
			function: 'new_range_proofs',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
