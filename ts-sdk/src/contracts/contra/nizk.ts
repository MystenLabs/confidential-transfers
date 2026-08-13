/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { bcs } from '@mysten/sui/bcs';
import { type Transaction, type TransactionArgument } from '@mysten/sui/transactions';

import { MoveStruct, normalizeMoveArguments } from '../utils/index.js';
import * as group_ops from './deps/sui/group_ops.js';

const $moduleName = '@local-pkg/contra::nizk';
export const DdhProof = new MoveStruct({
	name: `${$moduleName}::DdhProof`,
	fields: {
		commitments: bcs.vector(group_ops.Element),
		z: group_ops.Element,
	},
});
export const ElGamalProof = new MoveStruct({
	name: `${$moduleName}::ElGamalProof`,
	fields: {
		a: group_ops.Element,
		b: group_ops.Element,
		z1: group_ops.Element,
		z2: group_ops.Element,
	},
});
export interface NewDdhProofArguments {
	commitments: TransactionArgument;
	z: TransactionArgument;
}
export interface NewDdhProofOptions {
	package?: string;
	arguments: NewDdhProofArguments | [commitments: TransactionArgument, z: TransactionArgument];
}
export function newDdhProof(options: NewDdhProofOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<null>', null] satisfies (string | null)[];
	const parameterNames = ['commitments', 'z'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'nizk',
			function: 'new_ddh_proof',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface NewElgamalProofArguments {
	a: TransactionArgument;
	b: TransactionArgument;
	z1: TransactionArgument;
	z2: TransactionArgument;
}
export interface NewElgamalProofOptions {
	package?: string;
	arguments:
		| NewElgamalProofArguments
		| [
				a: TransactionArgument,
				b: TransactionArgument,
				z1: TransactionArgument,
				z2: TransactionArgument,
		  ];
}
export function newElgamalProof(options: NewElgamalProofOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = [null, null, null, null] satisfies (string | null)[];
	const parameterNames = ['a', 'b', 'z1', 'z2'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'nizk',
			function: 'new_elgamal_proof',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
