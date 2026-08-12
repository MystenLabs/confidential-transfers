/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { bcs } from '@mysten/sui/bcs';
import { type Transaction, type TransactionArgument } from '@mysten/sui/transactions';

import { MoveStruct, normalizeMoveArguments } from '../utils/index.js';
import * as group_ops from './deps/sui/group_ops.js';
import * as nizk from './nizk.js';
import * as twisted_elgamal from './twisted_elgamal.js';

const $moduleName = '@local-pkg/contra::auditors';
export const Auditors = new MoveStruct({
	name: `${$moduleName}::Auditors`,
	fields: {
		current_pks: bcs.vector(twisted_elgamal.PublicKey),
		previous_pks: bcs.vector(twisted_elgamal.PublicKey),
	},
});
export const AuditorPackage = new MoveStruct({
	name: `${$moduleName}::AuditorPackage`,
	fields: {
		handles: bcs.vector(bcs.vector(group_ops.Element)),
		proofs: bcs.vector(nizk.DdhProof),
	},
});
export const VerifiedAuditorHandles = new MoveStruct({
	name: `${$moduleName}::VerifiedAuditorHandles`,
	fields: {
		handles: bcs.vector(bcs.vector(group_ops.Element)),
		pk: twisted_elgamal.PublicKey,
	},
});
export interface NewAuditorPackageArguments {
	handles: TransactionArgument;
	proofs: TransactionArgument;
}
export interface NewAuditorPackageOptions {
	package?: string;
	arguments:
		| NewAuditorPackageArguments
		| [handles: TransactionArgument, proofs: TransactionArgument];
}
export function newAuditorPackage(options: NewAuditorPackageOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<vector<null>>', 'vector<null>'] satisfies (string | null)[];
	const parameterNames = ['handles', 'proofs'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'auditors',
			function: 'new_auditor_package',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
