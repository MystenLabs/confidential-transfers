/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { bcs } from '@mysten/sui/bcs';
import { type Transaction, type TransactionArgument } from '@mysten/sui/transactions';

import { MoveStruct, normalizeMoveArguments } from '../utils/index.js';
import * as group_ops from './deps/sui/group_ops.js';
import * as encrypted_amount from './encrypted_amount.js';
import * as nizk from './nizk.js';

const $moduleName = '@local-pkg/contra::auditors';
export const Auditor = new MoveStruct({
	name: `${$moduleName}::Auditor`,
	fields: {
		current_pk: bcs.option(group_ops.Element),
		previous_pk: bcs.option(group_ops.Element),
		previous_expiration_epoch: bcs.u64(),
	},
});
export const AuditorPackage = new MoveStruct({
	name: `${$moduleName}::AuditorPackage`,
	fields: {
		handles: bcs.vector(encrypted_amount.U32LimbHandles),
		proof: nizk.ElGamalProof,
	},
});
export interface NewAuditorPackageArguments {
	handles: TransactionArgument;
	proof: TransactionArgument;
}
export interface NewAuditorPackageOptions {
	package?: string;
	arguments:
		| NewAuditorPackageArguments
		| [handles: TransactionArgument, proof: TransactionArgument];
}
export function newAuditorPackage(options: NewAuditorPackageOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<null>', null] satisfies (string | null)[];
	const parameterNames = ['handles', 'proof'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'auditors',
			function: 'new_auditor_package',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
