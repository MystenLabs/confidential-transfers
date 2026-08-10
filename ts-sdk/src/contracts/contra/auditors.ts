/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { bcs } from '@mysten/sui/bcs';
import { type Transaction, type TransactionArgument } from '@mysten/sui/transactions';

import { MoveStruct, normalizeMoveArguments } from '../utils/index.js';
import * as encrypted_amount from './encrypted_amount.js';
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
export const AuditorEntry = new MoveStruct({
	name: `${$moduleName}::AuditorEntry`,
	fields: {
		handles: bcs.vector(encrypted_amount.DecryptionHandles),
		proof: nizk.ElGamalProof,
	},
});
export const AuditorPackage = new MoveStruct({
	name: `${$moduleName}::AuditorPackage`,
	fields: {
		entries: bcs.vector(AuditorEntry),
	},
});
export interface NewAuditorEntryArguments {
	handles: TransactionArgument;
	proof: TransactionArgument;
}
export interface NewAuditorEntryOptions {
	package?: string;
	arguments: NewAuditorEntryArguments | [handles: TransactionArgument, proof: TransactionArgument];
}
export function newAuditorEntry(options: NewAuditorEntryOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<null>', null] satisfies (string | null)[];
	const parameterNames = ['handles', 'proof'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'auditors',
			function: 'new_auditor_entry',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
export interface NewAuditorPackageArguments {
	entries: TransactionArgument;
}
export interface NewAuditorPackageOptions {
	package?: string;
	arguments: NewAuditorPackageArguments | [entries: TransactionArgument];
}
export function newAuditorPackage(options: NewAuditorPackageOptions) {
	const packageAddress = options.package ?? '@local-pkg/contra';
	const argumentsTypes = ['vector<null>'] satisfies (string | null)[];
	const parameterNames = ['entries'];
	return (tx: Transaction) =>
		tx.moveCall({
			package: packageAddress,
			module: 'auditors',
			function: 'new_auditor_package',
			arguments: normalizeMoveArguments(options.arguments, argumentsTypes, parameterNames),
		});
}
