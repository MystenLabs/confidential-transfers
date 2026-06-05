/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/**
 * Access policies for `ConfidentialToken<T>`. A `Policy` records the set of
 * operations that require a witness of a specific type, used to gate permissioned
 * versions of those operations.
 */

import { bcs } from '@mysten/sui/bcs';

import { MoveStruct } from '../utils/index.js';
import * as type_name from './deps/std/type_name.js';

const $moduleName = '@local-pkg/contra::policy';
export const Policy = new MoveStruct({
	name: `${$moduleName}::Policy`,
	fields: {
		witness_type: type_name.TypeName,
		permissioned_operations_bitmap: bcs.u32(),
	},
});
export const Auth = new MoveStruct({
	name: `${$moduleName}::Auth<phantom T>`,
	fields: {
		/** Bitmap with bit `o` set iff operation `o` is allowed. */
		operations: bcs.u32(),
		owner: bcs.Address,
	},
});
