/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/**
 * In addition to the fields declared in its type definition, a Sui object can have
 * dynamic fields that can be added after the object has been constructed. Unlike
 * ordinary field names (which are always statically declared identifiers) a
 * dynamic field name can be any value with the `copy`, `drop`, and `store`
 * abilities, e.g. an integer, a boolean, or a string. This gives Sui programmers
 * the flexibility to extend objects on-the-fly, and it also serves as a building
 * block for core collection types
 */

import { bcs, type BcsType } from '@mysten/sui/bcs';

import { MoveStruct } from '../utils/index.js';

const $moduleName = '0x2::dynamic_field';
/** Internal object used for storing the field and value */
export function Field<Name extends BcsType<any>, Value extends BcsType<any>>(
	...typeParameters: [Name, Value]
) {
	return new MoveStruct({
		name: `${$moduleName}::Field<${typeParameters[0].name as Name['name']}, ${typeParameters[1].name as Value['name']}>`,
		fields: {
			/**
			 * Determined by the hash of the object ID, the field name value and it's type,
			 * i.e. hash(parent.id || name || Name)
			 */
			id: bcs.Address,
			/** The value for the name of this field */
			name: typeParameters[0],
			/** The value bound to this field */
			value: typeParameters[1],
		},
	});
}
