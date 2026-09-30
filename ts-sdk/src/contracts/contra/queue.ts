/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { bcs, type BcsType } from '@mysten/sui/bcs';

import { MoveStruct } from '../utils/index.js';

const $moduleName = '@local-pkg/contra::queue';
/**
 * FIFO over a vector: reversed once on construction, so `pop_front` is an O(1)
 * `pop_back`.
 */
export function Queue<T extends BcsType<any>>(...typeParameters: [T]) {
	return new MoveStruct({
		name: `${$moduleName}::Queue<${typeParameters[0].name as T['name']}>`,
		fields: {
			reversed: bcs.vector(typeParameters[0]),
		},
	});
}
