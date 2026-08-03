/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { bcs } from '@mysten/sui/bcs';

import { MoveStruct } from '../utils/index.js';
import * as group_ops from './deps/sui/group_ops.js';

const $moduleName = '@local-pkg/contra::auditors';
export const Auditors = new MoveStruct({
	name: `${$moduleName}::Auditors`,
	fields: {
		current_pk: bcs.option(group_ops.Element),
		previous_pk: bcs.option(group_ops.Element),
		previous_expiration_epoch: bcs.u64(),
	},
});
