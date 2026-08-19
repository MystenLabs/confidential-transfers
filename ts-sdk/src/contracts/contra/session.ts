/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/

/**
 * The Fiat-Shamir transcript of one token account: the session it is bound to, and
 * the domain separator of each protocol proven against it.
 */

import { bcs } from '@mysten/sui/bcs';

import { MoveStruct } from '../utils/index.js';

const $moduleName = '@local-pkg/contra::session';
export const Session = new MoveStruct({
	name: `${$moduleName}::Session`,
	fields: {
		id: bcs.vector(bcs.u8()),
	},
});
