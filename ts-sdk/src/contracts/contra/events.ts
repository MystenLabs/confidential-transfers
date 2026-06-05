/**************************************************************
 * THIS FILE IS GENERATED AND SHOULD NOT BE MANUALLY MODIFIED *
 **************************************************************/
import { bcs } from '@mysten/sui/bcs';

import { MoveStruct, MoveTuple } from '../utils/index.js';
import * as auditors from './auditors.js';
import * as group_ops from './deps/sui/group_ops.js';
import * as encrypted_amount from './encrypted_amount.js';

const $moduleName = '@local-pkg/contra::events';
export const NewConfidentialTokenEvent = new MoveTuple({
	name: `${$moduleName}::NewConfidentialTokenEvent<phantom T>`,
	fields: [bcs.bool()],
});
export const PolicyUpdateEvent = new MoveTuple({
	name: `${$moduleName}::PolicyUpdateEvent<phantom T, phantom W>`,
	fields: [bcs.vector(bcs.u8())],
});
export const NewRegistrationEvent = new MoveStruct({
	name: `${$moduleName}::NewRegistrationEvent<phantom T>`,
	fields: {
		owner: bcs.Address,
		pk: group_ops.Element,
		verified_key_encryption: auditors.VerifiedKeyEncryption,
	},
});
export const UpdatedPublicKeyEvent = new MoveStruct({
	name: `${$moduleName}::UpdatedPublicKeyEvent<phantom T>`,
	fields: {
		owner: bcs.Address,
		new_pk: group_ops.Element,
		verified_key_encryption: auditors.VerifiedKeyEncryption,
	},
});
export const WrapEvent = new MoveStruct({
	name: `${$moduleName}::WrapEvent<phantom T>`,
	fields: {
		receiver: bcs.Address,
		amount: bcs.u64(),
		memo: bcs.vector(bcs.u8()),
	},
});
export const TransferEvent = new MoveStruct({
	name: `${$moduleName}::TransferEvent<phantom T>`,
	fields: {
		sender: bcs.Address,
		sender_pk: group_ops.Element,
		encrypted_amount_sender: encrypted_amount.EncryptedAmount,
		receiver: bcs.Address,
		receiver_pk: group_ops.Element,
		encrypted_amount_receiver: encrypted_amount.EncryptedAmount,
		memo: bcs.vector(bcs.u8()),
	},
});
export const MergeDepositsEvent = new MoveStruct({
	name: `${$moduleName}::MergeDepositsEvent<phantom T>`,
	fields: {
		account: bcs.Address,
	},
});
export const TryTransferFailedEvent = new MoveTuple({
	name: `${$moduleName}::TryTransferFailedEvent`,
	fields: [bcs.bool()],
});
export const TryUnwrapFailedEvent = new MoveTuple({
	name: `${$moduleName}::TryUnwrapFailedEvent`,
	fields: [bcs.bool()],
});
export const TrySetPublicKeyFailedEvent = new MoveTuple({
	name: `${$moduleName}::TrySetPublicKeyFailedEvent`,
	fields: [bcs.bool()],
});
export const UnwrapEvent = new MoveStruct({
	name: `${$moduleName}::UnwrapEvent<phantom T>`,
	fields: {
		sender: bcs.Address,
		amount: bcs.u64(),
	},
});
export const UpdateBalanceEvent = new MoveStruct({
	name: `${$moduleName}::UpdateBalanceEvent<phantom T>`,
	fields: {
		account: bcs.Address,
	},
});
export const SetBalanceByIssuerEvent = new MoveStruct({
	name: `${$moduleName}::SetBalanceByIssuerEvent<phantom T>`,
	fields: {
		account: bcs.Address,
		new_balance: encrypted_amount.EncryptedAmount,
	},
});
export const GlobalFreezeEvent = new MoveTuple({
	name: `${$moduleName}::GlobalFreezeEvent<phantom T>`,
	fields: [bcs.bool()],
});
export const GlobalUnfreezeEvent = new MoveTuple({
	name: `${$moduleName}::GlobalUnfreezeEvent<phantom T>`,
	fields: [bcs.bool()],
});
export const AccountFreezeEvent = new MoveStruct({
	name: `${$moduleName}::AccountFreezeEvent<phantom T>`,
	fields: {
		admin: bcs.Address,
		account: bcs.Address,
	},
});
export const AccountUnfreezeEvent = new MoveStruct({
	name: `${$moduleName}::AccountUnfreezeEvent<phantom T>`,
	fields: {
		account: bcs.Address,
	},
});
export const UpdateAuditorsEvent = new MoveStruct({
	name: `${$moduleName}::UpdateAuditorsEvent<phantom T>`,
	fields: {
		public_keys: bcs.vector(group_ops.Element),
		version: bcs.u32(),
		recommended_min_version: bcs.u32(),
	},
});
