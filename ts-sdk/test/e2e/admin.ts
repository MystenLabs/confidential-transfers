// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Admin/issuer operations for the e2e suites: per-account and global freeze,
 * the freeze-capability lifecycle, the Sui coin deny list (per-address and
 * global pause), and the issuer balance override (`set_balance_by_issuer`).
 *
 * Mirrors `TokenIssuer` as a small operation wrapper: each method builds the
 * Move call, signs it with the right authority (the freeze admin for
 * freezing, the issuer for everything else), and executes it. Methods that
 * have a negative-path test accept an `as` signer override so a test can
 * drive the call from an unauthorized address.
 */

import { Transaction } from '@mysten/sui/transactions';
import { SUI_DENY_LIST_OBJECT_ID } from '@mysten/sui/utils';

import * as contraContracts from '../../src/contracts/contra/contra.js';
import * as encryptedAmountContracts from '../../src/contracts/contra/encrypted_amount.js';
import { buildEncryption } from '../../src/helpers.js';
import { EncryptedAmount } from '../../src/twisted_elgamal.js';
import type { ContraTestClient, Harness, Signer } from './harness.js';
import type { TokenIssuer } from './token_issuer.js';

/**
 * Wraps the admin/issuer Move calls for a confidential token, signing each
 * with the appropriate on-chain authority.
 */
export class Admin {
	constructor(
		private readonly tokenIssuer: TokenIssuer,
		private readonly client: ContraTestClient,
		private readonly exec: Harness['exec'],
	) {}

	/** The issuer authority — holds the `TreasuryCap`, `DenyCap`, and `ManagementCap`. */
	private get issuer(): Signer {
		return { keypair: this.tokenIssuer.keypair, address: this.tokenIssuer.address };
	}

	/** The freeze-admin authority (granted a freeze capability by the issuer). */
	private get freezeAdmin(): Signer {
		return {
			keypair: this.tokenIssuer.freezeAdminKeypair,
			address: this.tokenIssuer.freezeAdminAddress,
		};
	}

	// === Per-account freeze ===

	/** Freeze `accountOwner`'s token account. Signed by `as` (default: the freeze admin). */
	async freezeAccount(accountOwner: string, as: Signer = this.freezeAdmin): Promise<void> {
		const tx = new Transaction();
		tx.add(
			contraContracts.accountFreeze({
				package: this.tokenIssuer.contraPackageId,
				typeArguments: [this.tokenIssuer.tokenType],
				arguments: {
					ct: this.tokenIssuer.confidentialTokenId,
					account: this.client.contra.getAccountId(accountOwner),
				},
			}),
		);
		tx.setSender(as.address);
		await this.exec(tx, as.keypair);
	}

	/** Unfreeze `accountOwner`'s token account. Signed by `as` (default: the issuer). */
	async unfreezeAccount(accountOwner: string, as: Signer = this.issuer): Promise<void> {
		const tx = new Transaction();
		tx.add(
			contraContracts.accountUnfreeze({
				package: this.tokenIssuer.contraPackageId,
				typeArguments: [this.tokenIssuer.tokenType],
				arguments: {
					Cap: this.tokenIssuer.treasuryCapId,
					account: this.client.contra.getAccountId(accountOwner),
				},
			}),
		);
		tx.setSender(as.address);
		await this.exec(tx, as.keypair);
	}

	// === Global freeze ===

	/** Globally freeze the token (`ct.is_active = false`). Signed by the freeze admin. */
	async globalFreeze(): Promise<void> {
		const tx = new Transaction();
		tx.add(
			contraContracts.globalFreeze({
				package: this.tokenIssuer.contraPackageId,
				typeArguments: [this.tokenIssuer.tokenType],
				arguments: { ct: this.tokenIssuer.confidentialTokenId },
			}),
		);
		tx.setSender(this.freezeAdmin.address);
		await this.exec(tx, this.freezeAdmin.keypair);
	}

	/** Globally unfreeze the token. Signed by the issuer. */
	async globalUnfreeze(): Promise<void> {
		const tx = new Transaction();
		tx.add(
			contraContracts.globalUnfreeze({
				package: this.tokenIssuer.contraPackageId,
				typeArguments: [this.tokenIssuer.tokenType],
				arguments: {
					ct: this.tokenIssuer.confidentialTokenId,
					Cap: this.tokenIssuer.treasuryCapId,
				},
			}),
		);
		tx.setSender(this.issuer.address);
		await this.exec(tx, this.issuer.keypair);
	}

	// === Freeze capability lifecycle ===

	/** Grant the freeze capability to `address`. Signed by the issuer (`ManagementCap` holder). */
	async issueFreezeCap(address: string): Promise<void> {
		await this.#freezeCapOp('issue_freeze_cap', address);
	}

	/** Revoke the freeze capability from `address`. Signed by the issuer. */
	async revokeFreezeCap(address: string): Promise<void> {
		await this.#freezeCapOp('revoke_freeze_cap', address);
	}

	/** Run a `contra::{issue,revoke}_freeze_cap` call, signed by the issuer. */
	async #freezeCapOp(op: 'issue_freeze_cap' | 'revoke_freeze_cap', address: string): Promise<void> {
		const tx = new Transaction();
		const builder =
			op === 'issue_freeze_cap' ? contraContracts.issueFreezeCap : contraContracts.revokeFreezeCap;
		tx.add(
			builder({
				package: this.tokenIssuer.contraPackageId,
				typeArguments: [this.tokenIssuer.tokenType],
				arguments: {
					ct: this.tokenIssuer.confidentialTokenId,
					T: this.tokenIssuer.managementCapId,
					addr: address,
				},
			}),
		);
		tx.setSender(this.issuer.address);
		await this.exec(tx, this.issuer.keypair);
	}

	// === Sui coin deny list ===

	/** Add `address` to the coin-level deny list. */
	async denyListAdd(address: string): Promise<void> {
		await this.#denyListOp('add', address);
	}

	/** Remove `address` from the coin-level deny list. */
	async denyListRemove(address: string): Promise<void> {
		await this.#denyListOp('remove', address);
	}

	/** Enable the coin-level global pause. */
	async enableGlobalPause(): Promise<void> {
		await this.#denyListOp('enable_global_pause');
	}

	/** Disable the coin-level global pause. */
	async disableGlobalPause(): Promise<void> {
		await this.#denyListOp('disable_global_pause');
	}

	/** Run a `0x2::coin::deny_list_v2_*` call, signed by the issuer (the `DenyCap` holder). */
	async #denyListOp(
		op: 'add' | 'remove' | 'enable_global_pause' | 'disable_global_pause',
		address?: string,
	): Promise<void> {
		const tx = new Transaction();
		const args =
			address !== undefined
				? [
						tx.object(SUI_DENY_LIST_OBJECT_ID),
						tx.object(this.tokenIssuer.denyCapId),
						tx.pure.address(address),
					]
				: [tx.object(SUI_DENY_LIST_OBJECT_ID), tx.object(this.tokenIssuer.denyCapId)];
		tx.moveCall({
			target: `0x2::coin::deny_list_v2_${op}`,
			typeArguments: [this.tokenIssuer.tokenType],
			arguments: args,
		});
		tx.setSender(this.issuer.address);
		await this.exec(tx, this.issuer.keypair);
	}

	// === Issuer balance override ===

	/**
	 * Overwrite `accountOwner`'s active balance with a trivial encryption of
	 * `value` (commitment `value*H`, identity decryption handle on every
	 * limb). The trivial encryption decrypts back to `value` under any
	 * private key, so callers can immediately verify via `getBalance`.
	 * Signed by `as` (default: the issuer).
	 */
	async setBalance(accountOwner: string, value: bigint, as: Signer = this.issuer): Promise<void> {
		const tx = new Transaction();
		const pid = this.tokenIssuer.contraPackageId;
		const ea = EncryptedAmount.trivial(value);
		const [l0, l1, l2, l3] = [ea.l0, ea.l1, ea.l2, ea.l3].map((ct) => buildEncryption(pid, ct));
		const newBalance = tx.add(
			encryptedAmountContracts.newEncryptedAmount({
				package: pid,
				arguments: { l0, l1, l2, l3 },
			}),
		);
		tx.add(
			contraContracts.setBalanceByIssuer({
				package: pid,
				typeArguments: [this.tokenIssuer.tokenType],
				arguments: {
					T: this.tokenIssuer.treasuryCapId,
					account: this.client.contra.getAccountId(accountOwner),
					newBalance,
				},
			}),
		);
		tx.setSender(as.address);
		await this.exec(tx, as.keypair);
	}
}
