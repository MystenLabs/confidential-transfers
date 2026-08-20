// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Issuer/admin flows: per-account and global freeze, the Sui coin deny list
 * (per-address and global pause), and the issuer balance override
 * (`set_balance_by_issuer`). Each test provisions its own fresh users and
 * drives the admin operations through the `Admin` wrapper.
 *
 * The two-or-more users a test needs are provisioned together via
 * `setupFreshUsersWithBalance`, which batches the issuer-signed funding/mint
 * into one PTB each and runs the per-user steps in parallel.
 */

import { Transaction } from '@mysten/sui/transactions';
import { beforeAll, describe, expect, it } from 'vitest';

import { Admin } from './admin.js';
import { createHarness, ONE } from './harness.js';
import type { Harness } from './harness.js';

describe('admin flows: freeze, deny list, seize (devnet)', () => {
	let tokenIssuer: Harness['tokenIssuer'];
	let client: Harness['client'];
	let exec: Harness['exec'];
	let wrapCoin: Harness['wrapCoin'];
	let transfer: Harness['transfer'];
	let unwrap: Harness['unwrap'];
	let setupFreshUserWithBalance: Harness['setupFreshUserWithBalance'];
	let setupFreshUsersWithBalance: Harness['setupFreshUsersWithBalance'];
	let admin: Admin;

	beforeAll(async () => {
		({
			tokenIssuer,
			client,
			exec,
			wrapCoin,
			transfer,
			unwrap,
			setupFreshUserWithBalance,
			setupFreshUsersWithBalance,
		} = await createHarness());
		admin = new Admin(tokenIssuer, client, exec);
	}, 180_000);

	it(
		'per-account freeze: admin freezes, ops abort, issuer unfreezes, ops resume',
		{ timeout: 300_000 },
		async () => {
			// Two users: `victim` will be frozen, `peer` is a sender/receiver counterparty.
			const [victim, peer] = await setupFreshUsersWithBalance([5n * ONE, 2n * ONE]);

			// Sanity: victim starts not frozen and ops work.
			expect(
				(await client.contra.getAccountStatus(victim.address, tokenIssuer.tokenType)).isFrozen,
			).toBe(false);

			// Freeze admin freezes the victim.
			await admin.freezeAccount(victim.address);
			expect(
				(await client.contra.getAccountStatus(victim.address, tokenIssuer.tokenType)).isFrozen,
			).toBe(true);

			// While frozen, the victim cannot wrap into its own account, transfer
			// out of, or unwrap from its private balance. Wrap into the victim
			// from a peer is also blocked (receiver-side `is_frozen` check).
			await tokenIssuer.mint(victim.address, 1n * ONE);
			await expect(
				wrapCoin(victim.address, victim.keypair, victim.address, 1n * ONE),
			).rejects.toThrow();
			await expect(
				wrapCoin(peer.address, peer.keypair, victim.address, 1n * ONE),
			).rejects.toThrow();
			await expect(
				transfer(victim.tokenAccount, victim.keypair, peer.address, 1n * ONE),
			).rejects.toThrow();
			await expect(
				transfer(peer.tokenAccount, peer.keypair, victim.address, 1n * ONE),
			).rejects.toThrow();
			await expect(unwrap(victim.tokenAccount, victim.keypair, 1n * ONE)).rejects.toThrow();

			// Only the issuer (TreasuryCap holder) can unfreeze. A non-issuer attempt aborts.
			await expect(admin.unfreezeAccount(victim.address, victim)).rejects.toThrow();

			// Issuer unfreezes; victim can now transact again.
			await admin.unfreezeAccount(victim.address);
			expect(
				(await client.contra.getAccountStatus(victim.address, tokenIssuer.tokenType)).isFrozen,
			).toBe(false);

			await transfer(victim.tokenAccount, victim.keypair, peer.address, 1n * ONE);
			const victimBal = await client.contra.getBalance(victim.tokenAccount);
			expect(victimBal.balance.amount).toBe(4n * ONE);
		},
	);

	it(
		'global freeze: admin freezes token, ops abort, issuer unfreezes',
		{ timeout: 300_000 },
		async () => {
			// `a` needs an active balance; `b` is just a registered transfer target.
			const [a, b] = await setupFreshUsersWithBalance([5n * ONE, 0n]);

			// Globally freeze the token (sets `ct.is_active = false`).
			await admin.globalFreeze();

			// While the token is globally frozen, wrap / transfer / unwrap all abort
			// with ETransferDenied regardless of which account is involved.
			await tokenIssuer.mint(a.address, 1n * ONE);
			await expect(wrapCoin(a.address, a.keypair, a.address, 1n * ONE)).rejects.toThrow();
			await expect(transfer(a.tokenAccount, a.keypair, b.address, 1n * ONE)).rejects.toThrow();
			await expect(unwrap(a.tokenAccount, a.keypair, 1n * ONE)).rejects.toThrow();

			// Issuer unfreezes globally. Operations resume; transfer from the
			// untouched active balance drives it down by 1.
			await admin.globalUnfreeze();

			await transfer(a.tokenAccount, a.keypair, b.address, 1n * ONE);
			const aBal = await client.contra.getBalance(a.tokenAccount);
			expect(aBal.balance.amount).toBe(4n * ONE);
		},
	);

	it(
		'deny list per-address: add blocks ops, remove restores them',
		{ timeout: 300_000 },
		async () => {
			const [denied, other] = await setupFreshUsersWithBalance([5n * ONE, 2n * ONE]);

			// Add `denied` to the coin-level deny list. Effective immediately
			// for `deny_list_v2_contains_next_epoch` (which the contract uses).
			await admin.denyListAdd(denied.address);

			// While denied:
			// - denied cannot transfer out (is_sender_denied in batched_transfer)
			// - denied cannot unwrap (is_sender_denied in unwrap)
			// - nobody can wrap into denied (is_receiver_denied in wrap)
			// - nobody can transfer to denied (is_receiver_denied in add_to_batch)
			await tokenIssuer.mint(denied.address, 1n * ONE);
			await expect(
				transfer(denied.tokenAccount, denied.keypair, other.address, 1n * ONE),
			).rejects.toThrow();
			await expect(unwrap(denied.tokenAccount, denied.keypair, 1n * ONE)).rejects.toThrow();
			await expect(
				wrapCoin(other.address, other.keypair, denied.address, 1n * ONE),
			).rejects.toThrow();
			await expect(
				transfer(other.tokenAccount, other.keypair, denied.address, 1n * ONE),
			).rejects.toThrow();

			// Note: Sui deny list adds also block the *sender* from using
			// coins of this type as inputs in the next epoch. The contra
			// `is_sender_denied` check above is what we care about here;
			// the next-epoch coin-input block is enforced by Sui itself.

			// Remove from deny list.
			await admin.denyListRemove(denied.address);

			// Operations resume.
			await transfer(denied.tokenAccount, denied.keypair, other.address, 1n * ONE);
			const deniedBal = await client.contra.getBalance(denied.tokenAccount);
			expect(deniedBal.balance.amount).toBe(4n * ONE);
		},
	);

	it(
		'deny list global pause: enable blocks ops, disable restores them',
		{ timeout: 300_000 },
		async () => {
			// `a` needs an active balance; `b` is just a registered transfer target.
			const [a, b] = await setupFreshUsersWithBalance([5n * ONE, 0n]);

			// Enable global pause (different from `contra::global_freeze`:
			// this flips the `0x2::coin` deny-list pause flag, which the
			// contract reads via `is_frozen<T>` -> `is_global_pause_enabled_next_epoch`).
			await admin.enableGlobalPause();

			await tokenIssuer.mint(a.address, 1n * ONE);
			await expect(wrapCoin(a.address, a.keypair, a.address, 1n * ONE)).rejects.toThrow();
			await expect(transfer(a.tokenAccount, a.keypair, b.address, 1n * ONE)).rejects.toThrow();
			await expect(unwrap(a.tokenAccount, a.keypair, 1n * ONE)).rejects.toThrow();

			await admin.disableGlobalPause();

			// Operations resume. Transfer from the untouched active balance.
			await transfer(a.tokenAccount, a.keypair, b.address, 1n * ONE);
			const aBal = await client.contra.getBalance(a.tokenAccount);
			expect(aBal.balance.amount).toBe(4n * ONE);
		},
	);

	it(
		'set_balance_by_issuer: issuer overwrites a user balance (seize/burn)',
		{ timeout: 300_000 },
		async () => {
			// User starts with a non-zero confidential balance and a pending
			// public deposit that should also be cleared by the issuer write.
			const user = await setupFreshUserWithBalance(7n * ONE);
			await tokenIssuer.mint(user.address, 3n * ONE);
			await wrapCoin(user.address, user.keypair, user.address, 3n * ONE);

			let bal = await client.contra.getBalance(user.tokenAccount);
			expect(bal.balance.amount).toBe(7n * ONE);
			expect(bal.pendingPublicBalance).toBe(3n * ONE);

			// Issuer seizes by overwriting the balance with an encryption of 0.
			// `set_balance_by_issuer` also clears all pending deposits and
			// resets `balance.terms` to 1.
			await admin.setBalance(user.address, 0n);

			bal = await client.contra.getBalance(user.tokenAccount);
			expect(bal.balance.amount).toBe(0n);
			expect(bal.balance.terms).toBe(1);
			expect(bal.pending.amount).toBe(0n);
			expect(bal.pendingPublicBalance).toBe(0n);

			// Issuer can also set a non-zero balance directly. The trivial
			// encryption of `v` has commitment `v*H` and identity decryption
			// handle, so it decrypts to `v` under any private key.
			await admin.setBalance(user.address, 12n * ONE);
			bal = await client.contra.getBalance(user.tokenAccount);
			expect(bal.balance.amount).toBe(12n * ONE);

			// Only the issuer can call this: a tx signed by the user (and not
			// passing a real TreasuryCap) cannot construct the call at all.
			await expect(admin.setBalance(user.address, 0n, user)).rejects.toThrow();
		},
	);

	it(
		'update_active_balance without merge re-normalizes the active balance',
		{ timeout: 300_000 },
		async () => {
			// A user with an active balance and no pending deposits. The SDK's
			// `updateBalance` with `merge: false` calls `contra::update_active_balance`
			// directly (no prepended `merge_deposits`), re-normalizing the
			// balance into canonical limb form; the cleartext balance is
			// unchanged. (Every other suite path uses `merge: true`.)
			const user = await setupFreshUserWithBalance(5n * ONE);

			const fn = await client.contra.updateBalance({
				tokenAccount: user.tokenAccount,
				merge: false,
			});
			const tx = new Transaction();
			tx.add(fn);
			tx.setSender(user.address);
			await exec(tx, user.keypair);

			const bal = await client.contra.getBalance(user.tokenAccount);
			expect(bal.balance.amount).toBe(5n * ONE);
			expect(bal.pending.amount).toBe(0n);
			expect(bal.pendingPublicBalance).toBe(0n);
			expect(bal.balance.terms).toBe(1);
		},
	);
});
