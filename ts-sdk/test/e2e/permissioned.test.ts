// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Flows that aren't reachable through the SDK: permissioned auth
 * (`with_witness` / `as_object`), the non-aborting and aborting batch
 * finalizers (`try_unwrap`, `try_finalize`, `finalize`), and the
 * freeze-admin lifecycle (`revoke_freeze_cap`), plus the `update_active_balance`
 * re-normalize path.
 *
 * The `with_witness` and `as_object` paths are exercised through a small
 * test-only Move module (`move/gated`) published at the start of this suite.
 */

import { bcs } from '@mysten/sui/bcs';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { deriveObjectID, SUI_FRAMEWORK_ADDRESS } from '@mysten/sui/utils';
import { beforeAll, describe, expect, it } from 'vitest';

import { getBulletproofs } from '../../src/bp.js';
import * as contraContracts from '../../src/contracts/contra/contra.js';
import {
	buildDdhProof,
	buildElGamalProof,
	buildEncryptedAmount,
	buildEncryptedAmountAndProof,
	buildWellFormedProof,
	point,
	PROTOCOL_DDH,
	PROTOCOL_ELGAMAL,
	PROTOCOL_RANGE_PROOF,
} from '../../src/helpers.js';
import { DdhTupleNizk, ElGamalNizk } from '../../src/nizk.js';
import { G, randomScalar } from '../../src/ristretto255.js';
import { TokenAccount } from '../../src/token_account.js';
import { Ciphertext, collapseBlindings, EncryptedAmount } from '../../src/twisted_elgamal.js';
import { Admin } from './admin.js';
import { Gated } from './gated.js';
import { createHarness, FUNDING_AMOUNT, ONE } from './harness.js';
import type { FreshUser, Harness } from './harness.js';

/** Split a u64 value into four u16 limbs (little-endian). Mirrors the SDK's private helper. */
function intoLimbs(value: bigint): readonly [bigint, bigint, bigint, bigint] {
	return [
		value & 0xffffn,
		(value >> 16n) & 0xffffn,
		(value >> 32n) & 0xffffn,
		(value >> 48n) & 0xffffn,
	];
}

describe('permissioned & uncovered flows (devnet)', () => {
	let contraInit: Harness['contraInit'];
	let tokenIssuer: Harness['tokenIssuer'];
	let client: Harness['client'];
	let exec: Harness['exec'];
	let packageConfig: Harness['packageConfig'];
	let wrapCoin: Harness['wrapCoin'];
	let unwrap: Harness['unwrap'];
	let mergeAndUpdate: Harness['mergeAndUpdate'];
	let setupFreshAccount: Harness['setupFreshAccount'];
	let setupFreshAccounts: Harness['setupFreshAccounts'];
	let setupFreshUser: Harness['setupFreshUser'];
	let setupFreshUsers: Harness['setupFreshUsers'];
	let setupFreshUsersWithBalance: Harness['setupFreshUsersWithBalance'];
	let admin: Admin;
	let gated: Gated;

	beforeAll(async () => {
		({
			contraInit,
			tokenIssuer,
			client,
			packageConfig,
			exec,
			wrapCoin,
			unwrap,
			mergeAndUpdate,
			setupFreshAccount,
			setupFreshAccounts,
			setupFreshUser,
			setupFreshUsers,
			setupFreshUsersWithBalance,
		} = await createHarness());
		admin = new Admin(tokenIssuer, client, exec);
		gated = await Gated.publish(contraInit, tokenIssuer, client, exec);
	}, 300_000);

	/**
	 * Build a single-recipient batched-transfer PTB whose balance proof is a
	 * random (invalid) `DdhProof`, so `batched_transfer` returns
	 * `TransferBatch::BalanceProofFailed`. The receiver/sender amounts and
	 * consistency proof are valid (length and commitment-sum match,
	 * consistency proof verifies), leaving the balance proof as the sole
	 * point of failure. The PTB ends in `finalizer` (`try_finalize` emits
	 * `TryTransferFailedEvent` and returns; `finalize` aborts).
	 */
	async function buildFailingBatchedTransferTx(
		sender: FreshUser,
		receiver: FreshUser,
		amount: bigint,
		finalizer: 'finalize' | 'try_finalize',
	): Promise<Transaction> {
		const pid = contraInit.contraPackageId;
		const senderPk = sender.tokenAccount.publicKey;
		const receiverPk = receiver.tokenAccount.publicKey;
		const elgamalDst = sender.tokenAccount.dst(PROTOCOL_ELGAMAL);

		// Receiver-side well-formed encrypted amount + sender-side raw 4-limb
		// encryption (same values & blindings, sender's key). The sum check in
		// `try_split_batch` passes by construction.
		const encAmountReceiver = intoLimbs(amount).map((v) => ({
			value: v,
			...Ciphertext.encryptWithConsistencyProof(elgamalDst, receiverPk, v),
		}));
		const encAmountSender = encAmountReceiver.map((limb) => ({
			ciphertext: Ciphertext.encryptWithBlinding(senderPk, limb.value, limb.blinding).ciphertext,
		}));

		// Consistency proof on the collapsed sender total (value=amount,
		// blinding=Σ collapsed blindings).
		const totalBlinding = collapseBlindings(encAmountReceiver);
		const { ciphertext: totalSenderEnc } = Ciphertext.encryptWithBlinding(
			senderPk,
			amount,
			totalBlinding,
		);
		const consistencyProof = ElGamalNizk.prove(
			elgamalDst,
			totalBlinding,
			amount,
			totalSenderEnc,
			senderPk,
		);

		// A well-formed (but arbitrary) new balance paired with a deliberately
		// invalid balance proof, so the balance proof inside `try_split_batch`
		// rejects it.
		const newBalanceLimbs = intoLimbs(0n).map((v) => ({
			value: v,
			...Ciphertext.encryptWithConsistencyProof(elgamalDst, senderPk, v),
		}));
		const fakeBalanceProof = new DdhTupleNizk(
			G.multiply(randomScalar()),
			G.multiply(randomScalar()),
			randomScalar(),
		);

		const { batchRangeProver } = await getBulletproofs();
		const tx = new Transaction();
		const senderAccountId = client.contra.getAccountId(sender.address);
		const auth = tx.add(
			contraContracts.authorizeAsSender({
				package: pid,
				typeArguments: [tokenIssuer.tokenType],
				arguments: { ct: tokenIssuer.confidentialTokenId },
			}),
		);
		let [batch] = tx.add(
			contraContracts.batchedTransfer({
				package: pid,
				typeArguments: [tokenIssuer.tokenType],
				arguments: {
					sender: senderAccountId,
					auth,
					ct: tokenIssuer.confidentialTokenId,
					receiverPks: tx.makeMoveVec({
						type: `${SUI_FRAMEWORK_ADDRESS}::group_ops::Element<${SUI_FRAMEWORK_ADDRESS}::ristretto255::G>`,
						elements: [point(receiverPk.toBytes())],
					}),
					receiverAmounts: tx.makeMoveVec({
						type: `${pid}::encrypted_amount::EncryptedAmount`,
						elements: [
							buildEncryptedAmount(
								pid,
								encAmountReceiver.map((l) => l.ciphertext),
							),
						],
					}),
					wellFormedProofs: buildWellFormedProof(
						batchRangeProver,
						sender.tokenAccount.dst(PROTOCOL_RANGE_PROOF),
						pid,
						[encAmountReceiver, newBalanceLimbs],
					),
					senderAmounts: tx.makeMoveVec({
						type: `${pid}::encrypted_amount::EncryptedAmount`,
						elements: [
							buildEncryptedAmount(
								pid,
								encAmountSender.map((l) => l.ciphertext),
							),
						],
					}),
					consistencyProof: buildElGamalProof(pid, consistencyProof),
					newBalance: buildEncryptedAmount(
						pid,
						newBalanceLimbs.map((l) => l.ciphertext),
					),
					balanceProof: buildDdhProof(pid, fakeBalanceProof),
				},
			}),
		);
		[batch] = tx.add(
			contraContracts.addToBatch({
				package: pid,
				typeArguments: [tokenIssuer.tokenType],
				arguments: { batch, receiver: client.contra.getAccountId(receiver.address), memo: [] },
			}),
		);
		const finalize =
			finalizer === 'finalize' ? contraContracts.finalize : contraContracts.tryFinalize;
		tx.add(
			finalize({
				package: pid,
				typeArguments: [tokenIssuer.tokenType],
				arguments: { batch },
			}),
		);
		tx.setSender(sender.address);
		return tx;
	}

	it(
		'set_policy + with_witness gates REGISTER behind a witness type',
		{ timeout: 300_000 },
		async () => {
			// Two fresh users with funded Accounts (but no TokenAccount yet).
			const [sdkUser, gatedUser] = await setupFreshAccounts(2);
			const auditorPks = tokenIssuer.getAuditorKeys(tokenIssuer.auditorVersion).publicKeys;

			// Gate REGISTER behind `GatedWitness`. After this, `as_sender`
			// produces an Auth without the REGISTER bit set, so the SDK's
			// register call fails on chain with EAuthorizationError.
			await gated.setPolicy([0]);

			const sdkRegTx = new Transaction();
			sdkRegTx.add(
				await client.contra.register({
					tokenAccount: sdkUser.tokenAccount,
					auditorPublicKeys: auditorPks,
				}),
			);
			sdkRegTx.setSender(sdkUser.address);
			await expect(exec(sdkRegTx, sdkUser.keypair)).rejects.toThrow();

			// Registration via the gated module's `with_witness` wrapper succeeds.
			await gated.register(gatedUser);

			// Verify the gated user is now registered.
			const status = await client.contra.getAccountStatus(gatedUser.address, tokenIssuer.tokenType);
			expect(status.isFrozen).toBe(false);

			// Clear the policy. A fresh user can again register via the SDK.
			await gated.setPolicy([]);
			const afterClear = await setupFreshAccount();
			const afterClearRegTx = new Transaction();
			afterClearRegTx.add(
				await client.contra.register({
					tokenAccount: afterClear.tokenAccount,
					auditorPublicKeys: auditorPks,
				}),
			);
			afterClearRegTx.setSender(afterClear.address);
			await exec(afterClearRegTx, afterClear.keypair);
		},
	);

	it('as_object: a Vault self-authenticates via its UID', { timeout: 300_000 }, async () => {
		// A Vault object's UID address self-authenticates: any holder of
		// `&mut Vault` can act on the contra Account registered for that
		// address. We register a `TokenAccount` for the vault's address
		// and wrap a coin into it, all via the object-bound auth path.
		const userKp = Ed25519Keypair.generate();
		const userAddr = userKp.getPublicKey().toSuiAddress();
		await contraInit.fund(userAddr, FUNDING_AMOUNT);
		const user = { keypair: userKp, address: userAddr };

		// Create+share a Vault; its object id doubles as the address that
		// `as_object` authenticates as.
		const vaultId = await gated.createVault(user);

		// Register a TokenAccount for the vault and wrap a freshly-minted
		// coin into it, both via the object-bound auth path.
		const vaultTokenAccount = new TokenAccount(
			vaultId,
			tokenIssuer.tokenType,
			packageConfig,
			randomScalar(),
		);
		await gated.vaultRegister(vaultId, vaultTokenAccount, user);

		const wrapAmount = 3n * ONE;
		await tokenIssuer.mint(userAddr, wrapAmount);
		await gated.vaultWrap(vaultId, wrapAmount, user);

		const bal = await client.contra.getBalance(vaultTokenAccount);
		expect(bal.pendingPublicBalance).toBe(wrapAmount);
	});

	it(
		'try_unwrap with a balance proof mismatched to the amount: returns zero coin and emits TryUnwrapFailedEvent',
		{ timeout: 300_000 },
		async () => {
			// Set up a user with a known active balance.
			const user = await setupFreshUser();
			const wrapAmount = 5n * ONE;
			await tokenIssuer.mint(user.address, wrapAmount);
			await wrapCoin(user.address, user.keypair, user.address, wrapAmount);
			await mergeAndUpdate(user.tokenAccount, user.keypair);

			const balBefore = await client.contra.getBalance(user.tokenAccount);
			expect(balBefore.balance.amount).toBe(wrapAmount);

			// Build a manual try_unwrap PTB where new_balance and balance_proof
			// commit to unwrapping `proofAmount`, but the call passes
			// `callAmount`. The on-chain `try_update_balance` then verifies
			// `new_balance == old - callAmount` against a proof that proves
			// `new_balance == old - proofAmount`, which fails. `try_unwrap`
			// returns a zero coin and emits `TryUnwrapFailedEvent` without aborting.
			const proofAmount = 2n * ONE;
			const callAmount = 3n * ONE;
			const pk = user.tokenAccount.publicKey;
			// Fiat-Shamir domain tags for this account, matching the SDK's
			// own balance-update path.
			const elgamalDst = user.tokenAccount.dst(PROTOCOL_ELGAMAL);
			const ddhDst = user.tokenAccount.dst(PROTOCOL_DDH);
			const oldBalanceCt = balBefore.balance.ciphertext.collapse();
			const newBalanceLimbs = intoLimbs(balBefore.balance.amount - proofAmount).map((v) => ({
				value: v,
				...Ciphertext.encryptWithConsistencyProof(elgamalDst, pk, v),
			}));
			const balanceProof = new EncryptedAmount(
				newBalanceLimbs[0].ciphertext,
				newBalanceLimbs[1].ciphertext,
				newBalanceLimbs[2].ciphertext,
				newBalanceLimbs[3].ciphertext,
			)
				.collapse()
				.subtract(oldBalanceCt)
				.add(Ciphertext.trivial(proofAmount))
				.proveIsZero(ddhDst, user.tokenAccount.privateKey, pk);

			const pid = contraInit.contraPackageId;
			const poolId = deriveObjectID(
				tokenIssuer.confidentialTokenId,
				`${pid}::contra::PoolKey`,
				bcs.byteVector().serialize([]).toBytes(),
			);

			const { batchRangeProver } = await getBulletproofs();
			const tx = new Transaction();
			const auth = tx.add(
				contraContracts.authorizeAsSender({
					package: pid,
					typeArguments: [tokenIssuer.tokenType],
					arguments: { ct: tokenIssuer.confidentialTokenId },
				}),
			);
			const { encryptedAmount: newBalanceEa, wellFormedProof: newBalanceProof } =
				buildEncryptedAmountAndProof(
					batchRangeProver,
					user.tokenAccount.dst(PROTOCOL_RANGE_PROOF),
					tx,
					pid,
					newBalanceLimbs,
				);
			const coin = tx.add(
				contraContracts.tryUnwrap({
					package: pid,
					typeArguments: [tokenIssuer.tokenType],
					arguments: {
						account: client.contra.getAccountId(user.address),
						auth,
						ct: tokenIssuer.confidentialTokenId,
						pool: poolId,
						newBalance: newBalanceEa,
						newBalanceProof,
						amount: callAmount,
						balanceProof: buildDdhProof(pid, balanceProof),
					},
				}),
			);
			tx.transferObjects([coin], user.address);
			tx.setSender(user.address);
			const result = await exec(tx, user.keypair);

			// TryUnwrapFailedEvent should be emitted; UnwrapEvent should not.
			const failEventType = `${pid}::events::TryUnwrapFailedEvent`;
			const unwrapEventType = `${pid}::events::UnwrapEvent<${tokenIssuer.tokenType}>`;
			const events = result.Transaction!.events!;
			expect(events.find((e) => e.eventType === failEventType)).toBeDefined();
			expect(events.find((e) => e.eventType === unwrapEventType)).toBeUndefined();

			// Balance is unchanged: try_unwrap doesn't mutate on proof failure.
			const balAfter = await client.contra.getBalance(user.tokenAccount);
			expect(balAfter.balance.amount).toBe(wrapAmount);
		},
	);

	it('revoke_freeze_cap: revoked address can no longer freeze', { timeout: 300_000 }, async () => {
		// Issue a freeze cap to a fresh admin, verify they can freeze,
		// revoke, verify they can no longer freeze.
		const adminKp = Ed25519Keypair.generate();
		const freshAdmin = { keypair: adminKp, address: adminKp.getPublicKey().toSuiAddress() };

		// Fund the fresh admin for gas, then grant it the freeze capability.
		await contraInit.fund(freshAdmin.address, FUNDING_AMOUNT);
		await admin.issueFreezeCap(freshAdmin.address);

		// The new admin can freeze an account.
		const victim = await setupFreshUser();
		await admin.freezeAccount(victim.address, freshAdmin);
		expect(
			(await client.contra.getAccountStatus(victim.address, tokenIssuer.tokenType)).isFrozen,
		).toBe(true);

		// Issuer unfreezes so the next freeze attempt would have to re-freeze,
		// then revokes the fresh admin's freeze capability.
		await admin.unfreezeAccount(victim.address);
		await admin.revokeFreezeCap(freshAdmin.address);

		// The same freeze call now aborts with EAuthorizationError.
		await expect(admin.freezeAccount(victim.address, freshAdmin)).rejects.toThrow();
	});

	it(
		'try_finalize with a failed balance proof emits TryTransferFailedEvent without aborting',
		{ timeout: 300_000 },
		async () => {
			// A batched transfer whose balance proof does not verify: on chain,
			// `batched_transfer` returns `TransferBatch::BalanceProofFailed`,
			// `add_to_batch` is a no-op, and `try_finalize` emits
			// `TryTransferFailedEvent` and returns `false` rather than aborting.
			const [sender, receiver] = await setupFreshUsers(2);

			const tx = await buildFailingBatchedTransferTx(sender, receiver, 1n * ONE, 'try_finalize');
			const result = await exec(tx, sender.keypair);

			// `TryTransferFailedEvent` is emitted; no `TransferEvent` is.
			const pid = contraInit.contraPackageId;
			const failEventType = `${pid}::events::TryTransferFailedEvent`;
			const transferEventType = `${pid}::events::TransferEvent<${tokenIssuer.tokenType}>`;
			const events = result.Transaction!.events!;
			expect(events.find((e) => e.eventType === failEventType)).toBeDefined();
			expect(events.find((e) => e.eventType === transferEventType)).toBeUndefined();

			// The receiver was not credited — `add_to_batch` mutates nothing on a
			// failed batch.
			const receiverBal = await client.contra.getBalance(receiver.tokenAccount);
			expect(receiverBal.pending.amount).toBe(0n);
		},
	);

	it('finalize aborts when the balance proof fails', { timeout: 300_000 }, async () => {
		// Same failing batch as above, but ended with `finalize` instead of
		// `try_finalize`: `finalize` asserts `try_finalize` returned `true`,
		// so a failed balance proof aborts the whole transaction.
		const [sender, receiver] = await setupFreshUsers(2);

		const tx = await buildFailingBatchedTransferTx(sender, receiver, 1n * ONE, 'finalize');
		await expect(exec(tx, sender.keypair)).rejects.toThrow();
	});

	it('set_policy + with_witness gates WRAP and UNWRAP', { timeout: 300_000 }, async () => {
		// Two users with active balances established *before* the policy is
		// set (so their setup wraps aren't themselves gated).
		const [a, b] = await setupFreshUsersWithBalance([3n * ONE, 3n * ONE]);

		// Gate WRAP (op 1) and UNWRAP (op 2) behind `GatedWitness`.
		await gated.setPolicy([1, 2]);

		// Fresh coins for the wrap attempts.
		await tokenIssuer.mintMany([
			{ recipient: a.address, amount: 1n * ONE },
			{ recipient: b.address, amount: 1n * ONE },
		]);

		// The SDK's `wrap` builds an `as_sender` auth, which lacks the WRAP
		// bit while the policy gates it -> aborts.
		await expect(wrapCoin(b.address, b.keypair, b.address, 1n * ONE)).rejects.toThrow();

		// The same wrap via `gated::gated_wrap` (a `with_witness` auth) succeeds.
		await gated.wrap(a, 1n * ONE);
		const aBal = await client.contra.getBalance(a.tokenAccount);
		expect(aBal.pendingPublicBalance).toBe(1n * ONE);

		// The SDK's `unwrap` (also `as_sender`) is blocked while UNWRAP is gated.
		await expect(unwrap(a.tokenAccount, a.keypair, 1n * ONE)).rejects.toThrow();

		// Clearing the policy restores the permissionless SDK paths.
		await gated.setPolicy([]);
		await wrapCoin(b.address, b.keypair, b.address, 1n * ONE);
	});
});
