// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Single entry point for everything that talks to the Contra SDK
 * (`ts-sdk`) and the Sui SDK (`@mysten/sui`).
 *
 * The file is organized into sections:
 *   1. Client construction                — Sui RPC, Contra client, Auditor.
 *   2. Read state (chain queries)         — balances, account status, auditors, pause/deny.
 *   3. End-user transactions              — mint, register, wrap, unwrap, transfer.
 *   4. Issuer transactions                — deny list, global pause, freeze admins.
 *   5. Auditor flow                       — decrypt a transfer's amount from its event.
 *   6. Faucet                             — testnet SUI for gas.
 *   7. Deployment                         — publish bytecodes and register BU.
 *   8. Tx helpers                         — execute and check for merge-failure events.
 *
 * Hooks (e.g. `useCurrentClient`, `useSignAndExecute`) stay where they
 * are — they're React-bound. Components pull values out of those hooks
 * and pass them as plain arguments to the functions here.
 */

import { bcs } from '@mysten/sui/bcs';
import { getFaucetHost, requestSuiFromFaucetV2 } from '@mysten/sui/faucet';
import type { SuiGrpcClient } from '@mysten/sui/grpc';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import type { TransactionResult } from '@mysten/sui/transactions';
import { SUI_DENY_LIST_OBJECT_ID, SUI_FRAMEWORK_ADDRESS } from '@mysten/sui/utils';
import { executeOrThrow, findObject, publishBytecodes, signExecuteAndWait } from 'contra-utils';
import {
	ContraAuditor,
	Ciphertext,
	ContraClient,
	contraContracts,
	DiscreteLogTable,
	G,
	point,
	pointFromBcs,
	randomScalar,
	TokenAccount,
	TransferEventBcs,
} from 'ts-sdk';
import type {
	ContraCompatibleClient,
	ContraPackageConfig,
	TokenAuditor,
	TokenBalance,
} from 'ts-sdk';

import { createGrpcClient, type Network } from './network';

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

/** On-chain TokenConfig — package + registry IDs needed to talk to the
 *  Contra contracts for a particular deployment. Mirrors the Move struct
 *  at `move/sources/token_config.move`. */
export interface TokenConfig {
	id: string;
	buPackage: string;
	buTreasury: string;
	contraPackage: string;
	tokenRegistry: string;
	accountRegistry: string;
	binaryDigest: number[];
}

/** Whether a wallet has registered the per-account and per-token-account
 *  objects. We need both to send/receive private transfers. */
export type AccountStatus =
	| 'loading'
	| 'registered'
	| 'needs-account'
	| 'needs-token-account'
	| 'error';

/** Compiled Move bytecodes produced by `sui move build`, used by the
 *  issuer to publish a fresh deployment. */
export interface Bytecodes {
	modules: string[];
	dependencies: string[];
	digest: number[];
}

/** A ristretto255 keypair for an auditor: scalar private key and 32-byte
 *  compressed public key, both serialized as lowercase hex (no `0x`). */
export interface AuditorKey {
	privateKey: string;
	publicKey: string;
}

export interface CreateTokenResult {
	buPackageId: string;
	buTreasuryId: string;
	contraPackageId: string;
	tokenRegistryId: string;
	accountRegistryId: string;
	confidentialTokenId: string;
	managementCapId: string;
	tokenConfigId: string;
	denyCapId: string;
	auditorKeys: AuditorKey[];
}

// ─────────────────────────────────────────────────────────────────────
// 1. Client construction
// ─────────────────────────────────────────────────────────────────────

/** A gRPC client for `network`. Used in non-React contexts (issuer flows, the
 *  worker, deployment); callers pass the active network from
 *  `useActiveNetwork()`. React components can also use dapp-kit's
 *  network-aware `useCurrentClient()` directly. */
export function getSuiClient(network: Network): SuiGrpcClient {
	return createGrpcClient(network);
}

/** Build a `ContraClient` for a given deployment. The client carries
 *  the package config and the precomputed discrete-log table used to
 *  decrypt twisted-ElGamal ciphertexts on the user side. */
export function createContraClient(
	suiClient: ContraCompatibleClient,
	config: TokenConfig,
	table: DiscreteLogTable,
): ContraClient {
	return new ContraClient({
		suiClient,
		packageConfig: contraPackageConfig(config),
		table,
	});
}

/** Build a per-transfer `ContraAuditor` from the token's auditor private key. It decrypts a
 *  transfer's amount from a `TransferEvent` (the two u32-limb auditor handles + the receiver's
 *  commitments) — it never recovers a user's viewing key. Uses a larger DLog table than the user
 *  because each auditor limb is up to 32 bits. */
export function createContraAuditor(
	tokenType: string,
	privateKeys: bigint[],
	table: DiscreteLogTable,
): ContraAuditor {
	return new ContraAuditor({ tokenType, privateKeys, table });
}

/** Helper for callers that already have a `TokenConfig`. */
export function contraPackageConfig(config: TokenConfig): ContraPackageConfig {
	return {
		packageId: config.contraPackage,
		accountRegistryId: config.accountRegistry,
		tokenRegistryId: config.tokenRegistry,
	};
}

/** Construct a user `TokenAccount` from a wallet address, coin type,
 *  package config, and locally-stored hex viewing key. */
export function makeTokenAccount(
	address: string,
	tokenType: string,
	packageConfig: ContraPackageConfig,
	encKeyHex: string,
): TokenAccount {
	return new TokenAccount(address, tokenType, packageConfig, BigInt('0x' + encKeyHex));
}

/** Construct a fresh `TokenAccount` with a randomly-generated viewing
 *  key — used during initial registration. */
export function generateTokenAccount(
	address: string,
	tokenType: string,
	packageConfig: ContraPackageConfig,
): TokenAccount {
	return new TokenAccount(address, tokenType, packageConfig);
}

// ─────────────────────────────────────────────────────────────────────
// 2. Read state (chain queries)
// ─────────────────────────────────────────────────────────────────────

/** Check whether a wallet has the on-chain Account and per-token
 *  TokenAccount objects required to send/receive private BU. */
export async function fetchAccountStatus(
	contraClient: ContraClient,
	suiClient: ContraCompatibleClient,
	address: string,
	tokenType: string,
): Promise<Exclude<AccountStatus, 'loading' | 'error'>> {
	const accountId = contraClient.getAccountId(address);
	const tokenAccountId = contraClient.getTokenAccountId(address, tokenType);
	const {
		objects: [accountRes, tokenAccountRes],
	} = await suiClient.core.getObjects({ objectIds: [accountId, tokenAccountId] });
	const hasAccount = !(accountRes instanceof Error);
	const hasTokenAccount = !(tokenAccountRes instanceof Error);
	if (hasAccount && hasTokenAccount) return 'registered';
	if (hasAccount) return 'needs-token-account';
	return 'needs-account';
}

/** Decrypt the user's confidential balance (active + pending). */
export function fetchConfidentialBalance(
	contraClient: ContraClient,
	tokenAccount: TokenAccount,
): Promise<TokenBalance> {
	return contraClient.getBalance(tokenAccount);
}

/** Sum the encrypted active and pending balances into a single number
 *  in BU units (1e9 = 1 BU). Useful for UI display. */
export function totalConfidentialBalanceBu(balance: TokenBalance): number {
	const total = balance.balance.amount + balance.pending.amount + balance.pendingPublicBalance;
	return Number(total) / 1e9;
}

/** Fetch the on-chain auditor config (the current auditor keys) for the given token. */
export function fetchAuditor(contraClient: ContraClient, tokenType: string): Promise<TokenAuditor> {
	return contraClient.getAuditor(tokenType);
}

/** BCS layout of the `bu_token::token_config::TokenConfig` Move struct.
 *  Parsed from the object's raw content so the shape is identical across
 *  RPC implementations. */
const TokenConfigBcs = bcs.struct('TokenConfig', {
	id: bcs.Address,
	bu_package: bcs.Address,
	bu_treasury: bcs.Address,
	contra_package: bcs.Address,
	token_registry: bcs.Address,
	account_registry: bcs.Address,
	binary_digest: bcs.vector(bcs.u8()),
});

/** Read a `TokenConfig` Move object. Returns the fields needed to
 *  construct a `ContraClient`. The `binaryDigest` lets the caller check
 *  the on-chain bytecode matches the bundle the app was built against. */
export async function fetchTokenConfig(
	suiClient: ContraCompatibleClient,
	configId: string,
): Promise<TokenConfig | undefined> {
	const {
		objects: [object],
	} = await suiClient.core.getObjects({
		objectIds: [configId],
		include: { content: true },
	});
	if (object instanceof Error) return undefined;
	const fields = TokenConfigBcs.parse(object.content);
	return {
		id: configId,
		buPackage: fields.bu_package,
		buTreasury: fields.bu_treasury,
		contraPackage: fields.contra_package,
		tokenRegistry: fields.token_registry,
		accountRegistry: fields.account_registry,
		binaryDigest: Array.from(fields.binary_digest),
	};
}

/** Read the on-chain `ConfidentialToken` object and extract its freeze
 *  admin set and active flag. */
export async function fetchFreezeAdmins(
	suiClient: ContraCompatibleClient,
	confidentialTokenId: string,
): Promise<{ admins: string[]; isActive: boolean | null }> {
	const {
		objects: [object],
	} = await suiClient.core.getObjects({
		objectIds: [confidentialTokenId],
		include: { content: true },
	});
	if (object instanceof Error) {
		return { admins: [], isActive: null };
	}
	const fields = contraContracts.ConfidentialToken.parse(object.content);
	return {
		admins: fields.freeze_admins.contents.map((a) => a.toLowerCase()),
		isActive: fields.is_active,
	};
}

/** Returns true if the global pause flag is set for `coinType` for the
 *  next epoch. We check the next-epoch flag (not current-epoch) so the
 *  UI reflects the issuer's most recent intent immediately. */
export async function isGlobalPauseEnabledNextEpoch(
	suiClient: ContraCompatibleClient,
	sender: string,
	coinType: string,
): Promise<boolean | null> {
	const tx = new Transaction();
	tx.moveCall({
		target: `0x2::coin::deny_list_v2_is_global_pause_enabled_next_epoch`,
		typeArguments: [coinType],
		arguments: [tx.object(SUI_DENY_LIST_OBJECT_ID)],
	});
	tx.setSender(sender);
	// checksEnabled: false is the devInspect analogue — it lets the
	// simulation call a non-entry view function without gas payment.
	const res = await suiClient.core.simulateTransaction({
		transaction: tx,
		checksEnabled: false,
		include: { commandResults: true },
	});
	const ret = res.commandResults?.[0]?.returnValues?.[0]?.bcs;
	if (ret && ret.length === 1) return ret[0] === 1;
	return null;
}

/** Returns true if `address` is on the deny list for `coinType` at the
 *  next epoch. */
export async function isAddressDeniedNextEpoch(
	suiClient: ContraCompatibleClient,
	sender: string,
	coinType: string,
	address: string,
): Promise<boolean> {
	const tx = new Transaction();
	tx.moveCall({
		target: `0x2::coin::deny_list_v2_contains_next_epoch`,
		typeArguments: [coinType],
		arguments: [tx.object(SUI_DENY_LIST_OBJECT_ID), tx.pure.address(address)],
	});
	tx.setSender(sender);
	const res = await suiClient.core.simulateTransaction({
		transaction: tx,
		checksEnabled: false,
		include: { commandResults: true },
	});
	const ret = res.commandResults?.[0]?.returnValues?.[0]?.bcs;
	return !!ret && ret.length === 1 && ret[0] === 1;
}

// ─────────────────────────────────────────────────────────────────────
// 3. End-user transactions
// ─────────────────────────────────────────────────────────────────────

/** Mint 10 BU test tokens to the caller's public balance. */
export function buildMintTx(config: TokenConfig): Transaction {
	const tx = new Transaction();
	tx.moveCall({
		target: `${config.buPackage}::bu::mint_10`,
		arguments: [tx.object(config.buTreasury)],
	});
	return tx;
}

/** Build a transaction that registers the wallet's private account
 *  and mints initial BU. Pass `accountStatus` so we can skip
 *  `newAccount` when only the per-token TokenAccount is missing.
 *
 *  Calls (in order):
 *    1. `contraClient.newAccount`        — only when no Account exists yet (creates for the sender,
 *                                          keyed at the token account's public key).
 *    2. `contraClient.register`          — registers the per-token TokenAccount under `Account.pk`.
 *    3. `contraClient.shareAccount`      — only when newAccount was used.
 *    4. `bu::mint_10`                    — fund the new account so the user can play.
 *
 *  Under per-transfer auditing, registration carries no auditor data.
 */
export async function buildRegisterAccountTx(opts: {
	contraClient: ContraClient;
	config: TokenConfig;
	tokenAccount: TokenAccount;
	address: string;
	tokenType: string;
	accountStatus: 'needs-account' | 'needs-token-account';
}): Promise<Transaction> {
	const { contraClient, config, tokenAccount, accountStatus } = opts;

	const tx = new Transaction();
	if (accountStatus === 'needs-account') {
		const account = tx.add(contraClient.newAccount({ owner: tokenAccount.address }));
		tx.add(await contraClient.register({ tokenAccount, account }));
		tx.add(contraClient.shareAccount({ account }));
	} else {
		tx.add(await contraClient.register({ tokenAccount }));
	}
	tx.moveCall({
		target: `${config.buPackage}::bu::mint_10`,
		arguments: [tx.object(config.buTreasury)],
	});
	return tx;
}

/** Wrap (public → private) `amountRaw` BU base units to `receiver`.
 *  Splits a coin off the sender's largest BU coin object and feeds it
 *  to `contraClient.wrap`. */
export async function buildWrapTx(opts: {
	suiClient: ContraCompatibleClient;
	contraClient: ContraClient;
	sender: string;
	receiver: string;
	tokenType: string;
	amountRaw: bigint;
	memo?: string;
}): Promise<Transaction> {
	const { objects: coins } = await opts.suiClient.core.listCoins({
		owner: opts.sender,
		coinType: opts.tokenType,
	});
	if (!coins.length) throw new Error('No BU coins found');

	const tx = new Transaction();
	const [payment] = tx.splitCoins(tx.object(coins[0].objectId), [opts.amountRaw]);
	tx.add(
		await opts.contraClient.wrap({
			coin: payment,
			receiver: opts.receiver,
			tokenType: opts.tokenType,
			memo: opts.memo,
		}),
	);
	return tx;
}

/** Unwrap (private → public) `amountRaw` BU base units, transferring
 *  the resulting coin to `recipient`. Returns the built transaction; the
 *  caller still needs to sign and check for `TryUnwrapFailedEvent`
 *  via `executeAndCheckMergeFailure`. */
export async function buildUnwrapTx(opts: {
	contraClient: ContraClient;
	tokenAccount: TokenAccount;
	amountRaw: bigint;
	recipient: string;
	merge?: boolean;
}): Promise<Transaction> {
	const unwrapFn: (tx: Transaction) => TransactionResult = await opts.contraClient.unwrap({
		tokenAccount: opts.tokenAccount,
		amount: opts.amountRaw,
		merge: opts.merge ?? true,
	});
	const tx = new Transaction();
	const coin = tx.add(unwrapFn);
	tx.transferObjects([coin], opts.recipient);
	return tx;
}

/** Private transfer: send `amountRaw` BU base units from the user's
 *  private balance to `receiverAddress`'s private account. The caller
 *  must check for `TryTransferFailedEvent` after execution. */
export async function buildTransferTx(opts: {
	contraClient: ContraClient;
	tokenAccount: TokenAccount;
	receiverAddress: string;
	amountRaw: bigint;
	merge?: boolean;
	memo?: string;
}): Promise<Transaction> {
	const transferFn = await opts.contraClient.transfer({
		tokenAccount: opts.tokenAccount,
		receiverAddress: opts.receiverAddress,
		amount: opts.amountRaw,
		merge: opts.merge ?? true,
		memo: opts.memo,
	});
	const tx = new Transaction();
	tx.add(transferFn);
	return tx;
}

/** Verify that `address` has registered the per-account object so we
 *  can target it as a private-transfer recipient. Returns true iff the
 *  account exists. */
export async function recipientHasPrivateAccount(
	contraClient: ContraClient,
	suiClient: ContraCompatibleClient,
	address: string,
): Promise<boolean> {
	try {
		const id = contraClient.getAccountId(address);
		const {
			objects: [object],
		} = await suiClient.core.getObjects({ objectIds: [id] });
		return !(object instanceof Error);
	} catch {
		return false;
	}
}

// ─────────────────────────────────────────────────────────────────────
// 4. Issuer transactions
// ─────────────────────────────────────────────────────────────────────

/** Add an address to the BU coin-level deny list. Effective for inputs
 *  immediately, and for receiving from the next epoch. */
export function buildAddDenyTx(opts: {
	coinType: string;
	denyCapId: string;
	address: string;
}): Transaction {
	const tx = new Transaction();
	tx.moveCall({
		target: `0x2::coin::deny_list_v2_add`,
		typeArguments: [opts.coinType],
		arguments: [
			tx.object(SUI_DENY_LIST_OBJECT_ID),
			tx.object(opts.denyCapId),
			tx.pure.address(opts.address),
		],
	});
	return tx;
}

export function buildRemoveDenyTx(opts: {
	coinType: string;
	denyCapId: string;
	address: string;
}): Transaction {
	const tx = new Transaction();
	tx.moveCall({
		target: `0x2::coin::deny_list_v2_remove`,
		typeArguments: [opts.coinType],
		arguments: [
			tx.object(SUI_DENY_LIST_OBJECT_ID),
			tx.object(opts.denyCapId),
			tx.pure.address(opts.address),
		],
	});
	return tx;
}

export function buildEnableGlobalPauseTx(opts: {
	coinType: string;
	denyCapId: string;
}): Transaction {
	const tx = new Transaction();
	tx.moveCall({
		target: `0x2::coin::deny_list_v2_enable_global_pause`,
		typeArguments: [opts.coinType],
		arguments: [tx.object(SUI_DENY_LIST_OBJECT_ID), tx.object(opts.denyCapId)],
	});
	return tx;
}

export function buildDisableGlobalPauseTx(opts: {
	coinType: string;
	denyCapId: string;
}): Transaction {
	const tx = new Transaction();
	tx.moveCall({
		target: `0x2::coin::deny_list_v2_disable_global_pause`,
		typeArguments: [opts.coinType],
		arguments: [tx.object(SUI_DENY_LIST_OBJECT_ID), tx.object(opts.denyCapId)],
	});
	return tx;
}

export function buildAddFreezeAdminTx(opts: {
	config: TokenConfig;
	confidentialTokenId: string;
	managementCapId: string;
	address: string;
}): Transaction {
	const tx = new Transaction();
	tx.add(
		contraContracts.issueFreezeCap({
			package: opts.config.contraPackage,
			typeArguments: [`${opts.config.buPackage}::bu::BU`],
			arguments: {
				ct: opts.confidentialTokenId,
				T: opts.managementCapId,
				addr: opts.address,
			},
		}),
	);
	return tx;
}

export function buildRemoveFreezeAdminTx(opts: {
	config: TokenConfig;
	confidentialTokenId: string;
	managementCapId: string;
	address: string;
}): Transaction {
	const tx = new Transaction();
	tx.add(
		contraContracts.revokeFreezeCap({
			package: opts.config.contraPackage,
			typeArguments: [`${opts.config.buPackage}::bu::BU`],
			arguments: {
				ct: opts.confidentialTokenId,
				T: opts.managementCapId,
				addr: opts.address,
			},
		}),
	);
	return tx;
}

export function buildGlobalFreezeTx(opts: {
	config: TokenConfig;
	confidentialTokenId: string;
}): Transaction {
	const tx = new Transaction();
	tx.add(
		contraContracts.globalFreeze({
			package: opts.config.contraPackage,
			typeArguments: [`${opts.config.buPackage}::bu::BU`],
			arguments: { ct: opts.confidentialTokenId },
		}),
	);
	return tx;
}

export function buildGlobalUnfreezeTx(opts: {
	config: TokenConfig;
	confidentialTokenId: string;
}): Transaction {
	const tx = new Transaction();
	tx.moveCall({
		target: `${opts.config.buPackage}::bu::unfreeze_confidential`,
		arguments: [tx.object(opts.config.buTreasury), tx.object(opts.confidentialTokenId)],
	});
	return tx;
}

/** Sign and execute a transaction with an issuer-held secret key
 *  (i.e. without a connected wallet). Used by the issuer monitor for
 *  deny-list, pause, and freeze-admin operations. */
export async function executeIssuerTx(opts: {
	client: ContraCompatibleClient;
	secretKey: string;
	transaction: Transaction;
}): Promise<{ digest: string }> {
	const keypair = Ed25519Keypair.fromSecretKey(opts.secretKey);
	const executed = await executeOrThrow(opts.client, opts.transaction, keypair, 'issuer tx');
	return { digest: executed.digest };
}

// ─────────────────────────────────────────────────────────────────────
// 5. Auditor flow (per-transfer)
// ─────────────────────────────────────────────────────────────────────

/** Decrypt the amount of a single transfer from its `TransferEvent`, from the auditor's
 *  perspective. Regroups the receiver's four u16 limbs into the two u32-limb commitments and pairs
 *  them with this auditor's handle set (the event carries one per auditor key), then BSGS-decrypts.
 *  Returns `null` if the event isn't a valid `TransferEvent`, carried no auditor data, or is out of
 *  range. */
export function auditTransferAmount(auditor: ContraAuditor, eventBcs: Uint8Array): bigint | null {
	try {
		return auditor.decryptTransferAmount(TransferEventBcs.parse(eventBcs));
	} catch (e) {
		console.error('[sdk] failed to audit-decrypt TransferEvent', e);
		return null;
	}
}

/** Decrypt the encrypted amount carried inside a `TransferEvent` from
 *  the perspective of either the sender or the receiver. Returns `null`
 *  if the event isn't a valid `TransferEvent` BCS payload or the local
 *  viewing key can't decrypt it. */
export function decryptTransferEventAmount(opts: {
	/** Raw BCS bytes of the event struct (`Event.bcs` from the RPC). */
	eventBcs: Uint8Array;
	side: 'sender' | 'receiver';
	tokenAccount: TokenAccount;
	table: DiscreteLogTable;
}): bigint | null {
	try {
		const decoded = TransferEventBcs.parse(opts.eventBcs);
		const limbs = decoded.encrypted_amount_receiver.map((e) => Ciphertext.fromBcs(e));
		if (opts.side === 'receiver') {
			return opts.tokenAccount.decryptAmount(limbs, opts.table);
		}
		return opts.tokenAccount.recoverSentAmount(
			limbs,
			pointFromBcs(decoded.seed_point),
			decoded.batch_index,
			opts.table,
		);
	} catch (e) {
		console.error('[sdk] failed to decrypt TransferEvent', e);
		return null;
	}
}

/** Cheaply check that a candidate auditor private key matches a given
 *  on-chain auditor public key (for verification UIs). */
export function auditorPrivateKeyMatchesPublic(
	privateKey: bigint,
	publicKeyBytes: Uint8Array,
): boolean {
	const expected = G.multiply(privateKey).toBytes();
	if (expected.length !== publicKeyBytes.length) return false;
	for (let i = 0; i < expected.length; i++) {
		if (expected[i] !== publicKeyBytes[i]) return false;
	}
	return true;
}

// ─────────────────────────────────────────────────────────────────────
// 6. Faucet
// ─────────────────────────────────────────────────────────────────────

export function requestSui(network: Network, address: string): Promise<unknown> {
	return requestSuiFromFaucetV2({
		host: getFaucetHost(network),
		recipient: address,
	});
}

// ─────────────────────────────────────────────────────────────────────
// 7. Deployment (issuer setup)
// ─────────────────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Deploy the BU token and Contra packages, register BU as a
 *  confidential token, and create an on-chain TokenConfig. Returns
 *  every object id the kaisho UI needs to drive the deployment plus a
 *  freshly-generated set of auditor keypairs. */
export async function createTokenFromBytecodes(
	bytecodes: Bytecodes,
	keypair: Ed25519Keypair,
	client: ContraCompatibleClient,
	log: (msg: string) => void = () => {},
): Promise<CreateTokenResult> {
	log('Publishing packages on chain...');
	const result = await publishBytecodes(bytecodes, keypair, client);
	const packageId = result.packageId;
	log(`Published package: ${packageId}`);

	const buTreasuryId = findObject(result.createdObjects, 'BuTreasury');
	const tokenRegistryId = findObject(result.createdObjects, 'TokenRegistry');
	const accountRegistryId = findObject(result.createdObjects, 'AccountRegistry');
	const denyCapId = findObject(result.createdObjects, 'DenyCapV2');
	log(`BuTreasury: ${buTreasuryId}`);
	log(`TokenRegistry: ${tokenRegistryId}`);
	log(`AccountRegistry: ${accountRegistryId}`);
	log(`DenyCap: ${denyCapId}`);

	log('Generating auditor keypair...');
	const auditorSk = randomScalar();
	const auditorKey: AuditorKey = {
		privateKey: auditorSk.toString(16),
		publicKey: bytesToHex(G.multiply(auditorSk).toBytes()),
	};
	// Per-transfer auditing uses a single auditor key. Kept as a one-element array so the stored
	// deployment shape (`auditorKeys[0]`) is unchanged.
	const auditorKeys: AuditorKey[] = [auditorKey];
	log(`Auditor pubkey: ${auditorKey.publicKey}`);

	log('Registering BU as confidential token...');
	const regTx = new Transaction();
	const elementType = `${SUI_FRAMEWORK_ADDRESS}::group_ops::Element<${SUI_FRAMEWORK_ADDRESS}::ristretto255::G>`;
	// `register_confidential` takes `vector<Element>`; register the single auditor pk as a one-element
	// vector (an empty vector would register with no auditors).
	const auditorPkArg = regTx.makeMoveVec({
		type: elementType,
		elements: [
			point(Uint8Array.from(auditorKey.publicKey.match(/.{2}/g)!.map((b) => parseInt(b, 16)))),
		],
	});
	regTx.moveCall({
		target: `${packageId}::bu::register_confidential`,
		arguments: [regTx.object(buTreasuryId), regTx.object(tokenRegistryId), auditorPkArg],
	});
	const regCreated = await signExecuteAndWait(regTx, keypair, client);
	const confidentialTokenId = findObject(regCreated, 'ConfidentialToken');
	log(`ConfidentialToken: ${confidentialTokenId}`);
	const managementCapId = findObject(regCreated, 'ManagementCap');
	log(`ManagementCap: ${managementCapId}`);

	log('Creating on-chain TokenConfig...');
	const tx = new Transaction();
	tx.moveCall({
		target: `${packageId}::token_config::create`,
		arguments: [
			tx.pure.address(packageId),
			tx.pure.address(buTreasuryId),
			tx.pure.address(packageId),
			tx.pure.address(tokenRegistryId),
			tx.pure.address(accountRegistryId),
			tx.pure.vector('u8', bytecodes.digest),
		],
	});
	const configCreated = await signExecuteAndWait(tx, keypair, client);
	const tokenConfigId = findObject(configCreated, 'TokenConfig');
	log(`TokenConfig: ${tokenConfigId}`);

	return {
		buPackageId: packageId,
		buTreasuryId,
		contraPackageId: packageId,
		tokenRegistryId,
		accountRegistryId,
		confidentialTokenId,
		managementCapId,
		tokenConfigId,
		denyCapId,
		auditorKeys,
	};
}

// ─────────────────────────────────────────────────────────────────────
// 8. Tx execution helpers
// ─────────────────────────────────────────────────────────────────────

/** Some Contra transactions emit a sentinel event when a merge step
 *  raced against another tx and the operation rolled back gracefully
 *  (e.g. `TryTransferFailedEvent`, `TryUnwrapFailedEvent`). Wait for
 *  the transaction with events, then return whether the sentinel fired. */
export async function transactionEmittedEvent(
	suiClient: ContraCompatibleClient,
	digest: string,
	eventTypeSubstring: string,
): Promise<boolean> {
	const result = await suiClient.core.waitForTransaction({
		digest,
		include: { events: true },
	});
	const txResponse = result.Transaction ?? result.FailedTransaction;
	return !!txResponse?.events?.some((e) => e.eventType.includes(eventTypeSubstring));
}
