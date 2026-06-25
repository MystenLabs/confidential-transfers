// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import {
	useCurrentAccount,
	useSignAndExecuteTransaction,
	useSuiClient,
	useSuiClientQuery,
} from '@mysten/dapp-kit';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import type { TokenBalance } from 'ts-sdk';

import { useContraClient } from '../hooks/useContraClient';
import { explorerUrl } from '../network';
import {
	buildMintTx,
	buildTransferTx,
	buildUnwrapTx,
	buildWrapTx,
	contraPackageConfig,
	fetchConfidentialBalance,
	makeTokenAccount,
	recipientHasPrivateAccount,
	requestSui,
	totalConfidentialBalanceBu,
	transactionEmittedEvent,
} from '../sdk';
import type { TokenConfig } from '../sdk';
import { AnimatedNumber } from './AnimatedNumber';
import { Sparkles } from './Sparkles';

type Source = 'public' | 'confidential';

function BalanceSkeleton() {
	return (
		<div className="flex flex-col gap-2 mt-2">
			<div className="skeleton h-8 w-24" />
			<div className="skeleton h-3 w-10" />
		</div>
	);
}

/** A small `?` badge that reveals an explanation on hover. The tooltip is
 *  rendered in a portal with fixed positioning so it is never clipped by the
 *  card's `overflow-hidden` / hover `transform`. */
function InfoDot({ text }: { text: string }) {
	const ref = useRef<HTMLSpanElement>(null);
	const [pos, setPos] = useState<{ top: number; left: number } | null>(null);

	const show = () => {
		const r = ref.current?.getBoundingClientRect();
		if (r) setPos({ top: r.top, left: r.left + r.width / 2 });
	};
	const hide = () => setPos(null);

	return (
		<>
			<span
				ref={ref}
				onMouseEnter={show}
				onMouseLeave={hide}
				className="inline-flex h-3.5 w-3.5 shrink-0 cursor-help items-center justify-center rounded-full bg-white/[0.06] text-[8px] font-bold leading-none text-zinc-500 transition-colors hover:bg-white/[0.12] hover:text-zinc-300"
			>
				?
			</span>
			{pos &&
				createPortal(
					<div
						className="pointer-events-none fixed z-[100] w-52 max-w-[calc(100vw-1rem)] -translate-x-1/2 -translate-y-full rounded-lg border border-white/10 bg-zinc-900 px-3 py-2 text-[10px] font-normal normal-case leading-relaxed tracking-normal text-zinc-300 shadow-xl"
						style={{ top: pos.top - 6, left: pos.left }}
					>
						{text}
					</div>,
					document.body,
				)}
		</>
	);
}

export function WalletCard({ config, encKey }: { config: TokenConfig; encKey: string }) {
	const account = useCurrentAccount();
	const client = useSuiClient();
	const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();

	// --- Token account link ---
	const contraClient = useContraClient(config);
	const coinType = `${config.buPackage}::bu::BU`;
	const tokenAccountId =
		contraClient && account ? contraClient.getTokenAccountId(account.address, coinType) : undefined;
	const { data: balanceData } = useSuiClientQuery(
		'getBalance',
		{ owner: account?.address ?? '', coinType },
		{ enabled: !!account, refetchInterval: 4_000 },
	);
	const publicBalance = balanceData ? Number(balanceData.totalBalance) / 1e9 : 0;

	// --- Confidential balance ---
	const tokenAccount = useMemo(
		() =>
			account
				? makeTokenAccount(account.address, coinType, contraPackageConfig(config), encKey)
				: null,
		[account, coinType, encKey, config],
	);

	const [confBalance, setConfBalance] = useState<TokenBalance | null>(null);

	const refreshConfBalance = useCallback(async () => {
		if (!contraClient || !tokenAccount) return;
		try {
			setConfBalance(await fetchConfidentialBalance(contraClient, tokenAccount));
		} catch (e) {
			console.error('fetchConfBalance failed:', e);
		}
	}, [contraClient, tokenAccount]);

	useEffect(() => {
		refreshConfBalance();
		const interval = setInterval(refreshConfBalance, 4_000);
		return () => clearInterval(interval);
	}, [refreshConfBalance]);

	const confidentialBalance = confBalance ? totalConfidentialBalanceBu(confBalance) : 0;

	// --- Mint ---
	const [minting, setMinting] = useState(false);
	const [mintError, setMintError] = useState<string>();
	const [mintResult, setMintResult] = useState<{ digest: string } | null>(null);

	useEffect(() => {
		if (!mintResult) return;
		const timer = setTimeout(() => setMintResult(null), 6000);
		return () => clearTimeout(timer);
	}, [mintResult]);

	// --- Wrap ---
	const [wrapping, setWrapping] = useState(false);
	const [wrapError, setWrapError] = useState<string>();
	const [wrapResult, setWrapResult] = useState<{
		digest: string;
		amount: string;
		action: string;
	} | null>(null);

	useEffect(() => {
		if (!wrapResult) return;
		const timer = setTimeout(() => setWrapResult(null), 6000);
		return () => clearTimeout(timer);
	}, [wrapResult]);

	// --- Transfer result ---
	const [transferring, setTransferring] = useState(false);
	const [transferResult, setTransferResult] = useState<{ digest: string; amount: string } | null>(
		null,
	);

	useEffect(() => {
		if (!transferResult) return;
		const timer = setTimeout(() => setTransferResult(null), 6000);
		return () => clearTimeout(timer);
	}, [transferResult]);

	const handleMint = async () => {
		if (!account) return;
		setMinting(true);
		setMintError(undefined);
		try {
			const { totalBalance } = await client.getBalance({ owner: account.address });
			if (totalBalance === '0') {
				await requestSui(account.address);
			}
			const tx = buildMintTx(config);
			const result = await signAndExecute({ transaction: tx });
			setMintResult({ digest: result.digest });
		} catch (e) {
			setMintError(String(e));
		} finally {
			setMinting(false);
		}
	};

	// --- Wrap / Unwrap modal ---
	const [modal, setModal] = useState<'wrap' | 'unwrap' | null>(null);
	const [modalAmount, setModalAmount] = useState('');

	const openModal = (direction: 'wrap' | 'unwrap') => {
		setModalAmount('');
		setModal(direction);
	};
	const handleConfirm = async () => {
		if (!account || !contraClient || !modal) return;
		const amount = Number(modalAmount);
		if (!amount || amount <= 0) return;

		setWrapping(true);
		setWrapError(undefined);
		try {
			const amountRaw = BigInt(Math.round(amount * 1e9));

			if (modal === 'wrap') {
				const tx = await buildWrapTx({
					suiClient: client,
					contraClient,
					sender: account.address,
					receiver: account.address,
					tokenType: coinType,
					amountRaw,
				});
				const result = await signAndExecute({ transaction: tx });
				setWrapResult({ digest: result.digest, amount: modalAmount, action: 'wrapped' });
			} else {
				if (!tokenAccount) return;
				const tx = await buildUnwrapTx({
					contraClient,
					tokenAccount,
					amountRaw,
					recipient: account.address,
				});
				const result = await signAndExecute({ transaction: tx });
				const failed = await transactionEmittedEvent(client, result.digest, 'TryUnwrapFailedEvent');
				if (failed) {
					setWrapError(
						'Unwrap could not be completed because the balance changed. Please try again.',
					);
					setWrapping(false);
					return;
				}
				setWrapResult({ digest: result.digest, amount: modalAmount, action: 'unwrapped' });
			}

			setModal(null);
			refreshConfBalance();
		} catch (e) {
			setWrapError(String(e));
		} finally {
			setWrapping(false);
		}
	};
	const modalMax = modal === 'wrap' ? publicBalance : confidentialBalance;
	const modalOverMax = modalAmount !== '' && Number(modalAmount) > modalMax;

	// --- Transfer ---
	const [transferSource, setTransferSource] = useState<Source | null>(null);
	const [recipient, setRecipient] = useState('');
	const [transferAmount, setTransferAmount] = useState('');
	const [transferMemo, setTransferMemo] = useState('');
	const [transferStatus, setTransferStatus] = useState<
		'idle' | 'checking' | 'error' | 'no-account'
	>('idle');
	const [transferError, setTransferError] = useState('');

	const transferMax = transferSource === 'public' ? publicBalance : confidentialBalance;
	const transferParsed = Number(transferAmount);
	const transferOverMax = transferAmount !== '' && transferParsed > transferMax;

	const selectSource = (s: Source) => {
		if (transferSource === s) {
			cancelTransfer();
			return;
		}
		setTransferSource(s);
		setRecipient('');
		setTransferAmount('');
		setTransferMemo('');
		setTransferStatus('idle');
		setTransferError('');
	};

	const cancelTransfer = () => {
		setTransferSource(null);
		setRecipient('');
		setTransferAmount('');
		setTransferMemo('');
		setTransferStatus('idle');
		setTransferError('');
	};

	const handleTransfer = async () => {
		if (!recipient || !transferAmount || transferParsed <= 0 || !account || !contraClient) return;
		setTransferStatus('checking');
		setTransferError('');

		const recipientReady = await recipientHasPrivateAccount(contraClient, client, recipient);
		if (!recipientReady) {
			setTransferStatus('no-account');
			setTransferError(
				'Recipient must enable confidential tokens for BU before receiving confidential transfers.',
			);
			return;
		}

		if (recipient === account.address) {
			setTransferStatus('error');
			setTransferError('Cannot transfer to yourself.');
			return;
		}

		const amountRaw = BigInt(Math.round(transferParsed * 1e9));
		const memo = transferMemo.trim();

		if (transferSource === 'public') {
			setTransferring(true);
			try {
				const tx = await buildWrapTx({
					suiClient: client,
					contraClient,
					sender: account.address,
					receiver: recipient,
					tokenType: coinType,
					amountRaw,
					memo,
				});
				const result = await signAndExecute({ transaction: tx });
				setTransferResult({ digest: result.digest, amount: transferAmount });
				cancelTransfer();
				refreshConfBalance();
			} catch (e) {
				setTransferStatus('error');
				setTransferError(String(e));
			} finally {
				setTransferring(false);
			}
		} else {
			if (!tokenAccount) return;
			setTransferring(true);
			try {
				const tx = await buildTransferTx({
					contraClient,
					tokenAccount,
					receiverAddress: recipient,
					amountRaw,
					memo,
				});
				const result = await signAndExecute({ transaction: tx });
				const failed = await transactionEmittedEvent(
					client,
					result.digest,
					'TryTransferFailedEvent',
				);
				if (failed) {
					setTransferStatus('error');
					setTransferError(
						'Transfer could not be completed because the balance changed. Please try again.',
					);
					setTransferring(false);
					return;
				}
				setTransferResult({ digest: result.digest, amount: transferAmount });
				cancelTransfer();
				refreshConfBalance();
			} catch (e) {
				setTransferStatus('error');
				setTransferError(String(e));
			} finally {
				setTransferring(false);
			}
		}
	};

	return (
		<>
			<div className="card card-shimmer card-tilt glow-border overflow-hidden">
				{/* ── Balances row ── */}
				<div className="flex">
					{/* Public */}
					<div className="relative flex-1 p-5">
						{account && (
							<a
								href={explorerUrl('account', account.address)}
								target="_blank"
								rel="noopener noreferrer"
								className="absolute top-3 right-3 text-zinc-600 hover:text-accent transition-colors"
								title="View on Suiscan"
							>
								<img
									src="/suiscan-icon.png"
									alt="Suiscan"
									className="h-4 w-4 opacity-50 hover:opacity-100 transition-opacity"
								/>
							</a>
						)}
						<div className="flex items-center gap-1.5">
							<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
								Public
							</p>
							<InfoDot text="A normal Sui Coin<BU>. The amount is visible to anyone on-chain." />
						</div>
						{balanceData ? (
							<>
								<p className="mt-2 text-3xl font-bold tabular-nums tracking-tight text-white">
									<AnimatedNumber value={publicBalance} />
								</p>
								<p className="mt-1 text-[11px] font-medium text-zinc-600">BU</p>
							</>
						) : (
							<BalanceSkeleton />
						)}
						<button
							className="mt-2 flex items-center gap-1.5 text-[11px] font-medium text-accent/70 hover:text-accent transition-colors disabled:text-zinc-700"
							onClick={handleMint}
							disabled={minting}
							title="Mint 10 BU test tokens to your public balance"
						>
							{minting ? (
								'Getting…'
							) : (
								<>
									Get 10 more BUs
									<img src="/lydian-lion.svg" alt="coin" className="inline h-4 w-4 rounded-full" />
								</>
							)}
						</button>
						{mintError && <p className="mt-1 text-[10px] text-red-400/80 break-all">{mintError}</p>}
					</div>

					{/* Divider with wrap/unwrap arrows */}
					<div className="flex flex-col items-center justify-center gap-2 border-l border-r border-white/[0.04] px-2.5">
						<button
							className="flex flex-col items-center gap-0.5 rounded-lg bg-white/[0.05] px-2 py-1.5 text-zinc-500 transition-all hover:bg-accent/10 hover:text-accent"
							onClick={() => openModal('wrap')}
							title="Wrap: move BU from your public balance into your confidential balance"
						>
							<svg width="16" height="16" viewBox="0 0 16 16" fill="none">
								<path
									d="M3 8h10M9 4l4 4-4 4"
									stroke="currentColor"
									strokeWidth="1.5"
									strokeLinecap="round"
									strokeLinejoin="round"
								/>
							</svg>
							<span className="text-[8px] font-semibold uppercase tracking-wide leading-none">
								To Private
							</span>
						</button>
						<button
							className="flex flex-col items-center gap-0.5 rounded-lg bg-white/[0.05] px-2 py-1.5 text-zinc-500 transition-all hover:bg-accent/10 hover:text-accent"
							onClick={() => openModal('unwrap')}
							title="Unwrap: move BU from your confidential balance back to your public balance"
						>
							<svg width="16" height="16" viewBox="0 0 16 16" fill="none">
								<path
									d="M13 8H3M7 4L3 8l4 4"
									stroke="currentColor"
									strokeWidth="1.5"
									strokeLinecap="round"
									strokeLinejoin="round"
								/>
							</svg>
							<span className="text-[8px] font-semibold uppercase tracking-wide leading-none">
								To Public
							</span>
						</button>
					</div>

					{/* Private */}
					<div className="relative flex-1 p-5">
						{tokenAccountId && (
							<a
								href={explorerUrl('object', tokenAccountId)}
								target="_blank"
								rel="noopener noreferrer"
								className="absolute top-3 right-3 text-zinc-600 hover:text-accent transition-colors"
								title="View on Suiscan"
							>
								<img
									src="/suiscan-icon.png"
									alt="Suiscan"
									className="h-4 w-4 opacity-50 hover:opacity-100 transition-opacity"
								/>
							</a>
						)}
						<div className="flex items-center gap-1.5">
							<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
								Private
							</p>
							<svg
								width="12"
								height="12"
								viewBox="0 0 16 16"
								fill="none"
								className="text-accent/50"
							>
								<path
									d="M4 7V5a4 4 0 118 0v2M3 7h10a1 1 0 011 1v6a1 1 0 01-1 1H3a1 1 0 01-1-1V8a1 1 0 011-1z"
									stroke="currentColor"
									strokeWidth="1.5"
									strokeLinecap="round"
								/>
							</svg>
							<InfoDot text="An on-chain encrypted ciphertext. Only your encryption key (or an auditor) can read the amount." />
						</div>
						{confBalance ? (
							<>
								<p className="mt-2 text-3xl font-bold tabular-nums tracking-tight text-white">
									<AnimatedNumber value={totalConfidentialBalanceBu(confBalance)} />
								</p>
								<p className="mt-1 text-[11px] font-medium text-zinc-600">BU</p>
								<div className="mt-2 space-y-0.5">
									<p className="flex items-center gap-1 text-[10px] text-zinc-600">
										<span className="text-zinc-500">Active (encrypted)</span>
										<InfoDot text="The merged, spendable portion of your confidential balance." />
										{(Number(confBalance.balance.amount) / 1e9).toString()}
									</p>
									<p className="flex items-center gap-1 text-[10px] text-zinc-600">
										<span className="text-zinc-500">Pending</span>
										<InfoDot text="Amounts you've received or wrapped that haven't been merged into Active yet. They merge automatically on your next send or unwrap." />
										{(
											(Number(confBalance.pending.amount) +
												Number(confBalance.pendingPublicBalance)) /
											1e9
										).toString()}
									</p>
								</div>
							</>
						) : (
							<BalanceSkeleton />
						)}
					</div>
				</div>

				{/* ── Send-from separator ── */}
				<div className="flex border-t border-white/[0.05]">
					<button
						className={`flex flex-1 items-center justify-center gap-1.5 py-3 text-[10px] font-semibold uppercase tracking-[0.12em] transition-colors ${
							transferSource === 'public' ? 'text-accent' : 'text-zinc-600 hover:text-zinc-400'
						}`}
						onClick={() => selectSource('public')}
						title="Send BU from your public balance to another user's confidential account"
					>
						<svg width="12" height="12" viewBox="0 0 16 16" fill="none">
							<path
								d="M8 3v10M4 9l4 4 4-4"
								stroke="currentColor"
								strokeWidth="1.5"
								strokeLinecap="round"
								strokeLinejoin="round"
							/>
						</svg>
						Send from Public
					</button>
					<div className="w-px bg-white/[0.05]" />
					<button
						className={`flex flex-1 items-center justify-center gap-1.5 py-3 text-[10px] font-semibold uppercase tracking-[0.12em] transition-colors ${
							transferSource === 'confidential'
								? 'text-accent'
								: 'text-zinc-600 hover:text-zinc-400'
						}`}
						onClick={() => selectSource('confidential')}
						title="Send BU from your private balance to another user's confidential account"
					>
						<svg width="12" height="12" viewBox="0 0 16 16" fill="none">
							<path
								d="M8 3v10M4 9l4 4 4-4"
								stroke="currentColor"
								strokeWidth="1.5"
								strokeLinecap="round"
								strokeLinejoin="round"
							/>
						</svg>
						Send from Private
					</button>
				</div>

				{/* ── Transfer drawer ── */}
				{transferSource && (
					<div className="flex flex-col gap-4 border-t border-white/[0.05] p-5">
						<div className="flex items-center justify-between">
							<p className="text-sm font-semibold text-white">Transfer to Private</p>
							<button
								className="text-zinc-600 hover:text-zinc-300 text-sm leading-none transition-colors"
								onClick={cancelTransfer}
							>
								&times;
							</button>
						</div>

						<input
							className="input-field font-mono text-xs"
							placeholder="Recipient address (0x...)"
							value={recipient}
							onChange={(e) => {
								setRecipient(e.target.value);
								setTransferStatus('idle');
								setTransferError('');
							}}
						/>

						<div>
							<input
								className="input-field w-full"
								type="number"
								min="0"
								placeholder="Amount (BU)"
								value={transferAmount}
								onChange={(e) => setTransferAmount(e.target.value)}
							/>
							{transferOverMax && (
								<p className="mt-1 text-[11px] text-amber-400/80">
									Amount exceeds available balance ({transferMax} BU)
								</p>
							)}
						</div>

						<input
							className="input-field w-full"
							placeholder="Memo (optional)"
							value={transferMemo}
							onChange={(e) => setTransferMemo(e.target.value)}
						/>

						{(transferStatus === 'no-account' || transferStatus === 'error') && (
							<p className="text-xs text-red-400/80 break-all">{transferError}</p>
						)}

						<button
							className="btn-primary"
							disabled={
								!recipient.trim() ||
								!transferAmount ||
								transferParsed <= 0 ||
								transferStatus === 'checking' ||
								transferring ||
								transferOverMax
							}
							onClick={handleTransfer}
							title="Sign and send the transfer transaction"
						>
							{transferring ? 'Sending…' : transferStatus === 'checking' ? 'Checking…' : 'Transfer'}
						</button>
					</div>
				)}
			</div>

			{/* ── Wrap / Unwrap modal ── */}
			{modal && (
				<div
					className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
					onClick={() => setModal(null)}
				>
					<div
						className="card mx-4 flex w-full max-w-sm flex-col gap-4 p-6"
						onClick={(e) => e.stopPropagation()}
					>
						<div>
							<p className="text-sm font-semibold text-white">
								{modal === 'wrap' ? 'Wrap' : 'Unwrap'}
							</p>
							<p className="mt-1 text-xs text-zinc-500">
								{modal === 'wrap'
									? 'Move BU from public balance to private balance'
									: 'Move BU from private balance to public balance'}
							</p>
						</div>
						<div>
							<input
								className="input-field w-full"
								type="number"
								min="0"
								placeholder="Amount (BU)"
								value={modalAmount}
								onChange={(e) => setModalAmount(e.target.value)}
								autoFocus
							/>
							{modalOverMax && (
								<p className="mt-1 text-[11px] text-amber-400/80">
									Amount exceeds available {modal === 'wrap' ? 'public' : 'private'} balance (
									{modalMax} BU)
								</p>
							)}
							{wrapError && (
								<p className="mt-1 text-[11px] text-red-400/80 break-all">{wrapError}</p>
							)}
						</div>
						<div className="flex gap-3">
							<button
								className="btn-primary flex-1"
								disabled={!modalAmount || Number(modalAmount) <= 0 || wrapping || modalOverMax}
								onClick={handleConfirm}
								title={
									modal === 'wrap'
										? 'Move BU from public to private balance'
										: 'Move BU from private to public balance'
								}
							>
								{wrapping
									? modal === 'wrap'
										? 'Wrapping…'
										: 'Unwrapping…'
									: modal === 'wrap'
										? 'Wrap'
										: 'Unwrap'}
							</button>
							<button
								className="btn-secondary flex-1"
								onClick={() => setModal(null)}
								title="Close without making changes"
							>
								Cancel
							</button>
						</div>
					</div>
				</div>
			)}

			{/* ── Success toasts ── */}
			{mintResult && (
				<div className="fixed bottom-6 left-1/2 z-50 toast-enter flex items-center gap-3 rounded-xl bg-zinc-900/95 border border-white/[0.08] px-5 py-3 shadow-2xl backdrop-blur-sm">
					<Sparkles count={10} />
					<p className="text-sm text-white font-medium">10 BU minted</p>
					<a
						href={explorerUrl('tx', mintResult.digest)}
						target="_blank"
						rel="noopener noreferrer"
						title="View on Suiscan"
					>
						<img src="/suiscan-icon.png" alt="Suiscan" className="h-4 w-4" />
					</a>
					<button
						className="ml-1 text-zinc-600 hover:text-zinc-300 text-xs transition-colors"
						onClick={() => setMintResult(null)}
					>
						&times;
					</button>
					<div className="toast-progress" />
				</div>
			)}
			{wrapResult && (
				<div className="fixed bottom-6 left-1/2 z-50 toast-enter flex items-center gap-3 rounded-xl bg-zinc-900/95 border border-white/[0.08] px-5 py-3 shadow-2xl backdrop-blur-sm">
					<Sparkles count={10} />
					<p className="text-sm text-white font-medium">
						{wrapResult.amount} BU {wrapResult.action}
					</p>
					<a
						href={explorerUrl('tx', wrapResult.digest)}
						target="_blank"
						rel="noopener noreferrer"
						title="View on Suiscan"
					>
						<img src="/suiscan-icon.png" alt="Suiscan" className="h-4 w-4" />
					</a>
					<button
						className="ml-1 text-zinc-600 hover:text-zinc-300 text-xs transition-colors"
						onClick={() => setWrapResult(null)}
					>
						&times;
					</button>
					<div className="toast-progress" />
				</div>
			)}
			{transferResult && (
				<div className="fixed bottom-6 left-1/2 z-50 toast-enter flex items-center gap-3 rounded-xl bg-zinc-900/95 border border-white/[0.08] px-5 py-3 shadow-2xl backdrop-blur-sm">
					<Sparkles count={10} />
					<p className="text-sm text-white font-medium">{transferResult.amount} BU sent</p>
					<a
						href={explorerUrl('tx', transferResult.digest)}
						target="_blank"
						rel="noopener noreferrer"
						title="View on Suiscan"
					>
						<img src="/suiscan-icon.png" alt="Suiscan" className="h-4 w-4" />
					</a>
					<button
						className="ml-1 text-zinc-600 hover:text-zinc-300 text-xs transition-colors"
						onClick={() => setTransferResult(null)}
					>
						&times;
					</button>
					<div className="toast-progress" />
				</div>
			)}
		</>
	);
}
