// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import type { Transaction } from '@mysten/sui/transactions';
import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import { useActiveNetwork } from '../hooks/useActiveNetwork';
import { useTokenConfig } from '../hooks/useTokenConfig';
import { explorerUrl, nsKey, type Network } from '../network';
import {
	buildAddDenyTx,
	buildAddFreezeAdminTx,
	buildDisableGlobalPauseTx,
	buildEnableGlobalPauseTx,
	buildGlobalFreezeTx,
	buildGlobalUnfreezeTx,
	buildRemoveDenyTx,
	buildRemoveFreezeAdminTx,
	executeIssuerTx,
	fetchFreezeAdmins,
	getSuiClient,
	isAddressDeniedNextEpoch,
	isGlobalPauseEnabledNextEpoch,
} from '../sdk';

interface StoredWallet {
	address: string;
	secretKey?: string;
	denyCapId?: string;
	managementCapId?: string;
	confidentialTokenId?: string;
}

function loadStoredWallet(configId: string, network: Network): StoredWallet | null {
	try {
		const raw = localStorage.getItem(nsKey('kaisho_issuer_wallets', network));
		if (!raw) return null;
		const wallets = JSON.parse(raw) as Record<string, StoredWallet | undefined>;
		const entry = wallets[configId];
		if (!entry || typeof entry.address !== 'string') return null;
		return entry;
	} catch {
		return null;
	}
}

const DENY_TRACKED_KEY = 'kaisho_deny_tracked';

function loadTrackedDeny(configId: string, network: Network): string[] {
	try {
		const raw = localStorage.getItem(nsKey(DENY_TRACKED_KEY, network));
		if (!raw) return [];
		const all = JSON.parse(raw) as Record<string, string[] | undefined>;
		return Array.isArray(all[configId]) ? (all[configId] as string[]) : [];
	} catch {
		return [];
	}
}

function saveTrackedDeny(configId: string, network: Network, addrs: string[]) {
	try {
		const raw = localStorage.getItem(nsKey(DENY_TRACKED_KEY, network));
		const all = (raw ? JSON.parse(raw) : {}) as Record<string, string[]>;
		all[configId] = Array.from(new Set(addrs.map((a) => a.toLowerCase())));
		localStorage.setItem(nsKey(DENY_TRACKED_KEY, network), JSON.stringify(all));
	} catch {
		// noop
	}
}

function isValidSuiAddr(s: string): boolean {
	return /^0x[0-9a-fA-F]{1,64}$/.test(s);
}

type ActionState =
	| { kind: 'idle' }
	| { kind: 'running'; label: string }
	| { kind: 'ok'; label: string; digest: string }
	| { kind: 'err'; label: string; message: string };

export function IssuerMonitor() {
	const { configId } = useParams<{ configId: string }>();
	const network = useActiveNetwork();
	const { config, isLoading, error: configError } = useTokenConfig(configId!);
	const [wallet, setWallet] = useState<StoredWallet | null>(null);
	const [denyAddr, setDenyAddr] = useState('');
	const [action, setAction] = useState<ActionState>({ kind: 'idle' });
	const [pauseChecking, setPauseChecking] = useState(false);
	const [pauseEnabled, setPauseEnabled] = useState<boolean | null>(null);
	const [trackedDeny, setTrackedDeny] = useState<string[]>([]);
	const [denyChecking, setDenyChecking] = useState(false);
	const [deniedNow, setDeniedNow] = useState<Set<string>>(new Set());
	const [freezeAdmins, setFreezeAdmins] = useState<string[] | null>(null);
	const [freezeChecking, setFreezeChecking] = useState(false);
	const [freezeAddr, setFreezeAddr] = useState('');
	const [tokenActive, setTokenActive] = useState<boolean | null>(null);

	useEffect(() => {
		if (!configId) return;
		setWallet(loadStoredWallet(configId, network));
		setTrackedDeny(loadTrackedDeny(configId, network));
	}, [configId, network]);

	const buType = useMemo(() => (config ? `${config.buPackage}::bu::BU` : null), [config]);

	const refreshPauseState = async () => {
		if (!buType) return;
		try {
			setPauseChecking(true);
			const client = getSuiClient(network);
			// We check the next-epoch flag (not current-epoch): `enable_global_pause`
			// flips the next-epoch state immediately and starts blocking new inputs,
			// while the current-epoch view doesn't change until the epoch boundary.
			// The button states should reflect the issuer's most recent intent.
			const enabled = await isGlobalPauseEnabledNextEpoch(client, wallet?.address ?? '0x0', buType);
			setPauseEnabled(enabled);
		} catch {
			setPauseEnabled(null);
		} finally {
			setPauseChecking(false);
		}
	};

	useEffect(() => {
		if (buType && wallet) {
			refreshPauseState();
		}
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [buType, wallet]);

	const refreshDenyList = async (candidates: string[] = trackedDeny) => {
		if (!buType || candidates.length === 0) {
			setDeniedNow(new Set());
			return;
		}
		try {
			setDenyChecking(true);
			const client = getSuiClient(network);
			// next_epoch reflects the issuer's most recent add/remove
			// immediately; current_epoch only catches up at the epoch boundary.
			const checks = await Promise.all(
				candidates.map(async (addr) => {
					try {
						const denied = await isAddressDeniedNextEpoch(
							client,
							wallet?.address ?? '0x0',
							buType,
							addr,
						);
						return [addr, denied] as const;
					} catch {
						return [addr, false] as const;
					}
				}),
			);
			setDeniedNow(new Set(checks.filter(([, d]) => d).map(([a]) => a)));
		} finally {
			setDenyChecking(false);
		}
	};

	useEffect(() => {
		if (buType) refreshDenyList();
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [buType, trackedDeny.length]);

	const refreshFreezeAdmins = async () => {
		if (!wallet?.confidentialTokenId) {
			setFreezeAdmins(null);
			setTokenActive(null);
			return;
		}
		try {
			setFreezeChecking(true);
			const client = getSuiClient(network);
			const { admins, isActive } = await fetchFreezeAdmins(client, wallet.confidentialTokenId);
			setFreezeAdmins(admins);
			setTokenActive(isActive);
		} catch {
			setFreezeAdmins(null);
		} finally {
			setFreezeChecking(false);
		}
	};

	useEffect(() => {
		if (wallet?.confidentialTokenId) refreshFreezeAdmins();
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [wallet?.confidentialTokenId]);

	/**
	 * Sign and execute an issuer-built transaction with the secret key
	 * stashed in this browser. `needsCap` lets us short-circuit with a
	 * helpful message when the cap that the action needs isn't on hand.
	 */
	const runIssuerTx = async (
		label: string,
		buildTx: () => Transaction,
		needsCap: 'deny' | 'management' | 'none',
	) => {
		if (!wallet?.secretKey) {
			setAction({ kind: 'err', label, message: 'Issuer secret key not in this browser.' });
			return;
		}
		if (needsCap === 'deny' && !wallet.denyCapId) {
			setAction({ kind: 'err', label, message: 'DenyCap not in this browser.' });
			return;
		}
		if (needsCap === 'management' && !wallet.managementCapId) {
			setAction({ kind: 'err', label, message: 'ManagementCap not in this browser.' });
			return;
		}
		try {
			setAction({ kind: 'running', label });
			const { digest } = await executeIssuerTx({
				client: getSuiClient(network),
				secretKey: wallet.secretKey,
				transaction: buildTx(),
			});
			setAction({ kind: 'ok', label, digest });
		} catch (e) {
			setAction({ kind: 'err', label, message: String(e) });
		}
	};

	const handleAddAdmin = async () => {
		const addr = freezeAddr.trim();
		if (!isValidSuiAddr(addr)) return;
		if (!config || !wallet?.confidentialTokenId || !wallet.managementCapId) return;
		await runIssuerTx(
			'Add freeze admin',
			() =>
				buildAddFreezeAdminTx({
					config,
					confidentialTokenId: wallet.confidentialTokenId!,
					managementCapId: wallet.managementCapId!,
					address: addr,
				}),
			'management',
		);
		setFreezeAddr('');
		refreshFreezeAdmins();
	};

	const handleRemoveAdmin = async (addr: string) => {
		if (!config || !wallet?.confidentialTokenId || !wallet.managementCapId) return;
		await runIssuerTx(
			'Remove freeze admin',
			() =>
				buildRemoveFreezeAdminTx({
					config,
					confidentialTokenId: wallet.confidentialTokenId!,
					managementCapId: wallet.managementCapId!,
					address: addr,
				}),
			'management',
		);
		refreshFreezeAdmins();
	};

	const handleGlobalFreeze = async () => {
		if (!config || !wallet?.confidentialTokenId) return;
		await runIssuerTx(
			'Freeze confidential token',
			() =>
				buildGlobalFreezeTx({
					config,
					confidentialTokenId: wallet.confidentialTokenId!,
				}),
			'none',
		);
		refreshFreezeAdmins();
	};

	const handleGlobalUnfreeze = async () => {
		if (!config || !wallet?.confidentialTokenId) return;
		await runIssuerTx(
			'Unfreeze confidential token',
			() =>
				buildGlobalUnfreezeTx({
					config,
					confidentialTokenId: wallet.confidentialTokenId!,
				}),
			'none',
		);
		refreshFreezeAdmins();
	};

	const trackAddr = (addr: string) => {
		if (!configId) return;
		const next = Array.from(new Set([...trackedDeny, addr.toLowerCase()]));
		setTrackedDeny(next);
		saveTrackedDeny(configId, network, next);
	};

	const handleAddDeny = async () => {
		const addr = denyAddr.trim();
		if (!buType || !wallet?.denyCapId) return;
		await runIssuerTx(
			'Add to deny list',
			() => buildAddDenyTx({ coinType: buType, denyCapId: wallet.denyCapId!, address: addr }),
			'deny',
		);
		refreshPauseState();
		trackAddr(addr);
		refreshDenyList(Array.from(new Set([...trackedDeny, addr.toLowerCase()])));
	};

	const handleRemoveDeny = async (addr?: string) => {
		const target = (addr ?? denyAddr).trim();
		if (!buType || !wallet?.denyCapId) return;
		await runIssuerTx(
			'Remove from deny list',
			() => buildRemoveDenyTx({ coinType: buType, denyCapId: wallet.denyCapId!, address: target }),
			'deny',
		);
		refreshPauseState();
		refreshDenyList();
	};

	const handleEnablePause = async () => {
		if (!buType || !wallet?.denyCapId) return;
		await runIssuerTx(
			'Enable global pause',
			() => buildEnableGlobalPauseTx({ coinType: buType, denyCapId: wallet.denyCapId! }),
			'deny',
		);
		refreshPauseState();
	};

	const handleDisablePause = async () => {
		if (!buType || !wallet?.denyCapId) return;
		await runIssuerTx(
			'Disable global pause',
			() => buildDisableGlobalPauseTx({ coinType: buType, denyCapId: wallet.denyCapId! }),
			'deny',
		);
		refreshPauseState();
	};

	if (isLoading) {
		return (
			<div className="card flex items-center justify-center gap-3 p-8">
				<div className="h-4 w-4 animate-spin rounded-full border-2 border-zinc-700 border-t-accent" />
				<p className="text-sm text-zinc-500">Loading token config...</p>
			</div>
		);
	}

	if (configError || !config) {
		return (
			<div className="card p-6 text-center">
				<p className="text-red-400/80">
					Failed to load TokenConfig <code className="text-xs break-all">{configId}</code>
				</p>
				{configError && <p className="mt-2 text-xs text-zinc-600">{String(configError)}</p>}
				<Link to="/" className="btn-primary mt-4 inline-block">
					Create a New Deployment
				</Link>
			</div>
		);
	}

	const isValidAddr = isValidSuiAddr(denyAddr.trim());
	const isValidFreezeAddr = isValidSuiAddr(freezeAddr.trim());
	const denyDisabled =
		!wallet?.secretKey || !wallet?.denyCapId || action.kind === 'running' || !isValidAddr;
	const pauseDisabled = !wallet?.secretKey || !wallet?.denyCapId || action.kind === 'running';
	const adminDisabled =
		!wallet?.secretKey ||
		!wallet?.managementCapId ||
		!wallet?.confidentialTokenId ||
		action.kind === 'running';
	const issuerIsAdmin = !!(
		wallet?.address && freezeAdmins?.some((a) => a.toLowerCase() === wallet.address.toLowerCase())
	);
	const freezeBtnDisabled =
		!wallet?.secretKey || !wallet?.confidentialTokenId || action.kind === 'running';

	return (
		<div className="flex flex-col gap-5">
			<div className="card p-6">
				<div className="flex items-center gap-2.5">
					<div className="h-2 w-2 rounded-full bg-accent" />
					<p className="text-sm font-semibold text-white">Issuer View</p>
				</div>
				{wallet?.address && (
					<p className="mt-1.5 text-xs text-zinc-500">
						Deployed by{' '}
						<a
							href={explorerUrl(network, 'account', wallet.address)}
							target="_blank"
							rel="noopener noreferrer"
							className="inline-flex items-center gap-1 text-zinc-400 hover:text-zinc-200"
							title="View the deployer account on Suiscan"
						>
							account
							<img src="/suiscan-icon.png" alt="Suiscan" className="h-3 w-3 opacity-50" />
						</a>
					</p>
				)}
				<p className="mt-3 text-xs text-zinc-500 leading-relaxed">
					As the token's issuer you hold its operational and compliance controls — block individual
					addresses, pause all activity, and manage who can freeze the confidential token.
				</p>
				<p className="mt-2 text-xs text-zinc-500 leading-relaxed">
					Every action below is a real on-chain transaction, signed automatically with the burner
					issuer key kept in this browser's local storage. If those keys aren't present, the
					corresponding controls are disabled.
				</p>
			</div>

			<div className="card p-5">
				<div className="flex items-center justify-between">
					<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
						Deny List
					</p>
					{!wallet?.secretKey || !wallet?.denyCapId ? (
						<span
							className="text-[10px] text-amber-400/80"
							title="The DenyCap and issuer secret key are kept in this browser's localStorage; if they're missing, redeploy from this browser to manage the deny list."
						>
							issuer keys not in this browser
						</span>
					) : null}
				</div>
				<p className="mt-2 text-xs text-zinc-500">
					Block a specific address from sending or receiving BU. Effect is immediate for inputs;
					receiving is blocked from the next epoch.
				</p>
				<div className="mt-3 flex flex-col gap-2">
					<input
						className="input-field font-mono text-xs"
						placeholder="0x... address"
						value={denyAddr}
						onChange={(e) => setDenyAddr(e.target.value)}
					/>
					<button
						className="btn-primary text-xs"
						disabled={denyDisabled}
						onClick={handleAddDeny}
						title="Add this address to the BU deny list"
					>
						Add
					</button>
				</div>
				<div className="mt-4 border-t border-white/[0.04] pt-3">
					<div className="flex items-center justify-between">
						<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
							Currently Denied
						</p>
						<div className="flex items-center gap-2">
							{denyChecking && (
								<div className="h-3 w-3 animate-spin rounded-full border border-zinc-700 border-t-accent" />
							)}
							<button
								className="text-[10px] text-zinc-500 hover:text-zinc-300"
								onClick={() => refreshDenyList()}
								title="Re-check the on-chain deny list status of tracked addresses"
							>
								Refresh
							</button>
						</div>
					</div>
					{deniedNow.size === 0 ? (
						<p className="mt-2 text-[11px] text-zinc-600">
							{trackedDeny.length === 0
								? 'No tracked addresses yet — add one above.'
								: 'No tracked address is on the deny list right now.'}
						</p>
					) : (
						<ul className="mt-2 flex flex-col gap-1.5">
							{Array.from(deniedNow).map((addr) => (
								<li
									key={addr}
									className="flex items-center gap-2 rounded-lg bg-black/40 px-2.5 py-1.5"
								>
									<code className="flex-1 truncate font-mono text-[11px] text-zinc-300">
										{addr}
									</code>
									<button
										className="shrink-0 text-[10px] text-zinc-500 hover:text-red-400 disabled:cursor-not-allowed disabled:opacity-40"
										disabled={!wallet?.secretKey || !wallet?.denyCapId || action.kind === 'running'}
										onClick={() => handleRemoveDeny(addr)}
										title="Remove this address from the BU deny list"
									>
										Remove
									</button>
								</li>
							))}
						</ul>
					)}
					{trackedDeny.length > deniedNow.size && (
						<p className="mt-2 text-[10px] text-zinc-600">
							{trackedDeny.length - deniedNow.size} tracked address
							{trackedDeny.length - deniedNow.size === 1 ? '' : 'es'} not currently denied (e.g.
							removed earlier).
						</p>
					)}
				</div>
			</div>

			<div className="card p-5">
				<div className="flex items-center justify-between">
					<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
						Global Pause
					</p>
					<span className="text-[10px] text-zinc-500">
						{pauseChecking
							? 'checking...'
							: pauseEnabled === null
								? 'unknown'
								: pauseEnabled
									? 'PAUSED'
									: 'active'}
					</span>
				</div>
				<p className="mt-2 text-xs text-zinc-500">
					Freezes the entire BU token: all wraps, transfers and unwraps abort. Use as an emergency
					stop.
				</p>
				<div className="mt-3 flex gap-2">
					<button
						className="btn-primary flex-1 text-xs"
						disabled={pauseDisabled || pauseEnabled === true}
						onClick={handleEnablePause}
						title="Globally pause all BU coin operations"
					>
						Pause
					</button>
					<button
						className="flex-1 rounded-lg bg-white/[0.05] px-3 py-1.5 text-xs font-medium text-zinc-300 transition-colors hover:bg-white/[0.08] disabled:cursor-not-allowed disabled:opacity-40"
						disabled={pauseDisabled || pauseEnabled === false}
						onClick={handleDisablePause}
						title="Lift the global pause on BU"
					>
						Resume
					</button>
				</div>
			</div>

			<div className="card p-5">
				<div className="flex items-center justify-between">
					<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
						Freezing Admins
					</p>
					<div className="flex items-center gap-2">
						{freezeChecking && (
							<div className="h-3 w-3 animate-spin rounded-full border border-zinc-700 border-t-accent" />
						)}
						<button
							className="text-[10px] text-zinc-500 hover:text-zinc-300"
							onClick={() => refreshFreezeAdmins()}
							title="Re-fetch the freeze admin set from the ConfidentialToken"
						>
							Refresh
						</button>
					</div>
				</div>
				<p className="mt-2 text-xs text-zinc-500">
					Addresses with the global freeze capability for the confidential token. Each admin can
					freeze the token; only the issuer can unfreeze.
				</p>
				<div className="mt-3 flex flex-col gap-2">
					<input
						className="input-field font-mono text-xs"
						placeholder="0x... address"
						value={freezeAddr}
						onChange={(e) => setFreezeAddr(e.target.value)}
					/>
					<button
						className="btn-primary text-xs"
						disabled={adminDisabled || !isValidFreezeAddr}
						onClick={handleAddAdmin}
						title="Grant the global freeze capability to this address"
					>
						Add
					</button>
				</div>
				<div className="mt-3">
					{freezeAdmins === null ? (
						<p className="text-[11px] text-zinc-600">
							{wallet?.confidentialTokenId
								? 'Loading…'
								: 'ConfidentialToken id not in this browser — redeploy to manage admins.'}
						</p>
					) : freezeAdmins.length === 0 ? (
						<p className="text-[11px] text-zinc-600">No freeze admins yet.</p>
					) : (
						<ul className="flex flex-col gap-1.5">
							{freezeAdmins.map((addr) => (
								<li
									key={addr}
									className="flex items-center gap-2 rounded-lg bg-black/40 px-2.5 py-1.5"
								>
									<code className="flex-1 truncate font-mono text-[11px] text-zinc-300">
										{addr}
									</code>
									{wallet?.address && addr.toLowerCase() === wallet.address.toLowerCase() && (
										<span className="shrink-0 rounded bg-accent/10 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-accent">
											you
										</span>
									)}
									<button
										className="shrink-0 text-[10px] text-zinc-500 hover:text-red-400 disabled:cursor-not-allowed disabled:opacity-40"
										disabled={adminDisabled}
										onClick={() => handleRemoveAdmin(addr)}
										title="Revoke the global freeze capability from this address"
									>
										Remove
									</button>
								</li>
							))}
						</ul>
					)}
				</div>
				{issuerIsAdmin && (
					<div className="mt-4 border-t border-white/[0.04] pt-3">
						<div className="flex items-center justify-between">
							<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
								Confidential Token Freeze
							</p>
							<span className="text-[10px] text-zinc-500">
								{tokenActive === null ? 'unknown' : tokenActive ? 'active' : 'FROZEN'}
							</span>
						</div>
						<p className="mt-2 text-xs text-zinc-500">
							Freezes the on-chain ConfidentialToken: all wraps, transfers and unwraps abort.
							Independent from the coin-level deny list.
						</p>
						<div className="mt-3 flex gap-2">
							<button
								className="btn-primary flex-1 text-xs"
								disabled={freezeBtnDisabled || tokenActive === false}
								onClick={handleGlobalFreeze}
								title="Freeze the confidential token (requires freeze admin)"
							>
								Freeze
							</button>
							<button
								className="flex-1 rounded-lg bg-white/[0.05] px-3 py-1.5 text-xs font-medium text-zinc-300 transition-colors hover:bg-white/[0.08] disabled:cursor-not-allowed disabled:opacity-40"
								disabled={freezeBtnDisabled || tokenActive === true}
								onClick={handleGlobalUnfreeze}
								title="Lift the freeze on the confidential token"
							>
								Unfreeze
							</button>
						</div>
					</div>
				)}
			</div>

			{action.kind !== 'idle' && (
				<div className="card p-4">
					{action.kind === 'running' && (
						<div className="flex items-center gap-2">
							<div className="h-3 w-3 animate-spin rounded-full border border-zinc-700 border-t-accent" />
							<p className="text-xs text-zinc-500">{action.label}…</p>
						</div>
					)}
					{action.kind === 'ok' && (
						<div>
							<p className="text-xs text-emerald-400/80">{action.label} succeeded.</p>
							<code className="mt-1 block break-all text-[10px] text-zinc-600">
								tx: {action.digest}
							</code>
						</div>
					)}
					{action.kind === 'err' && (
						<div>
							<p className="text-xs text-red-400/80">{action.label} failed.</p>
							<p className="mt-1 break-all text-[10px] text-zinc-600">{action.message}</p>
						</div>
					)}
				</div>
			)}

			<div className="card p-5">
				<p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
					Not yet supported
				</p>
				<ul className="list-disc pl-4 text-[11px] text-zinc-500">
					<li>Seizing / burning a user's confidential balance.</li>
					<li>Rotating the auditor key set.</li>
				</ul>
			</div>
		</div>
	);
}
