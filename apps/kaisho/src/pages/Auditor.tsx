// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import type { AuditorVersionEntry } from 'ts-sdk';

import { AuditAccountCard } from '../components/AuditAccountCard';
import { useActiveNetwork } from '../hooks/useActiveNetwork';
import { useContraAuditor } from '../hooks/useContraAuditor';
import { useContraClient } from '../hooks/useContraClient';
import { useTokenConfig } from '../hooks/useTokenConfig';
import { nsKey, type Network } from '../network';
import { auditorPrivateKeyMatchesPublic, fetchAuditors } from '../sdk';

type VerifyState = 'input' | 'verifying' | 'verified' | 'error';

interface KeyRow {
	version: string;
	index: string;
	privateKey: string;
}

/**
 * Load the issuer's local cache for `configId`. Accepts both the current
 * shape ({ auditorPrivateKey, auditorIndex }) and the legacy shape
 * ({ auditorKeys: [{ privateKey, publicKey }, …] }) so users with prior
 * deployments don't have to re-enter their key. The kaisho deploy flow
 * only writes the initial auditor set, so the stored entry maps to
 * version 0.
 */
function loadStoredAuditorKey(
	configId: string,
	network: Network,
): { version: number; index: number; privateKey: string } | null {
	try {
		const raw = localStorage.getItem(nsKey('kaisho_issuer_wallets', network));
		if (!raw) return null;
		const wallets = JSON.parse(raw) as Record<string, unknown>;
		const entry = wallets[configId] as
			| {
					auditorPrivateKey?: unknown;
					auditorIndex?: unknown;
					auditorKeys?: Array<{ privateKey?: unknown }>;
			  }
			| undefined;
		if (!entry) return null;
		if (typeof entry.auditorPrivateKey === 'string' && typeof entry.auditorIndex === 'number') {
			return { version: 0, index: entry.auditorIndex, privateKey: entry.auditorPrivateKey };
		}
		const legacy = entry.auditorKeys?.[0]?.privateKey;
		if (typeof legacy === 'string') {
			return { version: 0, index: 0, privateKey: legacy };
		}
		return null;
	} catch {
		return null;
	}
}

function emptyRow(): KeyRow {
	return { version: '', index: '', privateKey: '' };
}

interface ParsedRow {
	version: number;
	index: number;
	privateKey: bigint;
}

function parseRows(rows: KeyRow[]): { parsed?: ParsedRow[]; error?: string } {
	const parsed: ParsedRow[] = [];
	for (let i = 0; i < rows.length; i++) {
		const r = rows[i];
		const versionNum = Number(r.version.trim());
		const indexNum = Number(r.index.trim());
		const hex = r.privateKey.trim().replace(/^0x/, '');
		if (!Number.isInteger(versionNum) || versionNum < 0) {
			return { error: `Row ${i + 1}: version must be a non-negative integer.` };
		}
		if (!Number.isInteger(indexNum) || indexNum < 0) {
			return { error: `Row ${i + 1}: index must be a non-negative integer.` };
		}
		if (!hex || !/^[0-9a-fA-F]+$/.test(hex)) {
			return { error: `Row ${i + 1}: private key must be a hex string.` };
		}
		parsed.push({ version: versionNum, index: indexNum, privateKey: BigInt('0x' + hex) });
	}
	const seen = new Set<number>();
	for (const p of parsed) {
		if (seen.has(p.version)) {
			return { error: `Duplicate entry for version ${p.version}.` };
		}
		seen.add(p.version);
	}
	return { parsed };
}

export function Auditor() {
	const { configId } = useParams<{ configId: string }>();
	const network = useActiveNetwork();
	const { config, isLoading, error: configError } = useTokenConfig(configId!);
	const contraClient = useContraClient(config);
	const buTokenType = config ? `${config.buPackage}::bu::BU` : undefined;

	const [keyRows, setKeyRows] = useState<KeyRow[]>([emptyRow()]);
	const [verifyState, setVerifyState] = useState<VerifyState>('input');
	const [verifyError, setVerifyError] = useState('');
	const [unverifiedVersions, setUnverifiedVersions] = useState<number[]>([]);
	const [auditorEntries, setAuditorEntries] = useState<Map<number, AuditorVersionEntry> | null>(
		null,
	);

	// On mount / configId change: skip the prompt entirely if we already have
	// this deployment's keys in localStorage (the issuer's own browser).
	useEffect(() => {
		if (!configId) return;
		const stored = loadStoredAuditorKey(configId, network);
		if (!stored) return;
		const map = new Map<number, AuditorVersionEntry>();
		map.set(stored.version, {
			index: stored.index,
			privateKey: BigInt('0x' + stored.privateKey),
		});
		setAuditorEntries(map);
		setVerifyState('verified');
	}, [configId, network]);

	const handleVerify = async () => {
		setVerifyState('verifying');
		setVerifyError('');
		setUnverifiedVersions([]);
		try {
			const { parsed, error } = parseRows(keyRows);
			if (error || !parsed) {
				setVerifyError(error ?? 'Invalid input.');
				setVerifyState('error');
				return;
			}
			if (!contraClient || !config) {
				setVerifyError('Contra client not ready yet; please retry in a moment.');
				setVerifyState('error');
				return;
			}
			// We can only verify entries whose version matches the current
			// on-chain auditor set. Older versions are accepted on trust — the
			// chain doesn't expose historical auditor pubkeys, and the auditor
			// still needs them to decrypt accounts that haven't rotated.
			const tokenType = `${config.buPackage}::bu::BU`;
			const onChain = await fetchAuditors(contraClient, tokenType);
			const unverified: number[] = [];
			for (const entry of parsed) {
				if (entry.version !== onChain.version) {
					unverified.push(entry.version);
					continue;
				}
				if (entry.index >= onChain.pks.length) {
					setVerifyError(
						`Auditor index ${entry.index} is out of range; the on-chain auditor set has ${onChain.pks.length} key(s) at version ${onChain.version}.`,
					);
					setVerifyState('error');
					return;
				}
				if (!auditorPrivateKeyMatchesPublic(entry.privateKey, onChain.pks[entry.index].toBytes())) {
					setVerifyError(
						`The private key at row for version ${entry.version}, index ${entry.index} does not match the on-chain auditor public key.`,
					);
					setVerifyState('error');
					return;
				}
			}
			const map = new Map<number, AuditorVersionEntry>();
			for (const entry of parsed) {
				map.set(entry.version, { index: entry.index, privateKey: entry.privateKey });
			}
			setAuditorEntries(map);
			setUnverifiedVersions(unverified);
			setVerifyState('verified');
		} catch (e) {
			setVerifyError(String(e));
			setVerifyState('error');
		}
	};

	const auditorKeyForVersion = useMemo(
		() => auditorEntries ?? new Map<number, AuditorVersionEntry>(),
		[auditorEntries],
	);
	const auditor = useContraAuditor(config, buTokenType, auditorKeyForVersion);

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
					Back to Home
				</Link>
			</div>
		);
	}

	if (verifyState === 'input' || verifyState === 'verifying' || verifyState === 'error') {
		const canSubmit =
			keyRows.length > 0 &&
			keyRows.every((r) => r.version.trim() && r.index.trim() && r.privateKey.trim()) &&
			verifyState !== 'verifying';
		const updateRow = (i: number, patch: Partial<KeyRow>) => {
			setKeyRows((prev) => prev.map((r, j) => (i === j ? { ...r, ...patch } : r)));
		};
		return (
			<div className="card flex flex-col gap-4 p-6">
				<div className="flex flex-col gap-2">
					<p className="text-sm font-semibold text-white">Auditor View</p>
					<p className="text-xs text-zinc-500 leading-relaxed">
						Auditors hold a special decryption key the issuer set when the token was created. With
						it you can recover any account's viewing key and read its otherwise-confidential balance
						and history — balances are hidden from third parties, but never from an auditor.
					</p>
					<p className="text-xs text-zinc-500 leading-relaxed">
						Provide one auditor key per version you hold. Entries whose version matches the current
						on-chain auditor set are verified against the chain; older versions are accepted on
						trust so you can still decrypt accounts that haven't rotated.
					</p>
				</div>
				<p className="text-[11px] text-zinc-600 leading-relaxed">
					<span className="font-medium text-zinc-500">Version</span> is the auditor-set rotation;{' '}
					<span className="font-medium text-zinc-500">index</span> is the key's position within that
					set. Most deployments have a single key at version 0, index 0.
				</p>
				<div className="flex flex-col gap-3">
					{keyRows.map((row, i) => (
						<div
							key={i}
							className="flex flex-col gap-1.5 rounded-lg border border-white/[0.04] p-3"
						>
							<div className="flex items-center justify-between">
								<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
									Auditor Key #{i + 1}
								</p>
								{keyRows.length > 1 && (
									<button
										className="text-[10px] text-zinc-500 hover:text-red-400"
										onClick={() => setKeyRows((prev) => prev.filter((_, j) => j !== i))}
										title="Remove this entry"
									>
										Remove
									</button>
								)}
							</div>
							<div className="flex gap-2">
								<div className="flex w-20 flex-col gap-1">
									<label className="text-[10px] font-medium text-zinc-600">Version</label>
									<input
										className="input-field font-mono text-xs"
										placeholder="0"
										value={row.version}
										onChange={(e) => updateRow(i, { version: e.target.value })}
									/>
								</div>
								<div className="flex w-20 flex-col gap-1">
									<label className="text-[10px] font-medium text-zinc-600">Index</label>
									<input
										className="input-field font-mono text-xs"
										placeholder="0"
										value={row.index}
										onChange={(e) => updateRow(i, { index: e.target.value })}
									/>
								</div>
								<div className="flex flex-1 flex-col gap-1">
									<label className="text-[10px] font-medium text-zinc-600">Private key (hex)</label>
									<input
										className="input-field font-mono text-xs"
										placeholder="lowercase hex, no 0x"
										value={row.privateKey}
										onChange={(e) => updateRow(i, { privateKey: e.target.value })}
									/>
								</div>
							</div>
						</div>
					))}
				</div>
				<button
					className="text-xs text-zinc-500 hover:text-zinc-300"
					onClick={() => setKeyRows((prev) => [...prev, emptyRow()])}
					title="Add another (version, index, key) row"
				>
					+ Add another version
				</button>
				{verifyState === 'error' && (
					<p className="text-[11px] text-red-400/80 break-all">{verifyError}</p>
				)}
				<button
					className="btn-primary"
					disabled={!canSubmit}
					onClick={handleVerify}
					title="Verify each key against the on-chain auditor set where possible"
				>
					{verifyState === 'verifying' ? 'Verifying...' : 'Verify'}
				</button>
			</div>
		);
	}

	// verified
	return (
		<div className="flex flex-col gap-5">
			<div className="card p-6">
				<div className="flex items-center gap-2.5">
					<div className="h-2 w-2 rounded-full bg-accent" />
					<p className="text-sm font-semibold text-white">Auditor View</p>
				</div>
				<p className="mt-1.5 text-xs text-zinc-500">
					Holding {auditorKeyForVersion.size} auditor key
					{auditorKeyForVersion.size === 1 ? '' : 's'}.
				</p>
				<div className="mt-3 overflow-hidden rounded-lg border border-white/[0.04]">
					<table className="w-full font-mono text-[11px]">
						<thead className="bg-white/[0.03] text-[10px] uppercase tracking-[0.15em] text-zinc-500">
							<tr>
								<th className="px-2.5 py-1.5 text-left font-semibold">Version</th>
								<th className="px-2.5 py-1.5 text-left font-semibold">Index</th>
								<th className="px-2.5 py-1.5 text-left font-semibold">Private Key</th>
							</tr>
						</thead>
						<tbody>
							{Array.from(auditorKeyForVersion.entries())
								.sort(([a], [b]) => a - b)
								.map(([version, entry]) => (
									<tr key={version} className="border-t border-white/[0.04]">
										<td className="px-2.5 py-1.5 text-zinc-400">{version}</td>
										<td className="px-2.5 py-1.5 text-zinc-400">{entry.index}</td>
										<td className="px-2.5 py-1.5 text-zinc-300 break-all">
											{entry.privateKey.toString(16)}
										</td>
									</tr>
								))}
						</tbody>
					</table>
				</div>
				{unverifiedVersions.length > 0 && (
					<p className="mt-3 text-[11px] text-amber-400/80">
						Versions {unverifiedVersions.join(', ')} could not be verified on chain (older than the
						current auditor set) — accepted on trust.
					</p>
				)}
			</div>

			{contraClient && auditor ? (
				<AuditAccountCard config={config} contraClient={contraClient} auditor={auditor} />
			) : (
				<div className="card p-5">
					<p className="text-xs text-zinc-500">Loading auditor SDK…</p>
				</div>
			)}
		</div>
	);
}
