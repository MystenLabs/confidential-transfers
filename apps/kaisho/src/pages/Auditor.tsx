// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import { AuditedTransfers } from '../components/AuditedTransfers';
import { useActiveNetwork } from '../hooks/useActiveNetwork';
import { useContraAuditor } from '../hooks/useContraAuditor';
import { useContraClient } from '../hooks/useContraClient';
import { useTokenConfig } from '../hooks/useTokenConfig';
import { nsKey, type Network } from '../network';
import { auditorPrivateKeyMatchesPublic, fetchAuditor } from '../sdk';

type VerifyState = 'input' | 'verifying' | 'verified' | 'error';

/**
 * Load the issuer's locally-cached auditor private key for `configId`. Accepts the current shape
 * ({ auditorPrivateKey }) and the legacy shape ({ auditorKeys: [{ privateKey }, …] }) so users with
 * prior deployments don't have to re-enter their key.
 */
function loadStoredAuditorKey(configId: string, network: Network): string | null {
	try {
		const raw = localStorage.getItem(nsKey('kaisho_issuer_wallets', network));
		if (!raw) return null;
		const wallets = JSON.parse(raw) as Record<string, unknown>;
		const entry = wallets[configId] as
			| { auditorPrivateKey?: unknown; auditorKeys?: Array<{ privateKey?: unknown }> }
			| undefined;
		if (!entry) return null;
		if (typeof entry.auditorPrivateKey === 'string') return entry.auditorPrivateKey;
		const legacy = entry.auditorKeys?.[0]?.privateKey;
		return typeof legacy === 'string' ? legacy : null;
	} catch {
		return null;
	}
}

/** Parse a hex private key (with or without `0x`) into a scalar, or return an error message. */
function parseKey(input: string): { key?: bigint; error?: string } {
	const hex = input.trim().replace(/^0x/, '');
	if (!hex || !/^[0-9a-fA-F]+$/.test(hex)) return { error: 'Private key must be a hex string.' };
	return { key: BigInt('0x' + hex) };
}

export function Auditor() {
	const { configId } = useParams<{ configId: string }>();
	const network = useActiveNetwork();
	const { config, isLoading, error: configError } = useTokenConfig(configId!);
	const contraClient = useContraClient(config);
	const buTokenType = config ? `${config.buPackage}::bu::BU` : undefined;

	const [keyInput, setKeyInput] = useState('');
	const [verifyState, setVerifyState] = useState<VerifyState>('input');
	const [verifyError, setVerifyError] = useState('');
	const [auditorKey, setAuditorKey] = useState<bigint | null>(null);

	// On mount / configId change: skip the prompt entirely if we already have this deployment's key
	// in localStorage (the issuer's own browser).
	useEffect(() => {
		if (!configId) return;
		const stored = loadStoredAuditorKey(configId, network);
		if (!stored) return;
		const { key } = parseKey(stored);
		if (key === undefined) return;
		setAuditorKey(key);
		setVerifyState('verified');
	}, [configId, network]);

	const auditor = useContraAuditor(
		config,
		buTokenType,
		verifyState === 'verified' ? auditorKey : null,
	);

	const handleVerify = async () => {
		setVerifyState('verifying');
		setVerifyError('');
		try {
			const { key, error } = parseKey(keyInput);
			if (error || key === undefined) {
				setVerifyError(error ?? 'Invalid input.');
				setVerifyState('error');
				return;
			}
			if (!contraClient || !config) {
				setVerifyError('Contra client not ready yet; please retry in a moment.');
				setVerifyState('error');
				return;
			}
			const onChain = await fetchAuditor(contraClient, `${config.buPackage}::bu::BU`);
			if (onChain.currentPks.length === 0) {
				setVerifyError('Auditing is disabled for this token (no current auditor keys on chain).');
				setVerifyState('error');
				return;
			}
			if (!onChain.currentPks.some((pk) => auditorPrivateKeyMatchesPublic(key, pk.toBytes()))) {
				setVerifyError('This private key does not match any current on-chain auditor public key.');
				setVerifyState('error');
				return;
			}
			setAuditorKey(key);
			setVerifyState('verified');
		} catch (e) {
			setVerifyError(String(e));
			setVerifyState('error');
		}
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
					Back to Home
				</Link>
			</div>
		);
	}

	if (verifyState !== 'verified') {
		const canSubmit = keyInput.trim().length > 0 && verifyState !== 'verifying';
		return (
			<div className="card flex flex-col gap-4 p-6">
				<div className="flex flex-col gap-2">
					<p className="text-sm font-semibold text-white">Auditor View</p>
					<p className="text-xs text-zinc-500 leading-relaxed">
						Auditing is per-transfer: every confidential transfer carries auditor-readable
						ciphertexts of its amount. With the token's auditor key you can decrypt each transfer's
						amount from its on-chain event — but never a user's viewing key or standing balance.
					</p>
					<p className="text-xs text-zinc-500 leading-relaxed">
						Enter the auditor private key. It is verified against the current on-chain auditor
						public key.
					</p>
				</div>
				<div className="flex flex-col gap-1">
					<label className="text-[10px] font-medium text-zinc-600">Auditor private key (hex)</label>
					<input
						className="input-field font-mono text-xs"
						placeholder="lowercase hex, no 0x"
						value={keyInput}
						onChange={(e) => setKeyInput(e.target.value)}
						onKeyDown={(e) => {
							if (e.key === 'Enter' && canSubmit) handleVerify();
						}}
					/>
				</div>
				{verifyState === 'error' && (
					<p className="text-[11px] text-red-400/80 break-all">{verifyError}</p>
				)}
				<button
					className="btn-primary"
					disabled={!canSubmit}
					onClick={handleVerify}
					title="Verify the key against the current on-chain auditor public key"
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
					Holding the token's auditor key. Transfer amounts below are decrypted from on-chain
					events.
				</p>
			</div>

			{contraClient && auditor ? (
				<AuditedTransfers config={config} auditor={auditor} />
			) : (
				<div className="card p-5">
					<p className="text-xs text-zinc-500">Loading auditor SDK…</p>
				</div>
			)}
		</div>
	);
}
