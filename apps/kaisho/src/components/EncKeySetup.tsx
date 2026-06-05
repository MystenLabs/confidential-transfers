// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useSignAndExecuteTransaction, useSuiClient, useSuiClientQuery } from '@mysten/dapp-kit';
import { useEffect, useMemo, useState } from 'react';
import type { ContraClient } from 'ts-sdk';

import {
	buildRegisterAccountTx,
	contraPackageConfig,
	generateTokenAccount,
	requestDevnetSui,
} from '../sdk';
import type { AccountStatus, TokenConfig } from '../sdk';

const STORAGE_KEY_PREFIX = 'kaisho_enc_key';

function storageKey(configId: string, address: string) {
	return `${STORAGE_KEY_PREFIX}:${address}:${configId}`;
}

export function useEncKey(configId: string | undefined, address: string | undefined) {
	const [encKey, setEncKey] = useState<string | null>(() =>
		configId && address ? localStorage.getItem(storageKey(configId, address)) : null,
	);

	useEffect(() => {
		setEncKey(configId && address ? localStorage.getItem(storageKey(configId, address)) : null);
	}, [configId, address]);

	const saveKey = (key: string) => {
		if (!configId || !address) return;
		localStorage.setItem(storageKey(configId, address), key);
		setEncKey(key);
	};

	const clearKey = () => {
		if (!configId || !address) return;
		localStorage.removeItem(storageKey(configId, address));
		setEncKey(null);
	};

	return { encKey, saveKey, clearKey };
}

interface EncKeySetupProps {
	encKey: string | null;
	saveKey: (key: string) => void;
	contraClient: ContraClient;
	config: TokenConfig;
	accountStatus: AccountStatus;
	accountStatusError?: Error;
	refetchAccountStatus: () => void;
	address: string;
	tokenType: string;
}

type SetupStep = 'checking' | 'import-key' | 'generate-key' | 'registering' | 'ready';

/** The black "Your Encryption Key" panel: key value, an inline Copy button,
 *  and a note that the key lives in this browser's local storage. Shared by
 *  the account-creation step and the ready (already set up) state. */
function EncryptionKeyPanel({
	keyHex,
	copied,
	onCopy,
}: {
	keyHex: string;
	copied: boolean;
	onCopy: () => void;
}) {
	return (
		<div className="rounded-lg bg-black/50 px-3 py-2.5">
			<div className="flex items-center justify-between mb-1.5">
				<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-amber-500/70">
					Your Encryption Key
				</p>
				<button
					className="text-[11px] font-medium text-zinc-600 hover:text-zinc-300 transition-colors"
					onClick={onCopy}
					title="Copy encryption key to clipboard"
				>
					{copied ? 'Copied' : 'Copy'}
				</button>
			</div>
			<code className="block break-all font-mono text-[11px] leading-relaxed text-zinc-500">
				{keyHex}
			</code>
			<p className="mt-2 text-[10px] text-zinc-600 leading-relaxed">
				Stored in this browser's local storage. Use Copy to export it — you'll need it to access
				this balance from another browser or device.
			</p>
		</div>
	);
}

export function EncKeySetup({
	encKey,
	saveKey,
	contraClient,
	config,
	accountStatus,
	accountStatusError,
	refetchAccountStatus,
	address,
	tokenType,
}: EncKeySetupProps) {
	const suiClient = useSuiClient();
	const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();

	const [step, setStep] = useState<SetupStep>('checking');
	const [importInput, setImportInput] = useState('');
	const [importError, setImportError] = useState('');
	const [registerError, setRegisterError] = useState('');
	const [copied, setCopied] = useState(false);
	const [requestingFaucet, setRequestingFaucet] = useState(false);
	const [faucetError, setFaucetError] = useState('');

	// SUI balance check for gas
	const { data: suiBalance, refetch: refetchSuiBalance } = useSuiClientQuery(
		'getBalance',
		{ owner: address },
		{ refetchInterval: 10_000 },
	);
	const suiBalanceNum = suiBalance ? Number(suiBalance.totalBalance) / 1e9 : 0;
	const hasEnoughSui = suiBalanceNum > 1;

	const handleRequestFaucet = async () => {
		setRequestingFaucet(true);
		setFaucetError('');
		try {
			await requestDevnetSui(address);
			await refetchSuiBalance();
		} catch (e) {
			setFaucetError(String(e));
		} finally {
			setRequestingFaucet(false);
		}
	};

	// Auto-generate a TokenAccount for new users
	const generatedTokenAccount = useMemo(() => {
		if (accountStatus === 'needs-account' || accountStatus === 'needs-token-account') {
			return generateTokenAccount(address, tokenType, contraPackageConfig(config));
		}
		return null;
	}, [accountStatus, address, tokenType, config]);

	const generatedKeyHex = useMemo(
		() => generatedTokenAccount?.privateKey.toString(16) ?? null,
		[generatedTokenAccount],
	);

	// Drive the step from accountStatus
	useEffect(() => {
		if (encKey) {
			setStep('ready');
			return;
		}
		switch (accountStatus) {
			case 'loading':
				setStep('checking');
				break;
			case 'registered':
				setStep('import-key');
				break;
			case 'needs-account':
			case 'needs-token-account':
				setStep('generate-key');
				break;
			case 'error':
				setStep('checking');
				break;
		}
	}, [accountStatus, encKey]);

	// --- Handlers ---

	const handleImport = () => {
		const trimmed = importInput.trim();
		if (!trimmed) return;
		try {
			BigInt('0x' + trimmed);
		} catch {
			setImportError('Invalid key — must be a valid hex string');
			return;
		}
		setImportError('');
		saveKey(trimmed);
	};

	const handleRegister = async () => {
		if (!generatedTokenAccount || !generatedKeyHex) return;
		if (accountStatus !== 'needs-account' && accountStatus !== 'needs-token-account') return;
		setStep('registering');
		setRegisterError('');
		try {
			const tx = await buildRegisterAccountTx({
				contraClient,
				config,
				tokenAccount: generatedTokenAccount,
				address,
				tokenType,
				accountStatus,
			});
			const result = await signAndExecute({ transaction: tx });
			await suiClient.waitForTransaction({ digest: result.digest });
			saveKey(generatedKeyHex);
		} catch (e) {
			setRegisterError(String(e));
			setStep('generate-key');
		}
	};

	const copyKey = (value: string) => {
		navigator.clipboard.writeText(value);
		setCopied(true);
		setTimeout(() => setCopied(false), 2000);
	};

	// --- Render ---

	if (step === 'ready' && encKey) {
		return (
			<div className="card p-5">
				<EncryptionKeyPanel keyHex={encKey} copied={copied} onCopy={() => copyKey(encKey)} />
			</div>
		);
	}

	if (step === 'checking') {
		return (
			<div className="card flex flex-col items-center gap-4 p-8">
				{accountStatus === 'error' ? (
					<>
						<p className="text-sm text-red-400/80">Failed to check account status</p>
						{accountStatusError && (
							<p className="text-xs text-zinc-600 break-all">{accountStatusError.message}</p>
						)}
						<button
							className="btn-primary"
							onClick={refetchAccountStatus}
							title="Check account status again"
						>
							Retry
						</button>
					</>
				) : (
					<>
						<div className="h-5 w-5 animate-spin rounded-full border-2 border-zinc-700 border-t-accent" />
						<p className="text-sm text-zinc-500">Checking account status…</p>
					</>
				)}
			</div>
		);
	}

	if (step === 'import-key') {
		return (
			<div className="card flex flex-col gap-4 p-6">
				<div className="flex flex-col gap-1">
					<p className="text-sm font-semibold text-white">Import Encryption Key</p>
					<p className="text-xs text-zinc-500">
						Your account is already registered. Enter your encryption key to access your private
						balance.
					</p>
				</div>
				<input
					className="input-field font-mono text-xs"
					value={importInput}
					onChange={(e) => {
						setImportInput(e.target.value);
						setImportError('');
					}}
					placeholder="Paste your hex-encoded encryption key..."
				/>
				{importError && <p className="text-xs text-red-400/80">{importError}</p>}
				<button
					className="btn-primary"
					disabled={!importInput.trim()}
					onClick={handleImport}
					title="Import your existing encryption key to access your private balance"
				>
					Import
				</button>
			</div>
		);
	}

	if (step === 'generate-key') {
		return (
			<div className="card flex flex-col gap-4 p-6">
				<div className="flex flex-col gap-2">
					<p className="text-sm font-semibold text-white">Create Confidential Account</p>
					<p className="text-xs text-zinc-500 leading-relaxed">
						The chain only stores encrypted ciphertexts of your balance. The encryption key below is
						the only thing that can decrypt them — without it your private balance is unreadable
						(except for auditors).
					</p>
					<p className="text-xs text-zinc-500 leading-relaxed">
						This is separate from your Sui wallet — it only decrypts confidential amounts and never
						signs transactions.
					</p>
				</div>

				{generatedKeyHex && (
					<EncryptionKeyPanel
						keyHex={generatedKeyHex}
						copied={copied}
						onCopy={() => copyKey(generatedKeyHex)}
					/>
				)}

				{!hasEnoughSui && (
					<div className="rounded-lg border border-amber-500/15 bg-amber-500/[0.04] px-4 py-3">
						<p className="text-xs text-amber-400/80">
							You need SUI for gas to create your account (current balance: {suiBalanceNum} SUI).
						</p>
						<button
							className="mt-2 rounded-lg bg-amber-500/15 px-3 py-1.5 text-xs font-medium text-amber-300/80 transition-colors hover:bg-amber-500/25 disabled:opacity-50"
							onClick={handleRequestFaucet}
							disabled={requestingFaucet}
							title="Get free SUI on devnet to pay for gas fees"
						>
							{requestingFaucet ? 'Requesting...' : 'Request SUI from Faucet'}
						</button>
						{faucetError && (
							<p className="mt-1 text-[10px] text-red-400/80 break-all">{faucetError}</p>
						)}
					</div>
				)}

				{registerError && <p className="text-xs text-red-400/80 break-all">{registerError}</p>}

				<div className="rounded-lg border border-white/[0.06] bg-white/[0.02] px-4 py-3">
					<p className="text-[11px] text-zinc-500 leading-relaxed">
						Creating your account submits a transaction that registers your on-chain account. It
						also mints <strong className="text-zinc-300">10 BU</strong> test tokens to your public
						balance so you can wrap them and start sending right away.
					</p>
				</div>

				<button
					className="btn-primary"
					onClick={handleRegister}
					disabled={!hasEnoughSui}
					title="Create your on-chain confidential account and mint initial BU tokens"
				>
					Create Account
				</button>
			</div>
		);
	}

	if (step === 'registering') {
		return (
			<div className="card flex flex-col items-center gap-4 p-8">
				<div className="h-5 w-5 animate-spin rounded-full border-2 border-zinc-700 border-t-accent" />
				<p className="text-sm text-zinc-400">Creating your confidential account…</p>
				<p className="text-xs text-zinc-600">Please approve the transaction in your wallet</p>
			</div>
		);
	}

	return null;
}
