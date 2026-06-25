// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { createTokenFromBytecodes, getSuiClient, requestSui } from '../sdk';

const STEPS = [
	{
		id: 'wallet',
		label: 'Generating fresh wallet & funding from faucet',
		detail:
			'A brand-new Ed25519 burner keypair is created in this browser and funded with testnet SUI for gas. It only exists here — its secret never leaves localStorage.',
	},
	{
		id: 'publish',
		label: 'Publishing Contra and BU packages',
		detail:
			'One Sui publish transaction installs the Contra protocol modules plus a BU example token. The transaction returns shared TokenRegistry and AccountRegistry objects everyone uses.',
	},
	{
		id: 'register',
		label: 'Registering BU as a confidential token',
		detail:
			'Calls bu::register_confidential to wire BU to the TokenRegistry and generates a fresh auditor keypair whose public key is recorded on-chain.',
	},
	{
		id: 'config',
		label: 'Finalizing on-chain TokenConfig',
		detail:
			'Creates a single TokenConfig object that bundles every package and registry ID needed to talk to this deployment. Its object ID becomes the URL slug below.',
	},
] as const;

type StepId = (typeof STEPS)[number]['id'];
type StepState = 'pending' | 'active' | 'done';

export function Landing() {
	const navigate = useNavigate();
	const [running, setRunning] = useState(false);
	const [error, setError] = useState('');
	const [logs, setLogs] = useState<string[]>([]);
	const [showVerbose, setShowVerbose] = useState(false);
	// Once the user has opened the verbose log, we hold on the success screen
	// instead of auto-redirecting so they can read it. Tracked in a ref so the
	// in-flight handleDeploy reads the latest value without re-rendering.
	const verboseLatchedRef = useRef(false);
	const [completedConfigId, setCompletedConfigId] = useState<string | null>(null);
	const logEndRef = useRef<HTMLDivElement>(null);
	const [steps, setSteps] = useState<Record<StepId, StepState>>({
		wallet: 'pending',
		publish: 'pending',
		register: 'pending',
		config: 'pending',
	});

	useEffect(() => {
		if (showVerbose) logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
	}, [logs, showVerbose]);

	const advanceTo = (next: StepId) => {
		setSteps((prev) => {
			const updated = { ...prev };
			let reached = false;
			for (const s of STEPS) {
				if (s.id === next) {
					reached = true;
					updated[s.id] = 'active';
				} else if (!reached) {
					updated[s.id] = 'done';
				}
			}
			return updated;
		});
	};

	const finishAll = () => {
		setSteps({ wallet: 'done', publish: 'done', register: 'done', config: 'done' });
	};

	const handleDeploy = async () => {
		setRunning(true);
		setError('');
		setLogs([]);
		setCompletedConfigId(null);
		verboseLatchedRef.current = false;
		setSteps({ wallet: 'active', publish: 'pending', register: 'pending', config: 'pending' });
		const log = (msg: string) => setLogs((prev) => [...prev, msg]);
		try {
			log('Generating Ed25519 keypair...');
			const keypair = Ed25519Keypair.generate();
			const address = keypair.getPublicKey().toSuiAddress();
			const secretKey = keypair.getSecretKey();
			log(`Address: ${address}`);

			log('Requesting SUI from testnet faucet...');
			await requestSui(address);
			log('Faucet funded successfully.');

			advanceTo('publish');
			log('Loading pre-compiled Move bytecodes...');
			const bytecodes = await fetch('/bu_token_bytecodes.json').then((r) => r.json());
			log(`Loaded ${bytecodes.modules.length} modules.`);

			const client = getSuiClient();
			const tokenResult = await createTokenFromBytecodes(bytecodes, keypair, client, (msg) => {
				log(msg);
				if (msg.startsWith('Registering BU')) advanceTo('register');
				else if (msg.startsWith('Creating on-chain TokenConfig')) advanceTo('config');
			});

			const wallets = JSON.parse(localStorage.getItem('kaisho_issuer_wallets') || '{}');
			wallets[tokenResult.tokenConfigId] = {
				secretKey,
				address,
				auditorPrivateKey: tokenResult.auditorKeys[0].privateKey,
				auditorIndex: 0,
				denyCapId: tokenResult.denyCapId,
				managementCapId: tokenResult.managementCapId,
				confidentialTokenId: tokenResult.confidentialTokenId,
			};
			localStorage.setItem('kaisho_issuer_wallets', JSON.stringify(wallets));
			log('Deployment complete.');

			finishAll();
			// The TokenConfig object was just created on-chain; give the fullnode a
			// moment to index it before the next page tries to fetch it, otherwise
			// the ConfigHub load can race and 404.
			log('Waiting for created objects to be indexed...');
			await new Promise((resolve) => setTimeout(resolve, 2000));

			if (verboseLatchedRef.current) {
				setCompletedConfigId(tokenResult.tokenConfigId);
			} else {
				navigate(`/${tokenResult.tokenConfigId}`);
			}
		} catch (e) {
			log(`ERROR: ${e}`);
			setError(String(e));
		} finally {
			setRunning(false);
		}
	};

	return (
		<div className="flex flex-col gap-5">
			<div className="card card-shimmer card-tilt p-8 text-center">
				<h2 className="text-2xl font-bold tracking-tight text-white">Welcome to Kaisho</h2>
				<p className="mt-3 text-sm text-zinc-400 leading-relaxed">
					Confidential token transfers on Sui — balances and amounts hidden using homomorphic
					encryption and zero-knowledge proofs.
				</p>
				<p className="mt-3 text-sm text-zinc-400 leading-relaxed">
					This is a demo wallet that deploys and uses <strong className="text-white">BU</strong>{' '}
					tokens for confidential transfers. It is enabled only on Sui testnet, where it deploys
					fresh copies of BU and Contra for you to try it.
				</p>
			</div>

			{!running && !error && !completedConfigId && (
				<>
					<div className="card p-6">
						<p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
							What gets deployed
						</p>
						<ul className="mt-3 flex flex-col gap-3 text-xs text-zinc-400 leading-relaxed">
							<li className="flex gap-3">
								<span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent/10 text-[10px] font-bold text-accent">
									1
								</span>
								<span>
									<strong className="text-white">Contra Move contracts</strong> — the confidential
									transfer protocol.
								</span>
							</li>
							<li className="flex gap-3">
								<span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent/10 text-[10px] font-bold text-accent">
									2
								</span>
								<span>
									<strong className="text-white">BU test token</strong> — a sample fungible token
									registered under the protocol as a confidential token, with its own treasury and
									an auditor keypair.
								</span>
							</li>
							<li className="flex gap-3">
								<span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent/10 text-[10px] font-bold text-accent">
									3
								</span>
								<span>
									<strong className="text-white">Burner issuer wallet</strong> — a fresh Sui
									keypair, funded from the testnet faucet, kept only in this browser's localStorage.
								</span>
							</li>
						</ul>
					</div>

					<button
						className="btn-primary"
						onClick={handleDeploy}
						title="Generate a wallet, fund it, publish the Move contracts, and register BU"
					>
						Create Test Deployment
					</button>
				</>
			)}

			{(running || error || completedConfigId) && (
				<div className="card p-5">
					<p className="mb-4 text-[10px] font-semibold uppercase tracking-[0.15em] text-zinc-500">
						{error ? 'Failed' : completedConfigId ? 'Deployed' : 'Deploying...'}
					</p>
					<ul className="flex flex-col gap-3">
						{STEPS.map((step) => {
							const state = steps[step.id];
							return (
								<li key={step.id} className="flex items-start gap-3">
									<div className="mt-0.5">
										<StepIcon state={state} />
									</div>
									<div className="flex flex-col gap-1 min-w-0">
										<span
											className={`text-xs ${
												state === 'done'
													? 'text-zinc-300'
													: state === 'active'
														? 'text-white'
														: 'text-zinc-600'
											}`}
										>
											{step.label}
										</span>
										{state === 'active' && (
											<span className="text-[11px] text-zinc-500 leading-relaxed">
												{step.detail}
											</span>
										)}
									</div>
								</li>
							);
						})}
					</ul>
					{logs.length > 0 && (
						<div className="mt-4 border-t border-white/[0.04] pt-3">
							<button
								className="text-[11px] text-zinc-500 hover:text-zinc-300"
								onClick={() => {
									setShowVerbose((v) => {
										if (!v) verboseLatchedRef.current = true;
										return !v;
									});
								}}
								title="Toggle the raw deployment log"
							>
								{showVerbose ? '▼ Hide verbose output' : '▶ Show verbose output'}
							</button>
							{showVerbose && (
								<div className="mt-2 max-h-60 overflow-y-auto rounded-lg bg-black/50 px-3 py-2">
									{logs.map((line, i) => (
										<p
											key={i}
											className={`font-mono text-[11px] leading-relaxed ${
												line.startsWith('ERROR') ? 'text-red-400/80' : 'text-zinc-500'
											}`}
										>
											{line}
										</p>
									))}
									<div ref={logEndRef} />
								</div>
							)}
						</div>
					)}
					{error && (
						<>
							<p className="mt-4 break-all text-[11px] text-red-400/80">{error}</p>
							<button
								className="btn-primary mt-4 text-xs"
								onClick={handleDeploy}
								title="Retry the failed deployment"
							>
								Retry
							</button>
						</>
					)}
					{completedConfigId && (
						<button
							className="btn-primary mt-4 w-full text-xs"
							onClick={() => navigate(`/${completedConfigId}`)}
							title="Open the deployment hub"
						>
							Go to Deployment
						</button>
					)}
				</div>
			)}
		</div>
	);
}

function StepIcon({ state }: { state: StepState }) {
	if (state === 'done') {
		return (
			<div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent/20">
				<svg viewBox="0 0 20 20" className="h-3 w-3 text-accent" fill="currentColor">
					<path
						fillRule="evenodd"
						d="M16.7 5.3a1 1 0 010 1.4l-7 7a1 1 0 01-1.4 0l-4-4a1 1 0 011.4-1.4L9 11.6l6.3-6.3a1 1 0 011.4 0z"
					/>
				</svg>
			</div>
		);
	}
	if (state === 'active') {
		return (
			<div className="h-5 w-5 shrink-0 animate-spin rounded-full border-2 border-zinc-700 border-t-accent" />
		);
	}
	return <div className="h-5 w-5 shrink-0 rounded-full border-2 border-zinc-800" />;
}
