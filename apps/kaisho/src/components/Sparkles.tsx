// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from 'react';

interface Particle {
	id: number;
	x: number;
	y: number;
	size: number;
	delay: number;
	color: string;
}

const COLORS = ['#60a5fa', '#818cf8', '#34d399', '#fbbf24', '#f472b6'];

export function Sparkles({ count = 12 }: { count?: number }) {
	const [particles, setParticles] = useState<Particle[]>([]);

	useEffect(() => {
		const p: Particle[] = Array.from({ length: count }, (_, i) => ({
			id: i,
			x: Math.random() * 100,
			y: Math.random() * 100,
			size: 3 + Math.random() * 5,
			delay: Math.random() * 0.4,
			color: COLORS[Math.floor(Math.random() * COLORS.length)],
		}));
		setParticles(p);
	}, [count]);

	return (
		<div className="sparkle-container" aria-hidden="true">
			{particles.map((p) => (
				<div
					key={p.id}
					className="sparkle-particle"
					style={{
						left: `${p.x}%`,
						top: `${p.y}%`,
						width: p.size,
						height: p.size,
						background: p.color,
						animationDelay: `${p.delay}s`,
					}}
				/>
			))}
		</div>
	);
}
