// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState } from 'react';

interface AnimatedNumberProps {
	value: number;
	className?: string;
	/** Duration in ms (default 600) */
	duration?: number;
}

export function AnimatedNumber({ value, className, duration = 600 }: AnimatedNumberProps) {
	const [display, setDisplay] = useState(value);
	const prevRef = useRef(value);
	const rafRef = useRef<number | undefined>(undefined);

	useEffect(() => {
		const from = prevRef.current;
		const to = value;
		if (from === to) return;

		const start = performance.now();
		const animate = (now: number) => {
			const elapsed = now - start;
			const progress = Math.min(elapsed / duration, 1);
			// ease-out cubic
			const eased = 1 - Math.pow(1 - progress, 3);
			setDisplay(from + (to - from) * eased);
			if (progress < 1) {
				rafRef.current = requestAnimationFrame(animate);
			} else {
				prevRef.current = to;
			}
		};
		rafRef.current = requestAnimationFrame(animate);
		return () => {
			if (rafRef.current) cancelAnimationFrame(rafRef.current);
		};
	}, [value, duration]);

	// Format: show up to 4 decimal places, trim trailing zeros
	const formatted = display === 0 ? '0' : parseFloat(display.toFixed(4)).toString();

	return <span className={className}>{formatted}</span>;
}
