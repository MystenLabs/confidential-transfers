// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import react from '@vitejs/plugin-react-swc';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [react()],
	// The fastcrypto WASM bindings (`@contra/bulletproofs-wasm`, pulled in by
	// ts-sdk) ship a modern wasm-pack `web` build. Bump the target past Vite's
	// default for both the prod build and esbuild's dev pre-bundling so its
	// output passes through instead of erroring on newer syntax.
	build: {
		target: 'es2022',
	},
	// tableWorker dynamically imports ts-sdk, producing a split chunk that
	// Vite's default IIFE worker output can't represent. Emit workers as
	// ES modules instead — the worker is already created with
	// `{ type: 'module' }` so the browser loads it the same way.
	worker: {
		format: 'es',
	},
	optimizeDeps: {
		// `@contra/bulletproofs-wasm`'s `web` build locates its `.wasm` via
		// `new URL('...wasm', import.meta.url)`. Esbuild's prebundle drops that
		// asset reference, so keep ts-sdk and the wasm package out of the
		// prebundle and let Vite serve the `.wasm` directly via fs.allow below.
		exclude: ['ts-sdk', '@contra/bulletproofs-wasm'],
		esbuildOptions: { target: 'es2022' },
	},
	server: {
		host: '127.0.0.1',
		port: 5173,
		fs: {
			// Allow Vite to serve files from the workspace packages that live
			// outside the kaisho app root: ts-sdk and the
			// `utils/bulletproofs-wasm/` package (whose `web/*.wasm` is loaded
			// at runtime). `../..` is the repo root.
			allow: ['../..'],
		},
	},
});
