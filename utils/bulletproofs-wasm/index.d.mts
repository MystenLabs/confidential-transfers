// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Type declarations for the Node.js entry points (index.mjs / index.js).
// The wasm-pack `nodejs` build loads synchronously, so no async init is
// required; the no-op `init` accepts (and ignores) the browser entry's
// options for API parity.
export * from './nodejs/contra_bulletproofs_wasm.js';
export default function init(options?: { module_or_path?: unknown }): void;
