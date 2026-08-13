# Kaisho

Example wallet app. See the [top-level README](../../README.md) for what it does.

## Prerequisites

- Node.js 20+
- pnpm 10+
- [Sui CLI](https://docs.sui.io/guides/developer/getting-started/sui-install) (for local development only)

## Setup

On a fresh checkout, build the WASM bindings first — see
[`utils/bulletproofs-wasm`](../../utils/bulletproofs-wasm/README.md) — since
`ts-sdk` packs them at install time.

```bash
# From the repo root, build the ts-sdk first
cd ts-sdk
pnpm install
pnpm build

# Then install app dependencies
cd ../apps/kaisho
pnpm install
```

## Development

```bash
pnpm dev
```

This compiles the Move bytecodes from source (requires `sui` CLI) and starts the Vite dev server at `http://127.0.0.1:5173`.

To recompile the Move bytecodes without restarting the server:

```bash
pnpm compile-move
```

## Production Build

```bash
pnpm build
```

The production build uses the pre-compiled `public/bu_token_bytecodes.json` (committed to the repo) and does not require the `sui` CLI. This is what Vercel runs.

When any Move source changes -- in either `apps/kaisho/move/bu_token` or the top-level `move/` package (which is bundled in alongside the BU token) -- run `pnpm compile-move` locally and commit the updated `public/bu_token_bytecodes.json`.
