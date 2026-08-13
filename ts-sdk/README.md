# ts-sdk

TypeScript SDK for the project.

## Prerequisites

The WASM bindings, built first — see [`utils/bulletproofs-wasm`](../utils/bulletproofs-wasm/README.md). `pnpm install` packs that package as a `file:` dependency, so on a fresh checkout run its `pnpm build:wasm` **before** installing here, and re-run `pnpm install --force` here after rebuilding it.

## Build

```bash
pnpm install
pnpm build
```

Apps in this repo consume the built `dist/`, so rebuild after any change to `src/`.

## Test

```bash
pnpm test             # unit tests
pnpm test:e2e         # e2e tests against devnet (needs the sui CLI and faucet access)
pnpm vitest <filter>  # a specific test by name/path
```

## Codegen

```bash
pnpm codegen
```

Regenerates the BCS schemas in `src/contracts/` from the Move sources (requires the `sui` CLI). Run after any Move struct change; never hand-edit those files.
