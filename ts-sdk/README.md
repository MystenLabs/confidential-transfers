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

## Guardian approvals

Configure a `GuardianClient` with the Guardian package and object selected for the token, then pass
it to a protected transfer or unwrap. The client reads the current service URL and enclave keys from
the Guardian object, obtains and verifies an enclave signature, and adds the resulting approval to
the same transaction as the Contra operation.

```ts
import { GuardianClient } from 'ts-sdk';

const guardian = new GuardianClient({
	suiClient,
	packageId: guardianPackageId,
	guardianId,
});

const transfer = await contraClient.transfer({
	tokenAccount,
	receiverAddress,
	amount: 100n,
	guardian,
});
tx.add(transfer);
```

## Test

```bash
pnpm test             # unit tests
pnpm test:e2e         # e2e tests against devnet (needs the sui CLI and faucet access)
pnpm vitest <filter>  # a specific test by name/path
```

The live Guardian test is opt-in. It creates two funded devnet accounts, mints and wraps the test
token, then executes and verifies a Guardian-authorized transfer and unwrap on chain:

```bash
GUARDIAN_E2E_ID=<guardian-object-id> \
GUARDIAN_E2E_PACKAGE_ID=<guardian-package-id> \
GUARDIAN_E2E_CONTRA_PACKAGE_ID=<contra-package-id> \
GUARDIAN_E2E_ACCOUNT_REGISTRY_ID=<account-registry-id> \
GUARDIAN_E2E_TOKEN_REGISTRY_ID=<token-registry-id> \
GUARDIAN_E2E_TOKEN_TYPE=<test-token-type> \
GUARDIAN_E2E_TREASURY_ID=<permissionless-test-treasury-id> \
pnpm vitest run test/e2e/guardian.test.ts
```

## Codegen

```bash
pnpm codegen
```

Regenerates the BCS schemas in `src/contracts/` from the Move sources (requires the `sui` CLI). Run after any Move struct change; never hand-edit those files.
