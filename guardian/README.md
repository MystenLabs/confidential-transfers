# Guardian enclave service

The Guardian runs as a fleet of Nitro Enclaves behind a single Envoy proxy. Each
enclave generates its own encryption and signing keys at boot and becomes
eligible for traffic only after those keys are attested and registered on chain.
The proxy exposes the request-processing endpoint, load-balances across the
registered fleet, and retries another enclave when the selected instance cannot
open a request.

## Fleet operations

Guardian setup is intentionally split between the issuer and operator. The issuer
publishes the package, creates a `Guardian<T>`, and appoints an operator. The
operator deploys and registers the fleet. Only after that succeeds does the issuer
enable the Guardian for the confidential token.

### 1. Issuer: publish and create

The active Sui address must control the token's `ManagementCap<T>`. The Guardian
Move package must depend on the intended published Contra package.

The scripts use `contra-guardian-cli`, which builds and submits transactions
through `sui-rust-sdk`. By default they run it with Cargo and read the standard
`~/.sui/sui_config/client.yaml` wallet. Set `GUARDIAN_CLI` to a prebuilt binary;
`SUI_WALLET`, `SUI_ACTIVE_ADDRESS`, and `SUI_RPC_URL` override wallet selection.
The `sui` executable is not required.

```sh
# Optional when the Guardian package has not been published yet. Prints
# GUARDIAN_PACKAGE_ID for the remaining commands.
guardian/scripts/publish-guardian.sh <guardian-move-package-path> [build-environment]

export GUARDIAN_PACKAGE_ID=0x...
export MANAGEMENT_CAP_ID=0x...
export TOKEN_TYPE=0x...::coin::COIN

# Prints GUARDIAN_ID. PCR arguments are hexadecimal bytes, with or without 0x.
guardian/scripts/create-guardian.sh \
  <pcr0-hex> <pcr1-hex> <pcr2-hex> <operator-address>
export GUARDIAN_ID=0x...
```

Creation does not enable authority checks, so ordinary Contra operations continue
while the operator brings up the service.

### 2. Operator: deploy and register the fleet

The active Sui address must be the operator stored in the Guardian. These scripts
provision infrastructure through `joy/contra-guardian-dev` in `sui-operations`,
register each enclave's attested keys on chain, and only then open that enclave's
readiness gate.

Run the scripts from the repository root. Required environment:

```sh
export GUARDIAN_PACKAGE_ID=0x...
export GUARDIAN_ID=0x...
export TOKEN_TYPE=0x...::coin::COIN
```

Optional configuration and defaults:

```sh
export SUI_OPERATIONS_DIR=/path/to/sui-operations # ../sui-operations
export PULUMI_ORG=mysten
export PULUMI_STACK=devnet
export AWS_REGION=us-west-2
export SUI_GAS_BUDGET=100000000
# Optional: avoid `cargo run` on each invocation.
export GUARDIAN_CLI=/path/to/contra-guardian-cli
# Optional wallet/config overrides.
export SUI_WALLET=/path/to/client.yaml
export SUI_ACTIVE_ADDRESS=0x...
export SUI_RPC_URL=https://fullnode.devnet.sui.io:443
```

Bootstrap a fleet with an explicit size and full, pushed commit containing the
EIF sources. The host checks out that immutable revision before building:

```sh
guardian/scripts/bootstrap.sh <count> <contra-commit>
```

`bootstrap.sh` deploys and registers the enclave fleet, deploys the proxy, sets
the Guardian's on-chain URL, and prints the URL when the fleet is ready.

Converge it to an absolute size between 1 and 16, using the requested enclave
revision for any replacement or newly created hosts:

```sh
guardian/scripts/scale.sh <count> <contra-commit>
```

Scale-up registers new keys before refreshing Envoy's static endpoint list.
Scale-down stops routing to departing instances and removes their on-chain keys
before Pulumi destroys them. If an enclave restarts on an existing host,
running `guardian/scripts/register.sh <instance-id>` removes its prior tagged
key and registers the replacement.

### 3. Issuer: verify and enable

After `bootstrap.sh` succeeds, send an encrypted approval request through the
published Guardian URL and verify its signature before enabling it. Then use the
issuer-controlled address:

```sh
export CONFIDENTIAL_TOKEN_ID=0x...
guardian/scripts/enable-guardian.sh
```

Disable Guardian without deleting its object or fleet:

```sh
export CONTRA_PACKAGE_ID=0x...
guardian/scripts/disable-guardian.sh
```

Update PCRs, minimum version, or operator address:

```sh
guardian/scripts/update-guardian.sh \
  <pcr0-hex> <pcr1-hex> <pcr2-hex> <min-version> <operator-address>
```

Changing PCRs increments the Guardian version. Raising `min-version` removes
registered enclave keys from older versions; changing only the operator does not
remove existing keys.
