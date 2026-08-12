# Guardian

The Guardian is an off-chain service running in an attested TEE (using the
[Nautilus](https://docs.sui.io/concepts/cryptography/nautilus) pattern) that acts as a
second factor for confidential transfers and unwraps. When enabled by the issuer, a
transfer or unwrap checks:

1. [Unchanged] The existing zero-knowledge proofs onchain.
2. A registered enclave attesting that it independently re-checked the transfer
   arithmetic in plaintext. The enclave signature is verified onchain.

## Goals

- **Soundness.** A bug in the proof layer (verifier / Fiat–Shamir / range-proof bug)
  lets an attacker mint hidden value and nobody can observe it until unwrap time. The
  Guardian re-checks the plaintext arithmetic inside a TEE, so an attack requires
  breaking both the ZK layer and AWS Nitro isolation.
- **Not required for liveness.** The enclave holds no funds and no user state. If the
  fleet disappears, the issuer can disable guardian mode.
- **The enclave only checks the math.** There is no replay/expiry protection or domain
  separation, as they come from other components of the confidential transfer system.

On-chain counterpart: `../move/sources/guardian.move`.

## Registration

- The token holds `Option<GuardianPolicy>`: `Some` enables the guardian, `None`
  disables it.
- Issuer (`ManagementCap`) sets / unsets the policy, and updates it in one call —
  each of `pcrs` / `min_version` / `operator` is an `Option`, `None` a no-op.
- The operator (a single address) runs one serving endpoint (`url`) backed by
  multiple enclave instances, each holding its own `{ signing_pk, enc_pk }` pair
  generated inside the enclave. The operator registers and removes these
  `guardian_enclave_keys` and updates `url`.

```move
GuardianPolicy {
  operator: address,        // registers / removes keys and updates url; issuer can replace
  url: String,              // the one endpoint fronting the whole fleet; operator-updated,
                            // routing metadata only (nothing security-relevant)
  version: u16,             // incremented per PCR change; stamps new registrations
  min_version: u16,         // issuer bumps this to invalidate old-image keys lazily;
                            // guardian_enclave_keys is never cleared
  pcrs: Pcrs,               // (pcr0, pcr1, pcr2): image, kernel, application
  guardian_enclave_keys: VecMap<Ed25519PublicKey, GuardianEnclaveKey>,
}

GuardianEnclaveKey {
  signing_pk: Ed25519PublicKey,
  enc_pk: X25519PublicKey,
  version: u16,             // policy version at registration; valid while >= min_version
}
```

- Entry points: `set_guardian_policy(pcrs, operator, url)` / `unset_guardian_policy()` /
  `update_guardian_policy(pcrs?, min_version?, operator?)` for the issuer;
  `register_guardian_enclave(attestation)` / `remove_guardian_enclave(signing_pk)` /
  `set_guardian_url(url)` for the operator. The attestation's `user_data` is
  `signing_pk || enc_pk`, 32 bytes each.

## Enclave Scaling

Each enclave holds its own keys, generated inside the enclave.

- A booting instance exposes `/attestation`; the operator registers its keys
  (stamped with the current `policy.version`) and removes keys at leisure — a
  dead instance's key can never sign again, so removal is hygiene, not security.
- Clients seal each request to every registered `enc_pk`. The proxy round-robins;
  an instance that is not among the request's recipients answers 422 and the
  proxy retries the next host.
- Onchain, an approval is `{ signing_pk, signature }`: look the key up, verify
  the signature, require `key.version >= policy.min_version`.

(A shared-key design — one `enc_pk` provisioned to the whole fleet — was
considered and rejected: it would reintroduce key distribution, ceremony, and a
sealed-secrets channel, and weaken what attestation proves.)

## Transfer Flow

- Alice posts a BCS `SealedRequest` — a version byte plus the `UnsealedRequest` below,
  HPKE-sealed once per live `enc_pk`. Ciphertexts are collapses of the onchain 4-limb
  structures.

```
{
  old_encrypted_balance: (C_1_A, C_2_A),
  new_encrypted_balance: (C_1_A_new, C_2_A_new),
  recipients[]: {
    receiver_pk,
    encrypted_amount: (C_1_tx_i, C_2_tx_i),
    // private witnesses
    amount,
    blinding       // proves encrypted_amount well-formed to receiver_pk
  },

  // private witnesses
  x_a,             // opens both balances, whose blindings are unknowable
  old_balance      // sent so the enclave never solves a discrete log
}
```

- Enclave checks conditions and signs the payload:

```
derive sender_pk = x_a * G

checks, cheapest first:

total_txn_amount = sum of recipients[i].amount           // checked u64 add
new_balance = old_balance - total_txn_amount
  an overflow or underflow in either is an overdraft, caught with no curve operations

check old_encrypted_balance opens to old_balance under x_a
check new_encrypted_balance opens to new_balance under x_a
  (Ciphertext::verify_opening, two operations whatever the batch size)

for each recipient i:
  check recipients[i].encrypted_amount encrypts .amount to .receiver_pk under .blinding
  (Ciphertext::verify)

enclave signs `RequestPayload` (an enum; the variant tag separates transfers from unwraps):

Transfer {
  sender_pk,
  receiver_pks[],
  old_encrypted_balance,
  new_encrypted_balance,
  encrypted_amounts[]
}

Unwrap {
  sender_pk,
  old_encrypted_balance,
  new_encrypted_balance,
  amount
}
```

- Returns an `EnclaveResponse`: `{ signing_pk, signature }` on success, or a
  `{ error }` naming the failed check.
- Wallet sends onchain:

```move
fun batched_transfer(..., approval: Option<GuardianApproval>) { // { signing_pk, signature }
  if (ct.guardian_policy.is_none()) return;   // guardian off: ZK proofs only
  let policy = ct.guardian_policy.borrow();
  let key = policy.guardian_enclave_keys.get(&approval.signing_pk); // aborts if unknown
  assert!(key.version >= policy.min_version);
  let payload = { ... }; // RequestPayload, rebuilt onchain, never passed
  assert!(ed25519_verify(&approval.signature, &approval.signing_pk, &bcs::to_bytes(payload)));
}
```

A signed request is single-use: it binds `old_encrypted_balance`, which every transfer
overwrites —
valid exactly until the sender's active balance changes, no TTL needed. (Deposits land
in `pending`, so they don't invalidate an in-flight signed request.)

## Code layout

- `core/` — wire types, plaintext checks, HPKE sealing, keys, and response signing.
- `enclave/` — the binary: `/attestation`, `/registered` (GET gates the proxy, POST marks it), and `/process_request` for
  sealed requests.
- `docker/` — the reproducible EIF build (`make GIT_REVISION=<commit>`), always
  the real NSM-attesting enclave, consumed by the deploy stacks' user-data and
  by the release flow (see Operations).

Deployment lives in `sui-operations` (`contra-guardian-enclave`, and
`contra-guardian-proxy` for the ALB + Envoy config). Routing is round robin plus
retry-on-422, and a WAF per-IP rate limit at the ALB is enough DDoS protection —
per-request enclave work is a few scalar mults.
Devnet runs the real NSM build under `--debug-mode`: attestation documents are
genuinely signed but every PCR reads all-zero, so the policy pins zero PCRs once
and iteration only ever re-registers fresh keys; testnet+ pins real CI-built
measurements. The `non-enclave-dev` mock below is for machines with no NSM at all.

## Operations

Who signs what: the issuer (`ManagementCap`) changes trust — PCRs, `min_version`,
operator; the operator changes the fleet — instances and registered keys. All
operator flows are one workflow, `sui-operations/.github/workflows/contra-guardian-scale.yaml`,
which converges the fleet to `count` and the onchain key set to "keys held by
live enclaves": removes departing keys before shrinking, registers anything at
gate 503, and sweeps orphaned keys (a restarted enclave re-registers fresh; its
old key is deleted by the sweep).

- **Release**: bumping the workspace cargo version on main tags `v<version>`
  with the EIF + PCRs (`.github/workflows/guardian-release.yml`, verifiable by
  rebuilding the tag). Issuer pins the PCRs (`contra-guardian-update-pcrs.yaml`
  assembles the unsigned tx); operator rolls the fleet
  (`contra-guardian-scale.yaml`, `contra_commit: v<version>` — in-place today,
  so guarded transfers pause until re-registration). Pinning PCRs auto-bumps
  `version` and only affects new registrations, so a routine upgrade leaves old
  keys valid (both images serve; rollback = remove the new keys); a security fix
  additionally raises `min_version` — after the new fleet registers — killing
  every old-image signature at that instant, with no keyless window.
- **Scale up / down / recover**: dispatch scale with the desired `count`.
  Recovery from any drift is the same dispatch at the current count.
- **Bootstrap / devnet regenesis** (issuer + operator, manual today): publish +
  register the token (`scripts/issuer_setup.sh`), `set_guardian_policy`, then
  register each instance.
- **Monitoring**: `contra-guardian-monitor.yaml` scans every ~10 min — per-instance
  gate over SSM plus the public endpoint — and posts problems to Slack; recovery
  is a scale dispatch at the current count.
- **Not built yet**: blue-green rolls (`min_version` already permits the mixed
  fleet), a regenesis workflow.

Registration itself is one shared subflow — fetch `/attestation`, submit the
register tx, `POST /registered`, strictly in that order (the gate opens last so
Envoy only routes to keys the chain accepts). `scripts/register.sh` is the
canonical implementation (local fleet, manual SSM); the scale workflow inlines
the same steps over SSM `send-command` and adds the tagging the sweep reads.

## Test

```
cargo test --workspace --all-features   # or: --features contra-guardian-enclave/non-enclave-dev
cargo fmt && cargo xclippy              # lint
```

`non-enclave-dev` stubs the NSM attestation call so the guardian runs outside an
enclave; everything else — HPKE unseal, checks, signing — is the production path.
`enclave/tests/e2e.rs` serves a guardian in-process and verifies each response
against the signed payload.

## Local fleet

`scripts/` runs an e2e test against localnet with: issuer setup, a registered fleet, 
the production Envoy routing, and a wallet that submits the payload onchain.

Registration goes through `scripts/register.sh` — shared with the AWS deploy, where
operators run it as `HOST=<instance>:3000 ./register.sh`. It detects the document
shape: dev builds serve raw keys (`register_guardian_enclave_for_dev`), real
enclaves a signed document (`register_guardian_enclave` via `0x2::nitro_attestation`).

Prerequisites: `sui` (devnet toolchain), `jq`, and `envoy` (`brew install envoy`).

Terminal 1 — localnet (leave running; regenesis wipes prior publications):

```
sui start --with-faucet --force-regenesis
```

Terminal 2 — point the client at it and fund the active address:

```
sui client switch --env local
```

```
sui client faucet
```

Issuer setup: publishes contra + the BU test token (an ephemeral `test-publish`
with a per-run pubfile) and registers BU as a confidential token; IDs are added 
in `guardian/.fleet/issuer.env` after run:

```
./guardian/scripts/issuer_setup.sh
```

```
source guardian/.fleet/issuer.env
```

Fleet: `bootstrap` sets the guardian policy (issuer) and starts + registers
instance 1 (operator); `scale` adds more. The first start compiles the enclave
crate:

```
./guardian/scripts/bootstrap.sh
```

```
./guardian/scripts/scale.sh 2
```

Terminal 3 — Envoy on :8080 with the production routing (`/process_request` only, round
robin, retry-on-422, `GET /registered`-gated):

```
./guardian/scripts/proxy.sh
```

Terminal 2: the wallet reads the token's url and every registered `enc_pk`, it seals one
envelope per key, POSTs the BCS `SealedRequest` through Envoy, then builds and submits
a PTB, and the guardian approval response is verified onchain via `contra::verify_transfer_approval_for_dev`.

```
cargo run -p contra-guardian-enclave --example process_request --no-default-features --features non-enclave-dev
```

Teardown: `./guardian/scripts/remove.sh <port>` per instance (chain first, then
the process), Ctrl-C Envoy and the localnet, and `rm -rf guardian/.fleet` for a
clean slate.