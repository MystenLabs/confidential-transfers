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

- **Onchain option (implemented): each enclave registers with attestation against
  `policy.pcrs` and adds its own `{ enc_pk, signing_pk }` to the policy**
  - Client fetches all live `enc_pk`s onchain and encrypts the request to all keys;
    the LB forwards it to an instance and gets a response identified by `signing_pk`.
  - Onchain the client submits `enclave_sig, signing_pk`. Checks: 1) look up
    `signing_pk` in `guardian_enclave_keys`, 2) verify the sig, 3)
    `key.version >= policy.min_version`.
  - Provision new instances:
    - Each instance deploys and exposes `/attestation`.
    - Registers with its own `{ enc_pk, signing_pk }`.
  - Rotate keys:
    - Boot a new instance with its own keys; add it to the LB (if the LB routes a
      request to it early, it just fails and round-robins to the next).
    - One PTB: remove the old key + register the new key.
    - LB terminates the old instance.
  - Proxy:
    - Simple round robin: if a request (encrypted under a set of pks) is forwarded to
      a freshly registered instance not in that set, the instance returns failure and
      the LB tries the next.
    - Recipient-aware: only forward to instances whose key the request is encrypted
      under.
- **Offchain option (design alternative, not implemented): provision the fleet of
  enclaves to the same pk**
  - Client sends the request encrypted under the single `enc_key`.
  - Onchain the client submits `enclave_sig` only. Checks: 1) `enclave_sig` verifies
    against `enclave.active.signing_pk`, 2) `enclave.version >= policy.min_version`.
  - Provision new instances:
    - Primary:
      - One primary enclave generates fresh `{ enc_key, signing_key }`.
      - Registers onchain an enclave object
        `{ url, active: (enc_pk, signing_pk), standby: None }`, its attestation
        verified against the policy PCRs.
    - Scale up:
      - A child instance spins up in `pending_provisioning` mode and exposes
        `/provision_attestation`.
      - The primary calls the child's `/provision_attestation`, verifies the PCRs, and
        parses `provision_pk`.
      - The primary calls the child's `/provision` with `{ enc_key, signing_key }`
        encrypted under `provision_pk`.
      - The child boots with `{ enc_key, signing_key }`, enters ready mode, and serves
        traffic; the LB sends traffic to ready instances only.
  - Remove instance: drop it from the LB.
  - Rotate keys:
    - Boot a new primary with `{ new_enc_key, new_signing_key }`.
    - Update onchain `{ active: (new_enc_pk, new_signing_pk),
      standby: (enc_pk, signing_pk) }`.
    - All requests try to verify with the active pk first, then the standby.
    - Provision new child instances the same way.
    - Safe to remove the standby onchain once the old fleet drains.
  - Proxy: simple round robin.
- Scale up / down never involves the issuer: the operator registers a booting
  instance's key (stamped with the current `policy.version`) and removes keys at
  leisure — a dead instance's key can never sign again, so removal is hygiene, not
  security.
- Image updates (PCR changes — often routine dependency bumps): `update_pcrs` bumps
  `policy.version` and only affects *new* registrations; existing keys stay valid, and
  it is up to the issuer which keys to keep:
  - **Routine upgrade**: `update_pcrs`, register the new fleet, let both images serve
    while the old fleet drains, remove old keys when convenient. `min_version` never
    moves; in-flight signed requests survive and there is no downtime — `update_pcrs` is
    not a revocation, so the old fleet serves until the new one is registered.
  - **Security fix**: bump `min_version` in the same PTB as the new registrations —
    every old-image signature dies at that instant; clients retry, but there is no
    keyless window. Bundling the bump matters twice over: registering first avoids
    downtime, and lazy invalidation fails open if a security revocation is left "for
    later".
  - The grace window is closed-membership: after `update_pcrs` the old image can no
    longer register keys, so the set of grace keys only shrinks.
  - Rollback is free: old keys were never invalidated, so if the new image is broken,
    remove its keys and keep serving on the old fleet.
  - `min_version` is a floor (revoke everything older than X); revoking one specific
    version while keeping older ones is per-key `remove_guardian_enclave` instead.

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

## DDoS protection for enclave

- Basic per-IP rate limiting at the edge (e.g. Cloudflare) is enough: per-request
  enclave work is a few scalar mults.

## Code layout

- `core/` — wire types, plaintext checks, HPKE sealing, keys, and response signing.
- `enclave/` — the binary: `/attestation`, `/registered` (GET gates the proxy, POST marks it), and `/process_request` for
  sealed requests.
- `docker/` — the reproducible EIF build (`make GIT_REVISION=<commit>
  [FEATURES=non-enclave-dev]`), consumed by the deploy stacks' user-data.

Deployment lives in `sui-operations` (`contra-guardian-enclave`, and
`contra-guardian-proxy` for the ALB + Envoy config). Routing is round robin plus a
retry when an instance answers 422 ("not a recipient"), configured in Envoy.

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

`scripts/` runs a e2e test against localnet with: issuer setup, a registered fleet, 
the production Envoy routing, and a wallet that submits the payload onchain.

Registration uses `contra::register_guardian_enclave_for_dev` for any passed keys without the attestation file.

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