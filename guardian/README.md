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
  separation, as they come other components of the confidential transfer system. 

On-chain counterpart: `../move/sources/guardian.move`.

## Registration

- The token holds `Option<GuardianPolicy>`: `Some` enables the guardian, `None`
  disables it — no `enabled` flag needed.
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

- **Offchain option: provision the fleet of enclaves to the same pk**
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
- **Onchain option: each enclave registers with attestation against `policy.pcrs` and
  adds its own `{ enc_pk, signing_pk }` to the policy**
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
- Scale up / down never involves the issuer: the operator registers a booting
  instance's key (stamped with the current `policy.version`) and removes keys at
  leisure — a dead instance's key can never sign again, so removal is hygiene, not
  security.
- Image updates (PCR changes — often routine dependency bumps): `update_pcrs` bumps
  `policy.version` and only affects *new* registrations; existing keys stay valid, and
  it is up to the issuer which keys to keep:
  - **Routine upgrade**: `update_pcrs`, register the new fleet, let both images serve
    while the old fleet drains, remove old keys when convenient. `min_version` never
    moves; in-flight approvals survive and there is no downtime — `update_pcrs` is
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

- Alice calls the enclave with the request encrypted under all `enc_pk`s. Ciphertexts
  are collapses of the onchain 4-limb structures.

```
{
  pk_B[],
  enc_bal_A_old: (C_1_A, C_2_A),
  enc_bal_A_new: (C_1_A_new, C_2_A_new),
  enc_tx_amt[]: (C_1_tx_i, C_2_tx_i),

  // private witnesses
  x_A,           // opens both balances, whose blindings are unknowable
  bal_A_old,     // the plaintext m is sent so the enclave never solves a discrete log
  tx_amount[],
  r_tx[]         // proves each enc_tx_amt[i] well-formed to pk_B[i]
}
```

- Enclave checks conditions and signs the payload:

```
derive pk_A = x_A * G

check enc_bal_A_old opening:
  C_1_A - C_2_A / x_A == bal_A_old*H

for each recipient i:
  check enc_tx_amt[i] == (r_tx[i]*G + tx_amount[i]*H,  r_tx[i]*pk_B_i)

compute bal_A_new = bal_A_old - sum of tx_amount[i]
check bal_A_new >= 0
check C_1_A_new - C_2_A_new / x_A == bal_A_new*H

enclave signs payload (an enum; the variant tag separates transfers from unwraps):

Transfer {
  pk_A,
  pk_B[],
  enc_bal_A_old,
  enc_bal_A_new,
  enc_tx_amt[]
}

Unwrap {
  pk_A,
  enc_bal_A_old,
  enc_bal_A_new,
  amount
}
```

- Returns `{ enclave_sig, signing_pk }`.
- Wallet sends onchain:

```move
fun batch_transfer(..., guardian_sig, signing_pk) {
  if (ct.guardian_policy.is_none()) return;   // guardian off: ZK proofs only
  let policy = ct.guardian_policy.borrow();
  let key = policy.guardian_enclave_keys.get(&signing_pk); // aborts if unknown
  assert!(key.version >= policy.min_version);
  let payload = { ... }; // rebuilt onchain, never passed
  assert!(ed25519_verify(&guardian_sig, &signing_pk, &bcs::to_bytes(payload)));
}
```

Approvals are single-use: they bind `enc_bal_A_old`, which every transfer overwrites —
valid exactly until the sender's active balance changes, no TTL needed. (Deposits land
in `pending`, so they don't invalidate an in-flight approval.)

## DDoS protection for enclave

- Basic per-IP rate limiting at the edge (e.g. Cloudflare) is enough: per-request
  enclave work is a few scalar mults.

## Code layout

- `core/` — wire types, plaintext checks, approval signing. No Nitro, no networking.
- `enclave/` — the binary: key generation at boot, `/attestation`, `/health` +
  `/ready`, and `/approve` for sealed requests.

Deployment lives in `sui-operations` (`contra-guardian-enclave`, and
`contra-guardian-proxy` for the ALB + Envoy config). There is no proxy crate here:
routing is round robin plus a retry when an instance answers 422 ("not a recipient"),
which is Envoy config, not app logic.

## Test

```
cargo test --workspace --no-default-features --features contra-guardian-enclave/non-enclave-dev
```

`--features non-enclave-dev` stubs the NSM attestation call so the guardian runs
outside an enclave; everything else — HPKE unseal, checks, signing — is the
production path, and the binary warns once so a dev build is never mistaken for a
real enclave. `enclave/tests/e2e.rs` serves a guardian in-process and verifies each
approval against the payload the chain would rebuild.

## Local fleet

`scripts/` drives a local fleet against a localnet, mirroring what the deploy
workflow does in production. Set `PACKAGE_ID`, `TOKEN_ID`, `TOKEN_TYPE` (plus
`CAP_ID` for bootstrap); the active sui address must be the policy's operator.

```
./scripts/bootstrap.sh     # set the policy, start + register instance 1
./scripts/scale.sh 2       # add 2 more instances (issuer not involved)
./scripts/remove.sh 3002   # remove a key on chain, then stop the process
```

State lives in `.fleet/`. Registration uses `contra::register_guardian_enclave_for_dev`
because a mock attestation cannot pass `sui::nitro_attestation`; everything after
registration is the production path.
