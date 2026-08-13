# Auditor Support in Confidential Transfers

Confidential transfer protocols can let designated **auditors** decrypt user activity off-chain for compliance and oversight. Auditors are passive readers: they hold one or more secret keys whose public counterparts are registered on-chain, and never sign protocol transactions.

This document covers two options for implementing that.

## Option 1: Per-transfer (implemented)

### On-chain logic
The token issuer registers one or more auditor public keys on-chain. **Every** confidential transfer then carries an additional ciphertext of the transfer amount, encrypted under each auditor public key. A zero-knowledge proof attests that the auditor ciphertext encrypts the same amount as the sender and recipient ciphertexts, so the auditor's view cannot diverge from what actually moved on-chain.

User balances are encrypted only under the user's own key. Per-transfer overhead is proportional to the number of auditors: for `n` auditor keys, each transfer carries `n` extra ciphertexts and a ZK proof.


What an auditor sees directly from the chain:

- The amount of every transfer that occurred while their key was installed.
- The full amount of every wrap and unwrap (already public on-chain).
- Sender and recipient addresses for every transaction (already public on-chain).


### Off-chain logic
Auditors do not read balances directly; they reconstruct each account's running balance by aggregating the per-transfer amounts they decrypt. Reading is therefore **stateful**: the auditor maintains a running view of the transfer graph rather than answering balance queries from a single chain read. Transfers that occurred before the auditor key was registered remain opaque unless the auditor obtains the previous auditor set's secret keys and replays history from the chain.

### Possible deployment

- **Onboarding a new auditor.** The auditor generates a keypair off-chain and the issuer registers the public key on-chain. From that point users encrypt transfers under the new key. The new auditor does not gain visibility into pre-existing transfers; to read history, they receive the previous auditor set's secret keys to replay from the chain.
- **Auditor key rotation.** The auditor generates a new keypair and the issuer publishes the new public key on-chain. Optionally, the rotation may use a grace period during which both the old and new keys are accepted, so transfers in flight under the old key still validate. After the grace period, only the new key is accepted.
- **Auditor offboarding.** The offboarded key is removed from the on-chain registry and users stop encrypting under it. The offboarded auditor cannot decrypt any transfer that occurs after offboarding; earlier transfers remain readable to them with the keys they retained.
- **Auditor key leakage.** Anyone who obtains an auditor's secret keys can decrypt every transfer encrypted under those keys. Transfers under earlier or later auditor keys remain opaque to them.


## Option 2: Per-account

### On-chain logic

The token issuer registers one or more auditor public keys on-chain. When a user registers a token account, they encrypt their own viewing key under each auditor public key, and the resulting ciphertext is stored alongside the account on-chain. A zero-knowledge proof attests that the encrypted key matches the public key the user just registered for their account, so auditors cannot be handed a key that decrypts something else.

Per-transfer ciphertexts and proofs are unchanged from the non-audited case: transfers carry no auditor-specific overhead regardless of the number of auditors, and the auditor's visibility comes entirely from the registration-time key escrow. To read an account, the auditor decrypts the user's viewing key once and then reads the user's encrypted balances and transfer events directly off-chain.

Because the auditor of a token can decrypt the user's viewing key for that token, users must use a distinct viewing key (and account public key) per token; reusing the same key across tokens would let one token's auditor see the user's accounts in any other token sharing the key.

What an auditor sees, for accounts that registered their public keys while the auditor was in the on-chain auditor set:

- The user's full encrypted active and pending balances.
- The amount of every transfer sent to or from the account.
- The full amount of every wrap and unwrap (already public on-chain).
- Sender and recipient addresses for every transaction (already public on-chain).

Effectively, everything the account owner can see with their own viewing key.


### Off-chain logic

To read an account, the auditor:

1. Fetches the on-chain account state and locates the viewing-key ciphertext addressed to its own public key, using the auditor-set version the account was registered against.
2. Decrypts that ciphertext with its own auditor secret key to recover the user's viewing key.
3. Uses the recovered viewing key to decrypt the account's active and pending encrypted balances, and any encrypted transfer amounts in events involving the account.

Reading is **stateless**: each query is independently answerable from a single chain read plus the recovered viewing key, with no running aggregation.

Accounts that registered their public keys against an older or newer auditor set remain opaque to this auditor unless the issuer hands over the secret keys of the set the account is registered against.

### Possible deployment

- **Onboarding a new auditor.** The auditor generates a keypair off-chain and the issuer registers the public key on-chain, advancing the auditor-set version. Users may re-encrypt their viewing keys under the new set so the new auditor gains visibility going forward. To read accounts that haven't yet migrated, the new auditor needs the previous auditor set's secret keys.
- **Auditor key rotation.** The issuer publishes the rotated public key on-chain, advancing the auditor-set version. No grace period is needed for in-flight transfers, since transfers don't encrypt to the auditor key.
- **Auditor offboarding.** The offboarded key is removed from the on-chain set. The offboarded auditor still holds the viewing keys of every user whose registration set included them, so they continue to decrypt those accounts' future activity. Revoking this requires each affected user to generate a new viewing key and register it under the updated auditor set. The protocol signals on-chain to user wallets that rotation is recommended when necessary.
- **Auditor key leakage.** Anyone who obtains an auditor's secret key recovers every user viewing key that was encrypted under it, and thereby the full activity of those users — past and future — until those users rotate their viewing keys. Accounts whose registration set does not include the leaked key remain opaque. As in offboarding, revocation depends on users actually generating new viewing keys, not just re-encrypting existing ones.

## Proposal for issuer key derivation

In practice, monitoring platforms (acting as auditors) need full visibility into current and past activity and balances.
Under either option above, the issuer registers a sequence of auditor keypairs over time and must share the old secrets with new auditors so they can read history.

A hash-chain derivation lets the issuer manage all of this from a single master secret, and grants every new auditor retroactive visibility automatically.
The issuer picks a random master secret `msk` and defines a chain of per-version secrets and keypairs (informally):

```
msk_i = Hash("master" | msk_{i+1})    with    msk_N = msk
sk_i  = Hash("secret" | msk_i)
pk_i  = sk_i * G
```

where `N` bounds the number of rotations the issuer expects (e.g., `N = 10000`). The issuer keeps only `msk` and a counter `i`, starting at `i = 0`.

To rotate the auditor set:

1. Increment `i`.
2. Derive `msk_i` by hashing from `msk_N` down to index `i`.
3. Share `msk_i` with the next auditor set off-chain.
4. After a setup period (e.g., two days, to give the auditors time to bring their infrastructure online), call `update_auditor` with `pk_i` to switch the on-chain auditor key.

Given `msk_i`, an auditor can derive `msk_j` and `sk_j` for every `j < i`, and therefore decrypt anything encrypted under any earlier auditor public key. They cannot derive `msk_j` for `j > i`, so future rotations remain confidential to them.


The scheme applies to both options:

- In **Option 1**, the new auditor uses the derived `sk_j` keys to decrypt every historical transfer ciphertext directly from the chain, without further input from the issuer.
- In **Option 2**, the new auditor uses the derived `sk_j` keys to decrypt the user-key escrow ciphertexts on-chain and recover historical user viewing keys, without further input from the issuer.

It does not, however, address the offboarding asymmetry of Option 2: an offboarded auditor still holds the user viewing keys they recovered while their key was active, so revoking their visibility into ongoing activity still requires users to rotate their viewing keys.


## Comparison

The two options trade cost against operational complexity. The table below summarizes the differences, using `n` for the number of active auditors.

| Dimension | Per-transfer | Per-account |
|---|---|---|
| Per-transfer overhead | `n` extra ciphertexts and a ZK proof | None |
| Per-registration overhead | None | `n` encrypted-key blobs and well-formedness proofs |
| Reading mode | **Stateful**: auditor maintains a running view of the transfer graph | **Stateless**: each query answerable from a single chain read plus the recovered viewing key |
| Visibility scope | Per-transfer amounts from the moment the auditor's key was installed; balances reconstructed from the transfer graph | User balances and per-transfer amounts, past and future, for any account whose registration set includes the auditor's key |
| Cross-token key reuse | Reuse OK — auditors see only their own token's transfers | A distinct account public key (and viewing key) is required per token, since each token's auditors decrypt the user's full account view for that token |
| Auditor offboarding | The offboarded key is removed and users stop encrypting under it; the offboarded auditor cannot decrypt future transactions | The offboarded auditor still holds existing user viewing keys and continues to decrypt new activity on those accounts until each user rotates their viewing key under an updated auditor set |
| Retroactive privacy | New auditors see only transfers made after their key was registered; older transfers stay private | A new auditor gains full historical visibility once the user re-escrows their existing viewing key under the new set; preserving history privacy requires the user to generate a new viewing key |
| User viewing-key recovery | Not supported — auditors never see the user's viewing key, so a user who loses it cannot access their account | Possible — an auditor can decrypt the user's escrowed viewing key on-chain and hand it back to the user, providing a built-in backup for an otherwise inaccessible account |
