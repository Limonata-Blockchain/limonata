# SECURITY — x/encmempool/dkg

**Live and tested on testnet limonata_10777-1. Wired into consensus via CometBFT
vote extensions. Testnet only - not for mainnet use.**

## Threat model this DKG is built for

A threshold-ElGamal **decryption** key for the anti-MEV encrypted mempool, generated
without a trusted dealer. Security goal: the master secret `msk` is never held by any
party or any coalition of `< t` parties, and a tx body stays unreadable until `≥ t`
independent keypers cooperate (which only happens after the ciphertext order is
fixed).

## Load-bearing caveat: KEY BIASABILITY — ENCRYPTION ONLY

This is **plain single-round joint-Feldman** with **no** Pedersen commit-then-reveal
round and **no** proof-of-possession. Therefore the master public key `pub = msk·G`
is **biasable by a rushing adversary** who deals last: after observing the honest
dealers' commitments `Σ_honest C_{j,0}`, it chooses its own contribution `s_adv` to
steer `pub` toward any efficiently-checkable predicate (Gennaro–Jarecki–Krawczyk–Rabin
biasability). This has been demonstrated by review probes (grinding a chosen leading
byte of `msk·G`).

- **Benign for the intended use.** ElGamal semantic security does not require a
  uniform public key. `msk = Σ s_i` still mixes in honest secrets the adversary
  cannot know; `t-1` parties still cannot decrypt; biasing `pub` does not help decrypt
  any other party's ciphertext. Not triggerable in the live consensus-integrated flow
  (all dealings are collected before any complaint - no rushing window).
- **FATAL if reused for signatures.** For threshold Schnorr / ECDSA / EdDSA a biasable
  key breaks the security proof and is exploitable.
- **The WHOLE aggregate coefficient vector is adversary-influenced, not just `pub`.**
  A rushing last dealer influences every `V_j = Σ_i C_{i,j}`, including the top
  coefficient. In particular a degree collapse (zeroing the top aggregate coefficient
  so `t-1` shares suffice) would be a *total* secrecy break — but computing it needs the
  honest **scalar** coefficient sum, of which only the **point** `Σ_honest C_{j,·}` is
  public. So non-collapse (and the benign-for-encryption conclusion above) rests on the
  **same ECDLP barrier** as constant-term biasing. Do not assume only `pub` is biasable.

**RULE: the key produced by this package is for ENCRYPTION ONLY. NEVER sign with it.**
A signing deployment MUST add the Pedersen commit-then-reveal (GJKR) round before
disqualification, so no party sees others' contributions before committing to its own.

## Other hardening notes (see README §3)

- **Networking / DoS / equivocation** not modeled (in-memory plaintext channels only).
- **Enforcement wiring:** the live keeper routes decryption through
  `RecoverVerified` (DLEQ-gated) on the transparent-DKG path; embedders outside the
  keeper must do the same rather than call raw `threshold.Recover`.
- **Constant-time:** all secret-scalar operations use variable-time `*NonConst`
  secp256k1 variants (timing side-channel on shares).
- **RNG:** use `RunDKGSecure` (hard-wired `crypto/rand`) in production; `RunDKG(…,rng)`
  is for deterministic tests only. The DLEQ nonce is derived deterministically
  (`deriveDLEQNonce`) so it cannot be reused regardless of RNG.

## Reporting

This is Limonata testnet code. Do not deploy to mainnet.
