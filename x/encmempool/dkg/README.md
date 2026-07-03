# x/encmempool/dkg — Distributed Key Generation (PROTOTYPE)

> **STATUS: EXPERIMENTAL PROOF OF CONCEPT. NOT AUDITED. NOT WIRED INTO CONSENSUS.
> DO NOT USE ON MAINNET WITHOUT AN EXTERNAL CRYPTOGRAPHIC AUDIT.**

This package replaces the **trusted dealer** in
[`x/encmempool/threshold`](../threshold/threshold.go) (`threshold.Setup`) with a
**distributed key generation (DKG)**: `n` keypers jointly generate the
threshold-ElGamal key used by the anti-MEV encrypted mempool, so that **no single
party and no coalition of fewer than `t` parties ever holds the master secret key
`msk`** — not even transiently, not even the dealer.

The output is a **drop-in replacement** for `threshold.Setup`: the same
`Encrypt / ComputeShare / Recover / Decrypt` code path works unchanged on DKG output.

---

## 1. Construction

Plain **single-round joint-Feldman VSS** over `secp256k1` (additive notation,
generator `G`, group order `q`). Reconstruction threshold `t`; sharing polynomials
have degree `t-1`. Party indices are **1-based**, matching `threshold.go`'s share
index domain exactly (it evaluates the sharing polynomial at the point equal to the
share index).

**Round 1 — Dealing (`DealerRound` → `deal`).** Each party `i` picks a secret
degree-`t-1` polynomial `f_i` with `f_i(0) = s_i`, broadcasts Feldman commitments
`C_{i,j} = a_{i,j}·G` (`j = 0..t-1`), and sends each party `m` the point-to-point
share `f_i(m)`. (In this PoC the point-to-point shares are plaintext Go structs; a
real system delivers them over authenticated, encrypted channels.)

**Round 2 — Complaints (`ComplaintRound`).** Each party checks every share addressed
to it against the dealer's public commitments via the Feldman relation
`f_i(m)·G == Σ_j m^j · C_{i,j}` (`VerifyShare`), and files a `Complaint` on any
mismatch.

**Round 3 — Finalize (`Finalize`).** A dealer is **disqualified** iff (a) it is
malformed — missing, wrong number of commitments (≠ `t`), or missing a recipient's
share — or (b) a complaint against it is *valid*, meaning the disputed share fails
against **the dealer's own published commitments** (a publicly checkable,
incontrovertible fault — an accuser cannot frame an honest dealer). The surviving set
is `QUAL`. If `|QUAL| < t` the run fails. Otherwise:

- **Master public key** `pub = compress(V_0)` where `V_j = Σ_{i∈QUAL} C_{i,j}`, i.e.
  `V_0 = (Σ_{i∈QUAL} s_i)·G = msk·G`. **`msk*G` is built by summing commitment
  POINTS — the scalar `msk` is never formed anywhere.**
- **Each keyper's final share** `X_m = Σ_{i∈QUAL} f_i(m)` — a Shamir share of `msk`
  on a degree-`t-1` polynomial, evaluated at `m`. This is exactly what
  `threshold.Setup` would have produced from a single trusted polynomial.

### Per-share correctness proof (`proof.go`)

`ProveDecryptShare` / `VerifyDecryptShare` implement a non-interactive
**Chaum–Pedersen DLEQ** proving a keyper's partial decryption `D_m = x_m·A` was
formed with the *same* `x_m` as its **public** share key `Y_m = x_m·G` (which anyone
recomputes from the DKG commitments via `SharePubKey`), without revealing `x_m`.

`RecoverVerified` is the **enforced** combine path: it verifies every partial's DLEQ
against `Y_m` (and rejects duplicate indices) *before* Lagrange-combining the first
`t` good partials — so one malicious keyper can no longer silently corrupt a
recovery.

---

## 2. Compatibility with `x/encmempool/threshold`

The DKG is engineered to be a **byte-for-byte drop-in** for `threshold.Setup`:

| `threshold.Setup` output | DKG (`Result`) equivalent |
| --- | --- |
| `pub` (33-byte compressed `x·G`) | `Result.Pub` (33-byte compressed `msk·G`) |
| `[]Share{Index, Xi}` | `Result.Shares` (same type, 1-based `Index`) |

It reuses `threshold`'s exact conventions — the 1-based evaluation domain, Horner
polynomial evaluation, compressed-point encoding, and the `sha256(compressed point)`
KDF — so `threshold.Encrypt(res.Pub, …)`, `threshold.ComputeShare`,
`threshold.Recover`, and `threshold.Decrypt` all work **unmodified**. This is proven
by `TestCompatibilityDropIn`.

**Entry points:** use `RunDKGSecure(parties)` in real code (it hard-wires
`crypto/rand`). `RunDKG(parties, rng)` takes an injectable reader and exists **for
deterministic tests only** — see the RNG note below.

---

## 3. What is PROVEN (in tests) vs what an AUDIT must still check

### Proven here (see `dkg_test.go`, and `cmd/dkgdemo` for a live transcript)

- **Drop-in compatibility** — DKG `pub` feeds `threshold.Encrypt`, and any `t` of the
  `n` DKG shares decrypt via the unmodified threshold path (`TestCompatibilityDropIn`).
- **Threshold secrecy** — any `t` shares decrypt; any `t-1` shares do **not**
  (`TestThreshold`).
- **No master secret assembled** — `Result` exposes no scalar field; `pub` equals
  `compress(V_0)` built from commitment points; every share is consistent with the
  public commitments (`TestNoMasterSecretAssembled`).
- **Provably-cheating dealer disqualified** — a share inconsistent with commitments is
  detected, the dealer removed, the run completes with `|QUAL| ≥ t`
  (`TestMaliciousDealerDisqualified`).
- **Malformed dealer disqualified without a panic** — a short (`t-1`) commitment
  vector no longer indexes out of range; the dealer is dropped as malformed
  (`TestMalformedShortCommitmentDisqualified`).
- **Per-share DLEQ enforcement** — tampered / wrong-`Y` / forged partials are rejected;
  `RecoverVerified` drops bad partials and still recovers from an honest majority, and
  errors (with attribution) rather than emitting a wrong plaintext when too few good
  partials remain (`TestMaliciousDecryptorRejected`, `TestRecoverVerifiedEnforced`).
- **Deterministic-nonce DLEQ** — proofs are deterministic and the classic
  nonce-reuse share-extraction `x = (z1−z2)/(c1−c2)` fails (`TestDLEQNonceDerandomized`).
- **Re-run independence** — re-running yields an independent key; old shares cannot
  decrypt a new ciphertext (`TestRerunIndependence`).

### An external audit MUST still check (NOT covered here)

1. **KEY BIASABILITY (documented, deliberately not fixed).** This is plain
   single-round joint-Feldman with **no commit-then-reveal / proof-of-possession**
   phase. A *rushing* adversary who broadcasts its dealing **last** sees the honest
   partial sum `Σ_honest C_{j,0}` and can pick its own `s_adv` to steer `pub` to
   satisfy any efficiently-checkable predicate (the classic
   Gennaro–Jarecki–Krawczyk–Rabin biasability).
   - **Benign for THIS use.** The key is used **only** as a threshold-ElGamal
     *decryption* key. ElGamal semantic security does **not** need a uniform public
     key; `msk = Σ s_i` still mixes in honest secrets the adversary cannot know, and
     `t-1` parties still cannot decrypt. Biasing `pub` does not help decrypt anyone
     else's ciphertext.
   - **FATAL if repurposed for signatures.** For threshold Schnorr/ECDSA/EdDSA, a
     biasable key breaks the security proof and is exploitable. **RULE: this key is
     for ENCRYPTION ONLY — never sign with it.** A signing deployment MUST add the
     Pedersen commit-then-reveal round. See [`SECURITY.md`](./SECURITY.md).
2. **Networking / DoS not modeled.** Parties are in-memory structs; there is no
   network, no encrypted point-to-point channels, no equivocation model (the PoC
   stores a single shared plaintext `Shares` map), no message authentication, and no
   timeout/liveness handling. A real deployment must supply all of these.
3. **Complaint-round game theory.** An undetected bad share (a cheating dealer whose
   victim never complains — impossible to model over these plaintext channels)
   silently degrades exactly **one** keyper (availability erosion, no secret leak).
   The real adversary — equivocating on the private channel vs. the later-revealed
   value — is out of scope here and must be handled by the transport + a
   share-reveal/justification round.
4. **Enforcement wiring.** `RecoverVerified` exists but the live keeper
   (`x/encmempool/keeper/abci.go`) still calls raw `threshold.Recover` on the first
   `t` shares **without** DLEQ verification. Integration MUST route through
   `RecoverVerified` (carrying each partial's proof) so a single keyper cannot DoS a
   specific ciphertext's decryption.
5. **Constant-time / side-channels.** All secret-scalar multiplications use the
   variable-time `*NonConst` secp256k1 variants (and `InverseNonConst` in Lagrange),
   which leak via timing. A production keyper exposes `share.Xi` to a timing adversary
   on every partial decryption. Not addressed here.
6. **RNG rail.** `RunDKGSecure` hard-wires `crypto/rand`; `RunDKG(…, rng)` delegates
   *all* `msk` secrecy to the injected reader and is for reproducible tests only. The
   DLEQ nonce is now derived deterministically (RFC6979-style, `deriveDLEQNonce`) so
   it can never be reused regardless of RNG. An audit should still confirm every
   production secret is sourced from a CSPRNG.

---

## 4. Run the demo

```
go run ./x/encmempool/dkg/cmd/dkgdemo
```

Prints a real transcript: a 5-node/threshold-3 DKG, an encryption to the DKG key,
a 3-share decryption (success) vs. a 2-share attempt (fail), a rejected tampered
partial, and a re-run producing an independent key that the old shares cannot decrypt.

---

## 5. Honest banner

This is a **prototype**, not production. The math is sound for a threshold-ElGamal
**decryption** key at the PoC level (and was reviewed adversarially through three
independent lenses), but the security-relevant gaps above — biasability boundary,
networking/DoS, complaint-round adversary, enforcement wiring, constant-time — are
**not** production-hardened. **An external cryptographic audit is required before any
mainnet use.**
