// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package dkg

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ErrInsufficientVerified is the SENTINEL RecoverVerified wraps when fewer than t of the
// supplied partials pass DLEQ verification. The on-chain decrypt path treats it like a plain
// share shortfall (errNotEnoughShares) — a WITHIN-GRACE DEFER that can heal from late honest
// shares — rather than a hard drop, so a coalition that pads the RAW share count with chaff
// (a count that collapses below t once the chaff is DLEQ-dropped) cannot force a matured
// ciphertext to DROP instead of DEFER. It is deliberately DISTINCT from a malformed-ciphertext
// or bad-commitment error (t < 1, empty commitments, a failing Lagrange combine on verified
// shares), which stay terminal failures because no late honest share can heal them.
var ErrInsufficientVerified = errors.New("insufficient DLEQ-verified partials")

// dleqContext domain-separates the Fiat-Shamir CHALLENGE transcript.
const dleqContext = "limonata/encmempool/dkg/dleq/v1"

// dleqNonceContext domain-separates the deterministic NONCE derivation (distinct
// from the challenge domain so the nonce and challenge can never collide).
const dleqNonceContext = "limonata/encmempool/dkg/dleq-nonce/v1"

// DLEQProof is a non-interactive Chaum-Pedersen proof of equality of discrete logs:
// it proves knowledge of a scalar x such that D = x*A AND Y = x*G, WITHOUT
// revealing x. Applied to a keyper's partial decryption, it proves the DecryptShare
// D_m = x_m*A was formed with the SAME x_m as the keyper's PUBLIC share key
// Y_m = x_m*G (which anyone can recompute from the DKG public commitments). A bad
// partial is thus rejected BEFORE Recover, closing the "no per-share proof" gap.
type DLEQProof struct {
	C *secp256k1.ModNScalar // Fiat-Shamir challenge
	Z *secp256k1.ModNScalar // response z = k + c*x
}

// ProveDecryptShare computes keyper `share`'s partial decryption of ct (reusing
// threshold.ComputeShare so the on-wire DecryptShare is byte-identical to the
// unproven path) and a DLEQ proof binding it to Y = share.Xi*G.
//
// SECURITY (was HIGH finding): the Chaum-Pedersen commitment nonce k is derived
// DETERMINISTICALLY from the secret share and the full public transcript (RFC6979
// style, see deriveDLEQNonce) instead of from a caller-injected io.Reader. This
// permanently removes the nonce-reuse footgun: with the old injectable-RNG API a
// keyper that reused the RNG stream produced two proofs (c1,z1),(c2,z2) sharing k,
// leaking the secret share via x=(z1-z2)/(c1-c2). Here k is bound to (x,A,D,Y), so
// distinct ciphertexts always get distinct k and no RNG can ever cause reuse.
func ProveDecryptShare(share threshold.Share, ct *threshold.Ciphertext) (*threshold.DecryptShare, *DLEQProof, error) {
	ds, err := threshold.ComputeShare(share, ct) // D = x*A, compressed
	if err != nil {
		return nil, nil, err
	}
	A, err := parsePoint(ct.A)
	if err != nil {
		return nil, nil, err
	}
	D, err := parsePoint(ds.D)
	if err != nil {
		return nil, nil, err
	}
	var Y secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(share.Xi, &Y) // Y = x*G

	// Commit: T1 = k*G, T2 = k*A. k is derived deterministically (no RNG rail). CRITICAL AUDIT FIX:
	// the nonce MUST bind the SAME index the challenge binds (dleqChallenge). Otherwise two proofs over
	// the same (x, A) — hence the same D=x*A and Y=x*G — at DIFFERENT indices reuse k while the challenge
	// c differs, and any observer recovers x=(z1-z2)/(c1-c2). This is reachable in the complaint path,
	// where a node proves S=x*A with x = its ONE persistent enc private key at several owned eval-points
	// (indices) against dealer-chosen A: a malicious dealer sealing the same A to two of a victim's points
	// makes the victim leak its enc private key on-chain. Binding index makes k distinct per index.
	k := deriveDLEQNonce(share.Index, share.Xi, A, D, &Y)
	var T1, T2 secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(k, &T1)
	secp256k1.ScalarMultNonConst(k, A, &T2)

	// Challenge c = H(ctx, index, A, D, Y, T1, T2); response z = k + c*x. The keyper
	// index is bound into the challenge (AUDIT FIX below) so a proof is valid ONLY for
	// the index it was issued at.
	c := dleqChallenge(share.Index, A, D, &Y, &T1, &T2)
	cx := new(secp256k1.ModNScalar)
	cx.Set(c).Mul(share.Xi) // c*x
	z := new(secp256k1.ModNScalar)
	z.Set(k).Add(cx) // k + c*x
	return ds, &DLEQProof{C: c, Z: z}, nil
}

// VerifyDecryptShare checks proof for the partial decryption D (from ds) against
// the ephemeral A (= ct.A, compressed) and the keyper's public share key Y (from
// SharePubKey over the DKG public commitments). Returns true iff D = x*A for the
// same x with Y = x*G. A tampered D, a wrong Y, or a forged proof all fail.
func VerifyDecryptShare(A []byte, ds *threshold.DecryptShare, Y *secp256k1.JacobianPoint, proof *DLEQProof) bool {
	if proof == nil || proof.C == nil || proof.Z == nil || ds == nil || Y == nil {
		return false
	}
	Apt, err := parsePoint(A)
	if err != nil {
		return false
	}
	Dpt, err := parsePoint(ds.D)
	if err != nil {
		return false
	}
	// Reconstruct T1 = z*G - c*Y and T2 = z*A - c*D using scalar negation of c.
	negC := new(secp256k1.ModNScalar)
	negC.Set(proof.C).Negate()

	var zG, cY, T1 secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(proof.Z, &zG)
	secp256k1.ScalarMultNonConst(negC, Y, &cY)
	secp256k1.AddNonConst(&zG, &cY, &T1)

	var zA, cD, T2 secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(proof.Z, Apt, &zA)
	secp256k1.ScalarMultNonConst(negC, Dpt, &cD)
	secp256k1.AddNonConst(&zA, &cD, &T2)

	want := dleqChallenge(ds.Index, Apt, Dpt, Y, &T1, &T2)
	a := want.Bytes()
	b := proof.C.Bytes()
	return a == b
}

// dleqChallenge is the Fiat-Shamir hash of the transcript, reduced mod q.
//
// AUDIT FIX (index binding): the keyper `index` is committed into the transcript.
// Previously the challenge hashed only (ctx,A,D,Y); because SharePubKey reduces the
// index through scalarFromUint == SetInt(uint32(v)), two indices that agree mod 2^32
// (e.g. i and i+2^32) yield a BYTE-IDENTICAL Y, so ONE honest proof verified at BOTH
// indices — letting a replay of a single partial masquerade as a second distinct
// partial and silently poison RecoverVerified's Lagrange combine. Hashing the full
// uint64 index makes a proof valid only at the exact index it was issued for, so the
// replay's challenge no longer matches. (RecoverVerified additionally rejects any
// index >= 2^32 at ingest — see there.)
func dleqChallenge(index uint64, A, D, Y, T1, T2 *secp256k1.JacobianPoint) *secp256k1.ModNScalar {
	h := sha256.New()
	h.Write([]byte(dleqContext))
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], index)
	h.Write(idx[:])
	h.Write(compressCopy(A))
	h.Write(compressCopy(D))
	h.Write(compressCopy(Y))
	h.Write(compressCopy(T1))
	h.Write(compressCopy(T2))
	var b [32]byte
	copy(b[:], h.Sum(nil))
	c := new(secp256k1.ModNScalar)
	c.SetBytes(&b) // reduces mod q; identical reduction on prove & verify
	return c
}

// deriveDLEQNonce derives the Chaum-Pedersen commitment nonce k DETERMINISTICALLY
// (RFC6979 style) from the secret scalar x and the full public transcript (A,D,Y),
// consulting NO external RNG. Rationale (was the HIGH audit finding): binding k to
// the secret AND to the ciphertext-specific points guarantees that (1) two proofs
// for different ciphertexts use different k, and (2) two proofs for the same
// ciphertext are byte-identical (same single equation, leaks nothing) — so the
// catastrophic k-reuse that extracts x via (z1-z2)/(c1-c2) is unreachable no matter
// what io.Reader an integrator wires up. Rejection sampling with a counter keeps the
// output uniform and non-zero mod q, matching threshold.randScalar's convention.
func deriveDLEQNonce(index uint64, x *secp256k1.ModNScalar, A, D, Y *secp256k1.JacobianPoint) *secp256k1.ModNScalar {
	xb := x.Bytes()
	aC, dC, yC := compressCopy(A), compressCopy(D), compressCopy(Y)
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], index) // CRITICAL: bind the index the challenge also binds (no k-reuse across indices)
	var ctr [4]byte
	for {
		h := sha256.New()
		h.Write([]byte(dleqNonceContext))
		h.Write(idx[:])
		h.Write(xb[:])
		h.Write(aC)
		h.Write(dC)
		h.Write(yC)
		h.Write(ctr[:])
		var b [32]byte
		copy(b[:], h.Sum(nil))
		var k secp256k1.ModNScalar
		if k.SetBytes(&b) == 0 && !k.IsZero() { // == 0 means it did not overflow q (unbiased)
			out := new(secp256k1.ModNScalar)
			out.Set(&k)
			for i := range xb { // best-effort wipe of the secret bytes copy
				xb[i] = 0
			}
			return out
		}
		// bump the counter (little-endian) and retry
		for i := 0; i < len(ctr); i++ {
			ctr[i]++
			if ctr[i] != 0 {
				break
			}
		}
	}
}

// VerifiedShare bundles a keyper's partial decryption with the DLEQ proof that it
// was formed with the keyper's real share (D = x_m*A ^ Y_m = x_m*G).
type VerifiedShare struct {
	Share *threshold.DecryptShare
	Proof *DLEQProof
}

// RecoverVerified is the ENFORCED combine path the audit requires (finding: "the
// DLEQ proof exists but is NOT enforced on the recovery path — one malicious keyper
// can silently DoS decryption"). For each supplied partial it recomputes the
// keyper's PUBLIC share key Y_index directly from the DKG public commitments and
// rejects any partial whose DLEQ proof does not verify, before it can poison the
// Lagrange combine. It then combines the first t VERIFIED, distinct-index partials.
//
// Any integration (the encmempool keeper's decrypt path included) MUST route through
// this instead of threshold.Recover on untrusted partials: a single bad partial then
// gets dropped WITH ATTRIBUTION (the returned error / skipped index) instead of
// corrupting the shared secret and failing the AES-GCM open with no culprit — which
// is exactly the anti-MEV DoS the raw path leaves open.
func RecoverVerified(commitments []secp256k1.JacobianPoint, ctA []byte, t int, partials []VerifiedShare) (*secp256k1.JacobianPoint, error) {
	if t < 1 {
		return nil, fmt.Errorf("invalid threshold %d", t)
	}
	if len(commitments) == 0 {
		return nil, fmt.Errorf("no public commitments")
	}
	seen := make(map[uint64]bool)
	good := make([]*threshold.DecryptShare, 0, t)
	for _, vs := range partials {
		if vs.Share == nil || vs.Proof == nil {
			continue
		}
		// AUDIT FIX (index-truncation dedup bypass): reject any index that is not a
		// valid keyper index. A keyper index is always in [1, n] with n << 2^32, and
		// the index is reduced mod 2^32 (scalarFromUint) everywhere it feeds the
		// crypto. An out-of-range index (0, or >= 2^32) either evaluates the sharing
		// polynomial at 0 (== msk, unforgeable) or COLLIDES with a real index mod 2^32
		// while keying seen[] on the distinct full uint64 — the exact hole that let a
		// replay of ONE partial under {idx, idx+2^32} pass the t-distinct count and
		// silently corrupt the Lagrange combine. Dropping these makes the surviving
		// index domain injective under the mod-2^32 reduction, so seen[] on the full
		// uint64 now agrees with the reduction used by SharePubKey / lagrangeAtZero.
		if vs.Share.Index < 1 || vs.Share.Index >= (1<<32) {
			continue
		}
		if seen[vs.Share.Index] { // reject duplicate indices (a Lagrange-poisoning vector)
			continue
		}
		Y := SharePubKey(commitments, vs.Share.Index)
		if !VerifyDecryptShare(ctA, vs.Share, Y, vs.Proof) {
			continue // provably-bad partial: drop it, do not abort the honest majority
		}
		seen[vs.Share.Index] = true
		good = append(good, vs.Share)
		if len(good) == t {
			break
		}
	}
	if len(good) < t {
		// Wrap ErrInsufficientVerified so the on-chain decrypt path can tell "not enough
		// VERIFIED partials (heal-eligible: defer within grace)" apart from a terminal
		// malformed-input failure, and route this case into the same bounded DEFER branch as
		// a raw share shortfall instead of hard-dropping the ciphertext.
		return nil, fmt.Errorf("only %d/%d partials passed DLEQ verification: %w", len(good), t, ErrInsufficientVerified)
	}
	return threshold.Recover(good)
}
