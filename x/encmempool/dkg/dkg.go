// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

// Package dkg is an EXPERIMENTAL, standalone joint-Feldman VSS Distributed Key
// Generation for the threshold-ElGamal encrypted mempool. (It is plain single-round
// joint-Feldman — NOT the Pedersen/GJKR commit-then-reveal variant; see the KEY-
// BIASABILITY caveat below.) It replaces the TRUSTED dealer in package threshold
// (threshold.Setup) with a protocol in which n parties jointly generate a threshold
// key such that:
//
//   - the master secret key msk = Σ_{i∈QUAL} s_i is NEVER assembled in one place
//     (no party, and no coalition of < t parties, ever holds it as a scalar);
//   - the master public key pub = compress(msk*G) and the returned []threshold.Share
//     are a DROP-IN REPLACEMENT for threshold.Setup's output — threshold.Encrypt /
//     ComputeShare / Recover / Decrypt work UNCHANGED on DKG output;
//   - a malicious dealer that sends a share inconsistent with its public Feldman
//     commitments is DETECTED and DISQUALIFIED (a valid complaint), and the run
//     still completes as long as |QUAL| >= t.
//
// It also adds a Chaum-Pedersen NIZK (see proof.go) so a single keyper's partial
// decryption D_m = x_m*A can be verified against its PUBLIC share key Y_m = x_m*G
// BEFORE Recover — closing the "no per-share proof" gap of the prototype.
//
// This package is a CRYPTO PROOF OF CONCEPT: parties are in-memory Go structs that
// exchange messages via other structs (no networking, no encrypted point-to-point
// channels). It is NOT wired into any module, app.go, or consensus. It is NOT
// audited. Do not use in production without a security review.
//
// KEY-BIASABILITY CAVEAT (documented, deliberately NOT fixed here): this is plain
// joint-Feldman with a single dealing round and no commit-then-reveal / proof-of-
// possession phase, so a RUSHING adversary that broadcasts its dealing LAST can see
// the honest partial sum Σ_honest C_{j,0} and choose its own s_adv to steer the
// master public key pub = Σ C_{i,0} to satisfy any efficiently-checkable predicate
// (classic Gennaro-Jarecki-Krawczyk-Rabin biasability). This is BENIGN for the ONLY
// use here — a threshold-ElGamal DECRYPTION key: ElGamal semantic security does not
// require a uniform public key, msk = Σ s_i still mixes in honest secrets the
// adversary cannot know, and t-1 parties still cannot decrypt. It would be FATAL if
// this key or DKG were ever repurposed for threshold SIGNATURES (Schnorr/ECDSA/
// EdDSA), where a biasable key breaks the security proof. THE RULE: this key is for
// ENCRYPTION ONLY — never sign with it. A signing deployment MUST add the Pedersen
// commit-then-reveal round. See README.md / SECURITY.md.
//
// Notation: secp256k1, additive, G = generator, group order q. n parties indexed
// 1..n (the SAME 1-based index domain threshold.Setup uses: it evaluates the
// sharing polynomial at the point equal to the share index). Reconstruction
// threshold t; sharing polynomials have degree t-1.
package dkg

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"sort"

	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Fault is a testing hook that makes a Party misbehave as a dealer. Honest is the
// default; BadShare deals one share that is inconsistent with the published
// commitments (and cannot be defended), i.e. a provably-cheating dealer.
type Fault int

const (
	// Honest deals a correct Feldman sharing.
	Honest Fault = iota
	// BadShare sends one victim a share that does NOT match the dealer's public
	// commitments. It is detectable by the victim and disqualifies the dealer.
	BadShare
)

// Party is a DKG participant. Indices are 1-based to match threshold.go's share
// index domain. A Party holds only its OWN secret polynomial (coeffs); its secret
// contribution s_i = coeffs[0] never leaves the party, and the full master secret
// is never formed anywhere — that is the whole point.
type Party struct {
	Index uint64
	n, t  int
	all   []uint64 // indices of every party (1..n)
	fault Fault

	// filled during the protocol:
	coeffs []*secp256k1.ModNScalar // secret polynomial f_i, coeffs[0] = s_i (SECRET, never sent)
	share  *secp256k1.ModNScalar   // this party's final Shamir share X_i of msk (SECRET)
}

// MakeMalicious marks the party to deal a provably-inconsistent share (testing).
func (p *Party) MakeMalicious() { p.fault = BadShare }

// NewParties builds n honest parties (indices 1..n) for a (t,n) DKG.
func NewParties(n, t int) []*Party {
	all := make([]uint64, n)
	for i := 0; i < n; i++ {
		all[i] = uint64(i + 1)
	}
	parties := make([]*Party, n)
	for i := 0; i < n; i++ {
		parties[i] = &Party{Index: uint64(i + 1), n: n, t: t, all: all}
	}
	return parties
}

// Dealing is dealer i's output for the DKG round: public Feldman commitments plus
// the point-to-point shares f_i(m) it sends to each party m. In a real system the
// Shares would be delivered over encrypted channels; here they are plaintext.
type Dealing struct {
	Dealer      uint64
	Commitments []secp256k1.JacobianPoint        // C_{i,0..t-1} = a_{i,j}*G (public, broadcast)
	Shares      map[uint64]*secp256k1.ModNScalar // f_i(m) for each recipient m (point-to-point)
}

// Complaint is party By accusing dealer Against of sending an inconsistent share.
type Complaint struct {
	By      uint64
	Against uint64
}

// Result is the DKG output. It is intentionally SHAPED like threshold.Setup's
// output (Pub + []threshold.Share) and deliberately contains NO field holding the
// master secret scalar — see the no-master-secret property (test c).
type Result struct {
	Pub               []byte                    // compress(msk*G): drop-in for threshold.Setup's pub
	Shares            []threshold.Share         // Shamir shares of msk (one per QUAL party)
	PublicCommitments []secp256k1.JacobianPoint // V_j = Σ_{i∈QUAL} C_{i,j}; V_0 = msk*G
	Qual              []uint64                  // qualified party indices
	Disqualified      []uint64                  // parties removed by a valid complaint
}

// RunDKGSecure is the PRODUCTION entry point: it runs the DKG with crypto/rand as
// the entropy source, so an integrator cannot accidentally supply a weak/seeded
// io.Reader. Prefer this over RunDKG everywhere except deterministic tests. (Every
// dealer's secret polynomial is drawn from the same crypto/rand stream in party
// order; sequential draws from a CSPRNG are independent, so msk secrecy holds — the
// per-party-independent-entropy abstraction is cosmetic here, see RunDKG.)
func RunDKGSecure(parties []*Party) (*Result, error) { return RunDKG(parties, rand.Reader) }

// RunDKG runs the full protocol over the given party set with the injected RNG,
// and returns a fresh independent threshold key.
//
// SECURITY: rng MUST be a cryptographically-secure RNG (crypto/rand.Reader) in any
// real use — msk secrecy is delegated wholly to it. A low-entropy / seeded reader
// makes msk predictable and is for REPRODUCIBLE TESTS ONLY. Production code should
// call RunDKGSecure, which hard-wires crypto/rand and removes this footgun.
//
// Deterministic in rng: calling it again with a different party set (or a different
// RNG) yields an independent msk'/pub' — this is the "re-run on set change" story
// (no proactive resharing, exactly like Shutter/Penumbra: just run it again).
func RunDKG(parties []*Party, rng io.Reader) (*Result, error) {
	dealings, err := DealerRound(parties, rng)
	if err != nil {
		return nil, err
	}
	complaints := ComplaintRound(parties, dealings)
	return Finalize(parties, dealings, complaints)
}

// DealerRound: every party deals a Feldman VSS (commitments + point-to-point shares).
func DealerRound(parties []*Party, rng io.Reader) ([]*Dealing, error) {
	out := make([]*Dealing, 0, len(parties))
	for _, p := range parties {
		// AUDIT FIX (robustness): reject a degenerate threshold before deal() builds a
		// zero-length coeffs slice and evalPoly indexes coeffs[-1] (a panic — a
		// chain-halt-class fault if an integration mis-wires t). threshold.Setup guards
		// t>=1 identically; the DKG entry points must too.
		if p.t < 1 {
			return nil, fmt.Errorf("invalid threshold t=%d (must be >= 1)", p.t)
		}
		d, err := p.deal(rng)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// deal draws f_i, publishes C_{i,j}=a_{i,j}*G, and computes shares f_i(m). A
// malicious party additionally corrupts the share sent to one victim so that it
// no longer satisfies f_i(victim)*G == Σ_j victim^j C_{i,j}.
func (p *Party) deal(rng io.Reader) (*Dealing, error) {
	coeffs := make([]*secp256k1.ModNScalar, p.t)
	for j := range coeffs {
		s, err := randScalarFrom(rng)
		if err != nil {
			return nil, err
		}
		coeffs[j] = s
	}
	p.coeffs = coeffs // coeffs[0] = s_i is this party's secret; it never leaves the party.

	commit := make([]secp256k1.JacobianPoint, p.t)
	for j := range coeffs {
		secp256k1.ScalarBaseMultNonConst(coeffs[j], &commit[j])
	}

	shares := make(map[uint64]*secp256k1.ModNScalar, p.n)
	for _, m := range p.all {
		shares[m] = evalPoly(coeffs, m)
	}
	if p.fault == BadShare {
		v := p.victim()
		bad := new(secp256k1.ModNScalar)
		bad.Set(shares[v]).Add(scalarFromUint(1)) // off-by-one => fails Feldman check
		shares[v] = bad
	}
	return &Dealing{Dealer: p.Index, Commitments: commit, Shares: shares}, nil
}

// ComplaintRound: every party verifies the share addressed to it from each dealer
// against that dealer's public commitments, and files a complaint for any mismatch.
func ComplaintRound(parties []*Party, dealings []*Dealing) []Complaint {
	var complaints []Complaint
	for _, p := range parties {
		for _, d := range dealings {
			if !VerifyShare(d.Commitments, p.Index, d.Shares[p.Index]) {
				complaints = append(complaints, Complaint{By: p.Index, Against: d.Dealer})
			}
		}
	}
	return complaints
}

// Finalize builds QUAL (dealers with a valid complaint are dropped), aggregates the
// QUAL commitments into the master public key, and computes each QUAL party's final
// Shamir share. It returns an error if |QUAL| < t.
//
// NO-MASTER-SECRET INVARIANT: msk*G is computed by SUMMING COMMITMENT POINTS
// (V_0 = Σ C_{i,0}); the scalar msk = Σ s_i is never formed. Each party's final
// share X_m = Σ_{i∈QUAL} f_i(m) is a Shamir share (an evaluation), not the secret.
func Finalize(parties []*Party, dealings []*Dealing, complaints []Complaint) (*Result, error) {
	if len(parties) == 0 {
		return nil, fmt.Errorf("no parties")
	}
	t := parties[0].t
	// AUDIT FIX (robustness): guard t>=1 so a direct Finalize call with a degenerate
	// threshold returns a clean error instead of indexing V[0] out of range on an
	// empty aggregate below.
	if t < 1 {
		return nil, fmt.Errorf("invalid threshold t=%d (must be >= 1)", t)
	}
	byDealer := make(map[uint64]*Dealing, len(dealings))
	for _, d := range dealings {
		byDealer[d.Dealer] = d
	}
	// isParty is the set of REAL participant indices. A complaint whose accuser index
	// (By) is not a real party must be ignored — see the framing fix in the complaint
	// loop below.
	isParty := make(map[uint64]bool, len(parties))
	for _, p := range parties {
		isParty[p.Index] = true
	}

	disq := make(map[uint64]bool)

	// Structural well-formedness (was the "short commitment vector panics" finding):
	// a dealer MUST publish a degree-(t-1) polynomial, i.e. EXACTLY t Feldman
	// commitments, and a share to every party. A dealing that is missing, carries the
	// wrong number of commitments, or omits a recipient's share is provably malformed
	// and is disqualified BEFORE aggregation. Without this, an untrusted dealer that
	// broadcast t-1 commitments (with shares consistent with that lower-degree poly,
	// so no honest party complains) would survive QUAL and then index Commitments[t-1]
	// out of range in the V_j loop below — a consensus-halt-class panic on a network.
	for _, p := range parties {
		d, ok := byDealer[p.Index]
		if !ok || len(d.Commitments) != t || !dealsToAll(d, parties) {
			disq[p.Index] = true
		}
	}

	// A complaint is valid iff the disputed share fails against the dealer's OWN
	// public commitments — a publicly checkable, incontrovertible fault.
	//
	// AUDIT FIX (framing / liveness DoS): the accuser index c.By MUST be a real party.
	// Without this guard, an out-of-range By (0, n+1, 2^40, ...) is a nil-map miss on
	// d.Shares[c.By]; VerifyShare returns false on the nil share (dkg.go), so Finalize
	// would CONFLATE "the dealer never dealt to By" with "the dealer dealt By a bad
	// share" and disqualify a provably-honest dealer whose every real share verifies.
	// A single forged complaint could then evict any honest dealer, and enough of them
	// drive |QUAL| < t and abort the run — falsifying the documented "an accuser cannot
	// frame an honest dealer" guarantee. Bounding By to the party set closes it (a bare
	// By>=1 check is insufficient — By=n+1 still frames). c.Against out-of-range is
	// already safe: byDealer miss -> continue.
	for _, c := range complaints {
		if !isParty[c.By] {
			continue // accuser is not a real participant -> cannot be a valid fault proof
		}
		d, ok := byDealer[c.Against]
		if !ok || len(d.Commitments) != t {
			continue // malformed dealers are already handled by the structural pass
		}
		if !VerifyShare(d.Commitments, c.By, d.Shares[c.By]) {
			disq[c.Against] = true
		}
	}

	var qual, disqualified []uint64
	for _, p := range parties {
		if disq[p.Index] {
			disqualified = append(disqualified, p.Index)
		} else {
			qual = append(qual, p.Index)
		}
	}
	sort.Slice(qual, func(i, j int) bool { return qual[i] < qual[j] })
	sort.Slice(disqualified, func(i, j int) bool { return disqualified[i] < disqualified[j] })
	if len(qual) < t {
		return nil, fmt.Errorf("DKG failed: |QUAL|=%d < t=%d", len(qual), t)
	}

	// Aggregate commitments V_j = Σ_{i∈QUAL} C_{i,j}. V_0 = (Σ s_i)*G = msk*G.
	V := make([]secp256k1.JacobianPoint, t)
	for j := 0; j < t; j++ {
		first := true
		for _, i := range qual {
			cij := byDealer[i].Commitments[j]
			if first {
				V[j] = cij
				first = false
				continue
			}
			var sum secp256k1.JacobianPoint
			secp256k1.AddNonConst(&V[j], &cij, &sum)
			V[j] = sum
		}
	}
	pub := compressCopy(&V[0])

	// Final shares: X_m = Σ_{i∈QUAL} f_i(m) — a Shamir sharing of msk on degree t-1.
	shares := make([]threshold.Share, 0, len(qual))
	byIndex := make(map[uint64]*Party, len(parties))
	for _, p := range parties {
		byIndex[p.Index] = p
	}
	for _, m := range qual {
		X := new(secp256k1.ModNScalar)
		first := true
		for _, i := range qual {
			s := byDealer[i].Shares[m]
			if first {
				X.Set(s)
				first = false
				continue
			}
			X.Add(s)
		}
		byIndex[m].share = X
		shares = append(shares, threshold.Share{Index: m, Xi: X})
	}

	return &Result{
		Pub:               pub,
		Shares:            shares,
		PublicCommitments: V,
		Qual:              qual,
		Disqualified:      disqualified,
	}, nil
}

// VerifyShare checks the Feldman relation share*G == Σ_j index^j * commitments[j].
func VerifyShare(commitments []secp256k1.JacobianPoint, index uint64, share *secp256k1.ModNScalar) bool {
	if share == nil || len(commitments) == 0 {
		return false
	}
	var lhs secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(share, &lhs)
	rhs := SharePubKey(commitments, index)
	return bytes.Equal(compressCopy(&lhs), compressCopy(rhs))
}

// SharePubKey computes the PUBLIC share key Y_index = X_index*G directly from the
// public commitments, via Horner in the exponent: Σ_j index^j * commitments[j].
// With commitments = QUAL aggregate V, this is the public value against which a
// keyper's partial decryption is verified (see proof.go). No secret is needed.
func SharePubKey(commitments []secp256k1.JacobianPoint, index uint64) *secp256k1.JacobianPoint {
	// AUDIT FIX (defensive): guard the empty slice so this EXPORTED API returns nil
	// instead of indexing commitments[-1] and panicking (VerifyShare / RecoverVerified
	// already reject len==0 upstream, but a direct integration call must not panic — a
	// chain halt in a consensus context).
	if len(commitments) == 0 {
		return nil
	}
	zi := scalarFromUint(index)
	acc := commitments[len(commitments)-1] // value copy; slice not mutated
	for k := len(commitments) - 2; k >= 0; k-- {
		var scaled secp256k1.JacobianPoint
		secp256k1.ScalarMultNonConst(zi, &acc, &scaled) // index * acc
		var sum secp256k1.JacobianPoint
		secp256k1.AddNonConst(&scaled, &commitments[k], &sum) // + C_k
		acc = sum
	}
	out := acc
	return &out
}

// SharePubKeys returns Y_m for each requested index (convenience over SharePubKey).
func SharePubKeys(commitments []secp256k1.JacobianPoint, indices []uint64) map[uint64]*secp256k1.JacobianPoint {
	out := make(map[uint64]*secp256k1.JacobianPoint, len(indices))
	for _, m := range indices {
		out[m] = SharePubKey(commitments, m)
	}
	return out
}

// ---- small helpers (mirror threshold.go conventions exactly) ----

// evalPoly evaluates f(z) = Σ_k coeffs[k]*z^k at z (Horner), matching threshold.Setup.
func evalPoly(coeffs []*secp256k1.ModNScalar, z uint64) *secp256k1.ModNScalar {
	zi := scalarFromUint(z)
	var acc secp256k1.ModNScalar
	acc.Set(coeffs[len(coeffs)-1])
	for k := len(coeffs) - 2; k >= 0; k-- {
		acc.Mul(zi).Add(coeffs[k])
	}
	out := new(secp256k1.ModNScalar)
	out.Set(&acc)
	return out
}

func scalarFromUint(v uint64) *secp256k1.ModNScalar {
	var s secp256k1.ModNScalar
	s.SetInt(uint32(v)) // indices / small ints only
	return &s
}

// randScalarFrom draws a uniform non-zero scalar from the injected reader, using
// the same rejection sampling as threshold.randScalar (but RNG-injectable so the
// whole DKG is deterministic under a seeded reader — needed for reproducible tests).
func randScalarFrom(r io.Reader) (*secp256k1.ModNScalar, error) {
	for {
		var b [32]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return nil, err
		}
		var s secp256k1.ModNScalar
		if s.SetBytes(&b) == 0 && !s.IsZero() {
			return &s, nil
		}
	}
}

// compressCopy compresses a point without mutating the caller's point.
func compressCopy(p *secp256k1.JacobianPoint) []byte {
	q := *p
	q.ToAffine()
	return secp256k1.NewPublicKey(&q.X, &q.Y).SerializeCompressed()
}

func parsePoint(b []byte) (*secp256k1.JacobianPoint, error) {
	pk, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return nil, err
	}
	var j secp256k1.JacobianPoint
	pk.AsJacobian(&j)
	return &j, nil
}

// dealsToAll reports whether dealing d supplied a (non-nil) point-to-point share to
// every party — a well-formedness precondition so Finalize's share-sum never
// dereferences a missing Shares[m] entry from an untrusted dealer.
func dealsToAll(d *Dealing, parties []*Party) bool {
	for _, q := range parties {
		if d.Shares[q.Index] == nil {
			return false
		}
	}
	return true
}

func (p *Party) victim() uint64 {
	for _, m := range p.all {
		if m != p.Index {
			return m
		}
	}
	return p.Index
}
