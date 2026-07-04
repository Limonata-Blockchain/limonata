package dkg

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// These are REGRESSION tests for the fixes applied after the internal crypto audit of
// x/encmempool/dkg (see AUDIT.md). Each test would PASS on the fixed tree and FAIL on
// the pre-fix tree.

// ---------------------------------------------------------------------------
// FIX 1 (audit finding: "Complaint framing" — MEDIUM).
// Finalize must NOT disqualify a provably-honest dealer on a complaint whose accuser
// index (By) is not a real party. Pre-fix, an out-of-range By was a nil-map miss that
// VerifyShare read as a "bad share", evicting the honest dealer and (with enough forged
// complaints) driving |QUAL| < t.
// ---------------------------------------------------------------------------
func TestAuditFix_OutOfRangeComplaintCannotFrameHonestDealer(t *testing.T) {
	parties := NewParties(5, 3)
	dealings, err := DealerRound(parties, crand.Reader)
	if err != nil {
		t.Fatalf("DealerRound: %v", err)
	}

	// Dealer 1 is provably honest: every real share it dealt verifies against its own
	// commitments.
	d1 := dealings[0]
	for _, p := range parties {
		if !VerifyShare(d1.Commitments, p.Index, d1.Shares[p.Index]) {
			t.Fatalf("precondition: dealer 1's share to %d does not verify", p.Index)
		}
	}

	// Every out-of-range accuser index must be IGNORED, leaving the honest dealer in QUAL.
	for _, by := range []uint64{0, 6, 99, 1 << 32, (1 << 32) + 1, 1 << 40} {
		res, err := Finalize(parties, dealings, []Complaint{{By: by, Against: 1}})
		if err != nil {
			t.Fatalf("Finalize errored on forged complaint By=%d: %v", by, err)
		}
		if contains(res.Disqualified, 1) {
			t.Fatalf("FRAMING: forged complaint By=%d disqualified honest dealer 1 (disq=%v)", by, res.Disqualified)
		}
		if len(res.Qual) != 5 {
			t.Fatalf("forged complaint By=%d shrank QUAL to %v", by, res.Qual)
		}
	}

	// Escalation: forging enough out-of-range complaints must NOT abort the DKG.
	res, err := Finalize(parties, dealings, []Complaint{{By: 98, Against: 1}, {By: 99, Against: 2}, {By: 100, Against: 3}})
	if err != nil {
		t.Fatalf("forged complaints aborted the DKG (liveness DoS not fixed): %v", err)
	}
	if len(res.Qual) != 5 {
		t.Fatalf("forged complaints shrank QUAL: %v", res.Qual)
	}
}

// A LEGITIMATE in-range complaint against a genuinely-cheating dealer must still
// disqualify it — the framing fix must not neuter the real complaint mechanism.
func TestAuditFix_LegitimateComplaintStillDisqualifies(t *testing.T) {
	parties := NewParties(5, 3)
	parties[0].MakeMalicious() // dealer 1 deals one provably-bad share
	res, err := RunDKG(parties, crand.Reader)
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	if !contains(res.Disqualified, 1) {
		t.Fatalf("genuinely-malicious dealer 1 NOT disqualified: disq=%v", res.Disqualified)
	}
	if len(res.Qual) != 4 {
		t.Fatalf("expected |QUAL|=4 after one real disqualification, got %v", res.Qual)
	}
}

// ---------------------------------------------------------------------------
// FIX 2 (audit findings: "Fiat-Shamir omits keyper index" + "RecoverVerified
// distinct-index invariant defeated by uint64->uint32 truncation" — MEDIUM).
// A single observed honest partial replayed under a colliding out-of-range index
// (idx and idx+2^32 reduce to the same evaluation point) must NOT be counted as a
// second distinct partial, and RecoverVerified must never silently return a wrong
// secret from fewer than t genuine partials.
// ---------------------------------------------------------------------------
func TestAuditFix_TruncationReplayRejected(t *testing.T) {
	res, err := RunDKGSecure(NewParties(5, 3))
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	msg := []byte("no silent wrong secret from a replayed partial")
	ct, err := threshold.Encrypt(res.Pub, msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// honest partial + proof for keyper index 1.
	ds1, pf1, err := ProveDecryptShare(res.Shares[0], ct)
	if err != nil {
		t.Fatalf("prove 1: %v", err)
	}
	idx1 := res.Shares[0].Index
	collided := idx1 + (1 << 32)

	// The mod-2^32 index collision still exists at the evaluation layer: the fix is at
	// the trust boundary, not a change to the drop-in evaluation convention.
	if !bytes.Equal(compressCopy(SharePubKey(res.PublicCommitments, idx1)),
		compressCopy(SharePubKey(res.PublicCommitments, collided))) {
		t.Fatal("precondition: expected SharePubKey(idx) == SharePubKey(idx+2^32)")
	}

	// (a) transcript-binding: the honest proof for idx1 must NOT verify at the collided
	// index, even though Y is byte-identical. (Pre-fix the challenge omitted the index
	// and this ACCEPTED.)
	Ycollided := SharePubKey(res.PublicCommitments, collided)
	replayDs := &threshold.DecryptShare{Index: collided, D: ds1.D}
	if VerifyDecryptShare(ct.A, replayDs, Ycollided, pf1) {
		t.Fatal("SECURITY REGRESSION: honest proof accepted at a colliding out-of-range index")
	}
	// sanity: it still verifies at its real index.
	Y1 := SharePubKey(res.PublicCommitments, idx1)
	if !VerifyDecryptShare(ct.A, ds1, Y1, pf1) {
		t.Fatal("honest proof rejected at its own index")
	}

	// (b) end-to-end: {orig(idx1), replay(idx1+2^32, same D+proof), other(idx2)} at t=3
	// must ERROR (only 2 genuine partials), never silently return a wrong secret.
	ds2, pf2, err := ProveDecryptShare(res.Shares[1], ct)
	if err != nil {
		t.Fatalf("prove 2: %v", err)
	}
	shared, err := RecoverVerified(res.PublicCommitments, ct.A, 3, []VerifiedShare{
		{Share: ds1, Proof: pf1},
		{Share: replayDs, Proof: pf1},
		{Share: ds2, Proof: pf2},
	})
	if err == nil {
		// If it did not error, prove it at least did not decrypt (defence in depth).
		if pt, derr := threshold.Decrypt(shared, ct); derr == nil {
			t.Fatalf("SECURITY REGRESSION: replayed partial produced a decrypting secret: %q", pt)
		}
		t.Fatal("SECURITY REGRESSION: RecoverVerified returned a secret from < t genuine partials")
	}

	// positive: three genuinely-distinct verified partials still recover the plaintext.
	ds3, pf3, err := ProveDecryptShare(res.Shares[2], ct)
	if err != nil {
		t.Fatalf("prove 3: %v", err)
	}
	good, err := RecoverVerified(res.PublicCommitments, ct.A, 3, []VerifiedShare{
		{Share: ds1, Proof: pf1}, {Share: ds2, Proof: pf2}, {Share: ds3, Proof: pf3},
	})
	if err != nil {
		t.Fatalf("RecoverVerified rejected an honest quorum: %v", err)
	}
	pt, err := threshold.Decrypt(good, ct)
	if err != nil || !bytes.Equal(pt, msg) {
		t.Fatalf("honest quorum failed to decrypt: got=%q err=%v", pt, err)
	}
}

// ---------------------------------------------------------------------------
// FIX 3 (audit finding: "No t>=1 validation" — LOW). Degenerate threshold must return
// a clean error, not panic in evalPoly (coeffs[-1]).
// ---------------------------------------------------------------------------
func TestAuditFix_ThresholdZeroRejected(t *testing.T) {
	if _, err := DealerRound(NewParties(3, 0), crand.Reader); err == nil {
		t.Fatal("DealerRound(t=0) should return an error, not proceed")
	}
	if _, err := RunDKGSecure(NewParties(3, 0)); err == nil {
		t.Fatal("RunDKGSecure(t=0) should return an error, not panic")
	}
}

// ---------------------------------------------------------------------------
// FIX 4 (audit finding: "SharePubKey panics on empty commitments" — LOW). The exported
// API must return nil, not panic (a chain halt in a consensus context).
// ---------------------------------------------------------------------------
func TestAuditFix_SharePubKeyEmptyNoPanic(t *testing.T) {
	if got := SharePubKey(nil, 1); got != nil {
		t.Fatalf("SharePubKey(nil,1) = %v, want nil", got)
	}
	if got := SharePubKey([]secp256k1.JacobianPoint{}, 1); got != nil {
		t.Fatalf("SharePubKey([],1) = %v, want nil", got)
	}
	for _, m := range SharePubKeys(nil, []uint64{1, 2}) {
		if m != nil {
			t.Fatal("SharePubKeys(nil,...) returned a non-nil entry")
		}
	}
}

// ---------------------------------------------------------------------------
// FIX 5 (audit finding: "ParseShare ignores the SetBytes overflow flag" — LOW). A
// non-canonical (>= q) or zero serialized share must be rejected, not silently reduced.
// q is the secp256k1 group order.
// ---------------------------------------------------------------------------
func TestAuditFix_ParseShareRejectsNonCanonical(t *testing.T) {
	const qHex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"      // q -> reduces to 0
	const qPlus5Hex = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364146" // q+5 -> reduces to 5
	const zeroHex = "0000000000000000000000000000000000000000000000000000000000000000"

	for name, xi := range map[string]string{"xi==q": qHex, "xi==q+5": qPlus5Hex, "xi==0": zeroHex} {
		data := []byte(fmt.Sprintf(`{"index":1,"xi":%q}`, xi))
		if _, err := threshold.ParseShare(data); err == nil {
			t.Fatalf("ParseShare accepted a non-canonical/zero share (%s)", name)
		}
	}

	// positive: a real DKG share round-trips through Marshal/Parse unchanged.
	res, err := RunDKGSecure(NewParties(3, 2))
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	raw, err := threshold.MarshalShare(res.Shares[0])
	if err != nil {
		t.Fatalf("MarshalShare: %v", err)
	}
	back, err := threshold.ParseShare(raw)
	if err != nil {
		t.Fatalf("ParseShare rejected a legitimate share: %v", err)
	}
	if back.Index != res.Shares[0].Index {
		t.Fatalf("round-trip index mismatch: %d != %d", back.Index, res.Shares[0].Index)
	}
	a, b := back.Xi.Bytes(), res.Shares[0].Xi.Bytes()
	if !bytes.Equal(a[:], b[:]) {
		t.Fatal("round-trip Xi mismatch")
	}
}
