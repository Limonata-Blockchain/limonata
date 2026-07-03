package dkg

import (
	"bytes"
	crand "crypto/rand"
	"io"
	mrand "math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// seeded returns a deterministic io.Reader so a DKG run is reproducible.
func seeded(seed int64) io.Reader { return mrand.New(mrand.NewSource(seed)) }

// decryptWith runs the threshold decryption path on a subset of a Result's shares
// (selected by position) and returns the recovered plaintext (or an error).
func decryptWith(t *testing.T, res *Result, ct *threshold.Ciphertext, positions []int) ([]byte, error) {
	t.Helper()
	ds := make([]*threshold.DecryptShare, 0, len(positions))
	for _, p := range positions {
		d, err := threshold.ComputeShare(res.Shares[p], ct)
		if err != nil {
			t.Fatalf("ComputeShare: %v", err)
		}
		ds = append(ds, d)
	}
	shared, err := threshold.Recover(ds)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	return threshold.Decrypt(shared, ct)
}

func contains(xs []uint64, v uint64) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// (a) COMPATIBILITY — the money test: DKG output is a drop-in for threshold.Setup.
// Feed the DKG pub into threshold.Encrypt, then decrypt with any t of the n DKG
// shares via the UNMODIFIED threshold.ComputeShare/Recover/Decrypt.
func TestCompatibilityDropIn(t *testing.T) {
	parties := NewParties(5, 3)
	res, err := RunDKG(parties, crand.Reader)
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	if len(res.Pub) != 33 {
		t.Fatalf("pub not a 33-byte compressed point: %d", len(res.Pub))
	}
	if len(res.Shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(res.Shares))
	}

	msg := []byte("front-run THIS, searchers — DKG-keyed encrypted mempool 🍋")
	ct, err := threshold.Encrypt(res.Pub, msg)
	if err != nil {
		t.Fatalf("threshold.Encrypt on DKG pub: %v", err)
	}
	// any 3 of the 5 DKG shares
	got, err := decryptWith(t, res, ct, []int{0, 2, 4})
	if err != nil {
		t.Fatalf("decrypt with t DKG shares failed: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, msg)
	}
}

// (b) THRESHOLD — any t shares decrypt; any t-1 shares do NOT recover the secret.
func TestThreshold(t *testing.T) {
	res, err := RunDKG(NewParties(5, 3), crand.Reader)
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	msg := []byte("threshold means threshold")
	ct, err := threshold.Encrypt(res.Pub, msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// two DIFFERENT qualifying triples both decrypt.
	for _, triple := range [][]int{{0, 1, 2}, {1, 3, 4}} {
		got, err := decryptWith(t, res, ct, triple)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("t shares %v should decrypt: got=%q err=%v", triple, got, err)
		}
	}

	// t-1 = 2 shares must NOT recover the shared secret: AES-GCM auth must fail.
	for _, pair := range [][]int{{0, 1}, {2, 4}} {
		if got, err := decryptWith(t, res, ct, pair); err == nil {
			t.Fatalf("t-1 shares %v unexpectedly decrypted to %q", pair, got)
		}
	}
}

// (c) NO MASTER SECRET — the DKG never assembles msk = Σ s_i as a scalar. This is a
// STRUCTURAL guarantee: Result carries no top-level scalar field, msk*G is built by
// summing commitment POINTS (V_0), and the shares are a valid sharing of that pub
// (each Y_m = X_m*G matches the public commitments) — all without ever forming msk.
func TestNoMasterSecretAssembled(t *testing.T) {
	res, err := RunDKG(NewParties(5, 3), crand.Reader)
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}

	// Structural: Result exposes no scalar (msk would be a scalar) and no field
	// named like a master secret.
	scalarPtr := reflect.TypeOf((*secp256k1.ModNScalar)(nil))
	scalarVal := reflect.TypeOf(secp256k1.ModNScalar{})
	rt := reflect.TypeOf(*res)
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.Type == scalarPtr || f.Type == scalarVal {
			t.Fatalf("Result exposes top-level scalar field %q — msk must never be assembled", f.Name)
		}
		n := strings.ToLower(f.Name)
		if strings.Contains(n, "master") || strings.Contains(n, "msk") || strings.Contains(n, "secret") {
			t.Fatalf("Result has a master-secret-looking field %q", f.Name)
		}
	}

	// msk*G was assembled from commitment POINTS: pub == compress(V_0).
	if !bytes.Equal(res.Pub, compressCopy(&res.PublicCommitments[0])) {
		t.Fatal("pub != compress(V_0): msk*G was not built from the commitment points")
	}

	// The shares are a consistent Shamir sharing of pub WITHOUT msk ever existing:
	// each party's public share key X_m*G must equal SharePubKey(commitments, m).
	for _, sh := range res.Shares {
		var Ymfromshare secp256k1.JacobianPoint
		secp256k1.ScalarBaseMultNonConst(sh.Xi, &Ymfromshare)
		Ympublic := SharePubKey(res.PublicCommitments, sh.Index)
		if !bytes.Equal(compressCopy(&Ymfromshare), compressCopy(Ympublic)) {
			t.Fatalf("share %d not consistent with public commitments", sh.Index)
		}
	}
}

// (d) MALICIOUS DEALER — a party that deals a share inconsistent with its
// commitments is detected and disqualified, and the DKG still completes (|QUAL|>=t).
func TestMaliciousDealerDisqualified(t *testing.T) {
	parties := NewParties(5, 3)
	parties[0].MakeMalicious() // party index 1 cheats
	res, err := RunDKG(parties, crand.Reader)
	if err != nil {
		t.Fatalf("DKG should still complete with |QUAL|>=t: %v", err)
	}
	if !contains(res.Disqualified, 1) {
		t.Fatalf("malicious dealer 1 not disqualified: disq=%v", res.Disqualified)
	}
	if contains(res.Qual, 1) {
		t.Fatalf("malicious dealer 1 still in QUAL: %v", res.Qual)
	}
	if len(res.Qual) != 4 {
		t.Fatalf("expected |QUAL|=4, got %d (%v)", len(res.Qual), res.Qual)
	}
	for _, sh := range res.Shares {
		if sh.Index == 1 {
			t.Fatal("disqualified party 1 must not receive a final share")
		}
	}

	// The surviving key still works: any 3 of the 4 QUAL shares decrypt.
	msg := []byte("QUAL survives one bad dealer")
	ct, err := threshold.Encrypt(res.Pub, msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := decryptWith(t, res, ct, []int{0, 1, 2})
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("post-disqualification decrypt failed: got=%q err=%v", got, err)
	}
}

// (e) MALICIOUS DECRYPTOR — a tampered partial decryption is rejected by
// VerifyDecryptShare; an honest one passes. Also a wrong Y and a forged proof fail.
func TestMaliciousDecryptorRejected(t *testing.T) {
	res, err := RunDKG(NewParties(5, 3), crand.Reader)
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	msg := []byte("prove your partial")
	ct, err := threshold.Encrypt(res.Pub, msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	share := res.Shares[0]
	ds, proof, err := ProveDecryptShare(share, ct, crand.Reader)
	if err != nil {
		t.Fatalf("ProveDecryptShare: %v", err)
	}
	Y := SharePubKey(res.PublicCommitments, share.Index)

	// honest partial + proof verifies.
	if !VerifyDecryptShare(ct.A, ds, Y, proof) {
		t.Fatal("honest DecryptShare rejected by VerifyDecryptShare")
	}

	// tampered D (valid encoding, wrong scalar) is rejected.
	wrongXi := new(secp256k1.ModNScalar)
	wrongXi.Set(share.Xi).Add(scalarFromUint(1))
	badDs, err := threshold.ComputeShare(threshold.Share{Index: share.Index, Xi: wrongXi}, ct)
	if err != nil {
		t.Fatalf("ComputeShare: %v", err)
	}
	if VerifyDecryptShare(ct.A, badDs, Y, proof) {
		t.Fatal("tampered DecryptShare accepted")
	}

	// honest D against the WRONG public share key is rejected.
	Yother := SharePubKey(res.PublicCommitments, res.Shares[1].Index)
	if VerifyDecryptShare(ct.A, ds, Yother, proof) {
		t.Fatal("DecryptShare accepted against wrong Y")
	}

	// forged proof (tweaked response) is rejected.
	badZ := new(secp256k1.ModNScalar)
	badZ.Set(proof.Z).Add(scalarFromUint(1))
	if VerifyDecryptShare(ct.A, ds, Y, &DLEQProof{C: proof.C, Z: badZ}) {
		t.Fatal("forged proof accepted")
	}
}

// (f) RE-RUN INDEPENDENCE — deterministic under an injected RNG (same seed => same
// pub), and a fresh run yields an INDEPENDENT key (different seed => different pub,
// and run-1 shares cannot decrypt a run-2 ciphertext).
func TestRerunIndependence(t *testing.T) {
	run1a, err := RunDKG(NewParties(5, 3), seeded(1))
	if err != nil {
		t.Fatalf("run1a: %v", err)
	}
	run1b, err := RunDKG(NewParties(5, 3), seeded(1))
	if err != nil {
		t.Fatalf("run1b: %v", err)
	}
	// determinism: identical seed => identical pub.
	if !bytes.Equal(run1a.Pub, run1b.Pub) {
		t.Fatal("DKG not deterministic under injected RNG (same seed gave different pub)")
	}

	run2, err := RunDKG(NewParties(5, 3), seeded(2))
	if err != nil {
		t.Fatalf("run2: %v", err)
	}
	// independence: different seed => different pub.
	if bytes.Equal(run1a.Pub, run2.Pub) {
		t.Fatal("re-run produced the SAME pub — keys are not independent")
	}

	// run-1 shares cannot decrypt a run-2 ciphertext.
	msg := []byte("run 2 only")
	ct2, err := threshold.Encrypt(run2.Pub, msg)
	if err != nil {
		t.Fatalf("Encrypt under run2: %v", err)
	}
	if got, err := decryptWith(t, run1a, ct2, []int{0, 2, 4}); err == nil {
		t.Fatalf("run-1 shares decrypted a run-2 ciphertext: %q", got)
	}
}
