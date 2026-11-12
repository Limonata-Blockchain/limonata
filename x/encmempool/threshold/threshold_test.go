package threshold

import (
	"bytes"
	"testing"
)

// >= t shares decrypt correctly (the happy path).
func TestRoundtrip(t *testing.T) {
	pub, shares, err := Setup(5, 3)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("front-run THIS, searchers — encrypted mempool 🍋")
	ct, err := Encrypt(pub, msg)
	if err != nil {
		t.Fatal(err)
	}
	// any 3 of the 5 keypers (use indices 1, 3, 5)
	var ds []*DecryptShare
	for _, k := range []int{0, 2, 4} {
		d, err := ComputeShare(shares[k], ct)
		if err != nil {
			t.Fatal(err)
		}
		ds = append(ds, d)
	}
	shared, err := Recover(ds)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(shared, ct)
	if err != nil {
		t.Fatalf("decrypt failed with t shares: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("roundtrip mismatch: got %q", got)
	}
}

// A DIFFERENT subset of t shares must also decrypt (Lagrange works for any t-subset).
func TestAnyTSubset(t *testing.T) {
	pub, shares, _ := Setup(5, 3)
	msg := []byte("the order is fixed before anyone can read this")
	ct, _ := Encrypt(pub, msg)
	var ds []*DecryptShare
	for _, k := range []int{1, 2, 3} { // indices 2,3,4
		d, _ := ComputeShare(shares[k], ct)
		ds = append(ds, d)
	}
	shared, _ := Recover(ds)
	got, err := Decrypt(shared, ct)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("a different t-subset must decrypt; err=%v got=%q", err, got)
	}
}

// < t shares MUST NOT decrypt — this is the threshold (anti-MEV) guarantee.
func TestInsufficientSharesFails(t *testing.T) {
	pub, shares, _ := Setup(5, 3)
	ct, _ := Encrypt(pub, []byte("secret order flow"))
	var ds []*DecryptShare
	for _, k := range []int{0, 1} { // only 2 < t=3
		d, _ := ComputeShare(shares[k], ct)
		ds = append(ds, d)
	}
	shared, _ := Recover(ds)
	if _, err := Decrypt(shared, ct); err == nil {
		t.Fatal("SECURITY FAILURE: decryption succeeded with t-1 shares — threshold is broken")
	}
}

// A single keyper alone MUST NOT decrypt.
func TestSingleKeyperFails(t *testing.T) {
	pub, shares, _ := Setup(3, 2)
	ct, _ := Encrypt(pub, []byte("one keyper cannot front-run"))
	d, _ := ComputeShare(shares[0], ct)
	shared, _ := Recover([]*DecryptShare{d})
	if _, err := Decrypt(shared, ct); err == nil {
		t.Fatal("SECURITY FAILURE: a single keyper decrypted the message")
	}
}
