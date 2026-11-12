package threshold

import "testing"

// TestRegression_DecryptNonceLengthNoPanic is the primitive-side regression for the
// consensus-halt finding: threshold.Decrypt must return an ERROR (never panic) for a
// nonce whose length != NonceSize. crypto/cipher's gcm.Open panics on any other
// length; on the BeginBlock decrypt path the nonce is attacker-controlled, so a panic
// there halts every validator. A correct 12-byte nonce must still decrypt.
func TestRegression_DecryptNonceLengthNoPanic(t *testing.T) {
	pub, shares, err := Setup(3, 2)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := Encrypt(pub, []byte("secret payload"))
	if err != nil {
		t.Fatal(err)
	}
	var ds []*DecryptShare
	for _, i := range []int{0, 1} {
		d, err := ComputeShare(shares[i], ct)
		if err != nil {
			t.Fatal(err)
		}
		ds = append(ds, d)
	}
	shared, err := Recover(ds)
	if err != nil {
		t.Fatal(err)
	}

	// control: the genuine 12-byte nonce decrypts to the original plaintext.
	if len(ct.Nonce) != NonceSize {
		t.Fatalf("expected nonce size %d, got %d", NonceSize, len(ct.Nonce))
	}
	if _, err := Decrypt(shared, ct); err != nil {
		t.Fatalf("control: valid nonce must decrypt, got %v", err)
	}

	for _, nlen := range []int{0, 1, 11, 13, 16, 32} {
		nlen := nlen
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("nonce len=%d: Decrypt PANICKED (chain-halt vector): %v", nlen, r)
				}
			}()
			bad := &Ciphertext{A: ct.A, Nonce: make([]byte, nlen), Body: ct.Body}
			if _, err := Decrypt(shared, bad); err == nil {
				t.Fatalf("nonce len=%d: expected error, got nil", nlen)
			}
		}()
	}
}
