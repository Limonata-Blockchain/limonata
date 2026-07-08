package dkg_test

import (
	"testing"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/threshold"
)

func setupCT(t *testing.T, plain, submitter string) (a, nonce, body []byte, pok *dkg.EncKeyPoK) {
	t.Helper()
	pub, _, err := threshold.Setup(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	ct, p, err := dkg.EncryptWithPoK(pub, []byte(plain), submitter)
	if err != nil {
		t.Fatal(err)
	}
	return ct.A, ct.Nonce, ct.Body, p
}

// A well-formed proof verifies for the submitter and ciphertext it was made for.
func TestEncKeyPoK_Valid(t *testing.T) {
	a, nonce, body, pok := setupCT(t, "hello", "cosmos1submitter")
	if !dkg.VerifyEncKeyPoK(a, "cosmos1submitter", nonce, body, pok) {
		t.Fatal("a valid PoK must verify for its own submitter + ciphertext")
	}
	// Round-trips through the wire encoding.
	parsed, err := dkg.ParseEncKeyPoK(pok.Marshal())
	if err != nil {
		t.Fatalf("marshalled PoK must parse: %v", err)
	}
	if !dkg.VerifyEncKeyPoK(a, "cosmos1submitter", nonce, body, parsed) {
		t.Fatal("parsed PoK must verify")
	}
}

// THE same-A replay: an attacker copies a victim's A + PoK and submits under its OWN address.
// Verification must FAIL because the challenge binds the submitter.
func TestEncKeyPoK_SubmitterBinding_RejectsReplay(t *testing.T) {
	a, nonce, body, victimPoK := setupCT(t, "victim tx", "cosmos1victim")

	// The victim's own submission is fine.
	if !dkg.VerifyEncKeyPoK(a, "cosmos1victim", nonce, body, victimPoK) {
		t.Fatal("victim's own PoK must verify")
	}
	// The attacker copies A + the victim's PoK but submits as itself -> rejected.
	if dkg.VerifyEncKeyPoK(a, "cosmos1attacker", nonce, body, victimPoK) {
		t.Fatal("SAME-A REPLAY: a copied PoK must NOT verify under a different submitter")
	}
}

// Tampering with any bound field (A, nonce, body) breaks verification.
func TestEncKeyPoK_TamperRejected(t *testing.T) {
	a, nonce, body, pok := setupCT(t, "payload", "cosmos1s")

	badA := append([]byte{}, a...)
	badA[len(badA)-1] ^= 0x01
	if dkg.VerifyEncKeyPoK(badA, "cosmos1s", nonce, body, pok) {
		t.Fatal("a tampered A must be rejected")
	}
	badNonce := append([]byte{}, nonce...)
	badNonce[0] ^= 0x01
	if dkg.VerifyEncKeyPoK(a, "cosmos1s", badNonce, body, pok) {
		t.Fatal("a tampered nonce must be rejected")
	}
	badBody := append([]byte{}, body...)
	badBody[0] ^= 0x01
	if dkg.VerifyEncKeyPoK(a, "cosmos1s", nonce, badBody, pok) {
		t.Fatal("a tampered body must be rejected")
	}
}

// An attacker cannot forge a PoK for an A it did not create (Schnorr soundness): a proof built
// with a DIFFERENT r (its own ciphertext) does not verify against the victim's A.
func TestEncKeyPoK_ForgeRejected(t *testing.T) {
	victimA, nonce, body, _ := setupCT(t, "victim", "cosmos1x")
	_, _, _, attackerPoK := setupCT(t, "attacker", "cosmos1x") // a proof for a DIFFERENT A
	if dkg.VerifyEncKeyPoK(victimA, "cosmos1x", nonce, body, attackerPoK) {
		t.Fatal("a PoK made for a different A must not verify against the victim's A")
	}
}

// Malformed wire proofs are rejected by ParseEncKeyPoK.
func TestEncKeyPoK_ParseRejectsMalformed(t *testing.T) {
	if _, err := dkg.ParseEncKeyPoK(nil); err == nil {
		t.Fatal("nil proof must be rejected")
	}
	if _, err := dkg.ParseEncKeyPoK(make([]byte, 63)); err == nil {
		t.Fatal("wrong-length proof must be rejected")
	}
	if _, err := dkg.ParseEncKeyPoK(make([]byte, 64)); err == nil {
		t.Fatal("all-zero (zero scalar) proof must be rejected")
	}
}
