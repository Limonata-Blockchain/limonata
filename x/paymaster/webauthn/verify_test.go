package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// makeAssertion builds a valid WebAuthn assertion for the given challenge.
func makeAssertion(t *testing.T, priv *ecdsa.PrivateKey, challenge []byte, flags byte) (pub, sig, authData, clientDataJSON []byte) {
	t.Helper()
	cd := clientData{Type: "webauthn.get", Challenge: base64.RawURLEncoding.EncodeToString(challenge), Origin: "https://limonata.xyz"}
	clientDataJSON, _ = json.Marshal(cd)
	authData = make([]byte, 37) // 32 rpIdHash + 1 flags + 4 counter
	authData[32] = flags
	cdHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	sig, _ = ecdsa.SignASN1(rand.Reader, priv, digest[:])
	pub = elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y)
	return
}

func TestVerifyAssertionValid(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx-sign-bytes"))
	pub, sig, ad, cdj := makeAssertion(t, priv, ch[:], flagUserPresent|flagUserVerified)
	if err := VerifyAssertion(pub, sig, ad, cdj, ch[:], true); err != nil {
		t.Fatalf("valid assertion rejected: %v", err)
	}
	// also works with uncompressed pubkey
	pubU := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y) //nolint:staticcheck
	if err := VerifyAssertion(pubU, sig, ad, cdj, ch[:], true); err != nil {
		t.Fatalf("valid assertion (uncompressed key) rejected: %v", err)
	}
}

func TestVerifyAssertionChallengeMismatch(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx-A"))
	pub, sig, ad, cdj := makeAssertion(t, priv, ch[:], flagUserPresent|flagUserVerified)
	other := sha256.Sum256([]byte("tx-B"))
	if err := VerifyAssertion(pub, sig, ad, cdj, other[:], true); err != ErrChallenge {
		t.Fatalf("want ErrChallenge, got %v", err)
	}
}

func TestVerifyAssertionBadSig(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx"))
	pub, sig, ad, cdj := makeAssertion(t, priv, ch[:], flagUserPresent|flagUserVerified)
	sig[len(sig)-1] ^= 0xFF // tamper
	if err := VerifyAssertion(pub, sig, ad, cdj, ch[:], true); err != ErrSignature {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}

func TestVerifyAssertionWrongKey(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx"))
	_, sig, ad, cdj := makeAssertion(t, priv, ch[:], flagUserPresent|flagUserVerified)
	wrongPub := elliptic.MarshalCompressed(elliptic.P256(), attacker.X, attacker.Y)
	if err := VerifyAssertion(wrongPub, sig, ad, cdj, ch[:], true); err != ErrSignature {
		t.Fatalf("want ErrSignature for wrong key, got %v", err)
	}
}

func TestVerifyAssertionUserPresence(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx"))
	pub, sig, ad, cdj := makeAssertion(t, priv, ch[:], 0x00) // no UP
	if err := VerifyAssertion(pub, sig, ad, cdj, ch[:], false); err != ErrUserPresence {
		t.Fatalf("want ErrUserPresence, got %v", err)
	}
}

func TestVerifyAssertionUserVerifiedRequired(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx"))
	pub, sig, ad, cdj := makeAssertion(t, priv, ch[:], flagUserPresent) // UP but not UV
	if err := VerifyAssertion(pub, sig, ad, cdj, ch[:], true); err != ErrUserVerified {
		t.Fatalf("want ErrUserVerified, got %v", err)
	}
}
