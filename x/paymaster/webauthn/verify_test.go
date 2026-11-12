package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

// makeAssertionRP builds a valid WebAuthn assertion for the given challenge,
// relying-party id, and origin.
func makeAssertionRP(t *testing.T, priv *ecdsa.PrivateKey, challenge []byte, flags byte, rpID, origin string) (pub, sig, authData, clientDataJSON []byte) {
	t.Helper()
	cd := clientData{Type: "webauthn.get", Challenge: base64.RawURLEncoding.EncodeToString(challenge), Origin: origin}
	clientDataJSON, _ = json.Marshal(cd)
	rpHash := sha256.Sum256([]byte(rpID))
	authData = make([]byte, 37) // 32 rpIdHash + 1 flags + 4 counter
	copy(authData[:32], rpHash[:])
	authData[32] = flags
	cdHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	sig, _ = ecdsa.SignASN1(rand.Reader, priv, digest[:])
	sig, _ = NormalizeLowS(sig) // reference client behavior; Go does not guarantee low-s
	pub = elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y)
	return
}

// makeAssertion keeps the original helper shape: default RP + origin.
func makeAssertion(t *testing.T, priv *ecdsa.PrivateKey, challenge []byte, flags byte) (pub, sig, authData, clientDataJSON []byte) {
	t.Helper()
	return makeAssertionRP(t, priv, challenge, flags, "limonata.xyz", "https://limonata.xyz")
}

// rpOpts pins the given RP id + origin allowlist (the production configuration).
func rpOpts(rpID string, origins ...string) VerifyOptions {
	h := sha256.Sum256([]byte(rpID))
	return VerifyOptions{RequireUserVerified: true, ExpectedRPIDHash: h[:], AllowedOrigins: origins}
}

// uvOpts skips RP binding (the pre-activation / unset-params configuration).
func uvOpts(requireUV bool) VerifyOptions {
	return VerifyOptions{RequireUserVerified: requireUV}
}

func TestVerifyAssertionValid(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx-sign-bytes"))
	pub, sig, ad, cdj := makeAssertion(t, priv, ch[:], flagUserPresent|flagUserVerified)
	if err := VerifyAssertion(pub, sig, ad, cdj, ch[:], rpOpts("limonata.xyz", "https://limonata.xyz")); err != nil {
		t.Fatalf("valid assertion rejected: %v", err)
	}
	// also works with uncompressed pubkey
	pubU := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y) //nolint:staticcheck
	if err := VerifyAssertion(pubU, sig, ad, cdj, ch[:], rpOpts("limonata.xyz", "https://limonata.xyz")); err != nil {
		t.Fatalf("valid assertion (uncompressed key) rejected: %v", err)
	}
	// and with RP binding skipped (params unset)
	if err := VerifyAssertion(pub, sig, ad, cdj, ch[:], uvOpts(true)); err != nil {
		t.Fatalf("valid assertion (no RP binding) rejected: %v", err)
	}
}

func TestVerifyAssertionChallengeMismatch(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx-A"))
	pub, sig, ad, cdj := makeAssertion(t, priv, ch[:], flagUserPresent|flagUserVerified)
	other := sha256.Sum256([]byte("tx-B"))
	if err := VerifyAssertion(pub, sig, ad, cdj, other[:], uvOpts(true)); err != ErrChallenge {
		t.Fatalf("want ErrChallenge, got %v", err)
	}
}

func TestVerifyAssertionBadSig(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx"))
	pub, sig, ad, cdj := makeAssertion(t, priv, ch[:], flagUserPresent|flagUserVerified)
	sig[len(sig)-1] ^= 0xFF // tamper
	if err := VerifyAssertion(pub, sig, ad, cdj, ch[:], uvOpts(true)); err != ErrSignature {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}

func TestVerifyAssertionWrongKey(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx"))
	_, sig, ad, cdj := makeAssertion(t, priv, ch[:], flagUserPresent|flagUserVerified)
	wrongPub := elliptic.MarshalCompressed(elliptic.P256(), attacker.X, attacker.Y)
	if err := VerifyAssertion(wrongPub, sig, ad, cdj, ch[:], uvOpts(true)); err != ErrSignature {
		t.Fatalf("want ErrSignature for wrong key, got %v", err)
	}
}

func TestVerifyAssertionUserPresence(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx"))
	pub, sig, ad, cdj := makeAssertion(t, priv, ch[:], 0x00) // no UP
	if err := VerifyAssertion(pub, sig, ad, cdj, ch[:], uvOpts(false)); err != ErrUserPresence {
		t.Fatalf("want ErrUserPresence, got %v", err)
	}
}

func TestVerifyAssertionUserVerifiedRequired(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx"))
	pub, sig, ad, cdj := makeAssertion(t, priv, ch[:], flagUserPresent) // UP but not UV
	if err := VerifyAssertion(pub, sig, ad, cdj, ch[:], uvOpts(true)); err != ErrUserVerified {
		t.Fatalf("want ErrUserVerified, got %v", err)
	}
}

// Finding 1: origin outside the allowlist is rejected; a listed origin passes.
func TestVerifyAssertionOriginBinding(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx"))
	pub, sig, ad, cdj := makeAssertionRP(t, priv, ch[:], flagUserPresent|flagUserVerified, "limonata.xyz", "https://evil.com")
	if err := VerifyAssertion(pub, sig, ad, cdj, ch[:], rpOpts("limonata.xyz", "https://limonata.xyz")); err != ErrOrigin {
		t.Fatalf("want ErrOrigin, got %v", err)
	}
	pub, sig, ad, cdj = makeAssertionRP(t, priv, ch[:], flagUserPresent|flagUserVerified, "limonata.xyz", "https://limonata.xyz")
	if err := VerifyAssertion(pub, sig, ad, cdj, ch[:], rpOpts("limonata.xyz", "https://limonata.xyz")); err != nil {
		t.Fatalf("allowed origin rejected: %v", err)
	}
}

// Finding 2: an assertion whose signed rpIdHash is for a different RP is rejected.
func TestVerifyAssertionRPIDBinding(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx"))
	pub, sig, ad, cdj := makeAssertionRP(t, priv, ch[:], flagUserPresent|flagUserVerified, "evil.com", "https://limonata.xyz")
	if err := VerifyAssertion(pub, sig, ad, cdj, ch[:], rpOpts("limonata.xyz", "https://limonata.xyz")); err != ErrRPID {
		t.Fatalf("want ErrRPID, got %v", err)
	}
}

// NormalizeLowS must emit canonical DER even when s is already low: trailing
// garbage after the SEQUENCE (tolerated by encoding/asn1, rejected by the
// chain's strict verifier) must be stripped, and high-s flipped.
func TestNormalizeLowSCanonicalizes(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx"))
	pub, sig, ad, cdj := makeAssertion(t, priv, ch[:], flagUserPresent|flagUserVerified) // already low-s

	dirty := append(append([]byte{}, sig...), 0xDE, 0xAD)
	clean, err := NormalizeLowS(dirty)
	if err != nil {
		t.Fatalf("normalize with trailing bytes: %v", err)
	}
	if len(clean) != len(sig) {
		t.Fatalf("trailing bytes not stripped: %d vs %d", len(clean), len(sig))
	}
	if err := VerifyAssertion(pub, clean, ad, cdj, ch[:], uvOpts(true)); err != nil {
		t.Fatalf("canonicalized signature rejected: %v", err)
	}
}

// Finding 3: the high-s counterpart of a valid signature must be rejected.
func TestVerifyAssertionRejectsHighS(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ch := sha256.Sum256([]byte("tx"))
	pub, sig, ad, cdj := makeAssertion(t, priv, ch[:], flagUserPresent|flagUserVerified)

	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		t.Fatal(err)
	}
	n := elliptic.P256().Params().N
	parsed.S = new(big.Int).Sub(n, parsed.S) // flip to the high-s twin
	highS, err := asn1.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	opts := rpOpts("limonata.xyz", "https://limonata.xyz")
	if err := VerifyAssertion(pub, sig, ad, cdj, ch[:], opts); err != nil {
		t.Fatalf("low-s original rejected: %v", err)
	}
	if err := VerifyAssertion(pub, highS, ad, cdj, ch[:], opts); err != ErrSignature {
		t.Fatalf("want ErrSignature for high-s, got %v", err)
	}
}
