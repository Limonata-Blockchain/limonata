package webauthn

import (
	"crypto/sha256"
	"testing"
)

// TestSimulatedAuthenticatorRoundTrip proves the simulated client signer and the
// on-chain verifier agree on the happy path, that the packed-assertion codec is
// lossless, and that every tamper is rejected with the expected sentinel error.
func TestSimulatedAuthenticatorRoundTrip(t *testing.T) {
	auth, err := NewSimulatedAuthenticator("limonata.xyz")
	if err != nil {
		t.Fatal(err)
	}
	pub := auth.CompressedPubKey()
	if len(pub) != 33 {
		t.Fatalf("expected 33-byte compressed pubkey, got %d", len(pub))
	}

	challenge := sha256.Sum256([]byte("the-tx-direct-sign-bytes"))
	as, err := auth.Sign(challenge[:], "https://limonata.xyz", true)
	if err != nil {
		t.Fatal(err)
	}

	// Happy path.
	if err := VerifyAssertion(pub, as.Signature, as.AuthenticatorData, as.ClientDataJSON, challenge[:], true); err != nil {
		t.Fatalf("happy-path verify failed: %v", err)
	}

	// Codec is lossless: pack -> recognize -> unpack -> still verifies.
	blob := as.Marshal()
	if !IsWebAuthnSig(blob) {
		t.Fatal("packed blob not recognized as a WebAuthn signature")
	}
	got, err := UnmarshalAssertion(blob)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := VerifyAssertion(pub, got.Signature, got.AuthenticatorData, got.ClientDataJSON, challenge[:], true); err != nil {
		t.Fatalf("verify after codec roundtrip failed: %v", err)
	}

	// Wrong challenge (replay against a different tx) -> rejected.
	evil := sha256.Sum256([]byte("a-different-tx"))
	if err := VerifyAssertion(pub, got.Signature, got.AuthenticatorData, got.ClientDataJSON, evil[:], true); err != ErrChallenge {
		t.Fatalf("expected ErrChallenge, got %v", err)
	}

	// UV required but the authenticator did not verify the user -> rejected,
	// but the same assertion is accepted when UV is not required.
	noUV, err := auth.Sign(challenge[:], "https://limonata.xyz", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAssertion(pub, noUV.Signature, noUV.AuthenticatorData, noUV.ClientDataJSON, challenge[:], true); err != ErrUserVerified {
		t.Fatalf("expected ErrUserVerified, got %v", err)
	}
	if err := VerifyAssertion(pub, noUV.Signature, noUV.AuthenticatorData, noUV.ClientDataJSON, challenge[:], false); err != nil {
		t.Fatalf("UV-not-required path failed: %v", err)
	}

	// Wrong public key -> rejected.
	other, _ := NewSimulatedAuthenticator("limonata.xyz")
	if err := VerifyAssertion(other.CompressedPubKey(), got.Signature, got.AuthenticatorData, got.ClientDataJSON, challenge[:], true); err != ErrSignature {
		t.Fatalf("expected ErrSignature for wrong key, got %v", err)
	}

	// Tampered authenticatorData (attacker drops the UV flag) breaks the signature.
	tampered := append([]byte{}, got.AuthenticatorData...)
	tampered[32] = flagUserPresent
	if err := VerifyAssertion(pub, got.Signature, tampered, got.ClientDataJSON, challenge[:], false); err != ErrSignature {
		t.Fatalf("expected ErrSignature for tampered authData, got %v", err)
	}
}

func TestNonWebAuthnBlobIgnored(t *testing.T) {
	if IsWebAuthnSig([]byte("a normal secp256k1 signature blob")) {
		t.Fatal("false positive on a non-WebAuthn signature")
	}
	if _, err := UnmarshalAssertion([]byte("xx")); err == nil {
		t.Fatal("expected error decoding a too-short blob")
	}
}
