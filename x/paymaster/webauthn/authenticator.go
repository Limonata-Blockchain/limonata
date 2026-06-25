package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// SimulatedAuthenticator is a SOFTWARE stand-in for a hardware passkey / platform
// authenticator (Touch ID, Windows Hello, a security key). It is NOT a production
// signer: a real deployment NEVER holds the P-256 private key in process. The key
// lives in the device secure element and signing happens through the WebAuthn API
// (navigator.credentials.get) so the private key never leaves the hardware.
//
// It exists for two reasons:
//  1. the ante handler needs a deterministic counterparty in tests, and
//  2. client-SDK authors need an exact, executable reference for the bytes a real
//     authenticator must produce.
//
// Everything it emits is byte-for-byte what VerifyAssertion checks, so it doubles
// as the reference implementation of the experimental client signer logic.
type SimulatedAuthenticator struct {
	priv    *ecdsa.PrivateKey
	rpID    string
	counter uint32
}

// NewSimulatedAuthenticator creates a fresh P-256 credential for the given relying
// party id (e.g. "limonata.xyz").
func NewSimulatedAuthenticator(rpID string) (*SimulatedAuthenticator, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SimulatedAuthenticator{priv: priv, rpID: rpID}, nil
}

// NewSimulatedAuthenticatorFromSeed derives a DETERMINISTIC P-256 credential from a
// seed, so a dev tool can persist the seed and reuse the same passkey across runs.
// This is a test/dev convenience only; it is not how a real authenticator works.
func NewSimulatedAuthenticatorFromSeed(seed []byte, rpID string) (*SimulatedAuthenticator, error) {
	curve := elliptic.P256()
	n := curve.Params().N
	d := new(big.Int).SetBytes(seed)
	// map into [1, n-1]
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	return &SimulatedAuthenticator{priv: priv, rpID: rpID}, nil
}

// PrivateKeyBytes exports the raw P-256 private scalar (dev/test only).
func (a *SimulatedAuthenticator) PrivateKeyBytes() []byte { return a.priv.D.Bytes() }

// CompressedPubKey returns the 33-byte compressed P-256 public key. This is the
// exact byte layout of a cosmos-sdk secp256r1 PubKey, so it is what gets registered
// on the account and what the ante handler feeds to the verifier as pubKey.Bytes().
func (a *SimulatedAuthenticator) CompressedPubKey() []byte {
	return elliptic.MarshalCompressed(elliptic.P256(), a.priv.PublicKey.X, a.priv.PublicKey.Y)
}

// Sign produces a WebAuthn assertion binding `challenge`, which the client sets to
// the SHA-256 of the transaction's SIGN_MODE_DIRECT sign-bytes. origin is the
// WebAuthn origin (e.g. https://limonata.xyz); userVerified sets the UV flag.
//
// The byte construction mirrors a real authenticator exactly:
//   - clientDataJSON carries the challenge as base64url (no padding)
//   - authenticatorData = SHA256(rpID) || flags || counter(4-byte BE)
//   - the signature is ASN.1 DER ECDSA over SHA256(authenticatorData || SHA256(clientDataJSON))
func (a *SimulatedAuthenticator) Sign(challenge []byte, origin string, userVerified bool) (*Assertion, error) {
	clientDataJSON, err := json.Marshal(clientData{
		Type:      "webauthn.get",
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    origin,
	})
	if err != nil {
		return nil, err
	}

	rpIDHash := sha256.Sum256([]byte(a.rpID))
	flags := byte(flagUserPresent)
	if userVerified {
		flags |= flagUserVerified
	}
	a.counter++
	authData := make([]byte, 0, 37)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, byte(a.counter>>24), byte(a.counter>>16), byte(a.counter>>8), byte(a.counter))

	cdHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authData)+len(cdHash))
	signed = append(signed, authData...)
	signed = append(signed, cdHash[:]...)
	digest := sha256.Sum256(signed)

	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])
	if err != nil {
		return nil, err
	}
	return &Assertion{AuthenticatorData: authData, ClientDataJSON: clientDataJSON, Signature: sig}, nil
}
