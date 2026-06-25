// Package webauthn verifies WebAuthn (passkey) assertions over the P-256 curve.
//
// This is the cryptographic core of Limonata's gasless passkey experience: a
// passkey signs `authenticatorData || SHA256(clientDataJSON)` (NOT the raw tx
// sign-bytes), where clientDataJSON carries the challenge. The challenge MUST be
// bound to the transaction's sign-bytes hash. The standard secp256r1 sigverify
// cannot validate this shape, which is why a dedicated verifier is required.
//
// SECURITY: this is audit-mandatory before mainnet. The strict clientDataJSON
// parsing, challenge binding, and user-presence checks below are the load-bearing
// controls; do not relax them.
package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
)

// WebAuthn authenticatorData flag bits.
const (
	flagUserPresent  = 0x01 // UP
	flagUserVerified = 0x04 // UV
)

var (
	ErrClientData    = errors.New("webauthn: invalid clientDataJSON")
	ErrType          = errors.New("webauthn: clientData.type must be webauthn.get")
	ErrChallenge     = errors.New("webauthn: challenge does not bind to the transaction")
	ErrAuthData      = errors.New("webauthn: authenticatorData too short")
	ErrUserPresence  = errors.New("webauthn: user-presence flag not set")
	ErrUserVerified  = errors.New("webauthn: user-verification flag not set")
	ErrPubKey        = errors.New("webauthn: invalid P-256 public key")
	ErrSignature     = errors.New("webauthn: signature verification failed")
)

// clientData is the subset of the WebAuthn CollectedClientData we validate.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// VerifyAssertion verifies a WebAuthn assertion produced by a passkey.
//
//   - pubKey:            P-256 public key bytes (33-byte compressed or 65-byte uncompressed)
//   - sig:              ASN.1 DER ECDSA signature (as produced by WebAuthn authenticators)
//   - authenticatorData: raw authenticatorData
//   - clientDataJSON:    raw clientDataJSON
//   - expectedChallenge: the value the challenge must equal (e.g. the tx sign-bytes hash)
//   - requireUserVerified: enforce the UV bit (recommended for passkeys)
//
// Returns nil on success.
func VerifyAssertion(pubKey, sig, authenticatorData, clientDataJSON, expectedChallenge []byte, requireUserVerified bool) error {
	var cd clientData
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil {
		return ErrClientData
	}
	if cd.Type != "webauthn.get" {
		return ErrType
	}
	// Challenge binding: WebAuthn encodes the challenge as base64url (no padding).
	if cd.Challenge != base64.RawURLEncoding.EncodeToString(expectedChallenge) {
		return ErrChallenge
	}
	if len(authenticatorData) < 37 {
		return ErrAuthData
	}
	flags := authenticatorData[32]
	if flags&flagUserPresent == 0 {
		return ErrUserPresence
	}
	if requireUserVerified && flags&flagUserVerified == 0 {
		return ErrUserVerified
	}

	pub, err := parseP256(pubKey)
	if err != nil {
		return err
	}
	// The authenticator signs SHA256( authenticatorData || SHA256(clientDataJSON) ).
	cdHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authenticatorData)+len(cdHash))
	signed = append(signed, authenticatorData...)
	signed = append(signed, cdHash[:]...)
	digest := sha256.Sum256(signed)

	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return ErrSignature
	}
	return nil
}

func parseP256(b []byte) (*ecdsa.PublicKey, error) {
	curve := elliptic.P256()
	var x, y *big.Int
	switch len(b) {
	case 33:
		x, y = elliptic.UnmarshalCompressed(curve, b)
	case 65:
		x, y = elliptic.Unmarshal(curve, b) //nolint:staticcheck // stdlib P-256 point decode
	default:
		return nil, ErrPubKey
	}
	if x == nil {
		return nil, ErrPubKey
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
