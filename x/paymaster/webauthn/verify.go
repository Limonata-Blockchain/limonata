// Package webauthn verifies WebAuthn (passkey) assertions over the P-256 curve.
//
// This is the cryptographic core of Limonata's gasless passkey experience: a
// passkey signs `authenticatorData || SHA256(clientDataJSON)` (NOT the raw tx
// sign-bytes), where clientDataJSON carries the challenge. The challenge MUST be
// bound to the transaction's sign-bytes hash. The standard secp256r1 sigverify
// cannot validate this shape, which is why a dedicated verifier is required.
//
// SECURITY: this is audit-mandatory before mainnet. The strict clientDataJSON
// parsing, challenge binding, RP binding (rpIdHash + origin allowlist), low-s
// enforcement, and user-presence checks below are the load-bearing controls;
// do not relax them.
//
// Accepted limitation: the WebAuthn signature counter (authenticatorData[33:37])
// is deliberately NOT evaluated. On-chain counter tracking would require
// per-credential persistent state and breaks multi-device passkeys (iCloud /
// Google-synced credentials report counter 0). Replay is already prevented by
// challenge binding to the tx sign-bytes plus account-sequence enforcement in
// the ante decorator.
package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
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
	ErrClientData   = errors.New("webauthn: invalid clientDataJSON")
	ErrType         = errors.New("webauthn: clientData.type must be webauthn.get")
	ErrChallenge    = errors.New("webauthn: challenge does not bind to the transaction")
	ErrOrigin       = errors.New("webauthn: clientData.origin not allowed")
	ErrAuthData     = errors.New("webauthn: authenticatorData too short")
	ErrRPID         = errors.New("webauthn: authenticatorData rpIdHash mismatch")
	ErrUserPresence = errors.New("webauthn: user-presence flag not set")
	ErrUserVerified = errors.New("webauthn: user-verification flag not set")
	ErrPubKey       = errors.New("webauthn: invalid P-256 public key")
	ErrSignature    = errors.New("webauthn: signature verification failed")
)

// p256HalfOrder is N/2 for the low-s malleability check.
var p256HalfOrder = new(big.Int).Rsh(elliptic.P256().Params().N, 1)

// clientData is the subset of the WebAuthn CollectedClientData we validate.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// VerifyOptions carries the relying-party controls the chain pins in on-chain
// params (x/contest), plus the UV policy.
//
// ExpectedRPIDHash nil/empty and AllowedOrigins empty each SKIP their check.
// That is a rollout convenience only: the activation path (MsgSetPasskeyEnabled)
// refuses to enable the feature without an RP config, so a live chain never
// runs with the checks skipped.
type VerifyOptions struct {
	RequireUserVerified bool
	ExpectedRPIDHash    []byte   // SHA256(rpID); len!=32 = skip
	AllowedOrigins      []string // exact-match allowlist; empty = skip
}

// VerifyAssertion verifies a WebAuthn assertion produced by a passkey.
//
//   - pubKey:            P-256 public key bytes (33-byte compressed or 65-byte uncompressed)
//   - sig:               ASN.1 DER ECDSA signature (as produced by WebAuthn authenticators)
//   - authenticatorData: raw authenticatorData
//   - clientDataJSON:    raw clientDataJSON
//   - expectedChallenge: the value the challenge must equal (e.g. the tx sign-bytes hash)
//   - opts:              RP binding + user-verification policy
//
// Returns nil on success.
func VerifyAssertion(pubKey, sig, authenticatorData, clientDataJSON, expectedChallenge []byte, opts VerifyOptions) error {
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
	if len(opts.AllowedOrigins) > 0 && !originAllowed(cd.Origin, opts.AllowedOrigins) {
		return ErrOrigin
	}
	if len(authenticatorData) < 37 {
		return ErrAuthData
	}
	// RP binding: authenticatorData[0:32] is SHA256(rpId), signed by the authenticator.
	if len(opts.ExpectedRPIDHash) == 32 &&
		subtle.ConstantTimeCompare(authenticatorData[:32], opts.ExpectedRPIDHash) != 1 {
		return ErrRPID
	}
	flags := authenticatorData[32]
	if flags&flagUserPresent == 0 {
		return ErrUserPresence
	}
	if opts.RequireUserVerified && flags&flagUserVerified == 0 {
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
	// Low-s enforcement: (r, n-s) verifies too, and the signature is part of the
	// raw tx bytes, so without this the tx hash is malleable by any observer.
	return enforceLowS(sig)
}

func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if origin == a {
			return true
		}
	}
	return false
}

// enforceLowS rejects the high-s twin of an otherwise-valid signature. It runs
// AFTER ecdsa.VerifyASN1, whose strict parser guarantees the DER is minimal and
// fully consumed, so the laxer encoding/asn1 re-parse here cannot disagree.
func enforceLowS(der []byte) error {
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		return ErrSignature
	}
	if parsed.S == nil || parsed.S.Cmp(p256HalfOrder) > 0 {
		return ErrSignature
	}
	return nil
}

// NormalizeLowS rewrites an ASN.1 DER ECDSA signature to its low-s form
// (s > n/2 becomes n-s; (r, n-s) verifies iff (r, s) does).
//
// CLIENTS MUST CALL THIS before submitting an assertion: neither Go's
// crypto/ecdsa nor real WebAuthn authenticators guarantee low-s output, and the
// on-chain verifier rejects high-s signatures to prevent tx-hash malleability.
func NormalizeLowS(der []byte) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		return nil, ErrSignature
	}
	if parsed.R == nil || parsed.S == nil || parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
		return nil, ErrSignature
	}
	if parsed.S.Cmp(p256HalfOrder) > 0 {
		parsed.S = new(big.Int).Sub(elliptic.P256().Params().N, parsed.S)
	}
	// Always re-marshal (even when s was already low) so lax input encodings —
	// e.g. trailing bytes after the SEQUENCE, which encoding/asn1 tolerates but
	// the chain's strict verifier rejects — come out canonical.
	out, err := asn1.Marshal(parsed)
	if err != nil {
		return nil, ErrSignature
	}
	return out, nil
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
