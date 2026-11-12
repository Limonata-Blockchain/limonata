package webauthn

import (
	"encoding/binary"
	"errors"
)

// MagicPrefix marks a Cosmos tx signature blob as a packed WebAuthn assertion
// rather than a raw secp256r1 signature. The standard sig-verification path is
// used for everything that does NOT start with this prefix, so normal txs are
// completely unaffected.
var MagicPrefix = []byte("WAS1")

// Assertion is the WebAuthn `navigator.credentials.get` result needed to verify
// a passkey signature: the authenticator data, the clientDataJSON (which carries
// the tx-bound challenge), and the ASN.1 DER ECDSA P-256 signature.
type Assertion struct {
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
}

// Marshal packs the assertion into a tx signature blob:
//
//	MagicPrefix | u32(len authData) | authData | u32(len clientDataJSON) | clientDataJSON | signature
func (a Assertion) Marshal() []byte {
	out := append([]byte{}, MagicPrefix...)
	out = appendField(out, a.AuthenticatorData)
	out = appendField(out, a.ClientDataJSON)
	return append(out, a.Signature...)
}

// IsWebAuthnSig reports whether a tx signature blob is a packed WebAuthn assertion.
func IsWebAuthnSig(b []byte) bool {
	return len(b) >= len(MagicPrefix) && string(b[:len(MagicPrefix)]) == string(MagicPrefix)
}

// UnmarshalAssertion parses a blob produced by Marshal.
func UnmarshalAssertion(b []byte) (*Assertion, error) {
	if !IsWebAuthnSig(b) {
		return nil, errors.New("webauthn: not a WebAuthn assertion")
	}
	p := b[len(MagicPrefix):]
	ad, p, err := readField(p)
	if err != nil {
		return nil, err
	}
	cd, p, err := readField(p)
	if err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, errors.New("webauthn: empty signature")
	}
	return &Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: p}, nil
}

func appendField(out, f []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(f)))
	out = append(out, l[:]...)
	return append(out, f...)
}

func readField(p []byte) (field, rest []byte, err error) {
	if len(p) < 4 {
		return nil, nil, errors.New("webauthn: truncated assertion")
	}
	n := binary.BigEndian.Uint32(p[:4])
	p = p[4:]
	if uint32(len(p)) < n {
		return nil, nil, errors.New("webauthn: assertion field overflow")
	}
	return p[:n], p[n:], nil
}
