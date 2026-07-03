// Package threshold is a PROTOTYPE threshold-ElGamal (hash-DH) encryption scheme
// over secp256k1 for the encrypted mempool: a message is encrypted to a single
// threshold public key, and decryption requires >= t of n keyper shares — NO single
// keyper (and no t-1 coalition) can decrypt. That is the anti-MEV property: the tx
// body is unreadable until >= t independent keypers cooperate, which only happens
// AFTER the ciphertext order is fixed.
//
// PROTOTYPE CAVEATS: the key is created by a TRUSTED Shamir setup (no DKG), and this
// code is NOT audited. A production system replaces Setup() with a distributed key
// generation and adds proofs that each keyper's share is correct.
package threshold

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Share is one keyper's secret share f(index). Index must be >= 1.
type Share struct {
	Index uint64
	Xi    *secp256k1.ModNScalar
}

// Ciphertext is the hybrid-encrypted body: A = r*G, plus AES-256-GCM(msg) keyed by
// KDF(r*Y). Decryption needs r*Y = x*A, which only >= t keyper shares can recover.
type Ciphertext struct {
	A     []byte `json:"a"`     // compressed r*G
	Nonce []byte `json:"nonce"` // AES-GCM nonce
	Body  []byte `json:"body"`  // AES-256-GCM ciphertext
}

// DecryptShare is keyper i's partial decryption d_i = x_i * A.
type DecryptShare struct {
	Index uint64 `json:"index"`
	D     []byte `json:"d"` // compressed x_i*A
}

func randScalar() (*secp256k1.ModNScalar, error) {
	for {
		var b [32]byte
		if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
			return nil, err
		}
		var s secp256k1.ModNScalar
		if s.SetBytes(&b) == 0 && !s.IsZero() {
			return &s, nil
		}
	}
}

func scalarFromUint(v uint64) *secp256k1.ModNScalar {
	var s secp256k1.ModNScalar
	s.SetInt(uint32(v)) // share indices / small ints only
	return &s
}

func compress(p *secp256k1.JacobianPoint) []byte {
	p.ToAffine()
	return secp256k1.NewPublicKey(&p.X, &p.Y).SerializeCompressed()
}

func kdf(shared *secp256k1.JacobianPoint) [32]byte {
	return sha256.Sum256(compress(shared))
}

// Setup runs a TRUSTED Shamir (t,n) setup: random secret x, public key Y = x*G, and
// n shares f(1)..f(n) of a degree-(t-1) polynomial with f(0) = x.
func Setup(n, t int) (pub []byte, shares []Share, err error) {
	if t < 1 || t > n {
		return nil, nil, fmt.Errorf("invalid threshold: t=%d n=%d", t, n)
	}
	coeffs := make([]*secp256k1.ModNScalar, t) // coeffs[0] = secret x
	for i := range coeffs {
		if coeffs[i], err = randScalar(); err != nil {
			return nil, nil, err
		}
	}
	var Y secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(coeffs[0], &Y)
	pub = compress(&Y)

	shares = make([]Share, n)
	for i := 1; i <= n; i++ {
		zi := scalarFromUint(uint64(i))
		var acc secp256k1.ModNScalar // Horner: f(zi)
		acc.Set(coeffs[t-1])
		for k := t - 2; k >= 0; k-- {
			acc.Mul(zi).Add(coeffs[k])
		}
		xi := new(secp256k1.ModNScalar)
		xi.Set(&acc)
		shares[i-1] = Share{Index: uint64(i), Xi: xi}
	}
	return pub, shares, nil
}

// Encrypt encrypts msg to the threshold public key pub.
func Encrypt(pub, msg []byte) (*Ciphertext, error) {
	Ypub, err := secp256k1.ParsePubKey(pub)
	if err != nil {
		return nil, err
	}
	var Y secp256k1.JacobianPoint
	Ypub.AsJacobian(&Y)
	r, err := randScalar()
	if err != nil {
		return nil, err
	}
	var A, shared secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(r, &A) // A = r*G
	secp256k1.ScalarMultNonConst(r, &Y, &shared) // shared = r*Y
	key := kdf(&shared)

	gcm, err := newGCM(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return &Ciphertext{A: compress(&A), Nonce: nonce, Body: gcm.Seal(nil, nonce, msg, nil)}, nil
}

// ComputeShare is keyper i computing its partial decryption d_i = x_i * A.
func ComputeShare(s Share, ct *Ciphertext) (*DecryptShare, error) {
	Apub, err := secp256k1.ParsePubKey(ct.A)
	if err != nil {
		return nil, err
	}
	var A, D secp256k1.JacobianPoint
	Apub.AsJacobian(&A)
	secp256k1.ScalarMultNonConst(s.Xi, &A, &D)
	return &DecryptShare{Index: s.Index, D: compress(&D)}, nil
}

// lagrangeAtZero returns λ_i = Π_{j≠i} j/(j-i) (mod n) for index i over the set.
func lagrangeAtZero(i uint64, indices []uint64) *secp256k1.ModNScalar {
	num := scalarFromUint(1)
	den := scalarFromUint(1)
	for _, j := range indices {
		if j == i {
			continue
		}
		sj := scalarFromUint(j)
		num.Mul(sj)
		negI := scalarFromUint(i)
		negI.Negate()
		var diff secp256k1.ModNScalar
		diff.Set(sj).Add(negI) // j - i
		den.Mul(&diff)
	}
	den.InverseNonConst()
	return num.Mul(den)
}

// Recover combines >= t decryption shares via Lagrange into the shared secret x*A.
func Recover(shares []*DecryptShare) (*secp256k1.JacobianPoint, error) {
	if len(shares) == 0 {
		return nil, errors.New("no shares")
	}
	indices := make([]uint64, len(shares))
	for k, s := range shares {
		indices[k] = s.Index
	}
	var acc secp256k1.JacobianPoint
	first := true
	for _, s := range shares {
		Dpub, err := secp256k1.ParsePubKey(s.D)
		if err != nil {
			return nil, err
		}
		var D, term secp256k1.JacobianPoint
		Dpub.AsJacobian(&D)
		secp256k1.ScalarMultNonConst(lagrangeAtZero(s.Index, indices), &D, &term)
		if first {
			acc, first = term, false
			continue
		}
		var sum secp256k1.JacobianPoint
		secp256k1.AddNonConst(&acc, &term, &sum)
		acc = sum
	}
	return &acc, nil
}

// Decrypt recovers msg from the combined shared secret + ciphertext. Returns an
// error if the shared secret is wrong (e.g. < t shares) — AES-GCM authentication.
func Decrypt(shared *secp256k1.JacobianPoint, ct *Ciphertext) ([]byte, error) {
	key := kdf(shared)
	gcm, err := newGCM(key[:])
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, ct.Nonce, ct.Body, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// shareJSON is the on-disk form of a keyper's secret share.
type shareJSON struct {
	Index uint64 `json:"index"`
	Xi    string `json:"xi"` // hex of the 32-byte secret scalar
}

// MarshalShare serializes a keyper's secret share for storage (KEEP SECRET).
func MarshalShare(s Share) ([]byte, error) {
	if s.Xi == nil {
		return nil, errors.New("nil share scalar")
	}
	b := s.Xi.Bytes()
	return json.Marshal(shareJSON{Index: s.Index, Xi: hex.EncodeToString(b[:])})
}

// ParseShare parses a keyper's secret share produced by MarshalShare.
func ParseShare(data []byte) (Share, error) {
	var j shareJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return Share{}, err
	}
	raw, err := hex.DecodeString(j.Xi)
	if err != nil {
		return Share{}, fmt.Errorf("invalid xi hex: %w", err)
	}
	if len(raw) != 32 {
		return Share{}, fmt.Errorf("xi must be 32 bytes, got %d", len(raw))
	}
	var b [32]byte
	copy(b[:], raw)
	xi := new(secp256k1.ModNScalar)
	// AUDIT FIX (canonicality): honour the SetBytes overflow flag. A value >= the group
	// order q was previously reduced mod q and accepted silently, so distinct on-disk
	// encodings (v and v+q) mapped to the same scalar, and Xi=q parsed to a ZERO share.
	// A stored keyper share is always a reduced non-zero scalar, so rejecting an
	// overflow or a zero here only ever rejects a corrupt/non-canonical file.
	if overflow := xi.SetBytes(&b); overflow != 0 {
		return Share{}, errors.New("xi is not a canonical scalar (>= group order)")
	}
	if xi.IsZero() {
		return Share{}, errors.New("xi must be a non-zero scalar")
	}
	if j.Index < 1 {
		return Share{}, errors.New("share index must be >= 1")
	}
	return Share{Index: j.Index, Xi: xi}, nil
}
