// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package dkg

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// EncKeyPoK is a Schnorr proof of knowledge of the ephemeral scalar r behind a ciphertext's
// A = r*G, BOUND to the submitter and the ciphertext (nonce+body) so it is NON-TRANSFERABLE.
//
// WHY (CRITICAL same-A replay): a decryption share is d_i = x_i*A and the AES key is KDF(x*A),
// so ANY two ciphertexts sharing A share the decryption secret. The on-chain maturity gate ties
// share PUBLICATION to each ciphertext's own decrypt_height, but two same-A ciphertexts have
// INDEPENDENT maturities: an attacker who copies a victim's public A and gets a dummy ciphertext
// (carrying A) to mature EARLIER (a mempool race, or a proposer that delays the victim) obtains
// x*A before the victim's reveal and front-runs it. Binding A to the submitter closes this: the
// attacker cannot forge a PoK for A_victim (it does not know r_victim - Schnorr soundness), and
// cannot replay the victim's PoK because verification recomputes the challenge over the ATTACKER's
// submitter address. So no second ciphertext can ever carry another party's A, and x*A is only
// ever recoverable when the ORIGINAL ciphertext matures - the intended reveal.
type EncKeyPoK struct {
	C *secp256k1.ModNScalar // Fiat-Shamir challenge
	Z *secp256k1.ModNScalar // response z = k + c*r
}

// encPoKContext / encPoKNonceContext domain-separate the challenge and the deterministic nonce
// (distinct domains so the two hashes can never collide).
const (
	encPoKContext      = "limonata/encmempool/enc-pok/v1"
	encPoKNonceContext = "limonata/encmempool/enc-pok-nonce/v1"
)

// EncKeyPoKSize is the fixed wire size of a marshalled proof (two 32-byte scalars).
const EncKeyPoKSize = 64

// writeField hashes a length-prefixed field so distinct (submitter, nonce, body) tuples can never
// collide by concatenation (e.g. submitter||nonce == submitter'||nonce').
func writeField(h interface{ Write([]byte) (int, error) }, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	_, _ = h.Write(l[:])
	_, _ = h.Write(b)
}

// encPoKChallenge is the Fiat-Shamir hash of the transcript, reduced mod q. It binds A, the
// submitter, the ciphertext (nonce+body), and the commitment T.
func encPoKChallenge(a []byte, submitter string, nonce, body []byte, T *secp256k1.JacobianPoint) *secp256k1.ModNScalar {
	h := sha256.New()
	h.Write([]byte(encPoKContext))
	writeField(h, a)
	writeField(h, []byte(submitter))
	writeField(h, nonce)
	writeField(h, body)
	h.Write(compressCopy(T))
	var b [32]byte
	copy(b[:], h.Sum(nil))
	c := new(secp256k1.ModNScalar)
	c.SetBytes(&b) // reduces mod q; identical reduction on prove and verify
	return c
}

// deriveEncPoKNonce derives the Schnorr commitment nonce k DETERMINISTICALLY (RFC6979 style) from
// r and the full transcript, consulting NO external RNG - so k is unique per (r, transcript) and a
// mis-wired RNG can never cause the catastrophic k-reuse that would leak r.
func deriveEncPoKNonce(r *secp256k1.ModNScalar, submitter string, a, nonce, body []byte) *secp256k1.ModNScalar {
	rb := r.Bytes()
	var ctr [4]byte
	for {
		h := sha256.New()
		h.Write([]byte(encPoKNonceContext))
		h.Write(rb[:])
		writeField(h, a)
		writeField(h, []byte(submitter))
		writeField(h, nonce)
		writeField(h, body)
		h.Write(ctr[:])
		var b [32]byte
		copy(b[:], h.Sum(nil))
		var k secp256k1.ModNScalar
		if k.SetBytes(&b) == 0 && !k.IsZero() { // == 0: did not overflow q (unbiased)
			out := new(secp256k1.ModNScalar)
			out.Set(&k)
			for i := range rb { // best-effort wipe of the secret copy
				rb[i] = 0
			}
			return out
		}
		for i := 0; i < len(ctr); i++ {
			ctr[i]++
			if ctr[i] != 0 {
				break
			}
		}
	}
}

// ProveEncKeyPoK proves knowledge of r such that A = r*G, bound to (submitter, nonce, body).
// r is the ephemeral scalar threshold.EncryptWithR returns; the caller must pass the SAME
// submitter it will use on the MsgSubmitEncrypted.
func ProveEncKeyPoK(r *secp256k1.ModNScalar, submitter string, a, nonce, body []byte) *EncKeyPoK {
	k := deriveEncPoKNonce(r, submitter, a, nonce, body)
	var T secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(k, &T) // T = k*G
	c := encPoKChallenge(a, submitter, nonce, body, &T)
	cr := new(secp256k1.ModNScalar)
	cr.Set(c).Mul(r) // c*r
	z := new(secp256k1.ModNScalar)
	z.Set(k).Add(cr) // z = k + c*r
	return &EncKeyPoK{C: c, Z: z}
}

// VerifyEncKeyPoK checks that proof binds a (=A compressed) to submitter+ciphertext. Returns true
// iff the prover knew r with A = r*G for THIS submitter and ciphertext.
func VerifyEncKeyPoK(a []byte, submitter string, nonce, body []byte, proof *EncKeyPoK) bool {
	if proof == nil || proof.C == nil || proof.Z == nil {
		return false
	}
	A, err := parsePoint(a)
	if err != nil {
		return false
	}
	// T' = z*G - c*A
	negC := new(secp256k1.ModNScalar)
	negC.Set(proof.C).Negate()
	var zG, cA, T secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(proof.Z, &zG)
	secp256k1.ScalarMultNonConst(negC, A, &cA)
	secp256k1.AddNonConst(&zG, &cA, &T)
	want := encPoKChallenge(a, submitter, nonce, body, &T)
	return want.Bytes() == proof.C.Bytes()
}

// Marshal serializes the proof as C||Z (two 32-byte big-endian scalars).
func (p *EncKeyPoK) Marshal() []byte {
	if p == nil || p.C == nil || p.Z == nil {
		return nil
	}
	cb := p.C.Bytes()
	zb := p.Z.Bytes()
	out := make([]byte, EncKeyPoKSize)
	copy(out[:32], cb[:])
	copy(out[32:], zb[:])
	return out
}

// ParseEncKeyPoK parses a wire proof, rejecting the wrong length, non-canonical (>= q) scalars,
// and zero scalars.
func ParseEncKeyPoK(b []byte) (*EncKeyPoK, error) {
	if len(b) != EncKeyPoKSize {
		return nil, errors.New("enc-pok: proof must be 64 bytes")
	}
	var cb, zb [32]byte
	copy(cb[:], b[:32])
	copy(zb[:], b[32:])
	c := new(secp256k1.ModNScalar)
	z := new(secp256k1.ModNScalar)
	if c.SetBytes(&cb) != 0 || z.SetBytes(&zb) != 0 {
		return nil, errors.New("enc-pok: non-canonical scalar (>= group order)")
	}
	if c.IsZero() || z.IsZero() {
		return nil, errors.New("enc-pok: zero scalar")
	}
	return &EncKeyPoK{C: c, Z: z}, nil
}

// EncryptWithPoK encrypts msg to the threshold public key pub and returns the ciphertext together
// with a submitter-bound proof of knowledge of its ephemeral key. This is the reference client
// path for the encrypted mempool: the returned pok goes in MsgSubmitEncrypted.Pok.
func EncryptWithPoK(pub, msg []byte, submitter string) (*threshold.Ciphertext, *EncKeyPoK, error) {
	ct, r, err := threshold.EncryptWithR(pub, msg)
	if err != nil {
		return nil, nil, err
	}
	pok := ProveEncKeyPoK(r, submitter, ct.A, ct.Nonce, ct.Body)
	return ct, pok, nil
}
