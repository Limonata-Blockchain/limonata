package dkg

import (
	"crypto/sha256"
	"io"

	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// dleqContext domain-separates the Fiat-Shamir transcript for this scheme.
const dleqContext = "limonata/encmempool/dkg/dleq/v1"

// DLEQProof is a non-interactive Chaum-Pedersen proof of equality of discrete logs:
// it proves knowledge of a scalar x such that D = x*A AND Y = x*G, WITHOUT
// revealing x. Applied to a keyper's partial decryption, it proves the DecryptShare
// D_m = x_m*A was formed with the SAME x_m as the keyper's PUBLIC share key
// Y_m = x_m*G (which anyone can recompute from the DKG public commitments). A bad
// partial is thus rejected BEFORE Recover, closing the "no per-share proof" gap.
type DLEQProof struct {
	C *secp256k1.ModNScalar // Fiat-Shamir challenge
	Z *secp256k1.ModNScalar // response z = k + c*x
}

// ProveDecryptShare computes keyper `share`'s partial decryption of ct (reusing
// threshold.ComputeShare so the on-wire DecryptShare is byte-identical to the
// unproven path) and a DLEQ proof binding it to Y = share.Xi*G. Deterministic in rng.
func ProveDecryptShare(share threshold.Share, ct *threshold.Ciphertext, rng io.Reader) (*threshold.DecryptShare, *DLEQProof, error) {
	ds, err := threshold.ComputeShare(share, ct) // D = x*A, compressed
	if err != nil {
		return nil, nil, err
	}
	A, err := parsePoint(ct.A)
	if err != nil {
		return nil, nil, err
	}
	D, err := parsePoint(ds.D)
	if err != nil {
		return nil, nil, err
	}
	var Y secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(share.Xi, &Y) // Y = x*G

	// Commit: T1 = k*G, T2 = k*A.
	k, err := randScalarFrom(rng)
	if err != nil {
		return nil, nil, err
	}
	var T1, T2 secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(k, &T1)
	secp256k1.ScalarMultNonConst(k, A, &T2)

	// Challenge c = H(ctx, A, D, Y, T1, T2); response z = k + c*x.
	c := dleqChallenge(A, D, &Y, &T1, &T2)
	cx := new(secp256k1.ModNScalar)
	cx.Set(c).Mul(share.Xi) // c*x
	z := new(secp256k1.ModNScalar)
	z.Set(k).Add(cx) // k + c*x
	return ds, &DLEQProof{C: c, Z: z}, nil
}

// VerifyDecryptShare checks proof for the partial decryption D (from ds) against
// the ephemeral A (= ct.A, compressed) and the keyper's public share key Y (from
// SharePubKey over the DKG public commitments). Returns true iff D = x*A for the
// same x with Y = x*G. A tampered D, a wrong Y, or a forged proof all fail.
func VerifyDecryptShare(A []byte, ds *threshold.DecryptShare, Y *secp256k1.JacobianPoint, proof *DLEQProof) bool {
	if proof == nil || proof.C == nil || proof.Z == nil || ds == nil || Y == nil {
		return false
	}
	Apt, err := parsePoint(A)
	if err != nil {
		return false
	}
	Dpt, err := parsePoint(ds.D)
	if err != nil {
		return false
	}
	// Reconstruct T1 = z*G - c*Y and T2 = z*A - c*D using scalar negation of c.
	negC := new(secp256k1.ModNScalar)
	negC.Set(proof.C).Negate()

	var zG, cY, T1 secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(proof.Z, &zG)
	secp256k1.ScalarMultNonConst(negC, Y, &cY)
	secp256k1.AddNonConst(&zG, &cY, &T1)

	var zA, cD, T2 secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(proof.Z, Apt, &zA)
	secp256k1.ScalarMultNonConst(negC, Dpt, &cD)
	secp256k1.AddNonConst(&zA, &cD, &T2)

	want := dleqChallenge(Apt, Dpt, Y, &T1, &T2)
	a := want.Bytes()
	b := proof.C.Bytes()
	return a == b
}

// dleqChallenge is the Fiat-Shamir hash of the transcript, reduced mod q.
func dleqChallenge(A, D, Y, T1, T2 *secp256k1.JacobianPoint) *secp256k1.ModNScalar {
	h := sha256.New()
	h.Write([]byte(dleqContext))
	h.Write(compressCopy(A))
	h.Write(compressCopy(D))
	h.Write(compressCopy(Y))
	h.Write(compressCopy(T1))
	h.Write(compressCopy(T2))
	var b [32]byte
	copy(b[:], h.Sum(nil))
	c := new(secp256k1.ModNScalar)
	c.SetBytes(&b) // reduces mod q; identical reduction on prove & verify
	return c
}
