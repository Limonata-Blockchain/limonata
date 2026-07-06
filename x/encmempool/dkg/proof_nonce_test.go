// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package dkg

import (
	"testing"

	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TestDLEQ_NonceBindsIndex_NoKeyLeak is the CRYPTO-1 (external audit, CRITICAL) regression: the
// Chaum-Pedersen commitment nonce must bind the SAME index the challenge binds. Otherwise two proofs
// over the SAME secret x and SAME ephemeral A at DIFFERENT indices reuse the nonce k while the
// challenge c differs, and any observer recovers x = (z1 - z2) / (c1 - c2). That is reachable in the
// complaint path (a node proves S = encPriv*A at each owned eval-point against a dealer-chosen A; a
// malicious dealer sealing the same A to two of a victim's points would leak the victim's persistent
// enc private key on-chain). This test proves two shares with the SAME Xi and SAME A at indices 1 and 2
// and asserts the classic nonce-reuse extraction does NOT recover x.
func TestDLEQ_NonceBindsIndex_NoKeyLeak(t *testing.T) {
	res, err := RunDKGSecure(NewParties(5, 3))
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	ct, err := threshold.Encrypt(res.Pub, []byte("crypto-1 nonce-reuse regression"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	x := res.Shares[0].Xi // one secret scalar, deliberately reused at two DIFFERENT indices below

	_, p1, err := ProveDecryptShare(threshold.Share{Index: 1, Xi: x}, ct)
	if err != nil {
		t.Fatalf("prove idx1: %v", err)
	}
	_, p2, err := ProveDecryptShare(threshold.Share{Index: 2, Xi: x}, ct)
	if err != nil {
		t.Fatalf("prove idx2: %v", err)
	}

	// The index-bound challenge must differ between the two proofs (it already did pre-fix).
	if p1.C.Bytes() == p2.C.Bytes() {
		t.Fatal("challenge did not bind the index (c1 == c2)")
	}
	// x' = (z1 - z2) * inverse(c1 - c2): the classic k-reuse extraction. With the index bound into the
	// nonce, k1 != k2, so this MUST NOT recover the real secret x.
	num := new(secp256k1.ModNScalar).Set(p1.Z)
	num.Add(new(secp256k1.ModNScalar).Set(p2.Z).Negate()) // z1 - z2
	den := new(secp256k1.ModNScalar).Set(p1.C)
	den.Add(new(secp256k1.ModNScalar).Set(p2.C).Negate()) // c1 - c2
	if den.IsZero() {
		t.Fatal("c1 - c2 == 0")
	}
	den.InverseNonConst()
	xGuess := new(secp256k1.ModNScalar).Set(num).Mul(den)
	if xGuess.Bytes() == x.Bytes() {
		t.Fatal("CRYPTO-1: secret x recovered from two distinct-index proofs — the DLEQ nonce is not bound to the index")
	}
}
