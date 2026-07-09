// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package dkg

import (
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TestProbe_PointAtInfinityIngress checks whether the ingress point validator
// (ValidCompressedPoint / parsePoint) and the commitment aggregation handle the
// identity / point-at-infinity, and whether an aggregate that sums to infinity is a
// panic (consensus-halt class) or a benign deterministic value.
func TestProbe_PointAtInfinityIngress(t *testing.T) {
	// 1) Can the identity be encoded + accepted at ingress?
	//    Compressed encodings to probe: 0x00 (SEC infinity), 0x02||0..0, 0x03||0..0.
	for _, enc := range [][]byte{
		{0x00},
		append([]byte{0x02}, make([]byte, 32)...),
		append([]byte{0x03}, make([]byte, 32)...),
	} {
		if ValidCompressedPoint(enc) {
			t.Errorf("ingress ACCEPTED an identity-ish encoding %x (len %d)", enc, len(enc))
		} else {
			t.Logf("ingress rejects %x (len %d) — good", enc[:1], len(enc))
		}
	}

	// 2) Aggregate that sums to infinity: C + (-C). Feed as two valid commitments and
	//    aggregate exactly as FinalizePublicWeighted does (V_j = Σ C_ij), then compressCopy.
	var g secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(scalarFromUint(5), &g)
	var negG secp256k1.JacobianPoint
	negG.Set(&g)
	negG.Y.Negate(1)
	negG.Y.Normalize()
	// sanity: both are valid compressed points at ingress
	gC := compressCopy(&g)
	negC := compressCopy(&negG)
	if !ValidCompressedPoint(gC) || !ValidCompressedPoint(negC) {
		t.Fatalf("setup points not accepted at ingress")
	}
	// Aggregate them: sum should be the identity.
	var sum secp256k1.JacobianPoint
	secp256k1.AddNonConst(&g, &negG, &sum)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("PANIC while compressing an infinity aggregate (consensus-halt class): %v", r)
		}
	}()
	out := compressCopy(&sum)
	t.Logf("infinity aggregate compressed to %x (len %d); re-parse accepted=%v", out, len(out), ValidCompressedPoint(out))
}

func TestFinalizePublicRejectsInvalidAggregatePoint(t *testing.T) {
	var g secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(scalarFromUint(5), &g)
	var negG secp256k1.JacobianPoint
	negG.Set(&g)
	negG.Y.Negate(1)
	negG.Y.Normalize()

	_, err := FinalizePublicWeighted(
		[]uint64{1, 2},
		1,
		[]PublicDealing{
			{Dealer: 1, Commitments: [][]byte{compressCopy(&g)}},
			{Dealer: 2, Commitments: [][]byte{compressCopy(&negG)}},
		},
		nil,
		nil,
		2,
	)
	if err == nil {
		t.Fatal("aggregate point-at-infinity must fail the DKG round, not install an invalid active key")
	}
}
