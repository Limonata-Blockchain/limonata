// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package dkg

import (
	"bytes"
	"testing"

	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// compressedCommitments serializes parsed commitment points back to the compressed [][]byte the
// ShareKeysCompressed* helpers consume (mirroring how the keeper stores ActiveThresholdKey.PublicCommitments).
func compressedCommitments(pts []secp256k1.JacobianPoint) [][]byte {
	out := make([][]byte, len(pts))
	for i := range pts {
		out[i] = compressCopy(&pts[i])
	}
	return out
}

// TestShareKeysCompressedRange_MatchesUpTo verifies the CHUNKED precompute (HIGH-3): the concatenation
// of bounded ranges [1,2] ++ [3,S] reproduces exactly the full ShareKeysCompressedUpTo(1..S), so warming
// the Y-cache a slice per block yields the identical cache as one finalize burst.
func TestShareKeysCompressedRange_MatchesUpTo(t *testing.T) {
	res, err := RunDKGSecure(NewParties(5, 3))
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	const S = 5
	commBytes := compressedCommitments(res.PublicCommitments)
	full, err := ShareKeysCompressedUpTo(commBytes, S)
	if err != nil {
		t.Fatalf("upto: %v", err)
	}
	// Warm in two chunks, exactly as advancePrecomputeShareKeys would.
	a, err := ShareKeysCompressedRange(commBytes, 1, 2)
	if err != nil {
		t.Fatalf("range 1-2: %v", err)
	}
	b, err := ShareKeysCompressedRange(commBytes, 3, S)
	if err != nil {
		t.Fatalf("range 3-S: %v", err)
	}
	chunked := append(append([][]byte{}, a...), b...)
	if len(chunked) != len(full) {
		t.Fatalf("chunked len %d != full len %d", len(chunked), len(full))
	}
	for i := range full {
		if !bytes.Equal(full[i], chunked[i]) {
			t.Fatalf("Y_%d mismatch between chunked and full precompute", i+1)
		}
	}
	// Empty window is well-defined.
	if e, _ := ShareKeysCompressedRange(commBytes, 5, 4); len(e) != 0 {
		t.Fatalf("empty window should return no keys, got %d", len(e))
	}
}

// TestRecoverVerifiedWithKeys_MatchesRecompute verifies the CRIT-3 fix: resolving each partial's public
// share key Y from the precomputed cache yields the SAME recovered shared secret as recomputing
// SharePubKey, whether the cache is fully warm, partially warm (fallback path), or cold (nil getter).
func TestRecoverVerifiedWithKeys_MatchesRecompute(t *testing.T) {
	res, err := RunDKGSecure(NewParties(5, 3))
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	ct, err := threshold.Encrypt(res.Pub, []byte("cache vs recompute must agree"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	comm := res.PublicCommitments // already parsed points
	commBytes := compressedCommitments(comm)
	partials := make([]VerifiedShare, 0, 3)
	for i := 0; i < 3; i++ {
		ds, pf, perr := ProveDecryptShare(res.Shares[i], ct)
		if perr != nil {
			t.Fatalf("prove %d: %v", i, perr)
		}
		partials = append(partials, VerifiedShare{Share: ds, Proof: pf})
	}

	want, err := RecoverVerified(comm, ct.A, 3, partials)
	if err != nil {
		t.Fatalf("recompute recover: %v", err)
	}
	wantB := compressCopy(want)

	keys, err := ShareKeysCompressedUpTo(commBytes, 5)
	if err != nil {
		t.Fatalf("upto: %v", err)
	}
	warm := func(index uint64) []byte {
		if index >= 1 && int(index) <= len(keys) {
			return keys[index-1]
		}
		return nil
	}
	// A partially-warm cache: only even indices cached, odd ones fall back to SharePubKey.
	partial := func(index uint64) []byte {
		if index%2 == 0 {
			return warm(index)
		}
		return nil
	}

	for name, getter := range map[string]func(uint64) []byte{
		"fully-warm":     warm,
		"partially-warm": partial,
		"cold-nil":       nil,
	} {
		got, err := RecoverVerifiedWithKeys(comm, ct.A, 3, partials, getter, nil)
		if err != nil {
			t.Fatalf("%s recover: %v", name, err)
		}
		if !bytes.Equal(wantB, compressCopy(got)) {
			t.Fatalf("%s: cached recover != recompute recover", name)
		}
	}
}

// round-9 #5: preVerified must (a) give the IDENTICAL recovered secret as full verification for
// valid shares, and (b) actually SKIP the DLEQ - a partial with a corrupted proof that full
// verification would DROP is accepted when its index is marked preVerified. This pins both the
// correctness of the optimization and the invariant it rests on (only truly-verified shares may be
// flagged - a mis-flag skips a check, but the index-range/dedup Lagrange guards still run).
func TestRecoverVerifiedWithKeys_PreVerifiedSkipsDLEQ(t *testing.T) {
	res, err := RunDKGSecure(NewParties(5, 3))
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	ct, err := threshold.Encrypt(res.Pub, []byte("preverified must match full verify"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	comm := res.PublicCommitments
	build := func() []VerifiedShare {
		ps := make([]VerifiedShare, 0, 3)
		for i := 0; i < 3; i++ {
			ds, pf, perr := ProveDecryptShare(res.Shares[i], ct)
			if perr != nil {
				t.Fatalf("prove %d: %v", i, perr)
			}
			ps = append(ps, VerifiedShare{Share: ds, Proof: pf})
		}
		return ps
	}

	// (a) all-preVerified == full verification, byte-for-byte.
	want, err := RecoverVerified(comm, ct.A, 3, build())
	if err != nil {
		t.Fatalf("full-verify recover: %v", err)
	}
	all := func(uint64) bool { return true }
	got, err := RecoverVerifiedWithKeys(comm, ct.A, 3, build(), nil, all)
	if err != nil {
		t.Fatalf("preverified recover: %v", err)
	}
	if !bytes.Equal(compressCopy(want), compressCopy(got)) {
		t.Fatal("preVerified recover must equal full-verify recover for valid shares")
	}

	// (b) corrupt one partial's proof. Full verify drops it -> only 2/3 pass -> fails. Marking that
	// index preVerified accepts it (skip) -> 3/3 -> succeeds: proof the DLEQ is genuinely skipped.
	corrupt := build()
	corrupt[0].Proof.Z.Add(new(secp256k1.ModNScalar).SetInt(1)) // perturb Z -> proof no longer verifies
	if _, err := RecoverVerifiedWithKeys(comm, ct.A, 3, corrupt, nil, nil); err == nil {
		t.Fatal("a corrupted proof must be DROPPED by full verification (only 2/3 valid)")
	}
	badIdx := corrupt[0].Share.Index
	if _, err := RecoverVerifiedWithKeys(comm, ct.A, 3, corrupt, nil, func(i uint64) bool { return i == badIdx }); err != nil {
		t.Fatalf("preVerified must SKIP the DLEQ on the flagged index (got %v)", err)
	}
}
