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
		got, err := RecoverVerifiedWithKeys(comm, ct.A, 3, partials, getter)
		if err != nil {
			t.Fatalf("%s recover: %v", name, err)
		}
		if !bytes.Equal(wantB, compressCopy(got)) {
			t.Fatalf("%s: cached recover != recompute recover", name)
		}
	}
}
