// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package evmd

import (
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
)

func extVote(addr byte, power int64, extLen int) abci.ExtendedVoteInfo {
	return abci.ExtendedVoteInfo{
		Validator:          abci.Validator{Address: []byte{addr}, Power: power},
		VoteExtension:      make([]byte, extLen),
		ExtensionSignature: make([]byte, 64),
		BlockIdFlag:        cmtproto.BlockIDFlagCommit,
	}
}

// TestBoundedInjectedCommit_FullFits: a small commit that fits under maxTxBytes is returned untrimmed.
func TestBoundedInjectedCommit_FullFits(t *testing.T) {
	ec := abci.ExtendedCommitInfo{Votes: []abci.ExtendedVoteInfo{
		extVote(1, 10, 100), extVote(2, 10, 100), extVote(3, 10, 100),
	}}
	blob, ok := boundedInjectedCommit(ec, 1<<20)
	if !ok {
		t.Fatal("a small full commit must fit")
	}
	full, _ := marshalInjectedCommit(ec)
	if len(blob) != len(full) {
		t.Fatalf("full-fit must return the untrimmed blob: got %d want %d", len(blob), len(full))
	}
}

// TestBoundedInjectedCommit_TrimsMinorityBloat: a <1/3-power validator posts a huge extension; it is
// dropped to Absent while the >2/3 majority's extensions are kept, and the trimmed blob fits.
func TestBoundedInjectedCommit_TrimsMinorityBloat(t *testing.T) {
	ec := abci.ExtendedCommitInfo{Votes: []abci.ExtendedVoteInfo{
		extVote(1, 10, 200), extVote(2, 10, 200), extVote(3, 10, 200), // 75% power, small
		extVote(4, 10, 900_000), // 25% power, bloat
	}}
	blob, ok := boundedInjectedCommit(ec, 500_000)
	if !ok {
		t.Fatal("must trim the minority bloat and keep > 2/3")
	}
	if int64(len(blob)) >= 500_000 {
		t.Fatalf("trimmed blob must fit the budget, got %d", len(blob))
	}
	var ext abci.ExtendedCommitInfo
	if err := ext.Unmarshal(blob[len(veInjectMarker):]); err != nil {
		t.Fatalf("unmarshal trimmed commit: %v", err)
	}
	kept, absent := 0, 0
	for _, v := range ext.Votes {
		if v.BlockIdFlag == cmtproto.BlockIDFlagCommit && len(v.VoteExtension) > 0 {
			kept++
		} else {
			absent++
			if len(v.ExtensionSignature) != 0 {
				t.Fatal("a dropped vote must have its extension signature cleared")
			}
		}
	}
	if kept != 3 || absent != 1 {
		t.Fatalf("expected 3 kept + 1 absent, got %d kept / %d absent", kept, absent)
	}
}

// TestBoundedInjectedCommit_MajorityBloatFallsBack: a dominant (>2/3) validator's extension does not fit,
// so no injection carrying > 2/3 power is possible -> fall back (false), never a sub-2/3 partial commit.
func TestBoundedInjectedCommit_MajorityBloatFallsBack(t *testing.T) {
	ec := abci.ExtendedCommitInfo{Votes: []abci.ExtendedVoteInfo{
		extVote(1, 30, 900_000), // 75% power, huge — cannot fit
		extVote(2, 10, 200),     // 25% power, small
	}}
	if _, ok := boundedInjectedCommit(ec, 100_000); ok {
		t.Fatal("must fall back: without the dominant validator's extension, > 2/3 is impossible")
	}
}
