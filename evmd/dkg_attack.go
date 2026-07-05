// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package evmd

import (
	"os"
	"strconv"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	sdk "github.com/cosmos/cosmos-sdk/types"

	encmempoolkeeper "github.com/cosmos/evm/x/encmempool/keeper"
	encmempooltypes "github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// ENV-GATED, ExtendVote-ONLY ADVERSARY (throwaway audit builds ONLY).
//
// dkgAttackShares mutates ONLY the decryption-share list this node attaches to its OWN pre-commit
// vote extension — a node-local, NON-consensus value. It touches no committed state and no consume
// path, so a node running this variant is byte-for-byte consensus-identical to the honest binary:
// ConsumeVoteExtensions / ingestDecryptSharesBounded (the authoritative, deterministic bound) is the
// SAME code on every node, and the app-hash must agree across a mix of honest + adversary nodes.
//
// Both behaviours are strict no-ops unless their env var is set, so the default binary == honest.
//
//	DKG_HOLD_FILE=<path>  Withhold ALL of this node's decryption shares until <path> exists, then serve
//	                      normally. Drives the cycle-7 "matured-but-short honest ciphertext DEFERS, then
//	                      HEALS when the withholding validators release" live proof.
//	DKG_CHAFF9=<N>        Append up to N garbage decryption shares (valid structure: a well-formed
//	                      secp256k1 point D + a zero proof => the DLEQ verification ALWAYS fails, so chaff
//	                      can never enter state). Half are aimed at REAL in-flight ciphertexts at this
//	                      operator's OWNED eval points (loads the per-(operator,ciphertext) verify budget
//	                      and reaches the O(t) DLEQ verify — worst case); half at FABRICATED nonexistent
//	                      ciphertexts (must be classified out by the cycle-9 processed-set O(1) lookup
//	                      BEFORE any budget/verify). Drives the cycle-8/cycle-9 compute-DoS bound live
//	                      proof: even a max spray forces only O(cap x S) verifications/block, block time
//	                      stays flat, and nonexistent-ct chaff adds ZERO work.
//
// The honest shares are kept AHEAD of the chaff, so under the keeper's per-VE clamp the adversary's
// own legitimate contribution still survives while its chaff is bounded — a strictly harder test than
// a pure-chaff node (the adversary looks like a normal committee member that also spams).
func (app *EVMD) dkgAttackShares(ctx sdk.Context, op string, honest []encmempooltypes.VoteExtShare) []encmempooltypes.VoteExtShare {
	// (A) HOLD / withhold.
	if hf := os.Getenv("DKG_HOLD_FILE"); hf != "" {
		if _, err := os.Stat(hf); err != nil {
			return nil // withhold everything until the release flag file appears
		}
		return honest // released: serve normally (heal)
	}

	// (B) CHAFF spray.
	n, _ := strconv.Atoi(os.Getenv("DKG_CHAFF9"))
	if n <= 0 {
		return honest
	}
	k := app.EncMempoolKeeper
	h := uint64(ctx.BlockHeight())

	// This operator's OWNED eval points in the active epoch (chaff at owned points reaches the DLEQ
	// verify => maximal per-ciphertext budget pressure; non-owned points are cheap-rejected earlier).
	epoch := k.GetCurrentEpoch(ctx)
	var owned []uint64
	if round, ok := k.GetDkgRound(ctx, epoch); ok {
		if idx := encmempooltypes.MemberIndexByOperator(round.Members, op); idx != 0 {
			for _, m := range round.Members {
				if m.Index == idx {
					owned = m.OwnedEvalPoints()
					break
				}
			}
		}
	}
	if len(owned) == 0 {
		owned = []uint64{1, 2, 3, 4, 5, 6, 7, 8}
	}

	// Real in-flight ciphertext coordinates, from the SAME deferral window the honest builder serves.
	from := uint64(0)
	if h > encmempoolkeeper.StrandedDecryptGraceBlocks {
		from = h - encmempoolkeeper.StrandedDecryptGraceBlocks
	}
	type coord struct{ ep, dh, seq uint64 }
	var real []coord
	k.IterateInFlightFrom(ctx, from, 4096, func(e encmempooltypes.EncTx) bool {
		if e.Epoch != 0 {
			real = append(real, coord{e.Epoch, e.DecryptHeight, e.Seq})
		}
		return true
	})

	// A small pool of well-formed random points to reuse as garbage D (avoids per-share keygen while
	// keeping each share structurally valid enough to reach the DLEQ verify, which then fails).
	pool := make([][]byte, 0, 16)
	for i := 0; i < 16; i++ {
		if pk, err := secp256k1.GeneratePrivateKey(); err == nil {
			pool = append(pool, pk.PubKey().SerializeCompressed())
		}
	}
	if len(pool) == 0 {
		pool = append(pool, make([]byte, 33))
	}
	zeroProof := make([]byte, 64)

	// DKG_CHAFF9_FIRST=1: place chaff AHEAD of honest shares and aim it ONLY at REAL processed
	// ciphertexts at owned points. This makes the chaff SURVIVE the per-VE clamp (control 1) and reach
	// the per-(operator,ciphertext) DLEQ-verify budget (control 3), so the LIVE test can measure that
	// forced DLEQ verifications are bounded at owned-points-per-ciphertext (<= O(cap x S)), NOT the raw
	// spray. (Default: honest-first, where the operator's own honest shares saturate its 256 cap and the
	// clamp neutralises the chaff entirely — the attacker achieves 0 forced verifications.)
	chaffFirst := os.Getenv("DKG_CHAFF9_FIRST") == "1"

	chaff := make([]encmempooltypes.VoteExtShare, 0, n)
	for i := 0; i < n; i++ {
		idx := owned[i%len(owned)]
		var ep, dh, seq uint64
		if chaffFirst {
			if len(real) == 0 {
				break // nothing real to target; chaff-first mode wants real processed cts
			}
			rc := real[i%len(real)]
			ep, dh, seq = rc.ep, rc.dh, rc.seq // real processed ct at owned point => reaches DLEQ verify
		} else if len(real) > 0 && i%2 == 0 {
			rc := real[(i/2)%len(real)]
			ep, dh, seq = rc.ep, rc.dh, rc.seq // real processed ciphertext => budget + DLEQ verify
		} else {
			// fabricated NONEXISTENT ciphertext => must be dropped by the processed-set O(1) lookup.
			ep, dh, seq = epoch, h+1_000_000+uint64(i), uint64(900000+i)
		}
		chaff = append(chaff, encmempooltypes.VoteExtShare{
			Epoch: ep, DecryptHeight: dh, Seq: seq, Index: idx,
			D: pool[i%len(pool)], Proof: zeroProof,
		})
	}
	if chaffFirst {
		return append(chaff, honest...)
	}
	return append(append([]encmempooltypes.VoteExtShare(nil), honest...), chaff...)
}
