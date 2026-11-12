package keeper

import (
	"context"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtprotocrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"

	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

// ComputeCappedValidatorUpdates recomputes the FULL capped validator-power set
// for the current (post-staking-EndBlock) bonded set and returns the abci
// updates that move CometBFT from what vpcap last sent to the new capped set.
// The bool is false when the cap is disabled — the caller must then leave
// staking's own ValidatorUpdates untouched.
//
// Each validator's consensus power is capped at PerValidatorCapBps of the
// EFFECTIVE total. Shedding surplus shrinks the denominator, so we iterate a
// bounded fixed-point to a stable assignment (monotone non-increasing, floored
// at 1 for any bonded validator => converges). Pure integer math => deterministic.
//
// NOTE: with fewer than 10000/bps validators the cap can be infeasible (too
// little other power to dilute a whale); the fixed-point then flattens the
// dominant validator toward the floor — best-effort, deterministic, terminating.
// On a balanced set (the mainnet-genesis target) it cleanly enforces <=bps each.
func (k Keeper) ComputeCappedValidatorUpdates(ctx context.Context) ([]abci.ValidatorUpdate, bool, error) {
	p := k.GetParams(ctx)
	if !p.Enabled || p.PerValidatorCapBps == 0 || p.PerValidatorCapBps >= 10000 {
		return nil, false, nil
	}
	bps := int64(p.PerValidatorCapBps)
	r := k.stakingKeeper.PowerReduction(ctx)

	type vinfo struct {
		consAddr []byte
		pubKey   cmtprotocrypto.PublicKey
		raw      int64
	}
	var vals []vinfo
	var iterErr error
	if err := k.stakingKeeper.IterateBondedValidatorsByPower(ctx, func(_ int64, v stakingtypes.ValidatorI) bool {
		ca, err := v.GetConsAddr()
		if err != nil {
			iterErr = err
			return true
		}
		pk, err := v.TmConsPublicKey()
		if err != nil {
			iterErr = err
			return true
		}
		vals = append(vals, vinfo{consAddr: ca, pubKey: pk, raw: v.GetConsensusPower(r)})
		return false
	}); err != nil {
		return nil, false, err
	}
	if iterErr != nil {
		return nil, false, iterErr
	}

	// Fixed-point cap on the effective total (pure + unit-tested: see capPowers).
	raw := make([]int64, len(vals))
	for i := range vals {
		raw[i] = vals[i].raw
	}
	effective := capPowers(raw, bps)

	// Diff against last-sent; emit updates; persist the new set; zero out departed.
	last, err := k.GetAllLastSent(ctx)
	if err != nil {
		return nil, false, err
	}
	updates := []abci.ValidatorUpdate{}
	for i := range vals {
		key := string(vals[i].consAddr)
		power := effective[i]
		if prev, existed := last[key]; !existed || prev.Power != power {
			updates = append(updates, abci.ValidatorUpdate{PubKey: vals[i].pubKey, Power: power})
		}
		pkBz, err := vals[i].pubKey.Marshal()
		if err != nil {
			return nil, false, err
		}
		if err := k.SetLastSent(ctx, vals[i].consAddr, LastSent{PubKey: pkBz, Power: power}); err != nil {
			return nil, false, err
		}
		delete(last, key)
	}
	// Anything still in last = validator no longer bonded -> emit Power 0 + forget.
	for key, ls := range last {
		var pk cmtprotocrypto.PublicKey
		if err := pk.Unmarshal(ls.PubKey); err != nil {
			continue
		}
		updates = append(updates, abci.ValidatorUpdate{PubKey: pk, Power: 0})
		k.DeleteLastSent(ctx, []byte(key))
	}

	return updates, true, nil
}

// capPowers caps each entry at bps/10000 of the EFFECTIVE total via a bounded
// integer fixed-point: shedding surplus shrinks the denominator, so we iterate
// until stable (monotone non-increasing, floored at 1 for any positive input =>
// converges; <=64-round backstop). Pure + deterministic (integer math only).
//
// On a balanced set (>= 10000/bps validators) this cleanly enforces <=bps each.
// On an infeasible set (a whale + too little other power) it flattens the whale
// toward the floor — best-effort, still deterministic and terminating.
func capPowers(raw []int64, bps int64) []int64 {
	effective := make([]int64, len(raw))
	copy(effective, raw)
	for round := 0; round < 64; round++ {
		var total int64
		for _, e := range effective {
			total += e
		}
		if total <= 0 {
			break
		}
		capPow := total * bps / 10000
		if capPow < 1 {
			capPow = 1
		}
		changed := false
		for i := range raw {
			nv := raw[i]
			if nv > capPow {
				nv = capPow
			}
			// Never silently unbond a bonded validator in CometBFT's view.
			if raw[i] > 0 && nv < 1 {
				nv = 1
			}
			if nv != effective[i] {
				effective[i] = nv
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return effective
}
