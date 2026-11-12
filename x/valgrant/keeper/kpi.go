package keeper

import (
	"context"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// computeKPIs derives the decentralization metrics from the bonded set's
// consensus powers (which MUST be sorted DESCENDING) and a parallel mask of
// which validators are foundation-operated. Pure integer math => deterministic.
//
// Nakamoto coefficient = the minimum number of top validators whose cumulative
// power exceeds 1/3 of the total (the BFT halting threshold).
func computeKPIs(powersDesc []int64, isFoundation []bool) (active, nakamoto int, foundationBps, topBps, total int64) {
	active = len(powersDesc)
	for _, p := range powersDesc {
		total += p
	}
	if total <= 0 {
		return active, 0, 0, 0, 0
	}
	var cum int64
	for _, p := range powersDesc {
		nakamoto++
		cum += p
		if cum*3 > total {
			break
		}
	}
	var fpow int64
	for i, p := range powersDesc {
		if i < len(isFoundation) && isFoundation[i] {
			fpow += p
		}
	}
	foundationBps = fpow * 10000 / total
	topBps = powersDesc[0] * 10000 / total
	return active, nakamoto, foundationBps, topBps, total
}

// ComputeKPIs reads the current bonded set and returns a fresh KPISnapshot.
func (k Keeper) ComputeKPIs(ctx context.Context) (types.KPISnapshot, error) {
	pr := k.stakingKeeper.PowerReduction(ctx)
	vals, err := k.stakingKeeper.GetBondedValidatorsByPower(ctx)
	if err != nil {
		return types.KPISnapshot{}, err
	}
	fset := map[string]bool{}
	for _, f := range k.GetParams(ctx).FoundationValidators {
		fset[f] = true
	}
	powers := make([]int64, len(vals))
	isFound := make([]bool, len(vals))
	for i := range vals {
		powers[i] = vals[i].GetConsensusPower(pr)
		isFound[i] = fset[vals[i].GetOperator()]
	}
	active, nakamoto, fbps, topbps, total := computeKPIs(powers, isFound)
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	return types.KPISnapshot{
		Height:              sdkCtx.BlockHeight(),
		Unix:                sdkCtx.BlockTime().Unix(),
		ActiveValidators:    active,
		NakamotoCoefficient: nakamoto,
		FoundationVPBps:     fbps,
		TopValidatorVPBps:   topbps,
		TotalPower:          total,
	}, nil
}

// RecordKPISnapshot computes + persists the snapshot and emits a valgrant_kpi
// event. Called from EndBlock (after staking) so the bonded set is final for
// the block. v1: recorded for transparency; gating is done OFF-CHAIN.
func (k Keeper) RecordKPISnapshot(ctx context.Context) error {
	snap, err := k.ComputeKPIs(ctx)
	if err != nil {
		return err
	}
	if err := k.SetKPISnapshot(ctx, snap); err != nil {
		return err
	}
	sdk.UnwrapSDKContext(ctx).EventManager().EmitEvent(sdk.NewEvent(
		"valgrant_kpi",
		sdk.NewAttribute("active_validators", fmt.Sprintf("%d", snap.ActiveValidators)),
		sdk.NewAttribute("nakamoto", fmt.Sprintf("%d", snap.NakamotoCoefficient)),
		sdk.NewAttribute("foundation_vp_bps", fmt.Sprintf("%d", snap.FoundationVPBps)),
		sdk.NewAttribute("top_validator_vp_bps", fmt.Sprintf("%d", snap.TopValidatorVPBps)),
	))
	return nil
}
