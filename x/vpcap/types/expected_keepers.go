package types

import (
	"context"

	"cosmossdk.io/math"

	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

// StakingKeeper is the read-only subset of the x/staking keeper x/vpcap needs to
// read the bonded set's consensus power each block. *stakingkeeper.Keeper
// satisfies this (value-receiver methods).
type StakingKeeper interface {
	PowerReduction(ctx context.Context) math.Int
	IterateBondedValidatorsByPower(ctx context.Context, fn func(index int64, validator stakingtypes.ValidatorI) (stop bool)) error
}
