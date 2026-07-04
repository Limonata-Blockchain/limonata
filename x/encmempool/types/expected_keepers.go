package types

import (
	"context"

	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

// StakingKeeper is the read-only subset of x/staking the encmempool DKG needs to
// learn the currently-bonded validator set (the KEYPER SET). The active DKG member
// set each round is the genesis-declared DkgMembers INTERSECTED with this bonded
// set (matched by operator address); a change here is what triggers a DKG re-run.
// *stakingkeeper.Keeper satisfies this.
type StakingKeeper interface {
	IterateBondedValidatorsByPower(ctx context.Context, fn func(index int64, validator stakingtypes.ValidatorI) (stop bool)) error
}
