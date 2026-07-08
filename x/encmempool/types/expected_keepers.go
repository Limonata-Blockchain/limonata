package types

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"
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

// BankKeeper is the subset of x/bank the encrypted mempool needs to ESCROW and REFUND the
// refundable anti-sybil submit bond (round-9 #1): move a bond from the submitter into the module
// account at submit, and return it in full when the ciphertext is released. nil disables bonding
// (the keeper treats a zero bond param or a nil bank keeper as "no bond"). *bankkeeper.BaseKeeper
// satisfies this.
type BankKeeper interface {
	SendCoinsFromAccountToModule(ctx context.Context, senderAddr sdk.AccAddress, recipientModule string, amt sdk.Coins) error
	SendCoinsFromModuleToAccount(ctx context.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error
}
