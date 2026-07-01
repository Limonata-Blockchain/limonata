package types

import (
	"context"
	"time"

	"cosmossdk.io/core/address"
	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

// AccountKeeper defines the expected x/auth account keeper interface used by
// x/valgrant (create/store the PermanentLockedAccount; decode addresses).
type AccountKeeper interface {
	NewAccount(ctx context.Context, acc sdk.AccountI) sdk.AccountI
	GetAccount(ctx context.Context, addr sdk.AccAddress) sdk.AccountI
	SetAccount(ctx context.Context, acc sdk.AccountI)
	HasAccount(ctx context.Context, addr sdk.AccAddress) bool
	GetModuleAddress(moduleName string) sdk.AccAddress
	AddressCodec() address.Codec
}

// BankKeeper defines the expected x/bank keeper interface used by x/valgrant
// (fund grants from the pool; sweep principal back; balance checks).
type BankKeeper interface {
	SendCoinsFromModuleToAccount(ctx context.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error
	SendCoinsFromAccountToModule(ctx context.Context, senderAddr sdk.AccAddress, recipientModule string, amt sdk.Coins) error
	GetBalance(ctx context.Context, addr sdk.AccAddress, denom string) sdk.Coin
	GetAllBalances(ctx context.Context, addr sdk.AccAddress) sdk.Coins
	BlockedAddr(addr sdk.AccAddress) bool
	// BurnCoins permanently destroys coins held by a module account (removes them
	// from the module account AND from total supply). Requires the Burner perm.
	BurnCoins(ctx context.Context, moduleName string, amt sdk.Coins) error
}

// StakingKeeper defines the expected x/staking keeper interface used by
// x/valgrant clawback (enumerate delegations, force-undelegate, complete
// unbonding, bond denom + valoper codec).
type StakingKeeper interface {
	BondDenom(ctx context.Context) (string, error)
	ValidatorAddressCodec() address.Codec
	GetDelegatorDelegations(ctx context.Context, delegator sdk.AccAddress, maxRetrieve uint16) ([]stakingtypes.Delegation, error)
	Undelegate(ctx context.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress, sharesAmount math.LegacyDec) (time.Time, math.Int, error)
	CompleteUnbonding(ctx context.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) (sdk.Coins, error)
	// KPI reads (v1 decentralization snapshot, read-only).
	PowerReduction(ctx context.Context) math.Int
	GetBondedValidatorsByPower(ctx context.Context) ([]stakingtypes.Validator, error)
}
