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
	// GetUnbondingDelegation reads the grantee's live unbonding delegation at a
	// validator. The deferred clawback sweep uses it to track the SPECIFIC
	// UnbondingDelegationEntry its force-undelegation created and read that entry's
	// current, re-slash-aware Balance while it is still unbonding (HIGH-C). x/staking
	// mutates the entry's Balance in place on a re-slash, so the value observed on the
	// last pre-maturity block equals the amount CompleteUnbonding returns.
	GetUnbondingDelegation(ctx context.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) (stakingtypes.UnbondingDelegation, error)
	// GetValidator / GetDelegation / Delegate back the PER-VALIDATOR granted-share
	// ledger (HIGH-A-CROSS): the module performs the locked delegation at issuance
	// so it knows EXACTLY how many shares the grant minted at grant.ValidatorOp
	// (recorded on the Grant), and the staking hooks read the live delegation to
	// follow those shares through redelegation / partial-unbond. This decouples the
	// reclaim from the account-global DelegatedVesting aggregate.
	GetValidator(ctx context.Context, valAddr sdk.ValAddress) (stakingtypes.Validator, error)
	GetDelegation(ctx context.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress) (stakingtypes.Delegation, error)
	Delegate(ctx context.Context, delAddr sdk.AccAddress, bondAmt math.Int, tokenSrc stakingtypes.BondStatus, validator stakingtypes.Validator, subtractAccount bool) (math.LegacyDec, error)
	// ValidateUnbondAmount converts a token amount into the delegation shares that
	// represent it (capped at the delegation's shares; errors if the amount
	// exceeds the delegation's tokens). Used by the governance clawback to
	// undelegate EXACTLY the foundation-granted locked principal — never more —
	// so a validator's own self-bond is never force-unbonded or swept.
	ValidateUnbondAmount(ctx context.Context, delAddr sdk.AccAddress, valAddr sdk.ValAddress, amt math.Int) (math.LegacyDec, error)
	// KPI reads (v1 decentralization snapshot, read-only).
	PowerReduction(ctx context.Context) math.Int
	GetBondedValidatorsByPower(ctx context.Context) ([]stakingtypes.Validator, error)
}
