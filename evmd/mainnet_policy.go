package evmd

import (
	"context"
	"fmt"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

// These rules apply to the new mainnet only. Historical testnet replay and
// other chains using this application retain their existing behavior.
const MainnetChainID = "limonata_20777-1"

var (
	mainnetMaxSupply, _   = math.NewIntFromString("1000000000000000000000000000")
	mainnetMinSelfBond, _ = math.NewIntFromString("100000000000000000000000")
)

type mainnetSupplyReader interface {
	GetSupply(context.Context, string) sdk.Coin
}

// All minters receive the restricted bank keeper, including mint, gassponsor,
// EVM and ERC20. A mint-module parameter alone would not cover the other minters.
func mainnetMintRestriction(bank mainnetSupplyReader) banktypes.MintingRestrictionFn {
	return func(ctx context.Context, coins sdk.Coins) error {
		if sdk.UnwrapSDKContext(ctx).ChainID() != MainnetChainID {
			return nil
		}
		amount := coins.AmountOf("aLIMO")
		if amount.IsPositive() && bank.GetSupply(ctx, "aLIMO").Amount.Add(amount).GT(mainnetMaxSupply) {
			return fmt.Errorf("Limonata mainnet: mint would exceed the 1,000,000,000 LIMO supply cap")
		}
		return nil
	}
}

type mainnetValidatorReader interface {
	GetValidator(context.Context, sdk.ValAddress) (stakingtypes.Validator, error)
}

type mainnetStakingHooks struct {
	stakingtypes.StakingHooks
	keeper mainnetValidatorReader
}

func newMainnetStakingHooks(keeper mainnetValidatorReader) mainnetStakingHooks {
	return mainnetStakingHooks{StakingHooks: stakingtypes.NewMultiStakingHooks(), keeper: keeper}
}

// The keeper hook also covers authz and precompile entry points; checking only
// top-level transaction messages would let those paths bypass the minimum.
// SDK creation requires value >= MinSelfDelegation, and edits cannot lower it.
func (h mainnetStakingHooks) AfterValidatorCreated(ctx context.Context, address sdk.ValAddress) error {
	if sdk.UnwrapSDKContext(ctx).ChainID() != MainnetChainID {
		return nil
	}
	validator, err := h.keeper.GetValidator(ctx, address)
	if err != nil {
		return err
	}
	if validator.MinSelfDelegation.LT(mainnetMinSelfBond) {
		return fmt.Errorf("Limonata mainnet: validator min-self-delegation must be at least 100,000 LIMO")
	}
	return nil
}
