package keeper

import (
	"context"
	"encoding/json"
	"fmt"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// This chain has not launched. Historical testnet replay keeps its existing rules.
const protectedGrantChainID = "limonata_20777-1"

// Only ClawbackGrantGov installs this private context value, for the one grantee
// being reclaimed. It is not a transaction field or a persistent permission.
type mainnetClawbackKey struct{}

func mainnetGrantProtection(ctx context.Context) bool {
	return sdk.UnwrapSDKContext(ctx).ChainID() == protectedGrantChainID
}

// Mainnet seats belong to the grantee's own validator. Filling an omitted operator
// also covers issueGrant(address,amount,gas) through the existing EVM precompile.
func (k Keeper) bindMainnetGrantValidator(ctx context.Context, grantee, operator string) (string, error) {
	if !mainnetGrantProtection(ctx) {
		return operator, nil
	}
	account, err := k.accountKeeper.AddressCodec().StringToBytes(grantee)
	if err != nil {
		return "", err
	}
	want, err := k.stakingKeeper.ValidatorAddressCodec().BytesToString(account)
	if err != nil {
		return "", err
	}
	if operator != "" && operator != want {
		return "", fmt.Errorf("valgrant: mainnet grant must be bound to the grantee's own validator %s", want)
	}
	return want, nil
}

func (k Keeper) protectedMainnetGrant(ctx context.Context, delegator sdk.AccAddress) (*types.Grant, math.LegacyDec, error) {
	zero := math.LegacyZeroDec()
	if !mainnetGrantProtection(ctx) {
		return nil, zero, nil
	}
	grantee, err := k.accountKeeper.AddressCodec().BytesToString(delegator)
	if err != nil {
		return nil, zero, err
	}
	if ctx.Value(mainnetClawbackKey{}) == grantee {
		return nil, zero, nil
	}
	grant, found := k.GetGrant(ctx, grantee)
	if !found || grant.Status == "revoked" {
		return nil, zero, nil
	}
	shares, err := math.LegacyNewDecFromStr(grant.GrantedShares)
	if grant.ValidatorOp == "" || err != nil || !shares.IsPositive() {
		return nil, zero, fmt.Errorf("valgrant: active mainnet grant has no valid protected-share ledger")
	}
	return &grant, shares, nil
}

// A user's undelegation/redelegation may spend only shares above the protected
// amount. This runs after partial modifications and before complete removal;
// x/staking propagates the error and the transaction cache discards all writes.
func (k Keeper) guardMainnetGrantShares(ctx context.Context, delegator sdk.AccAddress, validator sdk.ValAddress, remaining math.LegacyDec) error {
	grant, protected, err := k.protectedMainnetGrant(ctx, delegator)
	if err != nil || grant == nil {
		return err
	}
	operator, err := k.stakingKeeper.ValidatorAddressCodec().BytesToString(validator)
	if err != nil {
		return err
	}
	if operator == grant.ValidatorOp && remaining.LT(protected) {
		return fmt.Errorf("valgrant: locked grant shares must remain on the granted validator; only the authorized clawback can remove them")
	}
	return nil
}

// Before a first self-delegation, all grant coins are still locked in-account.
// Prevent sending them to another validator instead of collateralizing the seat.
func (k Keeper) guardMainnetGrantDestination(ctx context.Context, delegator sdk.AccAddress, validator sdk.ValAddress) error {
	if err := k.guardMainnetPendingClawback(ctx, delegator, validator); err != nil {
		return err
	}
	grant, protected, err := k.protectedMainnetGrant(ctx, delegator)
	if err != nil || grant == nil {
		return err
	}
	operator, err := k.stakingKeeper.ValidatorAddressCodec().BytesToString(validator)
	if err != nil || operator == grant.ValidatorOp {
		return err
	}
	source, err := k.stakingKeeper.ValidatorAddressCodec().StringToBytes(grant.ValidatorOp)
	if err != nil {
		return err
	}
	if k.liveDelegationShares(ctx, delegator, sdk.ValAddress(source)).LT(protected) {
		return fmt.Errorf("valgrant: bond the locked grant to its own validator before delegating to another validator")
	}
	return nil
}

// CancelUnbondingDelegation also calls Delegate and its before hooks. While a
// reclaim is pending, pause staking changes at that validator so the beneficiary
// cannot cancel the admin's unbonding entry and stake the principal again.
func (k Keeper) guardMainnetPendingClawback(ctx context.Context, delegator sdk.AccAddress, validator sdk.ValAddress) error {
	if !mainnetGrantProtection(ctx) {
		return nil
	}
	grantee, err := k.accountKeeper.AddressCodec().BytesToString(delegator)
	if err != nil || ctx.Value(mainnetClawbackKey{}) == grantee {
		return err
	}
	bz, err := k.store(ctx).Get(pendingKey(grantee))
	if err != nil || bz == nil {
		return err
	}
	var pending types.PendingClawback
	if err := json.Unmarshal(bz, &pending); err != nil {
		return err
	}
	operator, err := k.stakingKeeper.ValidatorAddressCodec().BytesToString(validator)
	if err != nil {
		return err
	}
	for _, entry := range pending.Entries {
		if entry.Validator == operator {
			return fmt.Errorf("valgrant: staking changes at this validator are paused until the grant clawback finishes unbonding")
		}
	}
	return nil
}
