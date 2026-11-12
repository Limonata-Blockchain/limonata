package keeper

import (
	"context"

	errorsmod "cosmossdk.io/errors"
	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

type msgServer struct {
	Keeper
}

// NewMsgServerImpl returns the x/valgrant MsgServer backed by the keeper.
func NewMsgServerImpl(k Keeper) types.MsgServer { return &msgServer{Keeper: k} }

var _ types.MsgServer = msgServer{}

// IssueLocked creates a PermanentLockedAccount for the grantee and funds it with
// the locked principal + liquid gas allowance from the valgrant pool. Admin-gated.
func (m msgServer) IssueLocked(goCtx context.Context, msg *types.MsgIssueLocked) (*types.MsgIssueLockedResponse, error) {
	if err := m.requireAdmin(goCtx, msg.Admin); err != nil {
		return nil, err
	}
	ctx := sdk.UnwrapSDKContext(goCtx)

	bondDenom, err := m.stakingKeeper.BondDenom(goCtx)
	if err != nil {
		return nil, err
	}

	lockedAmt, ok := math.NewIntFromString(msg.LockedAmount)
	if !ok || !lockedAmt.IsPositive() {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "invalid locked_amount %q", msg.LockedAmount)
	}
	gasAmt, ok := math.NewIntFromString(msg.GasAllowance)
	if !ok || gasAmt.IsNegative() {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "invalid gas_allowance %q", msg.GasAllowance)
	}

	lockedCoins := sdk.NewCoins(sdk.NewCoin(bondDenom, lockedAmt))
	gasCoins := sdk.NewCoins()
	if gasAmt.IsPositive() {
		gasCoins = sdk.NewCoins(sdk.NewCoin(bondDenom, gasAmt))
	}
	validatorOperator, err := m.bindMainnetGrantValidator(goCtx, msg.Grantee, msg.ValidatorOperator)
	if err != nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, err.Error())
	}

	if err := m.IssueGrant(goCtx, msg.Grantee, lockedCoins, gasCoins); err != nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, err.Error())
	}

	// PER-VALIDATOR granted-share ledger (HIGH-A-CROSS): the MODULE performs the
	// locked delegation to grant.ValidatorOp so it records the EXACT shares the
	// grant minted there (the SDK does not track per-validator locked shares).
	// Delegating LOCKED (vesting) coins is fine - bank DelegateCoins fills the
	// PLVA's DelegatedVesting bucket. The recorded GrantedShares is then followed
	// through partial-unbond by the staking hooks, and the clawback reclaims
	// min(GrantedShares, live delegation shares) at grant.ValidatorOp - never the
	// account-global DelegatedVesting aggregate.
	//
	// HISTORICAL-CHAIN GUARANTEES (the fresh mainnet additionally blocks movements
	// below protected grant shares; see mainnet_lock.go). See hooks.go clamp and
	// the probes in
	// audit_split_delegation_probe_test.go). Shares are fungible, so the guarantee
	// is bounded-loss, NOT source-tracing:
	//   - The grantee never loses MORE than the grant. That holds.
	//   - The grantee's own self-bond at grant.ValidatorOp is NOT individually
	//     protected: a clawback may consume shares the grantee funded there, and
	//     the grantee's own value is preserved only in aggregate across validators.
	//   - Redelegation OUT of grant.ValidatorOp remains a partial evasion. No
	//     staking hook reports the destination side (BeginRedelegation writes its
	//     record AFTER Unbond and Delegate), so at hook time a redelegation and an
	//     undelegation are indistinguishable. Closing this needs a new hook or an
	//     EndBlock reconciliation, plus a state migration and a re-audit.
	// Public wording that is TRUE today: "governance can reclaim the grant; the
	// grantee never loses more than what was granted." NOT "full recovery guaranteed".
	//
	// If ValidatorOp is unset or the validator does not yet exist (bootstrap
	// order), the locked principal simply stays IN-ACCOUNT on the PLVA and is swept
	// by the immediate in-account path on clawback (GrantedShares stays 0).
	grantedShares := math.LegacyZeroDec()
	if validatorOperator != "" {
		if valBz, verr := m.stakingKeeper.ValidatorAddressCodec().StringToBytes(validatorOperator); verr == nil {
			if validator, gverr := m.stakingKeeper.GetValidator(goCtx, sdk.ValAddress(valBz)); gverr == nil {
				granteeBz, aerr := m.accountKeeper.AddressCodec().StringToBytes(msg.Grantee)
				if aerr != nil {
					return nil, errorsmod.Wrap(sdkerrors.ErrInvalidAddress, aerr.Error())
				}
				newShares, derr := m.stakingKeeper.Delegate(goCtx, granteeBz, lockedAmt, stakingtypes.Unbonded, validator, true)
				if derr != nil {
					return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, derr.Error())
				}
				grantedShares = newShares
			}
		}
	}

	// NOTE: the grant is recorded AFTER the module delegation above so the
	// delegation's own AfterDelegationModified hook is a no-op (no grant yet); the
	// authoritative GrantedShares/TrackedShares are set here from the mint result.
	grant := types.Grant{
		Grantee:      msg.Grantee,
		LockedAmount: lockedAmt.String(),
		GasAllowance: gasAmt.String(),
		ValidatorOp:  validatorOperator,
		IssuedHeight: uint64(ctx.BlockHeight()),
		IssuedTime:   ctx.BlockTime().Unix(),
		Status:       "active",
	}
	if grantedShares.IsPositive() {
		grant.GrantedShares = grantedShares.String()
		grant.TrackedShares = grantedShares.String()
	}
	if mainnetGrantProtection(goCtx) {
		// A fresh own validator starts at one token per share. Reserve the locked
		// shares now even when create-validator will happen in a later transaction.
		grant = m.seedGrantShares(grant, lockedAmt)
	}
	if err := m.SetGrant(goCtx, grant); err != nil {
		return nil, err
	}

	return &types.MsgIssueLockedResponse{}, nil
}

// Clawback revokes a grant and returns the foundation-granted LOCKED principal
// to the pool. Admin-gated.
//
// HIGH-D (cycle 7): this now executes the SAME surgical locked-share reclaim as
// the governance clawback (ClawbackGrantGov) - undelegating ONLY
// min(grant.GrantedShares, delegation shares) at grant.ValidatorOp and sweeping
// only the in-account LOCKED principal - instead of the retired blunt path that
// force-undelegated EVERY delegation (self-bond + other validators) and recorded
// each entry's full amount. The grantee's own self-bond, other-validator
// delegations, earned rewards, and gas allowance are never touched. The EVM
// precompile clawback(address) routes through this same handler, so both
// non-governance surfaces share the guarantee.
//
// Response mapping (the surgical reclaim's bonded portion IS the undelegation):
// UndelegateAmount == PendingAmount == the locked principal now unbonding
// (deferred sweep), SweptAmount == the in-account locked principal swept now.
func (m msgServer) Clawback(goCtx context.Context, msg *types.MsgClawback) (*types.MsgClawbackResponse, error) {
	if err := m.requireAdmin(goCtx, msg.Admin); err != nil {
		return nil, err
	}

	principalReturned, principalPending, _, _, _, err := m.Keeper.ClawbackGrantGov(goCtx, msg.Grantee, "admin_clawback")
	if err != nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, err.Error())
	}

	return &types.MsgClawbackResponse{
		UndelegateAmount: principalPending.String(),
		SweptAmount:      principalReturned.String(),
		PendingAmount:    principalPending.String(),
	}, nil
}

// ClawbackGrant is the GOVERNANCE-gated clawback: only the x/gov module account
// (the authority) may call it, so it executes ONLY via a passed proposal. It
// revokes a grant, returns the foundation-granted locked principal to the
// foundation reserve pool (never to the grantee), cancels unvested rewards owed
// to the grant, forfeits any on-chain exogenous deposit, and lets the validator
// seat fall out via unbonding. The runtime authority check mirrors
// MsgUpdateParams / x/encmempool. Rejects non-authority with code 4.
func (m msgServer) ClawbackGrant(goCtx context.Context, msg *types.MsgClawbackGrant) (*types.MsgClawbackGrantResponse, error) {
	// Stateless validation first (also enforced by the ante/msg router, but we
	// re-check here so a malformed msg is rejected cleanly - never panics).
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	// GOV-AUTHORITY GATE: authority must be the x/gov module account.
	govAddr := authtypes.NewModuleAddress(govtypes.ModuleName).String()
	if msg.Authority != govAddr {
		return nil, errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "expected gov authority %s, got %s", govAddr, msg.Authority)
	}

	pr, pp, rc, df, _, err := m.Keeper.ClawbackGrantGov(goCtx, msg.Grantee, msg.Reason)
	if err != nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, err.Error())
	}

	return &types.MsgClawbackGrantResponse{
		PrincipalReturned: pr.String(),
		PrincipalPending:  pp.String(),
		RewardsCancelled:  rc.String(),
		DepositForfeited:  df.String(),
	}, nil
}

// BurnPool permanently destroys LIMO from the valgrant reserve pool (admin-gated).
// amount "0"/empty burns the entire current pool balance. The coins are removed
// from the module account AND from total supply.
func (m msgServer) BurnPool(goCtx context.Context, msg *types.MsgBurnPool) (*types.MsgBurnPoolResponse, error) {
	if err := m.requireBurnAuthority(goCtx, msg.Admin); err != nil {
		return nil, err
	}

	burned, err := m.Keeper.BurnPool(goCtx, msg.Amount)
	if err != nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, err.Error())
	}

	return &types.MsgBurnPoolResponse{Burned: burned.String()}, nil
}

// UpdateParams sets the valgrant params. Gov-gated: only the x/gov module account
// may call it - the on-chain governance handoff lever to rotate the founder admin
// key or revoke it entirely (admin = "").
//
// It now writes BOTH params fields. Before, it wrote only p.Admin and silently
// carried the stored FoundationValidators forward, which meant the list the
// decentralisation KPI is computed from (FoundationVPBps in the per-block
// KPISnapshot) could NEVER be corrected after genesis: a validator that joined or
// left the foundation was mis-counted for the life of the chain, and the number
// published as the foundation voting-power KPI drifted from reality with no lever
// to fix it.
//
// REPLACEMENT SEMANTICS: msg.FoundationValidators REPLACES the stored list, it
// does not merge into it. A proposal that only means to rotate the admin key MUST
// restate the current list, or it clears it (and the KPI then reports foundation
// VP as 0). The alternative - treating an empty list as "leave it alone" - would
// make it impossible to ever clear the list, which is the one direction that
// matters when the foundation exits.
func (m msgServer) UpdateParams(goCtx context.Context, msg *types.MsgUpdateParams) (*types.MsgUpdateParamsResponse, error) {
	govAddr := authtypes.NewModuleAddress(govtypes.ModuleName).String()
	if msg.Authority != govAddr {
		return nil, errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "expected gov authority %s, got %s", govAddr, msg.Authority)
	}
	p := m.GetParams(goCtx)
	p.Admin = msg.Admin
	p.FoundationValidators = msg.FoundationValidators
	if err := m.SetParams(goCtx, p); err != nil {
		return nil, err
	}
	return &types.MsgUpdateParamsResponse{}, nil
}

func (m msgServer) requireAdmin(goCtx context.Context, signer string) error {
	admin := m.GetParams(goCtx).Admin
	if admin == "" {
		return errorsmod.Wrap(sdkerrors.ErrUnauthorized, "valgrant admin is not configured")
	}
	if signer != admin {
		return errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "signer %s is not the valgrant admin", signer)
	}
	return nil
}

// requireBurnAuthority gates BurnPool on EITHER the configured admin OR the
// x/gov module account. The gov path is how the Phase-2 taper burn is triggered:
// a passed gov proposal carrying MsgBurnPool sets msg.Admin to the gov module
// account (x/gov requires a proposal msg's signer to equal its authority). This
// dual gate applies ONLY to BurnPool; IssueLocked/Clawback stay founder-only.
func (m msgServer) requireBurnAuthority(goCtx context.Context, signer string) error {
	if signer == authtypes.NewModuleAddress(govtypes.ModuleName).String() {
		return nil
	}
	return m.requireAdmin(goCtx, signer)
}
