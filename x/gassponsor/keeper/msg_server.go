package keeper

import (
	"context"
	"encoding/json"

	errorsmod "cosmossdk.io/errors"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"

	"github.com/cosmos/evm/x/gassponsor/types"
)

type msgServer struct{ Keeper }

// NewMsgServerImpl returns the x/gassponsor Msg service implementation.
func NewMsgServerImpl(k Keeper) types.MsgServer { return &msgServer{Keeper: k} }

var _ types.MsgServer = msgServer{}

// UpdateParams atomically REPLACES the x/gassponsor params. Gov-gated: only the
// x/gov module account may call it - there is deliberately NO admin key on the
// module that MINTS the gasless subsidy.
//
// This is the on-chain KILL-SWITCH for gasless. Without this handler all 13
// gassponsor params were writable ONLY at InitGenesis, which means a mainnet born
// with refill_daily_mint_cap="0" (unlimited) could not have had that ceiling
// tightened, and a live pool drain could not have been stopped, without a
// coordinated binary upgrade.
//
// FULL-REPLACEMENT SEMANTICS, and the footgun it carries: the payload is decoded
// into a ZERO Params, so a proposal that omits a key silently RESETS it. Here that
// is not survivable - an omitted "enabled" turns gasless off, and an omitted cap
// decodes as "" which this module reads as UNLIMITED. The handler therefore
// refuses an INCOMPLETE payload (types.RequireCompleteParamsJSON) rather than
// ratcheting: governance keeps the authority to move every value in both
// directions, it just has to state each one, where voters can read it.
func (m msgServer) UpdateParams(goCtx context.Context, msg *types.MsgUpdateParams) (*types.MsgUpdateParamsResponse, error) {
	govAddr := authtypes.NewModuleAddress(govtypes.ModuleName).String()
	if msg.Authority != govAddr {
		return nil, errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "expected gov authority %s, got %s", govAddr, msg.Authority)
	}
	// Completeness check BEFORE decoding into the zero struct (see the footgun note).
	if err := types.RequireCompleteParamsJSON(msg.Params); err != nil {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, err.Error())
	}
	var p types.Params
	if err := json.Unmarshal(msg.Params, &p); err != nil {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "invalid params json: %v", err)
	}
	// Same validation the genesis path runs, so an update can never install params
	// InitGenesis would have rejected.
	if err := (types.GenesisState{Params: p}).Validate(); err != nil {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "invalid params: %v", err)
	}
	if err := m.SetParams(goCtx, p); err != nil {
		return nil, err
	}
	return &types.MsgUpdateParamsResponse{}, nil
}
