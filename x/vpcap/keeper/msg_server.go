package keeper

import (
	"context"
	"encoding/json"

	errorsmod "cosmossdk.io/errors"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"

	"github.com/cosmos/evm/x/vpcap/types"
)

type msgServer struct{ Keeper }

// NewMsgServerImpl returns the x/vpcap Msg service implementation.
func NewMsgServerImpl(k Keeper) types.MsgServer { return &msgServer{Keeper: k} }

var _ types.MsgServer = msgServer{}

// UpdateParams atomically REPLACES the x/vpcap params. Gov-gated: only the x/gov
// module account may call it, so the decentralisation cap can only be moved by a
// passed proposal - there is deliberately NO admin key on this module.
//
// Without this handler the 4 vpcap params were writable ONLY at InitGenesis: a
// mainnet born with enabled=false, or with the wrong per_validator_cap_bps, would
// have needed a coordinated binary upgrade to correct.
//
// FULL-REPLACEMENT SEMANTICS, and the footgun it carries: the payload is decoded
// into a ZERO Params, so a proposal that omits a key silently sets that key to its
// zero value. For "enabled" that means SILENTLY DISABLING THE CAP - the exact
// failure x/encmempool had to bolt a one-way ratchet on after the fact. A ratchet
// is wrong here (governance must legitimately be able to move the cap in both
// directions as the set grows), so instead the handler REFUSES an INCOMPLETE
// payload: see types.RequireCompleteParamsJSON.
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
	// Same validation the genesis path runs, so an update can never install a config
	// InitGenesis would have rejected.
	if err := (types.GenesisState{Params: p}).Validate(); err != nil {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "invalid params: %v", err)
	}
	if err := m.SetParams(goCtx, p); err != nil {
		return nil, err
	}
	return &types.MsgUpdateParamsResponse{}, nil
}
