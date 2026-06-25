package keeper

import (
	"context"
	"strconv"
	"strings"

	errorsmod "cosmossdk.io/errors"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/ethereum/go-ethereum/common"

	"github.com/cosmos/evm/x/contest/types"
)

type msgServer struct {
	Keeper
}

// NewMsgServerImpl returns the x/contest MsgServer backed by the keeper.
func NewMsgServerImpl(k Keeper) types.MsgServer { return &msgServer{Keeper: k} }

var _ types.MsgServer = msgServer{}

// RegisterShowcase adds/approves a showcase app in the on-chain registry so its
// activity is scored. Admin-gated: the signer must equal params.admin.
func (m msgServer) RegisterShowcase(goCtx context.Context, msg *types.MsgRegisterShowcase) (*types.MsgRegisterShowcaseResponse, error) {
	if err := m.requireAdmin(goCtx, msg.Admin); err != nil {
		return nil, err
	}
	vm := msg.Vm
	if vm == "" {
		vm = "evm"
	}
	if vm == "evm" && !common.IsHexAddress(msg.Address) {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid EVM contract address %q", msg.Address)
	}
	app := types.ShowcaseApp{Address: normalizeAddr(msg.Address, vm), Dev: msg.Dev, VM: vm, Approved: true}
	if err := m.SetShowcase(goCtx, app); err != nil {
		return nil, err
	}
	sdk.UnwrapSDKContext(goCtx).EventManager().EmitEvent(sdk.NewEvent(
		"contest_showcase_registered",
		sdk.NewAttribute("address", app.Address),
		sdk.NewAttribute("dev", app.Dev),
		sdk.NewAttribute("vm", app.VM),
	))
	return &types.MsgRegisterShowcaseResponse{}, nil
}

// RemoveShowcase removes a showcase app from the registry (admin-gated).
func (m msgServer) RemoveShowcase(goCtx context.Context, msg *types.MsgRemoveShowcase) (*types.MsgRemoveShowcaseResponse, error) {
	if err := m.requireAdmin(goCtx, msg.Admin); err != nil {
		return nil, err
	}
	m.DeleteShowcase(goCtx, normalizeAddr(msg.Address, "evm"))
	sdk.UnwrapSDKContext(goCtx).EventManager().EmitEvent(sdk.NewEvent(
		"contest_showcase_removed",
		sdk.NewAttribute("address", normalizeAddr(msg.Address, "evm")),
	))
	return &types.MsgRemoveShowcaseResponse{}, nil
}

// SetPasskeyEnabled toggles the experimental WebAuthn/P-256 passkey ante path
// (admin-gated). This is the governance switch for the audit-pending feature.
func (m msgServer) SetPasskeyEnabled(goCtx context.Context, msg *types.MsgSetPasskeyEnabled) (*types.MsgSetPasskeyEnabledResponse, error) {
	if err := m.requireAdmin(goCtx, msg.Admin); err != nil {
		return nil, err
	}
	p := m.GetParams(goCtx)
	p.PasskeyEnabled = msg.Enabled
	if err := m.SetParams(goCtx, p); err != nil {
		return nil, err
	}
	sdk.UnwrapSDKContext(goCtx).EventManager().EmitEvent(sdk.NewEvent(
		"contest_passkey_enabled",
		sdk.NewAttribute("enabled", strconv.FormatBool(msg.Enabled)),
	))
	return &types.MsgSetPasskeyEnabledResponse{}, nil
}

func (m msgServer) requireAdmin(goCtx context.Context, signer string) error {
	admin := m.GetParams(goCtx).Admin
	if admin == "" {
		return errorsmod.Wrap(sdkerrors.ErrUnauthorized, "contest admin is not configured")
	}
	if signer != admin {
		return errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "signer %s is not the contest admin", signer)
	}
	return nil
}

// normalizeAddr lower-cases EVM hex addresses so registry lookups match the
// PostHandler (which keys on strings.ToLower(to.Hex())). WASM addrs are kept as-is.
func normalizeAddr(addr, vm string) string {
	if vm == "evm" {
		return strings.ToLower(addr)
	}
	return addr
}
