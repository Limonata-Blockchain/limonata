package types

import (
	errorsmod "cosmossdk.io/errors"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// maxReasonLen bounds the free-text clawback reason recorded in the loud event,
// keeping the tx (and the emitted event) size deterministic and bounded.
const maxReasonLen = 512

// ValidateBasic performs stateless validation of MsgClawbackGrant. The
// authority/grantee bech32 well-formedness is checked here; the runtime
// gov-authority gate (authority == x/gov module account) is enforced in the
// msg server (stateful, mirrors x/valgrant MsgUpdateParams). Never panics.
func (m *MsgClawbackGrant) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Authority); err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid authority address %q: %s", m.Authority, err)
	}
	if _, err := sdk.AccAddressFromBech32(m.Grantee); err != nil {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidAddress, "invalid grantee address %q: %s", m.Grantee, err)
	}
	if len(m.Reason) > maxReasonLen {
		return errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "reason too long: %d > %d", len(m.Reason), maxReasonLen)
	}
	return nil
}
