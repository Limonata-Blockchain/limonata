package keeper

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// ResolveSponsor returns the sponsor account that should pay this transaction's
// fee, if any enabled policy matches. A policy matches when:
//   - AllowedSender is empty OR equals the fee payer,
//   - MsgTypeURL is empty OR at least one msg has that type,
//   - PerTxCap is empty OR the fee is <= the cap (per denom).
// The first matching policy wins.
func (k Keeper) ResolveSponsor(ctx context.Context, msgs []sdk.Msg, feePayer sdk.AccAddress, fee sdk.Coins) (sdk.AccAddress, bool) {
	policies, err := k.GetPolicies(ctx)
	if err != nil {
		return nil, false
	}
	for _, p := range policies {
		if p.AllowedSender != "" && p.AllowedSender != feePayer.String() {
			continue
		}
		if p.MsgTypeURL != "" && !msgMatches(msgs, p.MsgTypeURL) {
			continue
		}
		if p.PerTxCap != "" {
			capCoins, e := sdk.ParseCoinsNormalized(p.PerTxCap)
			if e != nil || !fee.IsAllLTE(capCoins) {
				continue
			}
		}
		sponsor, e := sdk.AccAddressFromBech32(p.Sponsor)
		if e != nil {
			continue
		}
		return sponsor, true
	}
	return nil, false
}

func msgMatches(msgs []sdk.Msg, typeURL string) bool {
	for _, m := range msgs {
		if sdk.MsgTypeURL(m) == typeURL {
			return true
		}
	}
	return false
}
