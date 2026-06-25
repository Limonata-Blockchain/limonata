package types

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Policy is a standing sponsorship authorization. A transaction is sponsored if
// it matches an enabled policy; the sponsor account then pays the fee.
type Policy struct {
	Sponsor       string `json:"sponsor"`                 // bech32 account that pays the fee
	AllowedSender string `json:"allowed_sender,omitempty"` // "" = any fee payer
	MsgTypeURL    string `json:"msg_type_url,omitempty"`   // "" = any message type
	PerTxCap      string `json:"per_tx_cap,omitempty"`     // "" = no cap; else coins, e.g. "20000000000aLIMO"
}

// GenesisState is the paymaster genesis (plain JSON, no proto).
type GenesisState struct {
	Policies []Policy `json:"policies"`
}

func DefaultGenesisState() *GenesisState { return &GenesisState{Policies: []Policy{}} }

func (gs GenesisState) Validate() error {
	for i, p := range gs.Policies {
		if _, err := sdk.AccAddressFromBech32(p.Sponsor); err != nil {
			return fmt.Errorf("policy %d: invalid sponsor %q: %w", i, p.Sponsor, err)
		}
		if p.AllowedSender != "" {
			if _, err := sdk.AccAddressFromBech32(p.AllowedSender); err != nil {
				return fmt.Errorf("policy %d: invalid allowed_sender %q: %w", i, p.AllowedSender, err)
			}
		}
		if p.PerTxCap != "" {
			if _, err := sdk.ParseCoinsNormalized(p.PerTxCap); err != nil {
				return fmt.Errorf("policy %d: invalid per_tx_cap %q: %w", i, p.PerTxCap, err)
			}
		}
	}
	return nil
}
