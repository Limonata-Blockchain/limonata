package cli

import (
	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

// NewTxCmd returns the x/valgrant transaction subcommands. Issuance and the
// admin clawback/burn are founder-only and driven off-chain; the only CLI-facing
// tx is the governance clawback, which must be carried by a gov proposal.
func NewTxCmd() *cobra.Command {
	txCmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "valgrant transaction subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}
	txCmd.AddCommand(NewClawbackGrantCmd())
	return txCmd
}

// NewClawbackGrantCmd builds a governance-gated MsgClawbackGrant whose authority
// is the x/gov module account. Because the message is gov-gated it can only be
// EXECUTED by a passed proposal — use this with --generate-only to emit the
// message JSON to embed in `tx gov submit-proposal`.
func NewClawbackGrantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clawback-grant [grantee] [reason]",
		Short: "Generate a governance MsgClawbackGrant (gov-gated) revoking a validator grant",
		Long: `Generate a governance-gated MsgClawbackGrant that revokes a validator-bootstrap
grant: it returns the foundation-granted locked principal to the foundation
reserve pool (never to the grantee), cancels unvested rewards owed to the grant,
forfeits any on-chain deposit, and lets the validator seat fall out via
unbonding. It reclaims ONLY the granted locked principal — never a validator's
own self-bond. The message authority is the x/gov module account, so it must be
carried by a governance proposal: use --generate-only and embed the output in
'tx gov submit-proposal'.`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cliCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			reason := ""
			if len(args) == 2 {
				reason = args[1]
			}
			msg := &types.MsgClawbackGrant{
				Authority: authtypes.NewModuleAddress(govtypes.ModuleName).String(),
				Grantee:   args[0],
				Reason:    reason,
			}
			if err := msg.ValidateBasic(); err != nil {
				return err
			}
			return tx.GenerateOrBroadcastTxCLI(cliCtx, cmd.Flags(), msg)
		},
	}
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}
