package ante

import (
	cosmosante "github.com/cosmos/evm/ante/cosmos"
	evmante "github.com/cosmos/evm/ante/evm"
	pmante "github.com/cosmos/evm/x/paymaster/ante"
	evmtypes "github.com/cosmos/evm/x/vm/types"
	ibcante "github.com/cosmos/ibc-go/v11/modules/core/ante"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	sdkvesting "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"
)

// newCosmosAnteHandler creates the default ante handler for Cosmos transactions
func newCosmosAnteHandler(ctx sdk.Context, options HandlerOptions) sdk.AnteHandler {
	feemarketParams := options.FeeMarketKeeper.GetParams(ctx)
	var txFeeChecker ante.TxFeeChecker
	if options.DynamicFeeChecker {
		txFeeChecker = evmante.NewDynamicFeeChecker(&feemarketParams)
	}

	return sdk.ChainAnteDecorators(
		cosmosante.NewRejectMessagesDecorator(), // reject MsgEthereumTxs
		cosmosante.NewAuthzLimiterDecorator( // disable the Msg types that cannot be included on an authz.MsgExec msgs field
			sdk.MsgTypeURL(&evmtypes.MsgEthereumTx{}),
			sdk.MsgTypeURL(&sdkvesting.MsgCreateVestingAccount{}),
		),
		ante.NewSetUpContextDecorator(),
		ante.NewExtensionOptionsDecorator(options.ExtensionOptionChecker),
		ante.NewValidateBasicDecorator(),
		ante.NewTxTimeoutHeightDecorator(),
		ante.NewValidateMemoDecorator(options.AccountKeeper),
		cosmosante.NewMinGasPriceDecorator(&feemarketParams, options.PaymasterKeeper),
		ante.NewConsumeGasForTxSizeDecorator(options.AccountKeeper),
		pmante.NewDeductFeeDecorator(options.AccountKeeper, options.BankKeeper, options.FeegrantKeeper, options.PaymasterKeeper, txFeeChecker),
		// SetPubKeyDecorator must be called before all signature verification decorators
		ante.NewSetPubKeyDecorator(options.AccountKeeper),
		ante.NewValidateSigCountDecorator(options.AccountKeeper),
		ante.NewSigGasConsumeDecorator(options.AccountKeeper, options.SigGasConsumer),
		cosmosante.NewWebAuthnSigVerificationDecorator(options.AccountKeeper, options.SignModeHandler, options.PasskeyEnabled),
		ante.NewIncrementSequenceDecorator(options.AccountKeeper),
		ibcante.NewRedundantRelayDecorator(options.IBCKeeper),
	)
}
