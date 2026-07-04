package evmd

import (
	"strings"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"

	evmmempool "github.com/cosmos/evm/mempool"
	"github.com/cosmos/evm/server"
	gassponsortypes "github.com/cosmos/evm/x/gassponsor/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	sdkmath "cosmossdk.io/math"

	"cosmossdk.io/log/v2"

	"github.com/cosmos/cosmos-sdk/baseapp"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// configureEVMMempool sets up the EVM mempool and related handlers using viper configuration.
func (app *EVMD) configureEVMMempool(appOpts servertypes.AppOptions, logger log.Logger) error {
	if evmtypes.GetChainConfig() == nil {
		logger.Debug("evm chain config is not set, skipping mempool configuration")
		return nil
	}

	var (
		mpConfig = server.ResolveMempoolConfig(app.GetAnteHandler(), appOpts, logger)

		txEncoder       = evmmempool.NewTxEncoder(app.txConfig)
		evmRechecker    = evmmempool.NewTxRechecker(mpConfig.AnteHandler, txEncoder)
		cosmosRechecker = evmmempool.NewTxRechecker(mpConfig.AnteHandler, txEncoder)
		cosmosPoolMaxTx = server.GetCosmosPoolMaxTx(appOpts, logger)
		checkTxTimeout  = server.GetMempoolCheckTxTimeout(appOpts, logger)
	)

	if cosmosPoolMaxTx < 0 {
		logger.Debug("evm mempool is disabled, skipping configuration")
		return nil
	}

	if err := server.ValidateReapBounds(appOpts, mpConfig.BlockGasLimit); err != nil {
		return err
	}

	// Relax mempool admission for txs a protocol gas-sponsorship mechanism (x/gassponsor)
	// is expected to pay for -- most importantly a brand-new 0-balance account's first
	// (onboarding-grant) tx, whose only cost is gas it does not itself hold. Without this,
	// legacypool's plain State.GetBalance(from) < tx.Cost() check rejects the tx before the
	// ante handler ever gets a chance to apply the real sponsorship decision.
	mpConfig.IsGasSponsored = app.isGasSponsoredHeuristic

	// create mempool
	mempool := evmmempool.NewMempool(
		app.CreateQueryContext,
		logger,
		app.EVMKeeper,
		app.FeeMarketKeeper,
		app.txConfig,
		evmRechecker,
		cosmosRechecker,
		mpConfig,
		cosmosPoolMaxTx,
	)

	app.EVMMempool = mempool

	// create ABCI handlers
	proposalHandler := baseapp.NewDefaultProposalHandler(mempool, NewNoCheckProposalTxVerifier(app.BaseApp))
	prepareProposalHandler := proposalHandler.PrepareProposalHandler()
	processProposalHandler := proposalHandler.ProcessProposalHandler()

	insertTxHandler := mempool.NewInsertTxHandler(app.TxDecode)
	reapTxsHandler := mempool.NewReapTxsHandler()
	checkTxHandler := mempool.NewCheckTxHandler(app.TxDecode, checkTxTimeout)

	// set handlers and the mempool. The TRANSPARENT in-node DKG COMPOSES around the EVM
	// mempool's PrepareProposal (inject the H-1 extended commit) and around the default
	// ProcessProposal (self-certify + strip the injected blob, then delegate the real txs).
	// Both wrappers are strict no-ops unless DkgEnabled && DkgTransparent, so the default
	// binary behaves exactly as before. ExtendVote/VerifyVoteExtension supply/verify the
	// per-node DKG contribution carried on consensus votes.
	app.SetPrepareProposal(app.wrapDkgPrepareProposal(prepareProposalHandler))
	app.SetProcessProposal(app.wrapDkgProcessProposal(processProposalHandler))
	app.SetExtendVoteHandler(app.dkgExtendVoteHandler())
	app.SetVerifyVoteExtensionHandler(app.dkgVerifyVoteExtensionHandler())
	app.SetInsertTxHandler(insertTxHandler)
	app.SetReapTxsHandler(reapTxsHandler)
	app.SetCheckTxHandler(checkTxHandler)

	app.SetMempool(mempool)

	app.SetPrepareCheckStater(func(_ sdk.Context) {
		if !mempool.HasEventBus() {
			mempool.NotifyNewBlock()
		}
	})

	return nil
}

// isGasSponsoredHeuristic is a READ-ONLY, best-effort approximation of
// x/gassponsor.Keeper.IsSponsored, used only to decide whether the EVM mempool
// should admit/keep a tx whose sender can't otherwise afford it. It is
// deliberately NOT the real decision:
//
//   - IsSponsored is stateful and DEBITS the baseline/onboarding day counters
//     exactly once per tx (from the ante, at execution time); calling it here
//     would double-count or mis-count against a query-context snapshot that
//     never commits.
//   - This heuristic only ever widens admission, never consensus outcomes: if
//     it says "sponsored" and the ante later disagrees, the tx fails/gets
//     evicted like any other tx invalidated between admission and execution.
//
// It mirrors IsSponsored's fall-through order using only side-effect-free
// keeper reads (GetParams / GetShowcase / GetAllBalances / EffectiveAllowance /
// AllowanceUsed / OnboardingUsed).
func (app *EVMD) isGasSponsoredHeuristic(from common.Address, tx *ethtypes.Transaction) bool {
	// Sponsorship only ever covers the fee leg, never the value leg: a tx that
	// moves value must still be affordable out of the sender's own balance.
	if tx.Value().Sign() != 0 {
		return false
	}

	ctx, err := app.CreateQueryContext(0, false)
	if err != nil {
		return false
	}

	p := app.GasSponsorKeeper.GetParams(ctx)
	if !p.Enabled {
		return false
	}

	sender := sdk.AccAddress(from.Bytes())

	// 1. Approved dApp destination: the approved-dApp path sponsors regardless
	// of sender balance (bounded per-tx by DappPerTxFeeCap at execution time).
	if to := tx.To(); to != nil {
		if showcase, ok := app.ContestKeeper.GetShowcase(ctx, strings.ToLower(to.Hex())); ok &&
			showcase.Approved && (showcase.VM == "" || showcase.VM == "evm") {
			return true
		}
	}

	held := app.BankKeeper.GetAllBalances(ctx, sender).AmountOf(gassponsortypes.FeeDenom)
	if held.IsZero() {
		// 2. Cold (0-balance) wallet: only the one-shot onboarding grant can pay
		// this. Check remaining lifetime budget without debiting it.
		grant, ok := sdkmath.NewIntFromString(p.OnboardingGrant)
		if !ok || !grant.IsPositive() {
			return false
		}
		used := app.GasSponsorKeeper.OnboardingUsed(ctx, sender)
		return used.LT(grant)
	}

	// 3. Holder: sponsored only while today's per-account baseline allowance
	// still has headroom.
	allow := app.GasSponsorKeeper.EffectiveAllowance(ctx, sender)
	if !allow.IsPositive() {
		return false
	}
	used := app.GasSponsorKeeper.AllowanceUsed(ctx, sender)
	return used.LT(allow)
}
