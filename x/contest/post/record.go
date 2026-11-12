// Package post records contest metrics after successful tx execution. It taps the
// PostHandler so it only counts txs that actually succeeded on-chain (not CheckTx,
// not simulation). For each EVM call to an approved Showcase contract it credits the
// developer's tx-volume and marks the sender active for the day (Tester-track UAW).
package post

import (
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/contest/keeper"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

type RecordDecorator struct {
	k keeper.Keeper
}

func NewRecordDecorator(k keeper.Keeper) RecordDecorator { return RecordDecorator{k: k} }

func (d RecordDecorator) PostHandle(ctx sdk.Context, tx sdk.Tx, simulate, success bool, next sdk.PostHandler) (sdk.Context, error) {
	if simulate || !success || ctx.IsCheckTx() {
		return next(ctx, tx, simulate, success)
	}
	if d.k.SnapshotDone(ctx) {
		return next(ctx, tx, simulate, success)
	}
	day := uint64(ctx.BlockTime().UTC().Unix() / 86400)
	for _, msg := range tx.GetMsgs() {
		ethMsg, ok := msg.(*evmtypes.MsgEthereumTx)
		if !ok {
			continue
		}
		ethTx := ethMsg.AsTransaction()
		if ethTx == nil || ethTx.To() == nil { // nil To = contract creation, no target app
			continue
		}
		contract := strings.ToLower(ethTx.To().Hex())
		app, found := d.k.GetShowcase(ctx, contract)
		if !found || !app.Approved {
			continue
		}
		d.k.AddDevTxVolume(ctx, app.Dev, 1)                                  // Developer track
		d.k.MarkActiveToday(ctx, day, strings.ToLower(ethMsg.GetSender().Hex())) // Tester track (deduped per day)
	}
	return next(ctx, tx, simulate, success)
}
