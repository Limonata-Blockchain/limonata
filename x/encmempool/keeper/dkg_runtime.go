package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/types"
)

const (
	transparentDkgRuntimeVoteExtensionsInactive = "vote_extensions_inactive"
	transparentDkgRuntimeInjectionOversize      = "injected_commit_oversize"
)

type transparentDkgRuntimeStatus struct {
	reason                     string
	currentHeight              int64
	voteExtensionsEnableHeight int64
	estimatedBytes             int64
	maxTxBytes                 int64
}

func transparentDkgRuntimeUnavailable(ctx sdk.Context, p types.Params) (transparentDkgRuntimeStatus, bool) {
	st := transparentDkgRuntimeStatus{currentHeight: ctx.BlockHeight()}
	if !p.DkgEnabled || !p.DkgTransparent {
		return st, false
	}
	cp := ctx.ConsensusParams()
	if cp.Abci == nil || !types.VoteExtEnabledAt(cp.Abci.VoteExtensionsEnableHeight, ctx.BlockHeight()) {
		if cp.Abci != nil {
			st.voteExtensionsEnableHeight = cp.Abci.VoteExtensionsEnableHeight
		}
		st.reason = transparentDkgRuntimeVoteExtensionsInactive
		return st, true
	}
	if cp.Block != nil && cp.Block.MaxBytes > 0 && !p.DkgInjectedCommitFitsMaxTxBytes(cp.Block.MaxBytes) {
		st.reason = transparentDkgRuntimeInjectionOversize
		st.estimatedBytes = p.DkgInjectedCommitBytesUpperBound()
		st.maxTxBytes = cp.Block.MaxBytes
		return st, true
	}
	return st, false
}
