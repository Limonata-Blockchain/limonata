package types

import (
	"encoding/json"
	"fmt"
)

// GENESIS TWIN of the HIGH-1 vote-extension guard.
//
// keeper/msg_server.go (UpdateParams) refuses to turn the TRANSPARENT in-node DKG on
// unless CometBFT vote extensions are already scheduled and the injected extended-commit
// aggregate fits the chain's block max_bytes. That guard protects a LIVE chain. It does
// NOT protect a chain that is BORN with dkg_enabled=true + dkg_transparent=true in
// app_state.encmempool while consensus.params.abci.vote_extensions_enable_height is 0:
// the DKG state machine opens a round, EndBlock requires a proposer-injected commit, and
// ProcessProposal rejects every proposal that cannot carry one -> no block is ever
// accepted after the first DKG open.
//
// WHY THIS LIVES IN A SEPARATE, PURE FUNCTION AND NOT IN GenesisState.Validate():
// GenesisState.Validate() is a pure function with no access to consensus params, and it
// is reached from AppModuleBasic.ValidateGenesis (offline `validate-genesis`) which only
// ever receives app_state.encmempool - never the consensus section of the genesis doc.
// The consensus params are only in hand at InitChain, in RequestInitChain.ConsensusParams.
// (sdk.Context.ConsensusParams() is NOT usable there: cosmos-sdk v0.54.3 sets the params
// on the context in FinalizeBlock/PrepareProposal/ProcessProposal only - baseapp/state's
// Manager.SetState never calls WithConsensusParams, so inside InitChainer the context
// carries the ZERO value and this check would reject every transparent genesis.)
//
// So the CALL SITE is evmd's InitChainer, and this file adds NO call from any existing
// x/encmempool code path. Every pre-existing file of this module stays byte-identical to
// the live v0.3.6 build: an added, never-called-from-consensus pure function cannot change
// the replay of any already-produced block.

// ValidateGenesisVoteExtensions checks an encmempool genesis fragment against the genesis
// consensus params.
//
//   - appStateJSON is the raw app_state["encmempool"] document; nil/empty means the module
//     is absent from the genesis and the check is a no-op.
//   - voteExtensionsEnableHeight is consensus.params.abci.vote_extensions_enable_height
//     (0 when unset, i.e. vote extensions are NOT scheduled).
//   - blockMaxBytes is consensus.params.block.max_bytes (0 or negative = unknown/unbounded,
//     in which case the size clause is skipped, exactly as in MsgUpdateParams).
//
// The predicate and both error strings mirror keeper/msg_server.go so the two doors report
// the same refusal.
func ValidateGenesisVoteExtensions(appStateJSON json.RawMessage, voteExtensionsEnableHeight, blockMaxBytes int64) error {
	if len(appStateJSON) == 0 {
		return nil
	}
	var gs GenesisState
	if err := json.Unmarshal(appStateJSON, &gs); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis: %w", ModuleName, err)
	}
	return gs.ValidateVoteExtensions(voteExtensionsEnableHeight, blockMaxBytes)
}

// ValidateVoteExtensions is the decoded form of ValidateGenesisVoteExtensions.
func (gs GenesisState) ValidateVoteExtensions(voteExtensionsEnableHeight, blockMaxBytes int64) error {
	p := gs.Params
	if !p.DkgEnabled || !p.DkgTransparent {
		return nil
	}
	if voteExtensionsEnableHeight == 0 {
		return fmt.Errorf(
			"%s genesis: dkg_transparent requires CometBFT vote extensions to be scheduled first (consensus param vote_extensions_enable_height must be non-zero)",
			ModuleName)
	}
	if blockMaxBytes > 0 && !p.DkgInjectedCommitFitsMaxTxBytes(blockMaxBytes) {
		return fmt.Errorf(
			"%s genesis: transparent DKG vote-extension aggregate is estimated at %d bytes but consensus max_tx_bytes is %d; lower dkg_max_members/dkg_share_budget or raise consensus block max bytes",
			ModuleName, p.DkgInjectedCommitBytesUpperBound(), blockMaxBytes)
	}
	return nil
}
