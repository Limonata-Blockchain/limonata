package evmd

import (
	"bytes"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	"github.com/cosmos/cosmos-sdk/baseapp"
	sdk "github.com/cosmos/cosmos-sdk/types"

	encmempooldkg "github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/dkgnode"
	encmempoolkeeper "github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	encmempooltypes "github.com/cosmos/evm/x/encmempool/types"
)

// ============================================================================
// TRANSPARENT in-node DKG — ABCI++ vote-extension wiring (the hardest consensus
// surface in the repo). A validator that simply RUNS THE BINARY participates in the
// DKG automatically: its node attaches its dealing / decryption shares / enc-key
// announcement to its consensus pre-commit vote (ExtendVote), CometBFT signs+tags it
// with the node's consensus identity, the proposer injects the H-1 ExtendedCommitInfo
// as a block-data pseudo-tx, ProcessProposal self-certifies it (ValidateVoteExtensions),
// and a PreBlocker deterministically consumes it into module state. No daemon, no
// account, no fees, no manual key registration.
//
// DORMANCY: every handler is a strict no-op unless the module params say DkgEnabled &&
// DkgTransparent AND CometBFT vote extensions are enabled (VoteExtensionsEnableHeight, a
// consensus param). So the default binary behaves EXACTLY as before — the gov kill-switch
// keeps the whole surface off.
// ============================================================================

// veInjectMarker prefixes the injected ExtendedCommitInfo pseudo-tx so ProcessProposal /
// PreBlock can recognize + strip it. A real protobuf-encoded sdk.Tx never begins with 0x00
// (protobuf field 0 is invalid), so this cannot collide with a genuine tx.
var veInjectMarker = []byte("\x00LIMO-DKG-VE\x00")

// veActive reports whether the transparent in-node DKG is switched on FOR THIS HEIGHT. It
// requires BOTH switches: the module params (DkgEnabled && DkgTransparent) AND CometBFT
// vote extensions active at this height (the consensus param VoteExtensionsEnableHeight).
//
// HIGH-1: keying only off the module params (as before) let governance flip DkgTransparent
// on while vote extensions were not enabled at the CometBFT level. ProcessProposal would then
// require/self-certify an injected commit whose extension signatures ValidateVoteExtensions
// cannot validate for a VE-disabled height -> every validator REJECTs -> chain HALT. Coupling
// veActive to the consensus param EXACTLY as baseapp.ValidateVoteExtensions gates (via
// VoteExtEnabledAt: enableHeight != 0 && height > enableHeight) makes every handler a strict
// no-op until VE is genuinely active, so flipping the module param on can never halt.
func (app *EVMD) veActive(ctx sdk.Context) bool {
	p := app.EncMempoolKeeper.GetParams(ctx)
	if !p.DkgEnabled || !p.DkgTransparent {
		return false
	}
	cp := app.GetConsensusParams(ctx)
	if cp.Abci == nil {
		return false
	}
	return encmempooltypes.VoteExtEnabledAt(cp.Abci.VoteExtensionsEnableHeight, ctx.BlockHeight())
}

// myOperator resolves THIS node's validator operator address for the transparent DKG. It
// reads the node's consensus address from <home>/config/priv_validator_key.json ONCE
// (node-local, no consensus obligation), then maps it to the operator via staking (a
// committed, deterministic read). It returns "" when the node is not a resolvable bonded
// validator (a full node, or staking not yet aware of it), in which case the node simply
// does not participate. This is what lets a node self-identify by OPERATOR — its real
// consensus identity — instead of by a spoofable enc-key match (HIGH-4), and sign an
// operator-bound proof-of-possession for its announced enc key (HIGH-2).
func (app *EVMD) myOperator(ctx sdk.Context) string {
	app.dkgConsAddrOnce.Do(func() {
		if app.dkgHome == "" {
			return
		}
		app.dkgConsAddr, _ = dkgnode.LoadConsAddress(app.dkgHome)
	})
	if len(app.dkgConsAddr) == 0 {
		return ""
	}
	val, err := app.StakingKeeper.GetValidatorByConsAddr(ctx, sdk.ConsAddress(app.dkgConsAddr))
	if err != nil {
		return ""
	}
	return val.GetOperator()
}

// encKey lazily loads (or, on first boot, generates+persists) the node's secp256k1 DKG
// enc key from <home>/dkg_enc_key.json. Errors degrade to non-participation (nil), never a
// halt — a node that cannot key itself simply contributes nothing.
func (app *EVMD) encKey() *dkgnode.EncKey {
	app.dkgEncKeyOnce.Do(func() {
		if app.dkgHome == "" {
			return
		}
		app.dkgEncKey, app.dkgEncKeyErr = dkgnode.LoadOrCreateEncKey(app.dkgHome)
	})
	return app.dkgEncKey
}

// ---- ExtendVote: attach this node's DKG contribution to its pre-commit vote ----

func (app *EVMD) dkgExtendVoteHandler() sdk.ExtendVoteHandler {
	return func(ctx sdk.Context, _ *abci.RequestExtendVote) (*abci.ResponseExtendVote, error) {
		empty := &abci.ResponseExtendVote{VoteExtension: []byte{}}
		if !app.veActive(ctx) {
			return empty, nil
		}
		ek := app.encKey()
		if ek == nil {
			return empty, nil // no key => no participation (never halt)
		}
		op := app.myOperator(ctx)
		if op == "" {
			return empty, nil // can't resolve our operator => can't self-identify / prove PoP
		}
		k := app.EncMempoolKeeper
		// Announce the enc key WITH an operator-bound proof-of-possession (HIGH-2/HIGH-4): the
		// consume path rejects an announcement whose PoP does not prove we hold this key under
		// this operator, so a node cannot claim another validator's observed public key.
		ve := encmempooltypes.VoteExtension{
			EncPubKey:    ek.Pub,
			EncPubKeyPoP: encmempooldkg.SignEncKeyPoP(ek.Priv, op),
		}

		// Dealing for the currently-open round, if I am a member and have not dealt yet.
		// Self-identify by OPERATOR (not by enc-key match) so a colliding key can't misindex us.
		if cur := k.GetCurrentEpoch(ctx); cur > 0 {
			if round, ok := k.GetDkgRound(ctx, cur); ok &&
				round.Status == encmempooltypes.DkgStatusOpen &&
				uint64(ctx.BlockHeight()) <= round.DealDeadline {
				if idx := encmempooltypes.MemberIndexByOperator(round.Members, op); idx != 0 {
					if _, dealt := k.GetDealing(ctx, round.Epoch, idx); !dealt {
						if d, err := dkgnode.BuildDealing(round.Epoch, round.Members, idx, int(round.Threshold)); err == nil {
							ve.Dealing = d
						}
					}
				}
			}
		}

		// Decryption shares for not-yet-matured ciphertexts I can serve.
		ve.Shares = app.buildDecryptShares(ctx, ek, op)

		return &abci.ResponseExtendVote{VoteExtension: encmempooltypes.MarshalVoteExtension(ve)}, nil
	}
}

// buildDecryptShares produces this node's DLEQ-proved decryption shares for in-flight
// ciphertexts of epochs it holds shares for — both NOT-YET-MATURED ones and matured ones
// still inside the keeper's bounded decrypt-deferral window (cycle-3 H-B: a matured
// ciphertext short of t shares is deferred up to StrandedDecryptGraceBlocks before its loud
// drop, so late shares from a recovering validator must keep being served or the deferral
// could never heal anything). HIGH-3: on the stake-weighted path this node owns a SET of
// Shamir evaluation points, so it contributes ONE decryption share per owned point per
// ciphertext. The per-epoch shares X_p are derived once from COMMITTED dealings + the
// epoch's QUAL set, then reused.
//
// CYCLE-3 M-2: the per-extension share cap is COUPLED to the share budget S
// (params.VoteExtShareCap() = max(256, S)): a member may own up to ALL S points of one
// ciphertext, so a fixed cap below S would leave a high-stake member unable to ever ship a
// complete share set (liveness break); the coupled cap still bounds the extension because
// validation bounds S itself (<= 2048, sized against VoteExtMaxBytes).
func (app *EVMD) buildDecryptShares(ctx sdk.Context, ek *dkgnode.EncKey, op string) []encmempooltypes.VoteExtShare {
	k := app.EncMempoolKeeper
	h := uint64(ctx.BlockHeight())
	shareCap := k.GetParams(ctx).VoteExtShareCap()
	// Serve from the start of the deferral window, not from the current height: entries
	// below h that are still stored are exactly the matured-but-deferred ones awaiting
	// shares (decrypted entries have left state). Already-recorded shares are deduped by
	// the consume path (first-wins per eval point), so re-serving is idempotent.
	from := uint64(0)
	if h > encmempoolkeeper.StrandedDecryptGraceBlocks {
		from = h - encmempoolkeeper.StrandedDecryptGraceBlocks
	}
	shareByEpoch := map[uint64]*sharedCache{}
	var out []encmempooltypes.VoteExtShare
	k.IterateInFlightFrom(ctx, from, shareCap, func(e encmempooltypes.EncTx) bool {
		if len(out) >= shareCap {
			return false // vote-extension share budget reached
		}
		if e.Epoch == 0 {
			return true // legacy trusted-setup path is not served by the in-node DKG
		}
		sc := shareByEpoch[e.Epoch]
		if sc == nil {
			sc = app.deriveEpochShares(ctx, ek, op, e.Epoch)
			shareByEpoch[e.Epoch] = sc
		}
		if !sc.ok {
			return true // not a member / not finalized: nothing to contribute
		}
		for _, sh := range sc.shares {
			if len(out) >= shareCap {
				break
			}
			d, proof, err := dkgnode.ProveShareFor(sh, e.A)
			if err != nil {
				continue
			}
			out = append(out, encmempooltypes.VoteExtShare{
				Epoch: e.Epoch, DecryptHeight: e.DecryptHeight, Seq: e.Seq,
				Index: sh.Index, D: d, Proof: proof,
			})
		}
		return true
	})
	return out
}

type sharedCache struct {
	ok     bool
	shares []threshold.Share
}

func (app *EVMD) deriveEpochShares(ctx sdk.Context, ek *dkgnode.EncKey, op string, epoch uint64) *sharedCache {
	k := app.EncMempoolKeeper
	round, ok := k.GetDkgRound(ctx, epoch)
	if !ok {
		return &sharedCache{}
	}
	idx := encmempooltypes.MemberIndexByOperator(round.Members, op)
	if idx == 0 {
		return &sharedCache{}
	}
	// Resolve THIS node's owned evaluation points from the round (its stake-allocated share
	// indices; a single point == its Index on the unweighted path).
	var myPoints []uint64
	for _, m := range round.Members {
		if m.Index == idx {
			myPoints = m.OwnedEvalPoints()
			break
		}
	}
	if len(myPoints) == 0 {
		return &sharedCache{}
	}
	ak, ok := k.GetActiveKey(ctx, epoch)
	if !ok {
		return &sharedCache{} // round not finalized yet
	}
	dealings := map[uint64]encmempooltypes.Dealing{}
	k.IterateDealings(ctx, epoch, func(d encmempooltypes.Dealing) { dealings[d.DealerIndex] = d })
	shares, err := dkgnode.DeriveShares(myPoints, ek.Priv, ak.Qual, dealings)
	if err != nil {
		return &sharedCache{}
	}
	return &sharedCache{ok: true, shares: shares}
}

// ---- VerifyVoteExtension: lenient structural check (heavy validation is on-chain) ----

func (app *EVMD) dkgVerifyVoteExtensionHandler() sdk.VerifyVoteExtensionHandler {
	return func(_ sdk.Context, req *abci.RequestVerifyVoteExtension) (*abci.ResponseVerifyVoteExtension, error) {
		accept := &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_ACCEPT}
		reject := &abci.ResponseVerifyVoteExtension{Status: abci.ResponseVerifyVoteExtension_REJECT}
		if len(req.VoteExtension) == 0 {
			return accept, nil // a non-participating node is fine
		}
		if len(req.VoteExtension) > encmempooltypes.VoteExtMaxBytes {
			return reject, nil // oversized: refuse (bounds block size)
		}
		if _, ok := encmempooltypes.UnmarshalVoteExtension(req.VoteExtension); !ok {
			return reject, nil // undecodable: refuse
		}
		// Everything else (crypto validity, membership, dedup) is enforced deterministically
		// on-chain in ProcessProposal + PreBlock, so accept structurally-valid extensions
		// generously — an honest node's extension always passes, preserving liveness.
		return accept, nil
	}
}

// ---- PrepareProposal: inject the H-1 extended commit ahead of the normal txs ----

func (app *EVMD) wrapDkgPrepareProposal(inner sdk.PrepareProposalHandler) sdk.PrepareProposalHandler {
	return func(ctx sdk.Context, req *abci.RequestPrepareProposal) (*abci.ResponsePrepareProposal, error) {
		// Dormant, or CometBFT vote extensions not yet enabled (empty LocalLastCommit) =>
		// behave EXACTLY like the underlying EVM-mempool handler.
		if !app.veActive(ctx) || len(req.LocalLastCommit.Votes) == 0 {
			return inner(ctx, req)
		}
		blob, err := marshalInjectedCommit(req.LocalLastCommit)
		if err != nil || int64(len(blob)) >= req.MaxTxBytes {
			return inner(ctx, req) // cannot build/fit the blob: fall back cleanly
		}
		// Reserve the blob's bytes so the composed proposal stays within MaxTxBytes.
		sub := *req
		sub.MaxTxBytes = req.MaxTxBytes - int64(len(blob))
		resp, err := inner(ctx, &sub)
		if err != nil {
			return nil, err
		}
		resp.Txs = append([][]byte{blob}, resp.Txs...)
		return resp, nil
	}
}

// marshalInjectedCommit serializes an ExtendedCommitInfo behind the inject marker.
func marshalInjectedCommit(ec abci.ExtendedCommitInfo) ([]byte, error) {
	bz, err := ec.Marshal()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(veInjectMarker)+len(bz))
	out = append(out, veInjectMarker...)
	return append(out, bz...), nil
}

// ---- ProcessProposal: self-certify the injected extended commit, then delegate ----

func (app *EVMD) wrapDkgProcessProposal(inner sdk.ProcessProposalHandler) sdk.ProcessProposalHandler {
	reject := func() (*abci.ResponseProcessProposal, error) {
		return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
	}
	return func(ctx sdk.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
		if len(req.Txs) == 0 || !bytes.HasPrefix(req.Txs[0], veInjectMarker) {
			// No injected blob: normal proposal. (First block after enable, or a proposer
			// that had no extensions.) Delegate unchanged.
			return inner(ctx, req)
		}
		// An injected blob is only legitimate while the transparent path is active.
		if !app.veActive(ctx) {
			return reject()
		}
		var ext abci.ExtendedCommitInfo
		if err := ext.Unmarshal(req.Txs[0][len(veInjectMarker):]); err != nil {
			return reject()
		}
		// SELF-CERTIFY: every extension signature must verify against its validator's consensus
		// key and the set must carry >= 2/3 voting power (else a proposer could inject forged /
		// partial extensions). Deterministic (reads consensus params + last commit + staking).
		if err := baseapp.ValidateVoteExtensions(ctx, app.StakingKeeper, req.Height, ctx.ChainID(), ext); err != nil {
			return reject()
		}
		// Validate the REMAINING txs exactly as the underlying handler would.
		sub := *req
		sub.Txs = req.Txs[1:]
		return inner(ctx, &sub)
	}
}

// ---- PreBlock: deterministically consume the injected extended commit ----

// consumeDkgVoteExtensions is invoked from app.PreBlocker BEFORE module PreBlock/BeginBlock/
// EndBlock, so enc-key announcements, dealings, and decryption shares are all in committed
// state before the DKG EndBlocker opens/finalizes and before BeginBlock decrypts. It resolves
// each extension's CONSENSUS address to an OPERATOR via staking (deterministic committed read)
// and hands the resolved pairs to the keeper's canonicalizing consume path.
func (app *EVMD) consumeDkgVoteExtensions(ctx sdk.Context, txs [][]byte) {
	if len(txs) == 0 || !bytes.HasPrefix(txs[0], veInjectMarker) || !app.veActive(ctx) {
		return
	}
	var ext abci.ExtendedCommitInfo
	if err := ext.Unmarshal(txs[0][len(veInjectMarker):]); err != nil {
		return
	}
	entries := make([]encmempoolkeeper.VEEntry, 0, len(ext.Votes))
	for _, v := range ext.Votes {
		// Only votes actually committed carry a usable, signed extension.
		if v.BlockIdFlag != cmtproto.BlockIDFlagCommit || len(v.VoteExtension) == 0 {
			continue
		}
		ve, ok := encmempooltypes.UnmarshalVoteExtension(v.VoteExtension)
		if !ok {
			continue
		}
		val, err := app.StakingKeeper.GetValidatorByConsAddr(ctx, sdk.ConsAddress(v.Validator.Address))
		if err != nil {
			continue
		}
		entries = append(entries, encmempoolkeeper.VEEntry{Operator: val.GetOperator(), VE: ve})
	}
	app.EncMempoolKeeper.ConsumeVoteExtensions(ctx, entries)
}
