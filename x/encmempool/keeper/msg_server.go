package keeper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"

	errorsmod "cosmossdk.io/errors"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

type msgServer struct{ Keeper }

// NewMsgServerImpl returns the x/encmempool MsgServer backed by the keeper.
func NewMsgServerImpl(k Keeper) types.MsgServer { return &msgServer{Keeper: k} }

var _ types.MsgServer = msgServer{}

// UpdateParams is the governance KILL-SWITCH for x/encmempool. It atomically REPLACES
// the module params, letting the gov authority toggle DkgEnabled / EncEnabled (and the
// safety-bounded DKG params) so that activating the dormant encrypted-mempool / validator
// DKG is REVERSIBLE by a vote — a bad activation can be turned back OFF without another
// coordinated chain upgrade (the module previously had NO params-mutation path at all, so
// activation was a one-way door).
//
// SAFETY:
//   - AUTHORITY-GATED: only the x/gov module account may call it (mirrors x/valgrant);
//     any other signer is rejected with ErrUnauthorized. The runtime gov module address
//     is compared directly, so no keeper/app.go re-wiring of an authority is required.
//   - FULLY VALIDATED: the replacement params must pass the SAME Params.Validate (which
//     calls ValidateDkgWindows) used at genesis — bounding DecryptDelay / thresholds /
//     DKG windows / ceilings and requiring a well-formed member/keyper set whenever
//     EncEnabled or DkgEnabled is true. An update that could strand EncTx state or panic
//     BeginBlock/EndBlock is rejected BEFORE it is written; the current params are left
//     untouched on any error.
//   - SAFE DISABLE: flipping EncEnabled=false or DkgEnabled=false stops new DKG rounds /
//     new encrypted-tx admission; already-in-flight EncTx are drained cleanly by
//     BeginBlock (decrypted if a key path is still live, else GC'd via releaseEncTx +
//     maybePruneEpoch), so no in-flight ciphertext is stranded and consensus never halts.
//     Re-enabling opens a fresh round via the existing EndBlock DKG state machine.
func (m msgServer) UpdateParams(goCtx context.Context, msg *types.MsgUpdateParams) (*types.MsgUpdateParamsResponse, error) {
	govAddr := authtypes.NewModuleAddress(govtypes.ModuleName).String()
	if msg.Authority != govAddr {
		return nil, errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "expected gov authority %s, got %s", govAddr, msg.Authority)
	}
	// params carries the JSON encoding of types.Params (the module stores params as
	// JSON-in-store, not proto). Decode then FULLY validate before writing.
	var p types.Params
	if err := json.Unmarshal(msg.Params, &p); err != nil {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "invalid params json: %v", err)
	}
	if err := p.Validate(); err != nil {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "invalid params: %v", err)
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	// HIGH-1: the TRANSPARENT in-node DKG rides ABCI++ vote extensions, which are governed by
	// a SEPARATE consensus param (VoteExtensionsEnableHeight). Enabling DkgTransparent while
	// vote extensions are not scheduled arms a path whose ProcessProposal would later reject
	// every proposal carrying the injected commit -> chain HALT. Refuse the activation here so
	// governance MUST schedule vote extensions (a consensus-params update) first. (The runtime
	// veActive guard is the belt to this suspenders: it also no-ops the handlers until VE is
	// actually active, so even a genesis misconfig cannot halt.)
	if p.DkgEnabled && p.DkgTransparent {
		cp := ctx.ConsensusParams()
		if cp.Abci == nil || cp.Abci.VoteExtensionsEnableHeight == 0 {
			return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest,
				"dkg_transparent requires CometBFT vote extensions to be scheduled first (consensus param vote_extensions_enable_height must be non-zero)")
		}
	}
	if err := m.SetParams(goCtx, p); err != nil {
		return nil, err
	}
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"encmempool_params_updated",
		sdk.NewAttribute("enc_enabled", strconv.FormatBool(p.EncEnabled)),
		sdk.NewAttribute("dkg_enabled", strconv.FormatBool(p.DkgEnabled)),
	))
	return &types.MsgUpdateParamsResponse{}, nil
}

// CommitTx records a hash-commitment at the current block height. It emits no
// transaction content (only the commitment hash is stored).
func (m msgServer) CommitTx(goCtx context.Context, msg *types.MsgCommitTx) (*types.MsgCommitTxResponse, error) {
	if len(msg.CommitHash) != sha256.Size {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "commit_hash must be %d bytes", sha256.Size)
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	height := uint64(ctx.BlockHeight())
	seq := m.nextSeq(goCtx)

	if err := m.SetCommit(goCtx, types.Commit{Sender: msg.Sender, CommitHash: msg.CommitHash, Height: height, Seq: seq}); err != nil {
		return nil, err
	}
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"encmempool_commit",
		sdk.NewAttribute("sender", msg.Sender),
		sdk.NewAttribute("commit_height", strconv.FormatUint(height, 10)),
		sdk.NewAttribute("seq", strconv.FormatUint(seq, 10)),
	))
	return &types.MsgCommitTxResponse{CommitHeight: height, Seq: seq}, nil
}

// RevealTx validates a reveal against its commitment and the reveal delay, then
// QUEUES it for deterministic execution in BeginBlock. It deliberately does not
// execute the payload or emit its contents here, so reveal ordering is decided by
// consensus (BeginBlock), not by the proposer's mempool ordering of reveal txs.
func (m msgServer) RevealTx(goCtx context.Context, msg *types.MsgRevealTx) (*types.MsgRevealTxResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	c, ok := m.GetCommit(goCtx, msg.CommitHeight, msg.Sender, msg.Seq)
	if !ok {
		return nil, errorsmod.Wrap(sdkerrors.ErrKeyNotFound, "no matching commit for (sender, commit_height, seq)")
	}
	if c.Sender != msg.Sender {
		return nil, errorsmod.Wrap(sdkerrors.ErrUnauthorized, "sender is not the committer")
	}
	// Reveal delay is evaluated at RUNTIME against current params and height.
	delay := m.GetParams(goCtx).RevealDelay
	if uint64(ctx.BlockHeight()) < msg.CommitHeight+delay {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest,
			"reveal too early: need height >= %d (commit %d + delay %d)", msg.CommitHeight+delay, msg.CommitHeight, delay)
	}
	// Binding: sha256(reveal_tx || salt) must equal the recorded commitment.
	h := sha256.Sum256(append(append([]byte{}, msg.RevealTx...), msg.Salt...))
	if !bytes.Equal(h[:], c.CommitHash) {
		return nil, errorsmod.Wrap(sdkerrors.ErrUnauthorized, "reveal does not match commitment hash")
	}

	if err := m.SetPending(goCtx, types.PendingReveal{
		Sender: msg.Sender, CommitHeight: msg.CommitHeight, Seq: msg.Seq, RevealTx: msg.RevealTx, Salt: msg.Salt,
	}); err != nil {
		return nil, err
	}
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"encmempool_reveal_queued",
		sdk.NewAttribute("sender", msg.Sender),
		sdk.NewAttribute("commit_height", strconv.FormatUint(msg.CommitHeight, 10)),
		sdk.NewAttribute("seq", strconv.FormatUint(msg.Seq, 10)),
	))
	return &types.MsgRevealTxResponse{}, nil
}

// SubmitEncrypted stores a threshold-encrypted tx (ciphertext only), ordered by
// (decrypt_height, seq). The body is unreadable until BeginBlock combines >= t
// keyper shares — that ordering-before-readability is the anti-MEV property.
func (m msgServer) SubmitEncrypted(goCtx context.Context, msg *types.MsgSubmitEncrypted) (*types.MsgSubmitEncryptedResponse, error) {
	p := m.GetParams(goCtx)
	if !p.EncEnabled {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "encrypted mempool is not enabled")
	}
	if len(msg.A) == 0 || len(msg.Body) == 0 {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "missing ciphertext (a/body)")
	}
	// Reject malformed ciphertexts at ingress. The nonce is attacker-controlled and,
	// if it reached the BeginBlock decrypt path with a wrong length, AES-GCM would
	// PANIC (halting consensus). Enforce the exact GCM nonce length here so bad
	// ciphertexts never enter state; the decrypt path is defended independently too.
	if len(msg.Nonce) != threshold.NonceSize {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "nonce must be %d bytes, got %d", threshold.NonceSize, len(msg.Nonce))
	}
	// ADMISSION CONTROL: reject at INGRESS once the in-flight EncTx ceilings are reached, so a
	// flooder cannot grow EncTx state (nor the per-block decrypt scan) without bound, nor starve
	// honest ciphertexts. The checks read O(1) maintained counters (never an O(backlog) scan).
	// A ceiling of 0 is disabled; the keeper's always-on absolute constant ceiling + the
	// BeginBlock last-resort drop remain the unconditional 'bounded state' backstop.
	if p.MaxInFlightEncTx > 0 && m.GetGlobalEncCount(goCtx) >= p.MaxInFlightEncTx {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "encrypted mempool full: %d in-flight ciphertexts at the global ceiling", p.MaxInFlightEncTx)
	}
	if p.MaxInFlightPerSubmitter > 0 && m.GetSubmitterEncCount(goCtx, msg.Submitter) >= p.MaxInFlightPerSubmitter {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "submitter is at its in-flight ceiling (%d ciphertexts)", p.MaxInFlightPerSubmitter)
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	// PER-SUBMITTER per-block admission RATE limit (Fix 1 C3'): the missing rate dimension on top of
	// the standing per-submitter inventory cap. Being per-submitter (NOT a global slot) means no single
	// address can monopolize ingress or let a proposer censor the encrypted mempool by ordering its own
	// ciphertexts first. It bounds maturing-ciphertext inflow so the per-block DLEQ-verify work stays
	// near marginal decryption progress (closing HIGH-U's "sustainable because there is no admission
	// rate limit" clause).
	if m.bumpEncSubmitsThisBlock(goCtx, msg.Submitter, uint64(ctx.BlockHeight())) > maxEncSubmitsPerBlockPerSubmitter {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest,
			"submitter exceeded the per-block admission rate (%d ciphertexts this block)", maxEncSubmitsPerBlockPerSubmitter)
	}
	// Stamp the ciphertext with the DKG epoch whose active key it was encrypted to,
	// so decryptMatured decrypts it under the SAME key/members even after a re-key.
	// Epoch 0 = the legacy trusted-setup path (params.ThresholdPub).
	epoch := uint64(0)
	if p.DkgEnabled {
		epoch = m.GetActiveEpoch(goCtx)
		if epoch == 0 {
			return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "DKG enabled but no active threshold key yet")
		}
	}
	e := m.SubmitEncTx(goCtx, msg.Submitter, uint64(ctx.BlockHeight()), p.DecryptDelay, msg.A, msg.Nonce, msg.Body, epoch)
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"encmempool_encrypted_submitted",
		sdk.NewAttribute("submitter", msg.Submitter),
		sdk.NewAttribute("decrypt_height", strconv.FormatUint(e.DecryptHeight, 10)),
		sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
		// epoch tells a keyper daemon WHICH DKG-derived share to use for this
		// ciphertext (0 = legacy trusted share). It matters across a re-key.
		sdk.NewAttribute("epoch", strconv.FormatUint(e.Epoch, 10)),
		// a_hex is the ciphertext's ephemeral public key r*G. It is PUBLIC (not the
		// body) and is what each keyper needs to compute its decryption share. Emitting
		// it lets keyper daemons act on block events without a custom query endpoint.
		sdk.NewAttribute("a_hex", hex.EncodeToString(msg.A)),
	))
	return &types.MsgSubmitEncryptedResponse{DecryptHeight: e.DecryptHeight, Seq: e.Seq}, nil
}

// SubmitDecryptionShare records an authorized keyper's partial decryption. On the
// DKG path the signer must be a QUAL member of the epoch that the referenced EncTx
// was encrypted to, and its index must match its member index; on the legacy path
// it must be a configured keyper. The DLEQ proof (if present) is stored so the
// decrypt path can route through dkg.RecoverVerified.
func (m msgServer) SubmitDecryptionShare(goCtx context.Context, msg *types.MsgSubmitDecryptionShare) (*types.MsgSubmitDecryptionShareResponse, error) {
	p := m.GetParams(goCtx)
	if !p.EncEnabled {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "encrypted mempool is not enabled")
	}
	if len(msg.D) == 0 {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "missing decryption share (d)")
	}
	if p.DkgEnabled {
		// Authorize against the active round for the EncTx's epoch. The EncTx tells us
		// which epoch (=> which Qual member set) this share belongs to.
		e, ok := m.GetEncTx(goCtx, msg.DecryptHeight, msg.Seq)
		if !ok {
			return nil, errorsmod.Wrap(sdkerrors.ErrKeyNotFound, "no matching encrypted tx for (decrypt_height, seq)")
		}
		round, ok := m.GetDkgRound(goCtx, e.Epoch)
		if !ok {
			return nil, errorsmod.Wrapf(sdkerrors.ErrKeyNotFound, "no DKG round for epoch %d", e.Epoch)
		}
		// Authorize by ROUND MEMBERSHIP, not QUAL. In joint-Feldman every member holds
		// a valid Shamir share X_m = Σ_{i∈QUAL} f_i(m) regardless of whether m itself
		// qualified as a DEALER (QUAL is the set of dealers, not of share-holders). A
		// member that cheated as a dealer — or merely failed to deal — still holds a
		// valid share; the DLEQ proof + dkg.RecoverVerified drop any INVALID partial on
		// the decrypt path, so admitting all members maximizes availability without
		// weakening correctness.
		idx := memberIndexByAccount(round, msg.Keyper)
		if idx == 0 {
			return nil, errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "%s is not a member of epoch %d", msg.Keyper, e.Epoch)
		}
		if msg.Index != idx {
			return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "member index mismatch: expected %d, got %d", idx, msg.Index)
		}
	} else {
		idx := keyperIndex(p.Keypers, msg.Keyper)
		if idx == 0 {
			return nil, errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "%s is not an authorized keyper", msg.Keyper)
		}
		if msg.Index != idx {
			return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "keyper index mismatch: expected %d, got %d", idx, msg.Index)
		}
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	if err := m.SetEncShare(goCtx, types.EncShare{
		Keyper: msg.Keyper, DecryptHeight: msg.DecryptHeight, Seq: msg.Seq, Index: msg.Index, D: msg.D, Proof: msg.Proof,
	}); err != nil {
		return nil, err
	}
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"encmempool_share_submitted",
		sdk.NewAttribute("keyper", msg.Keyper),
		sdk.NewAttribute("decrypt_height", strconv.FormatUint(msg.DecryptHeight, 10)),
		sdk.NewAttribute("seq", strconv.FormatUint(msg.Seq, 10)),
	))
	return &types.MsgSubmitDecryptionShareResponse{}, nil
}

// keyperIndex returns the 1-based position of addr in keypers, or 0 if absent.
func keyperIndex(keypers []string, addr string) uint64 {
	for i, k := range keypers {
		if k == addr {
			return uint64(i + 1)
		}
	}
	return 0
}

// memberIndexByAccount returns a round member's index by its account (signer)
// address, or 0 if the address is not a member of the round.
func memberIndexByAccount(round types.DkgRound, addr string) uint64 {
	for _, m := range round.Members {
		if m.AccountAddr == addr {
			return m.Index
		}
	}
	return 0
}

func memberByIndex(round types.DkgRound, idx uint64) (types.RoundMember, bool) {
	for _, m := range round.Members {
		if m.Index == idx {
			return m, true
		}
	}
	return types.RoundMember{}, false
}

// DkgDeal records a member/dealer's on-chain DKG dealing for the open epoch: its
// public Feldman commitments plus one share encrypted to each member. Validated for
// well-formedness (exactly t commitments, one share per member) so a qualified
// dealer always lets every member derive its share.
func (m msgServer) DkgDeal(goCtx context.Context, msg *types.MsgDkgDeal) (*types.MsgDkgDealResponse, error) {
	p := m.GetParams(goCtx)
	if !p.DkgEnabled {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "DKG is not enabled")
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	round, ok := m.GetDkgRound(goCtx, msg.Epoch)
	if !ok || round.Status != types.DkgStatusOpen {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "no open DKG round for epoch %d", msg.Epoch)
	}
	if uint64(ctx.BlockHeight()) > round.DealDeadline {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "deal window closed for epoch %d (deadline %d)", msg.Epoch, round.DealDeadline)
	}
	idx := memberIndexByAccount(round, msg.Dealer)
	if idx == 0 {
		return nil, errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "%s is not a member of epoch %d", msg.Dealer, msg.Epoch)
	}
	if len(msg.Commitments) != int(round.Threshold) {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "expected %d commitments, got %d", round.Threshold, len(msg.Commitments))
	}
	// HIGH-1: every Feldman commitment must be a well-formed COMPRESSED secp256k1 point
	// (parse + on-curve). A malformed commitment that only passed the count check would
	// be silently dropped by FinalizePublic (excluding the dealer), but rejecting the
	// whole dealing here keeps stored state well-formed and prevents a member from
	// wasting its one deal slot on garbage.
	if _, err := dkg.ParseCommitmentPoints(msg.Commitments); err != nil {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "malformed commitment (not a compressed secp256k1 point): %v", err)
	}
	// Require exactly one enc-share per member, covering every member index once, so
	// each member can derive its final share from a qualified dealer.
	n := len(round.Members)
	if len(msg.EncShares) != n {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "expected %d enc_shares, got %d", n, len(msg.EncShares))
	}
	seen := make(map[uint64]bool, n)
	stored := make([]types.DkgStoredEncShare, 0, n)
	for _, s := range msg.EncShares {
		if _, ismember := memberByIndex(round, s.MemberIndex); !ismember {
			return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "enc_share for non-member index %d", s.MemberIndex)
		}
		if seen[s.MemberIndex] {
			return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "duplicate enc_share for member %d", s.MemberIndex)
		}
		// HIGH-1 (root-cause fix): validate EVERY enc-share field so a structurally
		// unopenable share can NEVER enter QUAL. `A` must be a valid compressed secp256k1
		// point — the decrypt path (ComputeShare) and the complaint path
		// (VerifyDecryptShare) both parse it, so a bad A made the dealer both underivable
		// AND uncomplainable while it stayed in QUAL, corrupting every honest member's
		// aggregate share (the reported keyless-liveness DoS). The nonce must be the exact
		// AES-GCM length (else Decrypt cannot open the sealed share), and the body must be
		// present. Any malformed field REJECTS the whole dealing at ingress.
		if !dkg.ValidCompressedPoint(s.A) {
			return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "enc_share for member %d has a malformed A (not a compressed secp256k1 point)", s.MemberIndex)
		}
		if len(s.Nonce) != threshold.NonceSize {
			return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "enc_share for member %d has a %d-byte nonce, want %d", s.MemberIndex, len(s.Nonce), threshold.NonceSize)
		}
		if len(s.Body) == 0 {
			return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "empty enc_share body for member %d", s.MemberIndex)
		}
		seen[s.MemberIndex] = true
		stored = append(stored, types.DkgStoredEncShare{MemberIndex: s.MemberIndex, A: s.A, Nonce: s.Nonce, Body: s.Body})
	}

	dealing := types.Dealing{Epoch: msg.Epoch, DealerIndex: idx, Dealer: msg.Dealer, Commitments: msg.Commitments, EncShares: stored}
	if err := m.SetDealing(goCtx, dealing); err != nil {
		return nil, err
	}
	// Emit the dealing so a member's node can pick out the enc-share addressed to it
	// (and later sum QUAL dealers' shares) purely off block events.
	dealJSON, _ := json.Marshal(dealing)
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"encmempool_dkg_deal",
		sdk.NewAttribute("epoch", strconv.FormatUint(msg.Epoch, 10)),
		sdk.NewAttribute("dealer_index", strconv.FormatUint(idx, 10)),
		sdk.NewAttribute("deal_json", string(dealJSON)),
	))
	return &types.MsgDkgDealResponse{}, nil
}

// DkgComplaint verifies a framing-resistant complaint (the accuser proves, via a
// DLEQ over its own encryption key, that the dealer sealed it a share inconsistent
// with the dealer's public commitments) and, if justified, records it so finalize
// disqualifies the dealer.
func (m msgServer) DkgComplaint(goCtx context.Context, msg *types.MsgDkgComplaint) (*types.MsgDkgComplaintResponse, error) {
	p := m.GetParams(goCtx)
	if !p.DkgEnabled {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "DKG is not enabled")
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	round, ok := m.GetDkgRound(goCtx, msg.Epoch)
	if !ok || round.Status != types.DkgStatusOpen {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "no open DKG round for epoch %d", msg.Epoch)
	}
	if uint64(ctx.BlockHeight()) > round.ComplaintDeadline {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "complaint window closed for epoch %d", msg.Epoch)
	}
	accuserIdx := memberIndexByAccount(round, msg.Accuser)
	if accuserIdx == 0 {
		return nil, errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "%s is not a member of epoch %d", msg.Accuser, msg.Epoch)
	}
	accuser, _ := memberByIndex(round, accuserIdx)

	dealing, ok := m.GetDealing(goCtx, msg.Epoch, msg.Against)
	if !ok {
		return nil, errorsmod.Wrapf(sdkerrors.ErrKeyNotFound, "no dealing from member %d in epoch %d", msg.Against, msg.Epoch)
	}
	// Locate the enc-share the dealer addressed to the accuser.
	var enc *types.DkgStoredEncShare
	for i := range dealing.EncShares {
		if dealing.EncShares[i].MemberIndex == accuserIdx {
			enc = &dealing.EncShares[i]
			break
		}
	}
	if enc == nil {
		// The dealer never dealt to the accuser — that alone is a disqualifying fault.
		return m.recordComplaint(ctx, goCtx, msg.Epoch, msg.Against, accuserIdx)
	}

	cheated, proofValid := dkg.VerifyJustifiedComplaint(
		accuserIdx, accuser.EncPubKey, dealing.Commitments,
		enc.A, enc.Nonce, enc.Body, msg.SharedPoint, msg.DleqProof,
	)
	if !proofValid {
		return nil, errorsmod.Wrap(sdkerrors.ErrUnauthorized, "invalid complaint proof (cannot frame a dealer)")
	}
	if !cheated {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "dealer's share is valid; frivolous complaint")
	}
	return m.recordComplaint(ctx, goCtx, msg.Epoch, msg.Against, accuserIdx)
}

func (m msgServer) recordComplaint(ctx sdk.Context, goCtx context.Context, epoch, against, accuserIdx uint64) (*types.MsgDkgComplaintResponse, error) {
	if err := m.SetComplaint(goCtx, types.DkgComplaintRec{Epoch: epoch, Against: against, AccuserIndex: accuserIdx}); err != nil {
		return nil, err
	}
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"encmempool_dkg_complaint",
		sdk.NewAttribute("epoch", strconv.FormatUint(epoch, 10)),
		sdk.NewAttribute("against", strconv.FormatUint(against, 10)),
		sdk.NewAttribute("accuser_index", strconv.FormatUint(accuserIdx, 10)),
	))
	return &types.MsgDkgComplaintResponse{}, nil
}
