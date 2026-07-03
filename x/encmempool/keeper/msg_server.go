package keeper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	errorsmod "cosmossdk.io/errors"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

type msgServer struct{ Keeper }

// NewMsgServerImpl returns the x/encmempool MsgServer backed by the keeper.
func NewMsgServerImpl(k Keeper) types.MsgServer { return &msgServer{Keeper: k} }

var _ types.MsgServer = msgServer{}

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
	// AUDIT FIX (consensus halt): the nonce is fed verbatim into AES-256-GCM in
	// BeginBlock, and gcm.Open PANICS on any nonce length != NonceSize. Reject a
	// non-conforming nonce at ingress so a malformed ciphertext can never reach the
	// decrypt path (threshold.Decrypt now also guards this as defense-in-depth).
	if len(msg.Nonce) != threshold.NonceSize {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "nonce must be %d bytes", threshold.NonceSize)
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	e := m.SubmitEncTx(goCtx, msg.Submitter, uint64(ctx.BlockHeight()), p.DecryptDelay, msg.A, msg.Nonce, msg.Body)
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"encmempool_encrypted_submitted",
		sdk.NewAttribute("submitter", msg.Submitter),
		sdk.NewAttribute("decrypt_height", strconv.FormatUint(e.DecryptHeight, 10)),
		sdk.NewAttribute("seq", strconv.FormatUint(e.Seq, 10)),
		// a_hex is the ciphertext's ephemeral public key r*G. It is PUBLIC (not the
		// body) and is what each keyper needs to compute its decryption share. Emitting
		// it lets keyper daemons act on block events without a custom query endpoint.
		sdk.NewAttribute("a_hex", hex.EncodeToString(msg.A)),
	))
	return &types.MsgSubmitEncryptedResponse{DecryptHeight: e.DecryptHeight, Seq: e.Seq}, nil
}

// SubmitDecryptionShare records an authorized keyper's partial decryption. The
// signer must be a configured keyper and its index must match its position.
func (m msgServer) SubmitDecryptionShare(goCtx context.Context, msg *types.MsgSubmitDecryptionShare) (*types.MsgSubmitDecryptionShareResponse, error) {
	p := m.GetParams(goCtx)
	if !p.EncEnabled {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "encrypted mempool is not enabled")
	}
	idx := keyperIndex(p.Keypers, msg.Keyper)
	if idx == 0 {
		return nil, errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "%s is not an authorized keyper", msg.Keyper)
	}
	if msg.Index != idx {
		return nil, errorsmod.Wrapf(sdkerrors.ErrInvalidRequest, "keyper index mismatch: expected %d, got %d", idx, msg.Index)
	}
	if len(msg.D) == 0 {
		return nil, errorsmod.Wrap(sdkerrors.ErrInvalidRequest, "missing decryption share (d)")
	}
	ctx := sdk.UnwrapSDKContext(goCtx)
	if err := m.SetEncShare(goCtx, types.EncShare{
		Keyper: msg.Keyper, DecryptHeight: msg.DecryptHeight, Seq: msg.Seq, Index: msg.Index, D: msg.D,
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
