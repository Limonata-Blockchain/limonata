package keeper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strconv"

	errorsmod "cosmossdk.io/errors"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

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
