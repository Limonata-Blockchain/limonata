package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	clienttx "github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

const (
	flagEncKeyFile = "enc-key-file"
	flagShareDir   = "share-dir"
	// dkgWSSubscriber identifies this daemon's websocket subscription on the node.
	dkgWSSubscriber = "encmempool-dkg-daemon"
)

// DkgCmd is the parent for the on-chain validator-DKG node tooling: generate the
// per-validator encryption keypair (declared in genesis) and run the DKG daemon
// that AUTO-participates — it deals when a round opens, derives+persists this node's
// share after finalize, and posts DLEQ-proved decryption shares as ciphertexts
// mature. It mirrors the existing `keyper` daemon's broadcast plumbing.
func DkgCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dkg",
		Short: "On-chain validator DKG tools (keygen + auto-participation daemon)",
	}
	cmd.AddCommand(dkgKeygenCmd(), dkgStartCmd())
	return cmd
}

// dkgKeygenCmd generates a validator's DKG encryption keypair. The compressed
// public key goes into genesis params.dkg_members[i].enc_pubkey; the secret file is
// passed to `dkg start --enc-key-file`.
func dkgKeygenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate this validator's DKG encryption keypair (pub -> genesis, priv -> --out)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, _ := cmd.Flags().GetString(flagOutDir)
			pk, err := secp256k1.GeneratePrivateKey()
			if err != nil {
				return err
			}
			privHex := hex.EncodeToString(pk.Serialize())
			pub := pk.PubKey().SerializeCompressed()
			fmt.Printf("dkg encryption pubkey (put in genesis dkg_members[].enc_pubkey as base64/hex):\n")
			fmt.Printf("  hex: %s\n", hex.EncodeToString(pub))
			if out != "" {
				if err := os.WriteFile(out, []byte(privHex), 0o600); err != nil {
					return err
				}
				fmt.Printf("wrote secret enc key -> %s (KEEP SECRET)\n", out)
			} else {
				fmt.Printf("secret enc key (hex, KEEP SECRET): %s\n", privHex)
			}
			return nil
		},
	}
	cmd.Flags().String(flagOutDir, "", "write the secret enc key to this file (else printed)")
	return cmd
}

// loadEncPriv reads a 32-byte hex secret scalar written by `dkg keygen`.
func loadEncPriv(path string) (*secp256k1.ModNScalar, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	b, err := hex.DecodeString(trimWS(string(raw)))
	if err != nil || len(b) != 32 {
		return nil, nil, fmt.Errorf("enc key file must be 32-byte hex")
	}
	var sb [32]byte
	copy(sb[:], b)
	s := new(secp256k1.ModNScalar)
	if s.SetBytes(&sb) != 0 {
		return nil, nil, fmt.Errorf("enc key is not a canonical scalar")
	}
	var P secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(s, &P)
	P.ToAffine()
	pub := secp256k1.NewPublicKey(&P.X, &P.Y).SerializeCompressed()
	return s, pub, nil
}

func trimWS(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != '\n' && c != '\r' && c != ' ' && c != '\t' {
			out = append(out, c)
		}
	}
	return string(out)
}

// dkgDaemon holds the daemon's accumulated per-epoch view.
type dkgDaemon struct {
	acc      string
	encPriv  *secp256k1.ModNScalar
	encPub   []byte
	shareDir string

	rounds   map[uint64]*dkgRoundView                    // epoch -> my role/view
	incoming map[uint64]map[uint64]*threshold.Ciphertext // epoch -> dealer -> ct addressed to me
	derived  map[uint64]threshold.Share                  // epoch -> my final share X_m
	seenDeal map[uint64]bool                             // epoch -> already broadcast my deal
	seenSub  map[string]bool                             // decryptHeight:seq -> already posted a share
}

type dkgRoundView struct {
	epoch     uint64
	myIndex   uint64 // 0 if not a member
	threshold int
	allIndex  []uint64
	memberPub map[uint64][]byte
}

// dkgStartCmd runs the DKG auto-participation daemon.
func dkgStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Run the DKG daemon: auto-deal on round open, derive the share on finalize, post decrypt shares on maturity",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			clientCtx = clientCtx.WithSkipConfirmation(true) // daemon has no TTY
			encFile, _ := cmd.Flags().GetString(flagEncKeyFile)
			shareDir, _ := cmd.Flags().GetString(flagShareDir)
			pollMs, _ := cmd.Flags().GetInt(flagPollInterval)
			lookback, _ := cmd.Flags().GetInt64(flagLookback)

			encPriv, encPub, err := loadEncPriv(encFile)
			if err != nil {
				return fmt.Errorf("load enc key: %w", err)
			}
			from := clientCtx.GetFromAddress()
			if from.Empty() {
				return fmt.Errorf("--from is required (this member's funded account)")
			}
			if shareDir == "" {
				shareDir = clientCtx.HomeDir
			}
			if err := os.MkdirAll(shareDir, 0o700); err != nil {
				return err
			}
			node, err := clientCtx.GetNode()
			if err != nil {
				return err
			}
			factory, err := clienttx.NewFactoryCLI(clientCtx, cmd.Flags())
			if err != nil {
				return err
			}

			d := &dkgDaemon{
				acc: from.String(), encPriv: encPriv, encPub: encPub, shareDir: shareDir,
				rounds: map[uint64]*dkgRoundView{}, incoming: map[uint64]map[uint64]*threshold.Ciphertext{},
				derived: map[uint64]threshold.Share{}, seenDeal: map[uint64]bool{}, seenSub: map[string]bool{},
			}

			ctx := cmd.Context()
			st, err := node.Status(ctx)
			if err != nil {
				return err
			}
			next := st.SyncInfo.LatestBlockHeight + 1
			if lookback > 0 {
				if next = st.SyncInfo.LatestBlockHeight - lookback + 1; next < 1 {
					next = 1
				}
			}
			fmt.Printf("dkg daemon %s (enc pub %s) watching from height %d on %s\n",
				d.acc, hex.EncodeToString(encPub), next, clientCtx.NodeURI)

			poll := time.Duration(pollMs) * time.Millisecond

			// process scans every block in (next..=latest] via BlockResults — the
			// authoritative source of the FinalizeBlock + tx events the DKG runs on —
			// and broadcasts whatever this node owes (its dealing / decryption shares).
			// It advances `next` so no block is scanned twice and, crucially, NONE is
			// ever skipped even if a wake-up is missed: the loop always closes the gap
			// up to the latest height. This is the fix for the round that failed when
			// the old poll-scan fell behind the deal window.
			process := func(latest int64) {
				var msgs []sdk.Msg
				for h := next; h <= latest; h++ {
					res, err := node.BlockResults(ctx, &h)
					if err != nil {
						break // transient RPC error: retry this height on the next wake
					}
					msgs = append(msgs, d.scanBlock(res)...)
					next = h + 1
				}
				if len(msgs) > 0 {
					broadcastMsgs(clientCtx, factory, msgs)
				}
			}

			// Catch up to the current head once, then react in REAL TIME to each newly
			// committed block over a websocket subscription (watch the head), instead
			// of only waking on a fixed poll interval. Reacting the instant a round
			// opens is what lets a member reliably land its dealing INSIDE the deal
			// window on a live multi-node network. A periodic ticker is kept as a
			// safety net — and is the sole driver if the websocket is unavailable — so
			// the daemon can never silently fall behind.
			if st, err := node.Status(ctx); err == nil {
				process(st.SyncInfo.LatestBlockHeight)
			}
			blocks, closeWS := subscribeNewBlocks(ctx, clientCtx.NodeURI)
			defer closeWS()

			ticker := time.NewTicker(poll)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return nil
				case ev, ok := <-blocks:
					if !ok {
						blocks = nil // websocket closed: fall back to the safety-net ticker
						continue
					}
					if nb, isNB := ev.Data.(cmttypes.EventDataNewBlock); isNB && nb.Block != nil {
						process(nb.Block.Height)
					}
				case <-ticker.C:
					if st, err := node.Status(ctx); err == nil {
						process(st.SyncInfo.LatestBlockHeight)
					}
				}
			}
		},
	}
	cmd.Flags().String(flagEncKeyFile, "", "path to this member's DKG enc secret key (from `dkg keygen`)")
	cmd.Flags().String(flagShareDir, "", "directory to persist derived per-epoch shares (default: home dir)")
	cmd.Flags().Int(flagPollInterval, 1500, "safety-net poll interval in milliseconds (real-time reaction is via a websocket subscription; this is the fallback sweep)")
	cmd.Flags().Int64(flagLookback, 0, "on start, also scan this many past blocks")
	_ = cmd.MarkFlagRequired(flagEncKeyFile)
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// subscribeNewBlocks opens a websocket to the node and subscribes to committed
// blocks so the daemon reacts to a round opening in real time rather than on the
// next poll tick. It degrades GRACEFULLY: on any setup failure it returns a nil
// channel (which blocks forever in a select, leaving the caller's safety-net ticker
// as the sole driver) plus a no-op closer, so a node without a reachable websocket
// still participates via polling instead of the daemon erroring out.
func subscribeNewBlocks(ctx context.Context, nodeURI string) (<-chan coretypes.ResultEvent, func()) {
	noop := func() {}
	c, err := rpchttp.New(nodeURI, "/websocket")
	if err != nil {
		fmt.Printf("dkg: websocket unavailable (%v); using poll fallback\n", err)
		return nil, noop
	}
	if err := c.Start(); err != nil {
		fmt.Printf("dkg: websocket start failed (%v); using poll fallback\n", err)
		return nil, noop
	}
	ch, err := c.Subscribe(ctx, dkgWSSubscriber, cmttypes.EventQueryNewBlock.String())
	if err != nil {
		fmt.Printf("dkg: subscribe failed (%v); using poll fallback\n", err)
		_ = c.Stop()
		return nil, noop
	}
	fmt.Printf("dkg: watching new blocks in real time (websocket)\n")
	return ch, func() {
		// best-effort teardown (fresh context: the daemon's ctx is already cancelled).
		_ = c.UnsubscribeAll(context.Background(), dkgWSSubscriber)
		_ = c.Stop()
	}
}

// scanBlock dispatches on the encmempool DKG events in a block and returns any
// messages this node should broadcast (its dealing, or decryption shares).
func (d *dkgDaemon) scanBlock(res *coretypes.ResultBlockResults) []sdk.Msg {
	var out []sdk.Msg
	handle := func(evs []abci.Event) {
		for _, ev := range evs {
			switch ev.Type {
			case "encmempool_dkg_round_opened":
				if m := d.onRoundOpened(ev); m != nil {
					out = append(out, m)
				}
			case "encmempool_dkg_deal":
				d.onDeal(ev)
			case "encmempool_dkg_finalized":
				d.onFinalized(ev)
			case "encmempool_encrypted_submitted":
				if m := d.onSubmitted(ev); m != nil {
					out = append(out, m)
				}
			}
		}
	}
	for _, tr := range res.TxsResults {
		handle(tr.Events)
	}
	handle(res.FinalizeBlockEvents)
	return out
}

func attr(ev abci.Event, key string) string {
	for _, a := range ev.Attributes {
		if a.Key == key {
			return a.Value
		}
	}
	return ""
}

// onRoundOpened: if this node is a member of the new round, deal + return MsgDkgDeal.
func (d *dkgDaemon) onRoundOpened(ev abci.Event) sdk.Msg {
	var round types.DkgRound
	if json.Unmarshal([]byte(attr(ev, "round_json")), &round) != nil {
		return nil
	}
	if d.seenDeal[round.Epoch] {
		return nil
	}
	view := &dkgRoundView{epoch: round.Epoch, threshold: int(round.Threshold), memberPub: map[uint64][]byte{}}
	for _, m := range round.Members {
		view.allIndex = append(view.allIndex, m.Index)
		view.memberPub[m.Index] = m.EncPubKey
		if m.AccountAddr == d.acc {
			view.myIndex = m.Index
		}
	}
	d.rounds[round.Epoch] = view
	if view.myIndex == 0 {
		return nil // not a member of this round
	}
	commitments, shares, err := dkg.Deal(view.myIndex, view.allIndex, view.threshold, rand.Reader)
	if err != nil {
		fmt.Printf("dkg deal (epoch %d) failed: %v\n", round.Epoch, err)
		return nil
	}
	encShares := make([]*types.DkgEncShare, 0, len(view.allIndex))
	for _, idx := range view.allIndex {
		ct, err := dkg.EncryptShareTo(view.memberPub[idx], shares[idx])
		if err != nil {
			fmt.Printf("dkg encrypt share (epoch %d, member %d) failed: %v\n", round.Epoch, idx, err)
			return nil
		}
		encShares = append(encShares, &types.DkgEncShare{MemberIndex: idx, A: ct.A, Nonce: ct.Nonce, Body: ct.Body})
	}
	d.seenDeal[round.Epoch] = true
	fmt.Printf("dkg: dealing for epoch %d as member %d\n", round.Epoch, view.myIndex)
	return &types.MsgDkgDeal{Dealer: d.acc, Epoch: round.Epoch, Commitments: commitments, EncShares: encShares}
}

// onDeal: collect the enc-share addressed to me from a dealer.
func (d *dkgDaemon) onDeal(ev abci.Event) {
	var dealing types.Dealing
	if json.Unmarshal([]byte(attr(ev, "deal_json")), &dealing) != nil {
		return
	}
	view := d.rounds[dealing.Epoch]
	if view == nil || view.myIndex == 0 {
		return
	}
	for _, s := range dealing.EncShares {
		if s.MemberIndex == view.myIndex {
			if d.incoming[dealing.Epoch] == nil {
				d.incoming[dealing.Epoch] = map[uint64]*threshold.Ciphertext{}
			}
			d.incoming[dealing.Epoch][dealing.DealerIndex] = &threshold.Ciphertext{A: s.A, Nonce: s.Nonce, Body: s.Body}
		}
	}
}

// onFinalized: sum my shares from the QUAL dealers into X_m and persist it.
func (d *dkgDaemon) onFinalized(ev abci.Event) {
	epoch, _ := strconv.ParseUint(attr(ev, "epoch"), 10, 64)
	view := d.rounds[epoch]
	if view == nil || view.myIndex == 0 {
		return
	}
	var qual []uint64
	if json.Unmarshal([]byte(attr(ev, "qual")), &qual) != nil {
		return
	}
	X := new(secp256k1.ModNScalar)
	first := true
	for _, dealer := range qual {
		ct := d.incoming[epoch][dealer]
		if ct == nil {
			fmt.Printf("dkg: MISSING share from qual dealer %d in epoch %d (did daemon miss its deal block?)\n", dealer, epoch)
			return
		}
		s, err := dkg.DecryptShareFrom(d.encPriv, view.myIndex, ct)
		if err != nil {
			fmt.Printf("dkg: decrypt share from dealer %d (epoch %d) failed: %v\n", dealer, epoch, err)
			return
		}
		if first {
			X.Set(s)
			first = false
		} else {
			X.Add(s)
		}
	}
	share := threshold.Share{Index: view.myIndex, Xi: X}
	d.derived[epoch] = share
	if b, err := threshold.MarshalShare(share); err == nil {
		_ = os.WriteFile(d.sharePath(epoch), b, 0o600)
	}
	fmt.Printf("dkg: derived + persisted my share for epoch %d (member %d)\n", epoch, view.myIndex)
}

// onSubmitted: post my DLEQ-proved decryption share for a matured-soon ciphertext.
func (d *dkgDaemon) onSubmitted(ev abci.Event) sdk.Msg {
	epoch, _ := strconv.ParseUint(attr(ev, "epoch"), 10, 64)
	if epoch == 0 {
		return nil // legacy path — handled by the `keyper` daemon, not this one
	}
	dh, _ := strconv.ParseUint(attr(ev, "decrypt_height"), 10, 64)
	seq, _ := strconv.ParseUint(attr(ev, "seq"), 10, 64)
	aHex := attr(ev, "a_hex")
	if aHex == "" {
		return nil
	}
	key := attr(ev, "decrypt_height") + ":" + attr(ev, "seq")
	if d.seenSub[key] {
		return nil
	}
	share, ok := d.loadShare(epoch)
	if !ok {
		return nil // not a member / no share for this epoch
	}
	a, err := hex.DecodeString(aHex)
	if err != nil {
		return nil
	}
	ds, proof, err := dkg.ProveDecryptShare(share, &threshold.Ciphertext{A: a})
	if err != nil {
		fmt.Printf("dkg: prove decrypt share (epoch %d seq %d) failed: %v\n", epoch, seq, err)
		return nil
	}
	d.seenSub[key] = true
	fmt.Printf("dkg: posting decryption share for epoch %d decrypt_height %d seq %d\n", epoch, dh, seq)
	return &types.MsgSubmitDecryptionShare{
		Keyper: d.acc, DecryptHeight: dh, Seq: seq, Index: share.Index,
		D: ds.D, Proof: dkg.MarshalDLEQProof(proof),
	}
}

func (d *dkgDaemon) sharePath(epoch uint64) string {
	return filepath.Join(d.shareDir, fmt.Sprintf("dkg-share-%d.json", epoch))
}

// loadShare returns the derived share for an epoch, from memory or the persisted file.
func (d *dkgDaemon) loadShare(epoch uint64) (threshold.Share, bool) {
	if s, ok := d.derived[epoch]; ok {
		return s, true
	}
	b, err := os.ReadFile(d.sharePath(epoch))
	if err != nil {
		return threshold.Share{}, false
	}
	s, err := threshold.ParseShare(b)
	if err != nil {
		return threshold.Share{}, false
	}
	d.derived[epoch] = s
	return s, true
}

// broadcastMsgs sends each message with a locally-incremented account sequence so a
// burst within one poll does not hit the wrong-sequence error (mirrors submitShares).
func broadcastMsgs(clientCtx client.Context, factory clienttx.Factory, msgs []sdk.Msg) {
	accnum, seq, err := clientCtx.AccountRetriever.GetAccountNumberSequence(clientCtx, clientCtx.GetFromAddress())
	if err != nil {
		fmt.Printf("account lookup failed: %v\n", err)
		return
	}
	f := factory.WithAccountNumber(accnum)
	for i, msg := range msgs {
		ff := f.WithSequence(seq + uint64(i))
		if err := clienttx.BroadcastTx(clientCtx, ff, msg); err != nil {
			fmt.Printf("broadcast %T failed: %v\n", msg, err)
			continue
		}
	}
}
