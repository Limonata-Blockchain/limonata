package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	clienttx "github.com/cosmos/cosmos-sdk/client/tx"

	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

const (
	flagN            = "n"
	flagT            = "t"
	flagOutDir       = "out-dir"
	flagPubkey       = "pubkey"
	flagMessage      = "message"
	flagShareFile    = "share-file"
	flagPollInterval = "poll-interval"
	flagLookback     = "lookback"
)

// KeyperCmd is the parent for the encrypted-mempool threshold tools: trusted
// key setup, message encryption, and the keyper daemon that posts decryption
// shares. The keyper logic lives IN the chain binary (no separate download):
// validators who run a keyper just point this at their secret share.
func KeyperCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keyper",
		Short: "Encrypted-mempool threshold-encryption tools (setup, encrypt, keyper daemon)",
	}
	cmd.AddCommand(keyperSetupCmd(), keyperEncryptCmd(), keyperStartCmd())
	return cmd
}

// keyperSetupCmd runs the TRUSTED (t,n) setup: it prints the threshold public key
// (for the encmempool params) and writes/prints each keyper's secret share.
func keyperSetupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "TRUSTED threshold key setup: generate the public key + n secret shares",
		Long: "Generates a threshold public key (put in encmempool params.threshold_pub) and\n" +
			"n secret shares. Distribute keyper-share-i.json to keyper i. KEEP SHARES SECRET.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			n, _ := cmd.Flags().GetInt(flagN)
			t, _ := cmd.Flags().GetInt(flagT)
			outDir, _ := cmd.Flags().GetString(flagOutDir)

			pub, shares, err := threshold.Setup(n, t)
			if err != nil {
				return err
			}
			fmt.Printf("threshold public key:\n")
			fmt.Printf("  hex   : %s\n", hex.EncodeToString(pub))
			fmt.Printf("  base64: %s   <- set encmempool params.threshold_pub to this\n", base64.StdEncoding.EncodeToString(pub))
			fmt.Printf("threshold: need %d of %d keypers\n\n", t, n)

			for _, s := range shares {
				b, err := threshold.MarshalShare(s)
				if err != nil {
					return err
				}
				if outDir != "" {
					if err := os.MkdirAll(outDir, 0o700); err != nil {
						return err
					}
					path := filepath.Join(outDir, fmt.Sprintf("keyper-share-%d.json", s.Index))
					if err := os.WriteFile(path, b, 0o600); err != nil {
						return err
					}
					fmt.Printf("wrote keyper %d secret share -> %s\n", s.Index, path)
				} else {
					fmt.Printf("keyper %d secret share: %s\n", s.Index, string(b))
				}
			}
			fmt.Printf("\nKEEP THESE SHARES SECRET. Order params.keypers so keyper i (this share's index) is at position i.\n")
			return nil
		},
	}
	cmd.Flags().Int(flagN, 3, "total number of keypers (n)")
	cmd.Flags().Int(flagT, 2, "threshold of keypers needed to decrypt (t)")
	cmd.Flags().String(flagOutDir, "", "write shares to this directory (else printed to stdout)")
	return cmd
}

// keyperEncryptCmd encrypts a plaintext to the threshold public key and prints
// the (a, nonce, body) ciphertext parts to feed into `tx encmempool submit-encrypted`.
func keyperEncryptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a message to the threshold public key (prints a/nonce/body for submit-encrypted)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pubStr, _ := cmd.Flags().GetString(flagPubkey)
			msg, _ := cmd.Flags().GetString(flagMessage)
			pub, err := decodeKey(pubStr)
			if err != nil {
				return err
			}
			ct, err := threshold.Encrypt(pub, []byte(msg))
			if err != nil {
				return err
			}
			a := base64.StdEncoding.EncodeToString(ct.A)
			nonce := base64.StdEncoding.EncodeToString(ct.Nonce)
			body := base64.StdEncoding.EncodeToString(ct.Body)
			fmt.Printf("a    (base64): %s\n", a)
			fmt.Printf("nonce(base64): %s\n", nonce)
			fmt.Printf("body (base64): %s\n\n", body)
			fmt.Printf("submit with:\n  evmd tx encmempool submit-encrypted \\\n    --a %s --nonce %s --body %s \\\n    --from <you> --fees 5000000aLIMO -y\n", a, nonce, body)
			return nil
		},
	}
	cmd.Flags().String(flagPubkey, "", "threshold public key (hex or base64, 33-byte compressed)")
	cmd.Flags().String(flagMessage, "", "plaintext message to encrypt")
	_ = cmd.MarkFlagRequired(flagPubkey)
	_ = cmd.MarkFlagRequired(flagMessage)
	return cmd
}

// keyperStartCmd runs the keyper daemon: it watches the chain for newly-submitted
// ciphertexts and posts this keyper's decryption share for each. Fees are paid by
// the --from account, which must be the configured keyper address.
func keyperStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Run the keyper daemon: watch for encrypted txs and post this keyper's decryption shares",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			// A daemon has no TTY: never prompt for tx confirmation (else BroadcastTx
			// reads EOF on stdin and cancels every share).
			clientCtx = clientCtx.WithSkipConfirmation(true)
			shareFile, _ := cmd.Flags().GetString(flagShareFile)
			pollMs, _ := cmd.Flags().GetInt(flagPollInterval)
			lookback, _ := cmd.Flags().GetInt64(flagLookback)

			sb, err := os.ReadFile(shareFile)
			if err != nil {
				return fmt.Errorf("read share file: %w", err)
			}
			share, err := threshold.ParseShare(sb)
			if err != nil {
				return fmt.Errorf("parse share: %w", err)
			}
			from := clientCtx.GetFromAddress()
			if from.Empty() {
				return fmt.Errorf("--from is required (this keyper's funded account)")
			}
			keyperAddr := from.String()

			node, err := clientCtx.GetNode()
			if err != nil {
				return err
			}
			factory, err := clienttx.NewFactoryCLI(clientCtx, cmd.Flags())
			if err != nil {
				return err
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

			seen := map[string]bool{}
			poll := time.Duration(pollMs) * time.Millisecond
			fmt.Printf("keyper %s (share index %d) watching from height %d on %s\n",
				keyperAddr, share.Index, next, clientCtx.NodeURI)

			for {
				select {
				case <-ctx.Done():
					return nil
				default:
				}
				st, err := node.Status(ctx)
				if err != nil {
					time.Sleep(poll)
					continue
				}
				latest := st.SyncInfo.LatestBlockHeight

				var jobs []shareJob
				for h := next; h <= latest; h++ {
					res, err := node.BlockResults(ctx, &h)
					if err != nil {
						break // retry this height on the next pass
					}
					collectSubmits(res, seen, &jobs)
					next = h + 1
				}
				if len(jobs) > 0 {
					submitShares(clientCtx, factory, keyperAddr, share, jobs)
				}
				time.Sleep(poll)
			}
		},
	}
	cmd.Flags().String(flagShareFile, "", "path to this keyper's secret share file (from `keyper setup`)")
	cmd.Flags().Int(flagPollInterval, 1500, "poll interval in milliseconds")
	cmd.Flags().Int64(flagLookback, 0, "on start, also scan this many past blocks for pending ciphertexts")
	_ = cmd.MarkFlagRequired(flagShareFile)
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// shareJob is one ciphertext this keyper must produce a decryption share for.
type shareJob struct {
	decryptHeight uint64
	seq           uint64
	a             []byte
}

// collectSubmits scans a block's tx + finalize events for encmempool_encrypted_submitted
// and appends a share job for each not-yet-seen (decrypt_height, seq).
func collectSubmits(res *coretypes.ResultBlockResults, seen map[string]bool, jobs *[]shareJob) {
	scan := func(evs []abci.Event) {
		for _, ev := range evs {
			if ev.Type != "encmempool_encrypted_submitted" {
				continue
			}
			var aHex, dhS, seqS string
			for _, a := range ev.Attributes {
				switch a.Key {
				case "a_hex":
					aHex = a.Value
				case "decrypt_height":
					dhS = a.Value
				case "seq":
					seqS = a.Value
				}
			}
			if aHex == "" || dhS == "" || seqS == "" {
				continue
			}
			key := dhS + ":" + seqS
			if seen[key] {
				continue
			}
			a, err := hex.DecodeString(aHex)
			if err != nil {
				continue
			}
			dh, _ := strconv.ParseUint(dhS, 10, 64)
			seq, _ := strconv.ParseUint(seqS, 10, 64)
			seen[key] = true
			*jobs = append(*jobs, shareJob{decryptHeight: dh, seq: seq, a: a})
		}
	}
	for _, tr := range res.TxsResults {
		scan(tr.Events)
	}
	scan(res.FinalizeBlockEvents)
}

// submitShares computes + broadcasts this keyper's decryption share for each job,
// incrementing the account sequence locally so a burst within one block does not
// collide (the classic code-32 wrong-sequence error).
func submitShares(clientCtx client.Context, factory clienttx.Factory, keyperAddr string, share threshold.Share, jobs []shareJob) {
	accnum, seq, err := clientCtx.AccountRetriever.GetAccountNumberSequence(clientCtx, clientCtx.GetFromAddress())
	if err != nil {
		fmt.Printf("account lookup failed: %v\n", err)
		return
	}
	f := factory.WithAccountNumber(accnum)
	for i, j := range jobs {
		ds, err := threshold.ComputeShare(share, &threshold.Ciphertext{A: j.a})
		if err != nil {
			fmt.Printf("compute share (seq %d) failed: %v\n", j.seq, err)
			continue
		}
		msg := &types.MsgSubmitDecryptionShare{
			Keyper:        keyperAddr,
			DecryptHeight: j.decryptHeight,
			Seq:           j.seq,
			Index:         share.Index,
			D:             ds.D,
		}
		ff := f.WithSequence(seq + uint64(i))
		if err := clienttx.BroadcastTx(clientCtx, ff, msg); err != nil {
			fmt.Printf("broadcast share (decrypt_height=%d seq=%d) failed: %v\n", j.decryptHeight, j.seq, err)
			continue
		}
		fmt.Printf("posted decryption share: decrypt_height=%d seq=%d index=%d\n", j.decryptHeight, j.seq, share.Index)
	}
}

// decodeKey accepts a compressed 33-byte public key as hex or base64.
func decodeKey(s string) ([]byte, error) {
	if b, err := hex.DecodeString(s); err == nil && len(b) == 33 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 33 {
		return b, nil
	}
	return nil, fmt.Errorf("pubkey must be a 33-byte compressed key in hex or base64")
}
