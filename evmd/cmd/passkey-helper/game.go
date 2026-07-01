// game.go: the on-chain economy endpoints for Lemon 2048 (the MIT 2048 game runs in the
// browser). The player's passkey smart account is msg.sender. The relayer builds the
// claim(score)/buyUndo() calldata + the SA challenge (the browser signs it with Face ID),
// reads game state, and the move submits via the same execute() path.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/cosmos/evm/x/paymaster/webauthn"
)

var gameArcade = env("GAME_ARCADE", "")

const arcadeABIJSON = `[
 {"type":"function","name":"claim","stateMutability":"nonpayable","inputs":[{"name":"score","type":"uint256"}],"outputs":[]},
 {"type":"function","name":"buyUndo","stateMutability":"nonpayable","inputs":[],"outputs":[]},
 {"type":"function","name":"getPlayer","stateMutability":"view","inputs":[{"name":"a","type":"address"}],"outputs":[
   {"name":"started","type":"bool"},{"name":"highScore","type":"uint256"},{"name":"totalClaimed","type":"uint256"},
   {"name":"lastClaim","type":"uint64"},{"name":"undosBought","type":"uint256"},{"name":"juiceBalance","type":"uint256"}]}
]`

var arcadeABIParsed = mustABI(arcadeABIJSON)

const claimCooldown = 8 // seconds, mirrors the contract

func arcadeAddr() (common.Address, error) {
	if !common.IsHexAddress(gameArcade) {
		return common.Address{}, errors.New("GAME_ARCADE not configured")
	}
	return common.HexToAddress(gameArcade), nil
}

func handleGameState(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Address string `json:"address"`
	}
	if err := readJSON(r, &in); err != nil || !common.IsHexAddress(strings.TrimSpace(in.Address)) {
		writeJSON(w, 400, map[string]string{"error": "address required"})
		return
	}
	acct := common.HexToAddress(strings.TrimSpace(in.Address))
	arc, err := arcadeAddr()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	cl, err := evmClient()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer cl.Close()
	data, _ := arcadeABIParsed.Pack("getPlayer", acct)
	out, err := ethCall(cl, arc, data)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "getPlayer: " + err.Error()})
		return
	}
	vals, err := arcadeABIParsed.Unpack("getPlayer", out)
	if err != nil || len(vals) != 6 {
		writeJSON(w, 500, map[string]string{"error": "decode getPlayer"})
		return
	}
	started := vals[0].(bool)
	highScore := vals[1].(*big.Int)
	totalClaimed := vals[2].(*big.Int)
	lastClaim := vals[3].(uint64)
	undos := vals[4].(*big.Int)
	juiceBal := vals[5].(*big.Int)

	cooldown := int64(lastClaim) + claimCooldown - time.Now().Unix()
	if cooldown < 0 {
		cooldown = 0
	}
	writeJSON(w, 200, map[string]any{
		"address":          acct.Hex(),
		"started":          started,
		"high_score":       highScore.String(),
		"total_claimed":    fmtWei(totalClaimed),
		"undos":            undos.String(),
		"juice":            fmtWei(juiceBal),
		"cooldown_seconds": cooldown,
		"rules":            map[string]any{"score_per_juice": 40, "undo_cost": 8, "max_claim": 250, "cooldown": claimCooldown},
	})
}

// handleGameFundEvm drips a little LIMO to a MetaMask address so it can pay (near-zero)
// gas for direct claim()/buyUndo() calls. Idempotent-ish: only tops up if low.
func handleGameFundEvm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Address string `json:"address"`
	}
	if err := readJSON(r, &in); err != nil || !common.IsHexAddress(strings.TrimSpace(in.Address)) {
		writeJSON(w, 400, map[string]string{"error": "address required"})
		return
	}
	to := common.HexToAddress(strings.TrimSpace(in.Address))
	cl, err := evmClient()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer cl.Close()
	bal, _ := cl.BalanceAt(context.Background(), to, nil)
	threshold := big.NewInt(20000000000000000) // 0.02 LIMO
	if bal != nil && bal.Cmp(threshold) >= 0 {
		writeJSON(w, 200, map[string]any{"address": to.Hex(), "funded": false, "balance_limo": fmtWei(bal)})
		return
	}
	amt := big.NewInt(100000000000000000) // 0.1 LIMO
	h, _, err := sendTx(cl, to, amt, nil)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	nb, _ := cl.BalanceAt(context.Background(), to, nil)
	writeJSON(w, 200, map[string]any{"address": to.Hex(), "funded": true, "hash": h.Hex(), "balance_limo": fmtWei(nb)})
}

func handleGamePrepare(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PubkeyB64 string `json:"pubkey_b64"`
		Action    string `json:"action"` // "claim" | "undo"
		Score     uint64 `json:"score"`
	}
	if err := readJSON(r, &in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	x, y, err := xyFromB64(in.PubkeyB64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	arc, err := arcadeAddr()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	var calldata []byte
	switch in.Action {
	case "claim":
		calldata, err = arcadeABIParsed.Pack("claim", new(big.Int).SetUint64(in.Score))
	case "undo":
		calldata, err = arcadeABIParsed.Pack("buyUndo")
	default:
		writeJSON(w, 400, map[string]string{"error": "action must be claim or undo"})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "pack: " + err.Error()})
		return
	}
	cl, err := evmClient()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer cl.Close()
	resp, err := saPrepareCore(cl, x, y, arc, big.NewInt(0), calldata)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, resp)
}

// ---- selftest: claim a score + buy an undo via a passkey account on the live chain ----

func gameSelftest() error {
	seed := sha256.Sum256([]byte("limonata-passkey-vector-seed-v1"))
	auth, err := webauthn.NewSimulatedAuthenticatorFromSeed(seed[:], "limonata.xyz")
	if err != nil {
		return err
	}
	x, y, err := xyFromB64(base64.StdEncoding.EncodeToString(auth.CompressedPubKey()))
	if err != nil {
		return err
	}
	arc, err := arcadeAddr()
	if err != nil {
		return err
	}
	cl, err := evmClient()
	if err != nil {
		return err
	}
	defer cl.Close()
	acct, err := getAccountAddr(cl, x, y)
	if err != nil {
		return err
	}
	fmt.Println("player smart account:", acct.Hex())
	if _, err := deployIfNeeded(cl, x, y, acct); err != nil {
		return fmt.Errorf("deploy: %w", err)
	}

	do := func(name string, calldata []byte) error {
		nonce, err := accountNonce(cl, acct)
		if err != nil {
			return err
		}
		ch, err := opChallenge(acct, nonce, arc, big.NewInt(0), calldata)
		if err != nil {
			return err
		}
		assertion, err := auth.Sign(ch[:], "https://limonata.xyz", true)
		if err != nil {
			return err
		}
		rb, sb, err := derToRS(assertion.Signature)
		if err != nil {
			return err
		}
		cd := assertion.ClientDataJSON
		at := authTuple{
			AuthenticatorData: assertion.AuthenticatorData, ClientDataJSON: string(cd),
			ChallengeIndex: big.NewInt(int64(indexOf(cd, `"challenge":"`))),
			TypeIndex:      big.NewInt(int64(indexOf(cd, `"type":"webauthn.get"`))),
			R:              rb, S: sb,
		}
		execData, err := accountABIParsed.Pack("execute", arc, big.NewInt(0), calldata, at)
		if err != nil {
			return err
		}
		_, rc, err := sendTx(cl, acct, big.NewInt(0), execData)
		if err != nil {
			return err
		}
		if rc == nil || rc.Status != 1 {
			return fmt.Errorf("%s reverted/pending", name)
		}
		fmt.Printf("%s ok (tx %s)\n", name, rc.TxHash.Hex())
		return nil
	}

	claimData, _ := arcadeABIParsed.Pack("claim", big.NewInt(400)) // 400/40 = 10 JUICE
	if err := do("claim(400)", claimData); err != nil {
		return err
	}
	undoData, _ := arcadeABIParsed.Pack("buyUndo")
	if err := do("buyUndo", undoData); err != nil {
		return err
	}

	gp, _ := arcadeABIParsed.Pack("getPlayer", acct)
	out, _ := ethCall(cl, arc, gp)
	v, _ := arcadeABIParsed.Unpack("getPlayer", out)
	fmt.Printf("after: highScore=%v totalClaimed=%s undos=%v JUICE=%s\n",
		v[1], fmtWei(v[2].(*big.Int)), v[4], fmtWei(v[5].(*big.Int)))
	fmt.Println("GAME SELFTEST OK: claim + buyUndo executed via a passkey account on the live chain.")
	return nil
}
