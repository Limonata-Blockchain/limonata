// passkey-helper is the SERVER side of Limonata's browser "sign a tx with Face ID"
// experience. The browser cannot, on its own, build byte-correct Cosmos
// SIGN_MODE_DIRECT sign-bytes for a P-256 (secp256r1) account, so this helper does
// the protobuf-heavy parts and the browser does ONLY what must happen on-device:
// create the passkey and produce the WebAuthn assertion (Face ID / fingerprint).
//
// It exposes a tiny HTTP API (localhost only; the landing proxies to it):
//
//	POST /fund     {pubkey_b64}                       -> creates+funds the P-256 account (faucet bank send)
//	POST /prepare  {pubkey_b64,to,amount}             -> {address,accountNumber,sequence,body_b64,authinfo_b64,challenge_b64}
//	POST /submit   {body_b64,authinfo_b64,            -> {ok,code,hash,log}
//	                authenticator_data_b64,
//	                client_data_json_b64,signature_b64}
//	GET  /health
//
// The browser, between /prepare and /submit, calls navigator.credentials.get with
// challenge = base64decode(challenge_b64) and returns authenticatorData,
// clientDataJSON and the DER signature. /submit packs them EXACTLY as the passkey
// ante expects (the WAS1 blob) and broadcasts.
//
// `passkey-helper selftest` exercises /prepare -> sign (SimulatedAuthenticator) ->
// /submit IN PROCESS against the live node, to prove the pipeline end-to-end.
//
// SECURITY: this never holds a user key. The only private key it touches is the
// faucet key (FAUCET_PRIVKEY, used only to fund new demo accounts), read from env.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	rpchttp "github.com/cometbft/cometbft/rpc/client/http"

	"cosmossdk.io/math"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256r1"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	evmcryptocodec "github.com/cosmos/evm/crypto/codec"
	"github.com/cosmos/evm/crypto/ethsecp256k1"
	evmdconfig "github.com/cosmos/evm/evmd/config"
	"github.com/cosmos/evm/x/paymaster/webauthn"
)

// ---- config (env, with sane defaults for the live testnet) ----

var (
	node       = env("LIMONATA_NODE", "tcp://127.0.0.1:26657")
	chainID    = env("LIMONATA_CHAIN_ID", "limonata_10777-1")
	denom      = env("LIMONATA_DENOM", "aLIMO")
	listenAddr = env("PASSKEY_HELPER_ADDR", "127.0.0.1:8097")
	// 0.05 LIMO funded and KEPT by the user's passkey account, so they can see a real
	// balance. The demo transfer spends only a small slice of it.
	fundAmount = env("PASSKEY_DEMO_FUND_ALIMO", "50000000000000000")
	// The node's app.toml min-gas-price is 1e-18 aLIMO/gas, so a non-zero fee is
	// required. 300000 aLIMO over 300000 gas = 1 aLIMO/gas (far above the min) yet
	// is only 3e-13 LIMO in absolute terms.
	feeAmount = env("PASSKEY_FEE_ALIMO", "300000")
	gasLimit  = uint64(300000)
	rpID       = env("PASSKEY_RPID", "limonata.xyz")
	origin     = env("PASSKEY_ORIGIN", "https://limonata.xyz")
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// ---- codec / client context (ABCI queries over the CometBFT RPC) ----

func newCodec() *codec.ProtoCodec {
	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	evmcryptocodec.RegisterInterfaces(reg) // secp256r1 (P-256) + ethsecp256k1
	banktypes.RegisterInterfaces(reg)
	authtypes.RegisterInterfaces(reg)
	return codec.NewProtoCodec(reg)
}

func clientCtx() (client.Context, *rpchttp.HTTP, error) {
	rpc, err := rpchttp.New(node, "/websocket")
	if err != nil {
		return client.Context{}, nil, err
	}
	cdc := newCodec()
	ctx := client.Context{}.
		WithClient(rpc).
		WithCodec(cdc).
		WithInterfaceRegistry(cdc.InterfaceRegistry()).
		WithChainID(chainID)
	return ctx, rpc, nil
}

// queryAccount returns the on-chain account number + sequence. AccountInfo returns
// a plain BaseAccount view regardless of the concrete account type (BaseAccount for
// passkey accounts, EthAccount for the faucet), so we never need to unpack a
// chain-specific account type.
func queryAccount(ctx client.Context, addr string) (accNum, seq uint64, err error) {
	q := authtypes.NewQueryClient(ctx)
	res, err := q.AccountInfo(context.Background(), &authtypes.QueryAccountInfoRequest{Address: addr})
	if err != nil {
		return 0, 0, err
	}
	if res.Info == nil {
		return 0, 0, fmt.Errorf("account %s not found on chain", addr)
	}
	return res.Info.AccountNumber, res.Info.Sequence, nil
}

// queryBalance returns the spendable balance of `addr` in the fee/send denom.
func queryBalance(ctx client.Context, addr string) (math.Int, error) {
	q := banktypes.NewQueryClient(ctx)
	res, err := q.Balance(context.Background(), &banktypes.QueryBalanceRequest{Address: addr, Denom: denom})
	if err != nil {
		return math.ZeroInt(), err
	}
	if res.Balance == nil {
		return math.ZeroInt(), nil
	}
	return res.Balance.Amount, nil
}

// ---- SIGN_MODE_DIRECT construction (the exact bytes the ante recomputes) ----

func feeCoins() sdk.Coins {
	amt, ok := math.NewIntFromString(feeAmount)
	if !ok {
		amt = math.NewInt(300000)
	}
	return sdk.NewCoins(sdk.NewCoin(denom, amt))
}

// fmtLimo formats an aLIMO integer (18 decimals) as a human-readable LIMO string.
func fmtLimo(a math.Int) string {
	s := a.String()
	for len(s) < 19 {
		s = "0" + s
	}
	intPart := s[:len(s)-18]
	frac := strings.TrimRight(s[len(s)-18:], "0")
	if frac == "" {
		return intPart
	}
	return intPart + "." + frac
}

// buildUnsigned returns the canonical TxBody and AuthInfo protobuf bytes for a
// single-signer SIGN_MODE_DIRECT tx with the standard negligible fee.
func buildUnsigned(pub cryptotypes.PubKey, msg sdk.Msg, seq uint64) (bodyBytes, authInfoBytes []byte, err error) {
	anyMsg, err := codectypes.NewAnyWithValue(msg)
	if err != nil {
		return nil, nil, err
	}
	body := &txtypes.TxBody{Messages: []*codectypes.Any{anyMsg}}
	bodyBytes, err = body.Marshal()
	if err != nil {
		return nil, nil, err
	}
	pkAny, err := codectypes.NewAnyWithValue(pub)
	if err != nil {
		return nil, nil, err
	}
	ai := &txtypes.AuthInfo{
		SignerInfos: []*txtypes.SignerInfo{{
			PublicKey: pkAny,
			ModeInfo: &txtypes.ModeInfo{Sum: &txtypes.ModeInfo_Single_{
				Single: &txtypes.ModeInfo_Single{Mode: signing.SignMode_SIGN_MODE_DIRECT},
			}},
			Sequence: seq,
		}},
		Fee: &txtypes.Fee{Amount: feeCoins(), GasLimit: gasLimit},
	}
	authInfoBytes, err = ai.Marshal()
	return bodyBytes, authInfoBytes, err
}

func signBytesDirect(bodyBytes, authInfoBytes []byte, accNum uint64) ([]byte, error) {
	sd := &txtypes.SignDoc{
		BodyBytes:     bodyBytes,
		AuthInfoBytes: authInfoBytes,
		ChainId:       chainID,
		AccountNumber: accNum,
	}
	return sd.Marshal()
}

func broadcast(ctx client.Context, rpc *rpchttp.HTTP, bodyBytes, authInfoBytes, sigBlob []byte) (uint32, string, string, error) {
	raw := &txtypes.TxRaw{BodyBytes: bodyBytes, AuthInfoBytes: authInfoBytes, Signatures: [][]byte{sigBlob}}
	txBytes, err := raw.Marshal()
	if err != nil {
		return 0, "", "", err
	}
	res, err := rpc.BroadcastTxSync(context.Background(), txBytes)
	if err != nil {
		return 0, "", "", err
	}
	return res.Code, fmt.Sprintf("%X", res.Hash), res.Log, nil
}

// ---- faucet funding (ethsecp256k1 cosmos bank send) ----

func faucetPriv() (*ethsecp256k1.PrivKey, sdk.AccAddress, error) {
	h := strings.TrimPrefix(os.Getenv("FAUCET_PRIVKEY"), "0x")
	if h == "" {
		return nil, nil, errors.New("FAUCET_PRIVKEY not set")
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, nil, fmt.Errorf("FAUCET_PRIVKEY not hex: %w", err)
	}
	priv := &ethsecp256k1.PrivKey{Key: b}
	return priv, sdk.AccAddress(priv.PubKey().Address()), nil
}

// fundAccount sends `amount` aLIMO from the faucet to `to`, creating the account if
// it does not exist yet. Returns the funder address (the demo sends funds back to it).
func fundAccount(to string, amount string) (funder string, hash string, err error) {
	ctx, rpc, err := clientCtx()
	if err != nil {
		return "", "", err
	}
	priv, from, err := faucetPriv()
	if err != nil {
		return "", "", err
	}
	toAddr, err := sdk.AccAddressFromBech32(to)
	if err != nil {
		return "", "", fmt.Errorf("bad recipient: %w", err)
	}
	amt, ok := math.NewIntFromString(amount)
	if !ok {
		return "", "", fmt.Errorf("bad amount %q", amount)
	}
	accNum, seq, err := queryAccount(ctx, from.String())
	if err != nil {
		return "", "", fmt.Errorf("faucet account query: %w", err)
	}
	msg := banktypes.NewMsgSend(from, toAddr, sdk.NewCoins(sdk.NewCoin(denom, amt)))
	bodyBytes, aiBytes, err := buildUnsigned(priv.PubKey(), msg, seq)
	if err != nil {
		return "", "", err
	}
	sb, err := signBytesDirect(bodyBytes, aiBytes, accNum)
	if err != nil {
		return "", "", err
	}
	sig, err := priv.Sign(sb) // ethsecp256k1 = keccak256(signBytes) then ECDSA
	if err != nil {
		return "", "", err
	}
	code, h, log, err := broadcast(ctx, rpc, bodyBytes, aiBytes, sig)
	if err != nil {
		return "", "", err
	}
	if code != 0 {
		return "", "", fmt.Errorf("fund rejected (code %d): %s", code, log)
	}
	return from.String(), h, nil
}

// ---- HTTP handlers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func pubFromB64(b64 string) (*secp256r1.PubKey, sdk.AccAddress, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, nil, fmt.Errorf("pubkey not base64: %w", err)
	}
	pk, err := secp256r1.NewPubKeyFromBytes(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("not a 33-byte compressed P-256 key: %w", err)
	}
	return pk, sdk.AccAddress(pk.Address()), nil
}

func handleFund(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PubkeyB64 string `json:"pubkey_b64"`
	}
	if err := readJSON(r, &in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	_, addr, err := pubFromB64(in.PubkeyB64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	funder, hash, err := fundAccount(addr.String(), fundAmount)
	if err != nil {
		log.Printf("fund FAILED addr=%s err=%v", addr.String(), err)
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	// Read the resulting balance so the page can show the user their LIMO.
	var balStr string
	if ctx, _, e := clientCtx(); e == nil {
		if b, e2 := queryBalance(ctx, addr.String()); e2 == nil {
			balStr = fmtLimo(b)
		}
	}
	log.Printf("fund OK addr=%s amount=%s tx=%s", addr.String(), fundAmount, hash)
	writeJSON(w, 200, map[string]any{
		"funded_address": addr.String(),
		"funder_address": funder,
		"amount":         fundAmount,
		"amount_limo":    fmtLimo(mustInt(fundAmount)),
		"balance_limo":   balStr,
		"hash":           hash,
	})
}

func mustInt(s string) math.Int {
	if a, ok := math.NewIntFromString(s); ok {
		return a
	}
	return math.ZeroInt()
}

func handlePrepare(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PubkeyB64 string `json:"pubkey_b64"`
		To        string `json:"to"`
		Amount    string `json:"amount"`
	}
	if err := readJSON(r, &in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	pk, addr, err := pubFromB64(in.PubkeyB64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	toAddr, err := sdk.AccAddressFromBech32(strings.TrimSpace(in.To))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad recipient address"})
		return
	}
	ctx, _, err := clientCtx()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	accNum, seq, err := queryAccount(ctx, addr.String())
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "account not funded yet: " + err.Error()})
		return
	}
	// "max" sends the whole balance minus the fee, so demo funds cycle back to the
	// funder and the account ends at zero.
	var amt math.Int
	if strings.TrimSpace(in.Amount) == "max" {
		bal, err := queryBalance(ctx, addr.String())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "balance query: " + err.Error()})
			return
		}
		amt = bal.Sub(feeCoins().AmountOf(denom))
	} else {
		var ok bool
		amt, ok = math.NewIntFromString(strings.TrimSpace(in.Amount))
		if !ok {
			writeJSON(w, 400, map[string]string{"error": "bad amount"})
			return
		}
	}
	if !amt.IsPositive() {
		writeJSON(w, 400, map[string]string{"error": "amount not positive (insufficient balance)"})
		return
	}
	msg := banktypes.NewMsgSend(addr, toAddr, sdk.NewCoins(sdk.NewCoin(denom, amt)))
	bodyBytes, aiBytes, err := buildUnsigned(pk, msg, seq)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	sb, err := signBytesDirect(bodyBytes, aiBytes, accNum)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	challenge := sha256.Sum256(sb)
	writeJSON(w, 200, map[string]any{
		"address":        addr.String(),
		"account_number": accNum,
		"sequence":       seq,
		"body_b64":       base64.StdEncoding.EncodeToString(bodyBytes),
		"authinfo_b64":   base64.StdEncoding.EncodeToString(aiBytes),
		"challenge_b64":  base64.StdEncoding.EncodeToString(challenge[:]),
	})
}

func handleSubmit(w http.ResponseWriter, r *http.Request) {
	var in struct {
		BodyB64              string `json:"body_b64"`
		AuthInfoB64          string `json:"authinfo_b64"`
		AuthenticatorDataB64 string `json:"authenticator_data_b64"`
		ClientDataJSONB64    string `json:"client_data_json_b64"`
		SignatureB64         string `json:"signature_b64"`
	}
	if err := readJSON(r, &in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	dec := func(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(strings.TrimSpace(s)) }
	bodyBytes, e1 := dec(in.BodyB64)
	aiBytes, e2 := dec(in.AuthInfoB64)
	authData, e3 := dec(in.AuthenticatorDataB64)
	clientData, e4 := dec(in.ClientDataJSONB64)
	sig, e5 := dec(in.SignatureB64)
	for _, e := range []error{e1, e2, e3, e4, e5} {
		if e != nil {
			writeJSON(w, 400, map[string]string{"error": "bad base64 field: " + e.Error()})
			return
		}
	}
	if len(bodyBytes) == 0 || len(aiBytes) == 0 || len(authData) == 0 || len(clientData) == 0 || len(sig) == 0 {
		writeJSON(w, 400, map[string]string{"error": "missing tx or assertion field"})
		return
	}
	assertion := webauthn.Assertion{AuthenticatorData: authData, ClientDataJSON: clientData, Signature: sig}
	sigBlob := assertion.Marshal()

	ctx, rpc, err := clientCtx()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	code, hash, txLog, err := broadcast(ctx, rpc, bodyBytes, aiBytes, sigBlob)
	if err != nil {
		log.Printf("submit broadcast error: %v", err)
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	log.Printf("submit code=%d tx=%s log=%q", code, hash, txLog)
	writeJSON(w, 200, map[string]any{"ok": code == 0, "code": code, "hash": hash, "log": txLog})
}

// handleBalance returns the LIMO balance of an address (page shows "your LIMO").
func handleBalance(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Address string `json:"address"`
	}
	if err := readJSON(r, &in); err != nil || strings.TrimSpace(in.Address) == "" {
		writeJSON(w, 400, map[string]string{"error": "address required"})
		return
	}
	ctx, _, err := clientCtx()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	bal, err := queryBalance(ctx, strings.TrimSpace(in.Address))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"address": in.Address, "balance_alimo": bal.String(), "balance_limo": fmtLimo(bal)})
}

// handleTx confirms a tx landed in a block (the page polls this after submit so the
// user SEES the transaction, since the EVM explorer cannot show Cosmos txs).
func handleTx(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Hash string `json:"hash"`
	}
	if err := readJSON(r, &in); err != nil || strings.TrimSpace(in.Hash) == "" {
		writeJSON(w, 400, map[string]string{"error": "hash required"})
		return
	}
	hb, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(in.Hash), "0x"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad hash"})
		return
	}
	_, rpc, err := clientCtx()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	res, err := rpc.Tx(context.Background(), hb, false)
	if err != nil {
		// not indexed yet (still in mempool / not committed) -> not an error to the page
		writeJSON(w, 200, map[string]any{"found": false})
		return
	}
	writeJSON(w, 200, map[string]any{"found": true, "height": res.Height, "code": res.TxResult.Code})
}

// handleTxs lists the account's transactions (the page renders these as the
// "wallet history", since the EVM explorer cannot show a Cosmos account).
func handleTxs(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Address string `json:"address"`
	}
	if err := readJSON(r, &in); err != nil || strings.TrimSpace(in.Address) == "" {
		writeJSON(w, 400, map[string]string{"error": "address required"})
		return
	}
	addr := strings.TrimSpace(in.Address)
	_, rpc, err := clientCtx()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	type txItem struct {
		Hash   string `json:"hash"`
		Height int64  `json:"height"`
		Dir    string `json:"dir"`
		Code   uint32 `json:"code"`
	}
	page, perPage := 1, 15
	seen := map[string]*txItem{}
	search := func(query, dir string) {
		res, err := rpc.TxSearch(context.Background(), query, false, &page, &perPage, "desc")
		if err != nil || res == nil {
			return
		}
		for _, t := range res.Txs {
			h := fmt.Sprintf("%X", t.Hash)
			if ex, ok := seen[h]; ok {
				if ex.Dir != dir {
					ex.Dir = "self"
				}
				continue
			}
			seen[h] = &txItem{Hash: h, Height: t.Height, Dir: dir, Code: t.TxResult.Code}
		}
	}
	search(fmt.Sprintf("coin_spent.spender='%s'", addr), "out")
	search(fmt.Sprintf("coin_received.receiver='%s'", addr), "in")
	items := make([]*txItem, 0, len(seen))
	for _, v := range seen {
		items = append(items, v)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Height > items[j].Height })
	if len(items) > 15 {
		items = items[:15]
	}
	writeJSON(w, 200, map[string]any{"address": addr, "txs": items})
}

// ---- selftest: prove /prepare -> sign -> /submit on the live chain ----

func selftest() error {
	seed := sha256.Sum256([]byte("limonata-passkey-helper-selftest-v1"))
	auth, err := webauthn.NewSimulatedAuthenticatorFromSeed(seed[:], rpID)
	if err != nil {
		return err
	}
	pk, err := secp256r1.NewPubKeyFromBytes(auth.CompressedPubKey())
	if err != nil {
		return err
	}
	addr := sdk.AccAddress(pk.Address())
	fmt.Println("passkey address:", addr.String())

	funder, fhash, err := fundAccount(addr.String(), fundAmount)
	if err != nil {
		return fmt.Errorf("fund: %w", err)
	}
	fmt.Printf("funded by %s (tx %s); waiting for inclusion...\n", funder, fhash)
	time.Sleep(3 * time.Second)

	ctx, rpc, err := clientCtx()
	if err != nil {
		return err
	}
	accNum, seq, err := queryAccount(ctx, addr.String())
	if err != nil {
		return fmt.Errorf("query after fund: %w", err)
	}
	toAddr, _ := sdk.AccAddressFromBech32(funder)
	bal, err := queryBalance(ctx, addr.String())
	if err != nil {
		return fmt.Errorf("balance query: %w", err)
	}
	amt := bal.Sub(feeCoins().AmountOf(denom))
	msg := banktypes.NewMsgSend(addr, toAddr, sdk.NewCoins(sdk.NewCoin(denom, amt)))
	bodyBytes, aiBytes, err := buildUnsigned(pk, msg, seq)
	if err != nil {
		return err
	}
	sb, err := signBytesDirect(bodyBytes, aiBytes, accNum)
	if err != nil {
		return err
	}
	challenge := sha256.Sum256(sb)
	assertion, err := auth.Sign(challenge[:], origin, true) // userVerified=true (Face ID)
	if err != nil {
		return err
	}
	code, hash, log, err := broadcast(ctx, rpc, bodyBytes, aiBytes, assertion.Marshal())
	if err != nil {
		return err
	}
	fmt.Printf("passkey tx: code=%d hash=%s log=%q\n", code, hash, log)
	if code != 0 {
		return fmt.Errorf("passkey tx rejected")
	}
	fmt.Println("SELFTEST OK: a P-256 passkey tx was accepted by the live chain.")
	return nil
}

func main() {
	evmdconfig.SetBech32Prefixes(sdk.GetConfig())

	if len(os.Args) > 1 && os.Args[1] == "selftest" {
		if err := selftest(); err != nil {
			fmt.Fprintln(os.Stderr, "SELFTEST FAILED:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "sa-selftest" {
		if err := saSelftest(); err != nil {
			fmt.Fprintln(os.Stderr, "SA SELFTEST FAILED:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "game-selftest" {
		if err := gameSelftest(); err != nil {
			fmt.Fprintln(os.Stderr, "GAME SELFTEST FAILED:", err)
			os.Exit(1)
		}
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) })
	mux.HandleFunc("/fund", post(handleFund))
	mux.HandleFunc("/prepare", post(handlePrepare))
	mux.HandleFunc("/submit", post(handleSubmit))
	mux.HandleFunc("/balance", post(handleBalance))
	mux.HandleFunc("/tx", post(handleTx))
	mux.HandleFunc("/txs", post(handleTxs))
	// EVM smart-account ("real wallet") path
	mux.HandleFunc("/sa/address", post(saAddress))
	mux.HandleFunc("/sa/fund", post(saFund))
	mux.HandleFunc("/sa/prepare", post(saPrepare))
	mux.HandleFunc("/sa/submit", post(saSubmit))
	// Lemonade Tycoon game
	mux.HandleFunc("/game/state", post(handleGameState))
	mux.HandleFunc("/game/prepare", post(handleGamePrepare))
	mux.HandleFunc("/game/fund-evm", post(handleGameFundEvm))

	fmt.Println("passkey-helper listening on", listenAddr, "chain", chainID, "node", node)
	srv := &http.Server{Addr: listenAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "server error:", err)
		os.Exit(1)
	}
}

func post(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, 405, map[string]string{"error": "POST only"})
			return
		}
		h(w, r)
	}
}
