// sa.go: the EVM smart-account ("real wallet") path. A passkey controls a
// PasskeyAccount contract at a deterministic 0x address (visible in the EVM explorer
// and watchable in MetaMask). This relayer computes the address, funds it, builds the
// operation challenge, and submits the passkey-authorized execute() (paying gas). It
// never holds a user key; the only key it uses is the faucet/relayer EOA.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/cosmos/evm/x/paymaster/webauthn"
)

var (
	saEvmRPC   = env("SA_EVM_RPC", "http://127.0.0.1:8545")
	saFactory  = env("SA_FACTORY", "")
	saChainID  = bigFromEnv("SA_CHAIN_ID", 10777)
	saFundWei = env("SA_FUND_WEI", "50000000000000000") // 0.05 LIMO
	// The chain's base fee is ~0; use a tiny gas price so the explorer shows a ~0 fee,
	// consistent with the gasless demo. The relayer (not the user) pays it regardless.
	saGasPrice = bigFromEnv("SA_GAS_PRICE_WEI", 1000)
)

func bigFromEnv(k string, def int64) *big.Int {
	if v := env(k, ""); v != "" {
		if n, ok := new(big.Int).SetString(v, 10); ok {
			return n
		}
	}
	return big.NewInt(def)
}

// ---- ABIs (only the methods the relayer needs) ----

const factoryABI = `[
 {"type":"function","name":"getAddress","stateMutability":"view","inputs":[{"name":"x","type":"bytes32"},{"name":"y","type":"bytes32"}],"outputs":[{"name":"","type":"address"}]},
 {"type":"function","name":"createAccount","stateMutability":"nonpayable","inputs":[{"name":"x","type":"bytes32"},{"name":"y","type":"bytes32"}],"outputs":[{"name":"","type":"address"}]}
]`

const accountABI = `[
 {"type":"function","name":"nonce","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint256"}]},
 {"type":"function","name":"execute","stateMutability":"nonpayable","inputs":[
   {"name":"to","type":"address"},{"name":"value","type":"uint256"},{"name":"data","type":"bytes"},
   {"name":"auth","type":"tuple","components":[
     {"name":"authenticatorData","type":"bytes"},
     {"name":"clientDataJSON","type":"string"},
     {"name":"challengeIndex","type":"uint256"},
     {"name":"typeIndex","type":"uint256"},
     {"name":"r","type":"bytes32"},
     {"name":"s","type":"bytes32"}]}],
  "outputs":[{"name":"","type":"bytes"}]}
]`

// authTuple mirrors the Solidity WebAuthn.Auth struct (field order matters for ABI).
type authTuple struct {
	AuthenticatorData []byte
	ClientDataJSON    string
	ChallengeIndex    *big.Int
	TypeIndex         *big.Int
	R                 [32]byte
	S                 [32]byte
}

func mustABI(s string) abi.ABI {
	a, err := abi.JSON(strings.NewReader(s))
	if err != nil {
		panic(err)
	}
	return a
}

var (
	factoryABIParsed = mustABI(factoryABI)
	accountABIParsed = mustABI(accountABI)
)

func evmClient() (*ethclient.Client, error) { return ethclient.Dial(saEvmRPC) }

// fmtWei formats an 18-decimal wei amount as a human LIMO string.
func fmtWei(b *big.Int) string {
	if b == nil {
		return "0"
	}
	s := b.String()
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	for len(s) < 19 {
		s = "0" + s
	}
	ip, fp := s[:len(s)-18], strings.TrimRight(s[len(s)-18:], "0")
	out := ip
	if fp != "" {
		out += "." + fp
	}
	if neg {
		out = "-" + out
	}
	return out
}

func decompressP256(b []byte) (*big.Int, *big.Int) {
	return elliptic.UnmarshalCompressed(elliptic.P256(), b)
}

// derToRS parses an ASN.1 DER ECDSA signature into 32-byte r,s with low-s normalization.
func derToRS(der []byte) (r [32]byte, s [32]byte, err error) {
	var sig struct{ R, S *big.Int }
	if _, e := asn1.Unmarshal(der, &sig); e != nil {
		return r, s, e
	}
	n := elliptic.P256().Params().N
	half := new(big.Int).Rsh(n, 1)
	if sig.S.Cmp(half) > 0 {
		sig.S = new(big.Int).Sub(n, sig.S)
	}
	sig.R.FillBytes(r[:])
	sig.S.FillBytes(s[:])
	return r, s, nil
}

func indexOf(b []byte, sub string) int { return bytes.Index(b, []byte(sub)) }

func relayerKey() (*ecdsa.PrivateKey, common.Address, error) {
	h := strings.TrimPrefix(env("FAUCET_PRIVKEY", ""), "0x")
	if h == "" {
		return nil, common.Address{}, errors.New("FAUCET_PRIVKEY not set")
	}
	k, err := crypto.HexToECDSA(h)
	if err != nil {
		return nil, common.Address{}, err
	}
	return k, crypto.PubkeyToAddress(k.PublicKey), nil
}

func factoryAddr() (common.Address, error) {
	if !common.IsHexAddress(saFactory) {
		return common.Address{}, errors.New("SA_FACTORY not configured")
	}
	return common.HexToAddress(saFactory), nil
}

// ---- read helpers (eth_call) ----

func ethCall(cl *ethclient.Client, to common.Address, data []byte) ([]byte, error) {
	return cl.CallContract(context.Background(), ethereum.CallMsg{To: &to, Data: data}, nil)
}

func getAccountAddr(cl *ethclient.Client, x, y [32]byte) (common.Address, error) {
	fa, err := factoryAddr()
	if err != nil {
		return common.Address{}, err
	}
	data, err := factoryABIParsed.Pack("getAddress", x, y)
	if err != nil {
		return common.Address{}, err
	}
	out, err := ethCall(cl, fa, data)
	if err != nil {
		return common.Address{}, err
	}
	res, err := factoryABIParsed.Unpack("getAddress", out)
	if err != nil || len(res) == 0 {
		return common.Address{}, fmt.Errorf("getAddress decode: %v", err)
	}
	return res[0].(common.Address), nil
}

func accountNonce(cl *ethclient.Client, acct common.Address) (uint64, error) {
	code, err := cl.CodeAt(context.Background(), acct, nil)
	if err != nil {
		return 0, err
	}
	if len(code) == 0 {
		return 0, nil // not deployed yet
	}
	data, _ := accountABIParsed.Pack("nonce")
	out, err := ethCall(cl, acct, data)
	if err != nil {
		return 0, err
	}
	res, err := accountABIParsed.Unpack("nonce", out)
	if err != nil || len(res) == 0 {
		return 0, fmt.Errorf("nonce decode: %v", err)
	}
	return res[0].(*big.Int).Uint64(), nil
}

// challenge = keccak256(abi.encode(chainid, account, nonce, to, value, keccak256(data)))
func opChallenge(acct common.Address, nonce uint64, to common.Address, value *big.Int, data []byte) ([32]byte, error) {
	u256, _ := abi.NewType("uint256", "", nil)
	addr, _ := abi.NewType("address", "", nil)
	b32, _ := abi.NewType("bytes32", "", nil)
	args := abi.Arguments{{Type: u256}, {Type: addr}, {Type: u256}, {Type: addr}, {Type: u256}, {Type: b32}}
	var dataHash [32]byte
	copy(dataHash[:], crypto.Keccak256(data))
	packed, err := args.Pack(saChainID, acct, new(big.Int).SetUint64(nonce), to, value, dataHash)
	if err != nil {
		return [32]byte{}, err
	}
	var ch [32]byte
	copy(ch[:], crypto.Keccak256(packed))
	return ch, nil
}

// ---- write helper (send a legacy tx from the relayer, wait for the receipt) ----

func sendTx(cl *ethclient.Client, to common.Address, value *big.Int, data []byte) (common.Hash, *types.Receipt, error) {
	key, from, err := relayerKey()
	if err != nil {
		return common.Hash{}, nil, err
	}
	ctx := context.Background()
	nonce, err := cl.PendingNonceAt(ctx, from)
	if err != nil {
		return common.Hash{}, nil, err
	}
	gas := uint64(700000)
	if est, err := cl.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &to, Value: value, Data: data}); err == nil && est > 0 {
		gas = est + est/4 + 30000 // headroom
	}
	tx := types.NewTx(&types.LegacyTx{Nonce: nonce, GasPrice: saGasPrice, Gas: gas, To: &to, Value: value, Data: data})
	signed, err := types.SignTx(tx, types.NewEIP155Signer(saChainID), key)
	if err != nil {
		return common.Hash{}, nil, err
	}
	if err := cl.SendTransaction(ctx, signed); err != nil {
		return common.Hash{}, nil, err
	}
	h := signed.Hash()
	// wait for the receipt
	for i := 0; i < 20; i++ {
		if rc, err := cl.TransactionReceipt(ctx, h); err == nil && rc != nil {
			return h, rc, nil
		}
		time.Sleep(700 * time.Millisecond)
	}
	return h, nil, nil // submitted; receipt pending
}

func deployIfNeeded(cl *ethclient.Client, x, y [32]byte, acct common.Address) (bool, error) {
	code, err := cl.CodeAt(context.Background(), acct, nil)
	if err != nil {
		return false, err
	}
	if len(code) > 0 {
		return false, nil
	}
	fa, err := factoryAddr()
	if err != nil {
		return false, err
	}
	data, err := factoryABIParsed.Pack("createAccount", x, y)
	if err != nil {
		return false, err
	}
	_, rc, err := sendTx(cl, fa, big.NewInt(0), data)
	if err != nil {
		return false, err
	}
	if rc != nil && rc.Status != 1 {
		return false, errors.New("createAccount reverted")
	}
	return true, nil
}

// ---- pubkey parsing ----

func xyFromB64(pubB64 string) (x, y [32]byte, err error) {
	raw, e := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if e != nil {
		return x, y, fmt.Errorf("pubkey not base64: %w", e)
	}
	// accept 33-byte compressed or 65-byte uncompressed
	switch len(raw) {
	case 65:
		copy(x[:], raw[1:33])
		copy(y[:], raw[33:65])
	case 33:
		px, py := decompressP256(raw)
		if px == nil {
			return x, y, errors.New("bad compressed P-256 key")
		}
		px.FillBytes(x[:])
		py.FillBytes(y[:])
	default:
		return x, y, fmt.Errorf("pubkey must be 33 or 65 bytes, got %d", len(raw))
	}
	return x, y, nil
}

func b32(hexStr string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(hexStr), "0x"))
	if err != nil || len(raw) != 32 {
		return out, fmt.Errorf("expected 32-byte hex")
	}
	copy(out[:], raw)
	return out, nil
}

// ---- HTTP handlers ----

func saAddress(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PubkeyB64 string `json:"pubkey_b64"`
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
	cl, err := evmClient()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer cl.Close()
	acct, err := getAccountAddr(cl, x, y)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	bal, _ := cl.BalanceAt(context.Background(), acct, nil)
	code, _ := cl.CodeAt(context.Background(), acct, nil)
	_, relayer, _ := relayerKey()
	writeJSON(w, 200, map[string]any{
		"address": acct.Hex(), "balance_wei": bal.String(), "balance_limo": fmtWei(bal),
		"deployed": len(code) > 0, "relayer": relayer.Hex(),
	})
}

func saFund(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PubkeyB64 string `json:"pubkey_b64"`
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
	cl, err := evmClient()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer cl.Close()
	acct, err := getAccountAddr(cl, x, y)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	amt, _ := new(big.Int).SetString(saFundWei, 10)
	h, rc, err := sendTx(cl, acct, amt, nil)
	if err != nil {
		log.Printf("sa fund FAILED acct=%s err=%v", acct.Hex(), err)
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if rc != nil && rc.Status != 1 {
		writeJSON(w, 500, map[string]string{"error": "fund tx reverted"})
		return
	}
	bal, _ := cl.BalanceAt(context.Background(), acct, nil)
	_, relayer, _ := relayerKey()
	log.Printf("sa fund OK acct=%s tx=%s", acct.Hex(), h.Hex())
	writeJSON(w, 200, map[string]any{
		"address": acct.Hex(), "amount_limo": fmtWei(amt), "balance_limo": fmtWei(bal),
		"hash": h.Hex(), "relayer": relayer.Hex(),
	})
}

// saPrepareCore builds the operation challenge for execute(to,value,data) from the
// account owned by (x,y). Shared by /sa/prepare (plain transfers) and /game/prepare
// (contract calls), so both produce a challenge the browser signs identically.
func saPrepareCore(cl *ethclient.Client, x, y [32]byte, to common.Address, value *big.Int, data []byte) (map[string]any, error) {
	acct, err := getAccountAddr(cl, x, y)
	if err != nil {
		return nil, err
	}
	nonce, err := accountNonce(cl, acct)
	if err != nil {
		return nil, err
	}
	ch, err := opChallenge(acct, nonce, to, value, data)
	if err != nil {
		return nil, err
	}
	code, _ := cl.CodeAt(context.Background(), acct, nil)
	return map[string]any{
		"address": acct.Hex(), "nonce": nonce, "needs_deploy": len(code) == 0,
		"to": to.Hex(), "value_wei": value.String(), "data_hex": "0x" + hex.EncodeToString(data),
		"challenge_b64": base64.StdEncoding.EncodeToString(ch[:]),
		"challenge_hex": "0x" + hex.EncodeToString(ch[:]),
	}, nil
}

func saPrepare(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PubkeyB64 string `json:"pubkey_b64"`
		To        string `json:"to"`
		ValueWei  string `json:"value_wei"`
		DataHex   string `json:"data_hex"`
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
	if !common.IsHexAddress(strings.TrimSpace(in.To)) {
		writeJSON(w, 400, map[string]string{"error": "bad recipient 0x address"})
		return
	}
	to := common.HexToAddress(strings.TrimSpace(in.To))
	value, ok := new(big.Int).SetString(strings.TrimSpace(in.ValueWei), 10)
	if !ok || value.Sign() < 0 {
		writeJSON(w, 400, map[string]string{"error": "bad value"})
		return
	}
	data, derr := hexData(in.DataHex)
	if derr != nil {
		writeJSON(w, 400, map[string]string{"error": derr.Error()})
		return
	}
	cl, err := evmClient()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer cl.Close()
	resp, err := saPrepareCore(cl, x, y, to, value, data)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, resp)
}

// hexData parses optional "0x..." calldata; empty -> nil.
func hexData(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0x" {
		return nil, nil
	}
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}

func saSubmit(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PubkeyB64            string `json:"pubkey_b64"`
		To                   string `json:"to"`
		ValueWei             string `json:"value_wei"`
		AuthenticatorDataB64 string `json:"authenticator_data_b64"`
		ClientDataJSONB64    string `json:"client_data_json_b64"`
		ChallengeIndex       uint64 `json:"challenge_index"`
		TypeIndex            uint64 `json:"type_index"`
		RHex                 string `json:"r_hex"`
		SHex                 string `json:"s_hex"`
		DataHex              string `json:"data_hex"`
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
	if !common.IsHexAddress(strings.TrimSpace(in.To)) {
		writeJSON(w, 400, map[string]string{"error": "bad recipient"})
		return
	}
	to := common.HexToAddress(strings.TrimSpace(in.To))
	value, ok := new(big.Int).SetString(strings.TrimSpace(in.ValueWei), 10)
	if !ok {
		writeJSON(w, 400, map[string]string{"error": "bad value"})
		return
	}
	authData, e1 := base64.StdEncoding.DecodeString(in.AuthenticatorDataB64)
	clientData, e2 := base64.StdEncoding.DecodeString(in.ClientDataJSONB64)
	rb, e3 := b32(in.RHex)
	sb, e4 := b32(in.SHex)
	for _, e := range []error{e1, e2, e3, e4} {
		if e != nil {
			writeJSON(w, 400, map[string]string{"error": "bad field: " + e.Error()})
			return
		}
	}
	if len(authData) == 0 || len(clientData) == 0 {
		writeJSON(w, 400, map[string]string{"error": "missing assertion field"})
		return
	}
	cl, err := evmClient()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer cl.Close()
	acct, err := getAccountAddr(cl, x, y)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if _, err := deployIfNeeded(cl, x, y, acct); err != nil {
		writeJSON(w, 500, map[string]string{"error": "deploy: " + err.Error()})
		return
	}
	callData, derr := hexData(in.DataHex)
	if derr != nil {
		writeJSON(w, 400, map[string]string{"error": "bad data_hex: " + derr.Error()})
		return
	}
	auth := authTuple{
		AuthenticatorData: authData,
		ClientDataJSON:    string(clientData),
		ChallengeIndex:    new(big.Int).SetUint64(in.ChallengeIndex),
		TypeIndex:         new(big.Int).SetUint64(in.TypeIndex),
		R:                 rb,
		S:                 sb,
	}
	data, err := accountABIParsed.Pack("execute", to, value, callData, auth)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "pack execute: " + err.Error()})
		return
	}
	h, rc, err := sendTx(cl, acct, big.NewInt(0), data)
	if err != nil {
		log.Printf("sa submit FAILED acct=%s err=%v", acct.Hex(), err)
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	status := uint64(0)
	if rc != nil {
		status = rc.Status
	}
	log.Printf("sa submit acct=%s tx=%s status=%d", acct.Hex(), h.Hex(), status)
	writeJSON(w, 200, map[string]any{"ok": rc != nil && rc.Status == 1, "hash": h.Hex(), "status": status})
}

// ---- selftest: full EVM smart-account flow on the live chain ----

func saSelftest() error {
	seed := sha256.Sum256([]byte("limonata-passkey-vector-seed-v1")) // same key as the test vector
	auth, err := webauthn.NewSimulatedAuthenticatorFromSeed(seed[:], "limonata.xyz")
	if err != nil {
		return err
	}
	x, y, err := xyFromB64(base64.StdEncoding.EncodeToString(auth.CompressedPubKey()))
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
	fmt.Println("smart account:", acct.Hex())

	amt, _ := new(big.Int).SetString(saFundWei, 10)
	if _, _, err := sendTx(cl, acct, amt, nil); err != nil {
		return fmt.Errorf("fund: %w", err)
	}
	if _, err := deployIfNeeded(cl, x, y, acct); err != nil {
		return fmt.Errorf("deploy: %w", err)
	}
	nonce, err := accountNonce(cl, acct)
	if err != nil {
		return err
	}
	_, relayer, _ := relayerKey()
	sendAmt := big.NewInt(10000000000000000) // 0.01 LIMO back to the relayer
	ch, err := opChallenge(acct, nonce, relayer, sendAmt, nil)
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
	authStruct := authTuple{
		AuthenticatorData: assertion.AuthenticatorData,
		ClientDataJSON:    string(cd),
		ChallengeIndex:    big.NewInt(int64(indexOf(cd, `"challenge":"`))),
		TypeIndex:         big.NewInt(int64(indexOf(cd, `"type":"webauthn.get"`))),
		R:                 rb,
		S:                 sb,
	}
	data, err := accountABIParsed.Pack("execute", relayer, sendAmt, []byte(nil), authStruct)
	if err != nil {
		return err
	}
	balBefore, _ := cl.BalanceAt(context.Background(), acct, nil)
	h, rc, err := sendTx(cl, acct, big.NewInt(0), data)
	if err != nil {
		return fmt.Errorf("execute: %w", err)
	}
	if rc == nil {
		return fmt.Errorf("execute receipt pending (tx %s)", h.Hex())
	}
	balAfter, _ := cl.BalanceAt(context.Background(), acct, nil)
	fmt.Printf("execute tx %s status=%d\n", h.Hex(), rc.Status)
	fmt.Printf("account balance %s -> %s wei\n", balBefore, balAfter)
	if rc.Status != 1 {
		return errors.New("execute reverted (passkey verification failed on-chain)")
	}
	fmt.Println("SA SELFTEST OK: a passkey-signed EVM smart-account tx executed on the live chain.")
	return nil
}
