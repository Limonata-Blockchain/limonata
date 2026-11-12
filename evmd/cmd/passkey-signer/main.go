// passkey-signer is a DEV/TEST tool: it builds a real Cosmos bank transaction,
// authorizes it with a simulated WebAuthn (P-256) passkey, packs the assertion into
// the tx signature exactly as a passkey client would, and broadcasts it to a node.
//
// It exists to prove the passkey ante end-to-end on a real chain. It is NOT a
// production signer: a real passkey key never leaves the device secure element.
//
// Usage:
//
//	passkey-signer keygen
//	    -> prints a reusable seed (hex) and the derived cosmos secp256r1 address.
//	       Fund that address, then:
//
//	passkey-signer send -seed <hex> -node tcp://host:26657 -chain-id <id> \
//	    -to <addr> -denom <d> -amount <n> -fee-denom <d> -fee <n> \
//	    -account-number <N> -sequence <S> [-tamper]
//	    -> builds, passkey-signs, and broadcasts; prints the CheckTx code/hash.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	rpchttp "github.com/cometbft/cometbft/rpc/client/http"

	"cosmossdk.io/math"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256r1"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	evmcryptocodec "github.com/cosmos/evm/crypto/codec"
	evmdconfig "github.com/cosmos/evm/evmd/config"
	"github.com/cosmos/evm/x/paymaster/webauthn"
)

const rpID = "limonata.xyz"
const origin = "https://limonata.xyz"

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func txConfig() client.TxConfig {
	reg := codectypes.NewInterfaceRegistry()
	std.RegisterInterfaces(reg)
	evmcryptocodec.RegisterInterfaces(reg) // registers secp256r1 (P-256)
	banktypes.RegisterInterfaces(reg)
	cdc := codec.NewProtoCodec(reg)
	return authtx.NewTxConfig(cdc, authtx.DefaultSignModes)
}

func authFromSeed(seedHex string) (*webauthn.SimulatedAuthenticator, *secp256r1.PubKey, sdk.AccAddress) {
	seed, err := hex.DecodeString(seedHex)
	die(err)
	a, err := webauthn.NewSimulatedAuthenticatorFromSeed(seed, rpID)
	die(err)
	pk, err := secp256r1.NewPubKeyFromBytes(a.CompressedPubKey())
	die(err)
	return a, pk, sdk.AccAddress(pk.Address())
}

func main() {
	evmdconfig.SetBech32Prefixes(sdk.GetConfig())

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: passkey-signer <keygen|send> ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		seed := make([]byte, 32)
		_, err := rand.Read(seed)
		die(err)
		a, _, addr := authFromSeed(hex.EncodeToString(seed))
		fmt.Printf("seed=%s\naddress=%s\npubkey_compressed=%s\n",
			hex.EncodeToString(seed), addr.String(), hex.EncodeToString(a.CompressedPubKey()))
	case "send":
		fs := flag.NewFlagSet("send", flag.ExitOnError)
		seedHex := fs.String("seed", "", "P-256 seed hex from keygen")
		node := fs.String("node", "tcp://127.0.0.1:26657", "CometBFT RPC")
		chainID := fs.String("chain-id", "", "chain id")
		to := fs.String("to", "", "recipient bech32 address")
		denom := fs.String("denom", "stake", "send denom")
		amount := fs.Int64("amount", 1, "send amount")
		feeDenom := fs.String("fee-denom", "stake", "fee denom")
		fee := fs.Int64("fee", 1, "fee amount")
		gas := fs.Uint64("gas", 600000, "gas limit")
		accNum := fs.Uint64("account-number", 0, "signer account number")
		seq := fs.Uint64("sequence", 0, "signer sequence")
		tamper := fs.Bool("tamper", false, "sign a WRONG challenge (negative test)")
		die(fs.Parse(os.Args[2:]))

		a, pk, addr := authFromSeed(*seedHex)
		toAddr, err := sdk.AccAddressFromBech32(*to)
		die(err)

		cfg := txConfig()
		txb := cfg.NewTxBuilder()
		msg := banktypes.NewMsgSend(addr, toAddr, sdk.NewCoins(sdk.NewCoin(*denom, math.NewInt(*amount))))
		die(txb.SetMsgs(msg))
		txb.SetGasLimit(*gas)
		txb.SetFeeAmount(sdk.NewCoins(sdk.NewCoin(*feeDenom, math.NewInt(*fee))))

		// empty sig fixes the SignerInfo (pubkey + sign mode + sequence)
		die(txb.SetSignatures(signing.SignatureV2{
			PubKey:   pk,
			Data:     &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT},
			Sequence: *seq,
		}))

		signerData := authsigning.SignerData{
			Address: addr.String(), ChainID: *chainID,
			AccountNumber: *accNum, Sequence: *seq, PubKey: pk,
		}
		signBytes, err := authsigning.GetSignBytesAdapter(
			context.Background(), cfg.SignModeHandler(),
			signing.SignMode_SIGN_MODE_DIRECT, signerData, txb.GetTx())
		die(err)

		challenge := sha256.Sum256(signBytes)
		ch := challenge[:]
		if *tamper {
			bad := sha256.Sum256([]byte("attacker-substituted-bytes"))
			ch = bad[:]
		}
		assertion, err := a.Sign(ch, origin, true)
		die(err)

		die(txb.SetSignatures(signing.SignatureV2{
			PubKey:   pk,
			Data:     &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT, Signature: assertion.Marshal()},
			Sequence: *seq,
		}))

		txBytes, err := cfg.TxEncoder()(txb.GetTx())
		die(err)

		c, err := rpchttp.New(*node, "/websocket")
		die(err)
		res, err := c.BroadcastTxSync(context.Background(), txBytes)
		die(err)
		fmt.Printf("checktx_code=%d\nhash=%X\nlog=%s\n", res.Code, res.Hash, res.Log)
		if res.Code != 0 {
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", os.Args[1])
		os.Exit(2)
	}
}
