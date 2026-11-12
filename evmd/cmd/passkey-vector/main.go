// passkey-vector emits a deterministic WebAuthn assertion vector (JSON) used to
// test the Solidity PasskeyAccount / WebAuthn verifier against the SAME bytes the
// chain's Go authenticator produces. It mirrors exactly what the browser must do:
// parse the DER signature into (r,s) and normalize s to the low half.
package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/cosmos/evm/x/paymaster/webauthn"
)

func main() {
	seed := sha256.Sum256([]byte("limonata-passkey-vector-seed-v1"))
	auth, err := webauthn.NewSimulatedAuthenticatorFromSeed(seed[:], "limonata.xyz")
	if err != nil {
		panic(err)
	}
	// decompress the 33-byte compressed key into x,y
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), auth.CompressedPubKey())
	if x == nil {
		panic("decompress failed")
	}

	challenge := sha256.Sum256([]byte("limonata-passkey-vector-challenge"))
	assertion, err := auth.Sign(challenge[:], "https://limonata.xyz", true)
	if err != nil {
		panic(err)
	}

	// DER -> r,s
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(assertion.Signature, &sig); err != nil {
		panic(err)
	}
	// low-s normalization (the EVM verifier rejects high-s for malleability)
	n := elliptic.P256().Params().N
	halfN := new(big.Int).Rsh(n, 1)
	if sig.S.Cmp(halfN) > 0 {
		sig.S = new(big.Int).Sub(n, sig.S)
	}

	cd := assertion.ClientDataJSON
	typeIndex := bytes.Index(cd, []byte(`"type":"webauthn.get"`))
	challengeIndex := bytes.Index(cd, []byte(`"challenge":"`))

	to32 := func(b *big.Int) string { var p [32]byte; b.FillBytes(p[:]); return "0x" + hex.EncodeToString(p[:]) }

	out := map[string]any{
		"x":              to32(x),
		"y":              to32(y),
		"challenge":      "0x" + hex.EncodeToString(challenge[:]),
		"authData":       "0x" + hex.EncodeToString(assertion.AuthenticatorData),
		"clientDataJSON": string(cd),
		"r":              to32(sig.R),
		"s":              to32(sig.S),
		"challengeIndex": challengeIndex,
		"typeIndex":      typeIndex,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stderr, "vector ok")
}
