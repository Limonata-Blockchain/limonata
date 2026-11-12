// demogen prints the threshold material for a live-chain encrypted-mempool demo:
// the threshold public key (for genesis), a ciphertext, and two keypers' shares.
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/cosmos/evm/x/encmempool/threshold"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func main() {
	msg := []byte("buy 1000 ETH at market - DEMO on a live chain, searchers blind")
	pub, shares, err := threshold.Setup(3, 2) // 3 keypers, need 2
	if err != nil {
		panic(err)
	}
	ct, err := threshold.Encrypt(pub, msg)
	if err != nil {
		panic(err)
	}
	d1, _ := threshold.ComputeShare(shares[0], ct) // keyper index 1
	d2, _ := threshold.ComputeShare(shares[1], ct) // keyper index 2
	fmt.Printf("PUB=%s\n", b64(pub))
	fmt.Printf("A=%s\n", b64(ct.A))
	fmt.Printf("NONCE=%s\n", b64(ct.Nonce))
	fmt.Printf("BODY=%s\n", b64(ct.Body))
	fmt.Printf("D1=%s\n", b64(d1.D))
	fmt.Printf("D2=%s\n", b64(d2.D))
	fmt.Printf("MSG=%s\n", string(msg))
}
