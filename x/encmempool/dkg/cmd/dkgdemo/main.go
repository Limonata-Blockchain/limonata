// dkgdemo runs an END-TO-END transcript of the joint-Feldman DKG driving the
// threshold-ElGamal encrypted mempool, printing real values at each step:
//
//	1. a 5-node, threshold-3 DKG produces a master public key (no trusted dealer);
//	2. a message is encrypted to that key with the UNMODIFIED threshold.Encrypt;
//	3. 3 shares decrypt it (success); 2 shares do not (threshold holds);
//	4. a tampered partial decryption is rejected by the enforced DLEQ path;
//	5. a re-run over a CHANGED 5-node set yields an INDEPENDENT key — the old
//	   shares cannot decrypt the new ciphertext.
//
// It is a demo, not a test; run: go run ./x/encmempool/dkg/cmd/dkgdemo
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func hx(b []byte) string { return hex.EncodeToString(b) }

// decrypt runs the raw threshold path over the shares at the given positions.
func decrypt(res *dkg.Result, ct *threshold.Ciphertext, positions []int) ([]byte, error) {
	ds := make([]*threshold.DecryptShare, 0, len(positions))
	for _, p := range positions {
		d, err := threshold.ComputeShare(res.Shares[p], ct)
		if err != nil {
			return nil, err
		}
		ds = append(ds, d)
	}
	shared, err := threshold.Recover(ds)
	if err != nil {
		return nil, err
	}
	return threshold.Decrypt(shared, ct)
}

func mustDS(sh threshold.Share, ct *threshold.Ciphertext) *threshold.DecryptShare {
	d, err := threshold.ComputeShare(sh, ct)
	if err != nil {
		panic(err)
	}
	return d
}

func main() {
	line := "--------------------------------------------------------------------"

	// 1. DKG over 5 nodes, threshold 3. No trusted dealer; crypto/rand entropy.
	fmt.Println(line)
	fmt.Println("STEP 1  Distributed key generation (n=5, t=3, no trusted dealer)")
	fmt.Println(line)
	res, err := dkg.RunDKGSecure(dkg.NewParties(5, 3))
	if err != nil {
		panic(err)
	}
	fmt.Printf("  master public key  pub = %s\n", hx(res.Pub))
	fmt.Printf("  QUAL (qualified)       = %v\n", res.Qual)
	fmt.Printf("  disqualified           = %v\n", res.Disqualified)
	fmt.Printf("  #shares issued         = %d (one per QUAL keyper)\n", len(res.Shares))
	fmt.Println("  NOTE: pub was summed from Feldman commitment POINTS; the master")
	fmt.Println("        secret scalar msk was NEVER assembled anywhere.")

	// 2. Encrypt to the DKG key with the UNCHANGED threshold.Encrypt.
	fmt.Println(line)
	fmt.Println("STEP 2  Encrypt a tx body to the DKG key (drop-in threshold.Encrypt)")
	fmt.Println(line)
	msg := []byte("buy 5000 LIMO at market - searchers cannot read this until reveal")
	ct, err := threshold.Encrypt(res.Pub, msg)
	if err != nil {
		panic(err)
	}
	fmt.Printf("  plaintext              = %q\n", string(msg))
	fmt.Printf("  ciphertext.A  (r*G)    = %s\n", hx(ct.A))
	fmt.Printf("  ciphertext.Body        = %s\n", hx(ct.Body))

	// 3a. 3 shares decrypt.
	fmt.Println(line)
	fmt.Println("STEP 3  Threshold decryption")
	fmt.Println(line)
	got, err := decrypt(res, ct, []int{0, 2, 4})
	if err != nil {
		panic("t shares should decrypt: " + err.Error())
	}
	fmt.Printf("  [3 shares -> keypers %v]  DECRYPTED: %q\n",
		[]uint64{res.Shares[0].Index, res.Shares[2].Index, res.Shares[4].Index}, string(got))

	// 3b. 2 shares fail.
	if _, err := decrypt(res, ct, []int{0, 2}); err != nil {
		fmt.Printf("  [2 shares -> keypers %v]  REJECTED (as required): %v\n",
			[]uint64{res.Shares[0].Index, res.Shares[2].Index}, err)
	} else {
		panic("SECURITY FAILURE: 2 shares decrypted")
	}

	// 4. Tampered partial is rejected by the enforced DLEQ recovery path.
	fmt.Println(line)
	fmt.Println("STEP 4  Reject a tampered partial decryption (DLEQ enforced)")
	fmt.Println(line)
	mk := func(pos int) dkg.VerifiedShare {
		d, pf, err := dkg.ProveDecryptShare(res.Shares[pos], ct)
		if err != nil {
			panic(err)
		}
		return dkg.VerifiedShare{Share: d, Proof: pf}
	}
	// forge a partial for the keyper at position 1: real proof, but a corrupted D
	// computed from (x+1) instead of x.
	victim := res.Shares[1]
	wrong := new(secp256k1.ModNScalar).Set(victim.Xi)
	var one secp256k1.ModNScalar
	one.SetInt(1)
	wrong.Add(&one)
	badD, _ := threshold.ComputeShare(threshold.Share{Index: victim.Index, Xi: wrong}, ct)
	_, realProof, _ := dkg.ProveDecryptShare(victim, ct)
	Yv := dkg.SharePubKey(res.PublicCommitments, victim.Index)
	fmt.Printf("  keyper %d honest partial verifies?   %v\n", victim.Index,
		dkg.VerifyDecryptShare(ct.A, mustDS(victim, ct), Yv, realProof))
	fmt.Printf("  keyper %d TAMPERED partial verifies?  %v  (rejected -> not counted)\n",
		victim.Index, dkg.VerifyDecryptShare(ct.A, badD, Yv, realProof))
	// RecoverVerified drops the bad one and still decrypts from the honest majority.
	shared, err := dkg.RecoverVerified(res.PublicCommitments, ct.A, 3,
		[]dkg.VerifiedShare{{Share: badD, Proof: realProof}, mk(0), mk(2), mk(4)})
	if err != nil {
		panic(err)
	}
	pt, _ := threshold.Decrypt(shared, ct)
	fmt.Printf("  RecoverVerified(bad + 3 good) -> DECRYPTED: %q\n", string(pt))

	// 5. Re-run over a CHANGED set -> independent key; old shares cannot decrypt.
	fmt.Println(line)
	fmt.Println("STEP 5  Re-run DKG on a changed 5-node set (key rotation)")
	fmt.Println(line)
	res2, err := dkg.RunDKGSecure(dkg.NewParties(5, 3))
	if err != nil {
		panic(err)
	}
	fmt.Printf("  new master public key   = %s\n", hx(res2.Pub))
	fmt.Printf("  identical to old key?   = %v (independent re-genesis)\n", hx(res.Pub) == hx(res2.Pub))
	ct2, err := threshold.Encrypt(res2.Pub, []byte("post-rotation order flow"))
	if err != nil {
		panic(err)
	}
	if _, err := decrypt(res, ct2, []int{0, 2, 4}); err != nil {
		fmt.Printf("  OLD shares on NEW ciphertext -> REJECTED (as required): %v\n", err)
	} else {
		panic("SECURITY FAILURE: old shares decrypted a post-rotation ciphertext")
	}
	fmt.Println(line)
	fmt.Println("DEMO OK")
	fmt.Println(line)
}
