package dkg

import (
	"crypto/sha256"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// ============================================================================
// Enc-key PROOF-OF-POSSESSION (HIGH-2 / HIGH-4).
//
// The transparent DKG binds a secp256k1 ECIES enc key to a validator OPERATOR. Without
// a proof-of-possession any node could announce ANOTHER validator's PUBLIC enc key (it
// is observable from vote extensions) as its own, colliding two operators onto one key
// and knocking the honest owner out of threshold decryption. The PoP is an ECDSA
// signature, by the enc PRIVATE key, over the announcing operator's identity:
//
//	PoP = ECDSA_sign( encPriv, sha256( DOMAIN || operator ) )
//
// Binding to the operator is what makes the PoP NON-REPLAYABLE across operators: an
// attacker that copies a victim's (key, PoP) into its OWN (CometBFT-signed) vote
// extension is rejected, because the consume path verifies the PoP against the operator
// it resolved from the attacker's OWN consensus address — a different message than the
// one the victim signed. A self-referential PoP (over the key alone) would be replayable
// and is therefore NOT used.
//
// Verification is deterministic (an ECDSA verify over committed inputs) and panic-safe
// (malformed key/signature -> a parse error -> reject), so it is safe to run inside the
// consensus consume path. It introduces no new cryptography — it reuses the same
// secp256k1 curve the enc keys already live on.
// ============================================================================

// encKeyPoPDomain domain-separates the enc-key proof-of-possession from every other
// signature the module might ever produce over a secp256k1 key.
var encKeyPoPDomain = []byte("LIMO-DKG-ENCKEY-POP\x00")

// popDigest is the 32-byte message an enc-key PoP signs/verifies: a domain-separated
// hash of the operator address the key is being bound to.
func popDigest(operator string) []byte {
	h := sha256.New()
	h.Write(encKeyPoPDomain)
	h.Write([]byte(operator))
	return h.Sum(nil)
}

// SignEncKeyPoP produces a proof-of-possession for an enc key bound to `operator`,
// signed by the enc PRIVATE key. It is used NODE-LOCALLY (in ExtendVote) and by tests;
// it never runs in the consensus consume path. The returned bytes are a DER-encoded
// ECDSA signature carried in the vote extension.
func SignEncKeyPoP(encPriv *secp256k1.ModNScalar, operator string) []byte {
	if encPriv == nil || operator == "" {
		return nil
	}
	priv := secp256k1.NewPrivateKey(encPriv)
	sig := ecdsa.Sign(priv, popDigest(operator))
	return sig.Serialize()
}

// VerifyEncKeyPoP checks that `pop` is a valid proof-of-possession for the compressed
// enc pubkey `encPub`, bound to `operator`. It returns false (never panics) on any
// malformed input, so it is safe to call in the deterministic on-chain consume path.
func VerifyEncKeyPoP(encPub []byte, operator string, pop []byte) bool {
	if operator == "" || len(pop) == 0 || !ValidCompressedPoint(encPub) {
		return false
	}
	pub, err := secp256k1.ParsePubKey(encPub)
	if err != nil {
		return false
	}
	sig, err := ecdsa.ParseDERSignature(pop)
	if err != nil {
		return false
	}
	return sig.Verify(popDigest(operator), pub)
}
