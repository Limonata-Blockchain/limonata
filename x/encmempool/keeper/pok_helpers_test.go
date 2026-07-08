package keeper_test

import (
	"testing"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// encWithPoK builds a real ciphertext (encrypted to pub) plus a submitter-bound proof of knowledge
// of its ephemeral key, ready to submit. SubmitEncrypted now requires the PoK (the same-A replay
// binding), so every success-path test constructs its ciphertext through this helper.
func encWithPoK(t *testing.T, pub []byte, plain, submitter string) *types.MsgSubmitEncrypted {
	t.Helper()
	ct, pok, err := dkg.EncryptWithPoK(pub, []byte(plain), submitter)
	if err != nil {
		t.Fatalf("EncryptWithPoK: %v", err)
	}
	return &types.MsgSubmitEncrypted{
		Submitter: submitter, A: ct.A, Nonce: ct.Nonce, Body: ct.Body, Pok: pok.Marshal(),
	}
}

// throwawayThresholdPub returns a valid threshold public key for tests that submit ciphertexts but
// never decrypt them (SubmitEncrypted never uses the threshold key - encryption is client-side).
func throwawayThresholdPub(t *testing.T) []byte {
	t.Helper()
	pub, _, err := threshold.Setup(1, 1)
	if err != nil {
		t.Fatalf("threshold.Setup: %v", err)
	}
	return pub
}
