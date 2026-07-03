package keeper_test

// Regression tests for the x/encmempool audit (branch limonata-encmempool-audit).
// These exercise the FIXED behaviour through the real keeper / msg_server / BeginBlock
// path. Each fails against the pre-fix source and passes after the fix.
//
// Shared helpers (newKeeper, enableParams, decryptedPlaintext, hasEvent) live in
// threshold_e2e_test.go.

import (
	"context"
	"strings"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// recoverPanic runs fn and reports whether it panicked. A panic inside BeginBlock is
// a chain halt, so "did not panic" is the property under test.
func recoverPanic(fn func()) (panicked bool, msg string) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			switch e := r.(type) {
			case error:
				msg = e.Error()
			case string:
				msg = e
			default:
				msg = "non-string panic"
			}
		}
	}()
	fn()
	return
}

// TestRegression_NonceLengthNoHalt regresses the CRITICAL consensus-halt finding: a
// non-12-byte AES-256-GCM nonce made gcm.Open PANIC inside BeginBlock (an
// un-recovered panic over deterministic committed state => a uniform chain halt the
// instant governance sets EncEnabled=true). The fix (a nonce-length guard in
// threshold.Decrypt) must turn every bad-length nonce into a graceful
// encmempool_decrypt_failed with NO panic. The nonce is stored here directly so the
// BeginBlock decrypt path is exercised in isolation (the ingress guard is covered
// separately below).
func TestRegression_NonceLengthNoHalt(t *testing.T) {
	pub, shares, err := threshold.Setup(3, 2)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := threshold.Encrypt(pub, []byte("victim swap 5000 TOKEN"))
	if err != nil {
		t.Fatal(err)
	}
	keypers := []string{"kp1", "kp2", "kp3"}

	for _, nlen := range []int{0, 1, 11, 13, 16, 24} {
		k, ctx := newKeeper(t, 10)
		if err := k.SetParams(ctx, enableParams(pub, 2, 2, keypers)); err != nil {
			t.Fatal(err)
		}
		e := k.SubmitEncTx(ctx, "attacker", 10, 2, ct.A, make([]byte, nlen), ct.Body)
		for _, i := range []int{0, 2} { // honest quorum of shares (share depends only on A)
			ds, err := threshold.ComputeShare(shares[i], ct)
			if err != nil {
				t.Fatal(err)
			}
			if err := k.SetEncShare(ctx, types.EncShare{
				Keyper: keypers[i], DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: ds.Index, D: ds.D,
			}); err != nil {
				t.Fatal(err)
			}
		}
		bctx := ctx.WithBlockHeight(int64(e.DecryptHeight)).WithEventManager(sdk.NewEventManager())
		panicked, pmsg := recoverPanic(func() { _ = k.BeginBlock(bctx) })
		if panicked {
			t.Fatalf("nonce len=%d: BeginBlock PANICKED (chain halt): %q", nlen, pmsg)
		}
		if !hasEvent(bctx, "encmempool_decrypt_failed") {
			t.Fatalf("nonce len=%d: expected graceful encmempool_decrypt_failed, got none", nlen)
		}
	}
}

// TestRegression_SubmitEncryptedRejectsBadNonce is the ingress half of the halt fix:
// SubmitEncrypted must reject a non-12-byte nonce BEFORE it enters state, and still
// accept a genuine 12-byte nonce.
func TestRegression_SubmitEncryptedRejectsBadNonce(t *testing.T) {
	pub, _, err := threshold.Setup(3, 2)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := threshold.Encrypt(pub, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	k, ctx := newKeeper(t, 10)
	if err := k.SetParams(ctx, enableParams(pub, 2, 2, []string{"kp1", "kp2", "kp3"})); err != nil {
		t.Fatal(err)
	}
	srv := keeper.NewMsgServerImpl(k)
	var goCtx context.Context = ctx

	for _, nlen := range []int{0, 11, 13, 16} {
		_, err := srv.SubmitEncrypted(goCtx, &types.MsgSubmitEncrypted{
			Submitter: "a", A: ct.A, Nonce: make([]byte, nlen), Body: ct.Body,
		})
		if err == nil {
			t.Fatalf("nonce len=%d: SubmitEncrypted must reject, got nil error", nlen)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "nonce") {
			t.Fatalf("nonce len=%d: rejected but not for a nonce reason: %v", nlen, err)
		}
	}
	// control: a genuine 12-byte nonce is accepted.
	if _, err := srv.SubmitEncrypted(goCtx, &types.MsgSubmitEncrypted{
		Submitter: "a", A: ct.A, Nonce: ct.Nonce, Body: ct.Body,
	}); err != nil {
		t.Fatalf("valid 12-byte nonce must be accepted, got %v", err)
	}
}
