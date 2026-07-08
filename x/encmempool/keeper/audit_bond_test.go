package keeper_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/keeper"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// mockBank is an in-memory BankKeeper for the round-9 #1 bond tests: it tracks balances keyed by
// account bech32 / module name and moves coins between them, rejecting an under-funded escrow.
type mockBank struct{ bal map[string]sdk.Coins }

func (b *mockBank) SendCoinsFromAccountToModule(_ context.Context, from sdk.AccAddress, module string, amt sdk.Coins) error {
	if !b.bal[from.String()].IsAllGTE(amt) {
		return fmt.Errorf("insufficient funds")
	}
	b.bal[from.String()] = b.bal[from.String()].Sub(amt...)
	b.bal[module] = b.bal[module].Add(amt...)
	return nil
}

func (b *mockBank) SendCoinsFromModuleToAccount(_ context.Context, module string, to sdk.AccAddress, amt sdk.Coins) error {
	b.bal[module] = b.bal[module].Sub(amt...)
	b.bal[to.String()] = b.bal[to.String()].Add(amt...)
	return nil
}

func (b *mockBank) BurnCoins(_ context.Context, module string, amt sdk.Coins) error {
	if !b.bal[module].IsAllGTE(amt) {
		return fmt.Errorf("insufficient funds to burn")
	}
	b.bal[module] = b.bal[module].Sub(amt...) // destroyed (not credited anywhere)
	return nil
}

// round-9 #1: SubmitEncrypted ESCROWS the bond from the submitter into the module account, and the
// decrypt-time release REFUNDS it in full. An under-funded submitter is rejected with no state change.
func TestSubmitBond_EscrowedThenRefundedOnDecrypt(t *testing.T) {
	pub, shares, err := threshold.Setup(3, 2)
	require.NoError(t, err)
	bank := &mockBank{bal: map[string]sdk.Coins{}}
	k, ctx := newKeeperBank(t, 10, bank)

	p := enableParams(pub, 2, 2, []string{"kp1", "kp2", "kp3"})
	p.EncSubmitBond = 100
	p.EncSubmitBondDenom = "stake"
	require.NoError(t, k.SetParams(ctx, p))

	sub := sdk.AccAddress([]byte("submitteraddr1234567")).String()
	bank.bal[sub] = sdk.NewCoins(sdk.NewInt64Coin("stake", 1000))
	srv := keeper.NewMsgServerImpl(k)

	ct, pok, err := dkg.EncryptWithPoK(pub, []byte("anti-MEV trade"), ctx.ChainID(), sub)
	require.NoError(t, err)
	resp, err := srv.SubmitEncrypted(ctx, &types.MsgSubmitEncrypted{
		Submitter: sub, A: ct.A, Nonce: ct.Nonce, Body: ct.Body, Pok: pok.Marshal(),
	})
	require.NoError(t, err)

	// ESCROWED: submitter -100, module +100, and the EncTx records the bond.
	require.Equal(t, int64(900), bank.bal[sub].AmountOf("stake").Int64())
	require.Equal(t, int64(100), bank.bal[types.ModuleName].AmountOf("stake").Int64())
	e, ok := k.GetEncTx(ctx, resp.DecryptHeight, resp.Seq)
	require.True(t, ok)
	require.Equal(t, uint64(100), e.Bond)
	require.Equal(t, "stake", e.BondDenom)

	// post 2 of 3 shares, then decrypt at maturity -> the ciphertext is released -> bond refunded.
	for _, i := range []int{0, 2} {
		ds, derr := threshold.ComputeShare(shares[i], ct)
		require.NoError(t, derr)
		require.NoError(t, k.SetEncShare(ctx, types.EncShare{
			Keyper: []string{"kp1", "kp2", "kp3"}[i], DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: ds.Index, D: ds.D,
		}))
	}
	bctx := ctx.WithBlockHeight(int64(e.DecryptHeight)).WithEventManager(sdk.NewEventManager())
	require.NoError(t, k.BeginBlock(bctx))

	// REFUNDED in full: submitter back to 1000, module drained to 0.
	require.Equal(t, int64(1000), bank.bal[sub].AmountOf("stake").Int64(), "bond must be refunded on release")
	require.Equal(t, int64(0), bank.bal[types.ModuleName].AmountOf("stake").Int64())
}

// An under-funded submitter cannot escrow the bond -> the submission is rejected with NO state change.
func TestSubmitBond_RejectedWhenUnderfunded(t *testing.T) {
	pub := throwawayThresholdPub(t)
	bank := &mockBank{bal: map[string]sdk.Coins{}}
	k, ctx := newKeeperBank(t, 10, bank)

	p := enableParams(pub, 2, 2, []string{"kp1", "kp2"})
	p.EncSubmitBond = 100
	p.EncSubmitBondDenom = "stake"
	require.NoError(t, k.SetParams(ctx, p))

	sub := sdk.AccAddress([]byte("poorsubmitteraddr123")).String()
	bank.bal[sub] = sdk.NewCoins(sdk.NewInt64Coin("stake", 50)) // < 100 bond
	srv := keeper.NewMsgServerImpl(k)

	ct, pok, err := dkg.EncryptWithPoK(pub, []byte("no funds"), ctx.ChainID(), sub)
	require.NoError(t, err)
	_, err = srv.SubmitEncrypted(ctx, &types.MsgSubmitEncrypted{
		Submitter: sub, A: ct.A, Nonce: ct.Nonce, Body: ct.Body, Pok: pok.Marshal(),
	})
	require.Error(t, err, "an under-funded submitter must be rejected")
	require.Equal(t, uint64(0), k.GetGlobalEncCount(ctx), "no EncTx may be stored when the bond escrow fails")
	require.Equal(t, int64(50), bank.bal[sub].AmountOf("stake").Int64(), "no funds moved on a rejected submit")
}

// round-10 #1: a burn fraction makes the bond a REAL per-submit cost. With burn_bps=1000 (10%), a
// 100 bond escrows 100, then on release BURNS 10 and refunds 90 - the submitter is out 10 no matter
// how well funded, so a sybil swarm pays a real, non-refundable cost per ciphertext.
func TestSubmitBond_PartialBurnOnRelease(t *testing.T) {
	pub, shares, err := threshold.Setup(3, 2)
	require.NoError(t, err)
	bank := &mockBank{bal: map[string]sdk.Coins{}}
	k, ctx := newKeeperBank(t, 10, bank)

	p := enableParams(pub, 2, 2, []string{"kp1", "kp2", "kp3"})
	p.EncSubmitBond = 100
	p.EncSubmitBondDenom = "stake"
	p.EncSubmitBondBurnBps = 1000 // 10% burned, 90% refundable
	require.NoError(t, k.SetParams(ctx, p))

	sub := sdk.AccAddress([]byte("burnsubmitteraddr123")).String()
	bank.bal[sub] = sdk.NewCoins(sdk.NewInt64Coin("stake", 1000))
	srv := keeper.NewMsgServerImpl(k)

	ct, pok, err := dkg.EncryptWithPoK(pub, []byte("trade"), ctx.ChainID(), sub)
	require.NoError(t, err)
	resp, err := srv.SubmitEncrypted(ctx, &types.MsgSubmitEncrypted{Submitter: sub, A: ct.A, Nonce: ct.Nonce, Body: ct.Body, Pok: pok.Marshal()})
	require.NoError(t, err)
	require.Equal(t, int64(900), bank.bal[sub].AmountOf("stake").Int64(), "full 100 escrowed")
	e, ok := k.GetEncTx(ctx, resp.DecryptHeight, resp.Seq)
	require.True(t, ok)
	require.Equal(t, uint64(10), e.BondBurn, "10%% of 100 stamped as the burn")

	for _, i := range []int{0, 2} {
		ds, derr := threshold.ComputeShare(shares[i], ct)
		require.NoError(t, derr)
		require.NoError(t, k.SetEncShare(ctx, types.EncShare{
			Keyper: []string{"kp1", "kp2", "kp3"}[i], DecryptHeight: e.DecryptHeight, Seq: e.Seq, Index: ds.Index, D: ds.D,
		}))
	}
	bctx := ctx.WithBlockHeight(int64(e.DecryptHeight)).WithEventManager(sdk.NewEventManager())
	require.NoError(t, k.BeginBlock(bctx))

	// 90 refunded, 10 burned (gone), module drained -> submitter is a real 10 out of pocket.
	require.Equal(t, int64(990), bank.bal[sub].AmountOf("stake").Int64(), "90 refunded, 10 burned")
	require.Equal(t, int64(0), bank.bal[types.ModuleName].AmountOf("stake").Int64(), "module drained (refund + burn)")
}
