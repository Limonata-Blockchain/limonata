package keeper

import (
	"context"
	"fmt"
	"testing"

	corestore "cosmossdk.io/core/store"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/sponsorpool/types"
)

const poolMod = "paymaster_gas_pool"

// --- in-memory store (Get/Set/Delete only; iterators unused by the keeper) ---

type memStore struct{ m map[string][]byte }

func (s *memStore) Get(k []byte) ([]byte, error) {
	v, ok := s.m[string(k)]
	if !ok {
		return nil, nil
	}
	return v, nil
}
func (s *memStore) Has(k []byte) (bool, error)                              { _, ok := s.m[string(k)]; return ok, nil }
func (s *memStore) Set(k, v []byte) error                                   { s.m[string(k)] = append([]byte{}, v...); return nil }
func (s *memStore) Delete(k []byte) error                                   { delete(s.m, string(k)); return nil }
func (s *memStore) Iterator(a, b []byte) (corestore.Iterator, error)        { return nil, nil }
func (s *memStore) ReverseIterator(a, b []byte) (corestore.Iterator, error) { return nil, nil }

type memSvc struct{ s *memStore }

func (v memSvc) OpenKVStore(ctx context.Context) corestore.KVStore { return v.s }

// --- mock bank tracking module + account aLIMO balances ---

type mockBank struct {
	mod map[string]math.Int
	acc map[string]math.Int
}

func amtOf(c sdk.Coins) math.Int { return c.AmountOf(types.FeeDenom) }
func bget(m map[string]math.Int, k string) math.Int {
	if v, ok := m[k]; ok {
		return v
	}
	return math.ZeroInt()
}
func (b *mockBank) SendCoinsFromAccountToModule(ctx context.Context, s sdk.AccAddress, mod string, c sdk.Coins) error {
	a := amtOf(c)
	if bget(b.acc, s.String()).LT(a) {
		return fmt.Errorf("insufficient account funds")
	}
	b.acc[s.String()] = bget(b.acc, s.String()).Sub(a)
	b.mod[mod] = bget(b.mod, mod).Add(a)
	return nil
}
func (b *mockBank) SendCoinsFromModuleToAccount(ctx context.Context, mod string, r sdk.AccAddress, c sdk.Coins) error {
	a := amtOf(c)
	if bget(b.mod, mod).LT(a) {
		return fmt.Errorf("insufficient module funds")
	}
	b.mod[mod] = bget(b.mod, mod).Sub(a)
	b.acc[r.String()] = bget(b.acc, r.String()).Add(a)
	return nil
}

func L(n int64) math.Int { return math.NewInt(n).Mul(math.NewInt(1_000_000_000_000_000_000)) } // n LIMO -> aLIMO

func TestSponsorpoolEscrow(t *testing.T) {
	ctx := context.Background()
	bank := &mockBank{mod: map[string]math.Int{}, acc: map[string]math.Int{}}
	A := sdk.AccAddress([]byte("aaaaaaaaaaaaaaaaaaaa"))
	B := sdk.AccAddress([]byte("bbbbbbbbbbbbbbbbbbbb"))
	bank.acc[A.String()] = L(100)
	bank.acc[B.String()] = L(100)
	X := "0x1111111111111111111111111111111111111111"
	Y := "0x2222222222222222222222222222222222222222"

	k := NewKeeper(memSvc{&memStore{m: map[string][]byte{}}}, bank, poolMod)
	if err := k.SetParams(ctx, types.DefaultParams()); err != nil { // per-tx cap 1000 LIMO
		t.Fatal(err)
	}

	eq := func(got, want math.Int, msg string) {
		t.Helper()
		if !got.Equal(want) {
			t.Fatalf("%s: got %s want %s", msg, got, want)
		}
	}

	// deposits from two sponsors to the same contract -> go into the gas pool
	if err := k.Deposit(ctx, A, X, L(5)); err != nil {
		t.Fatal(err)
	}
	if err := k.Deposit(ctx, B, X, L(3)); err != nil {
		t.Fatal(err)
	}
	eq(k.EscrowOf(ctx, X), L(8), "escrow after deposits")
	eq(k.ContributionOf(ctx, A, X), L(5), "A contribution")
	eq(k.ContributionOf(ctx, B, X), L(3), "B contribution")
	eq(bget(bank.mod, poolMod), L(8), "deposits landed in the gas pool")
	eq(bget(bank.acc, A.String()), L(95), "A debited")

	// reserve 2 LIMO for a tx hitting X: decrements escrow only (the pool pays via x/vm)
	if !k.Reserve(ctx, X, L(2)) {
		t.Fatal("Reserve should succeed (funded, under cap)")
	}
	eq(k.EscrowOf(ctx, X), L(6), "escrow after reserve")
	eq(bget(bank.mod, poolMod), L(8), "Reserve must NOT move coins (pool pays separately)")

	// decline: over per-tx cap, and unfunded contract
	if k.Reserve(ctx, X, L(1001)) {
		t.Fatal("Reserve over per-tx cap must decline")
	}
	if k.Reserve(ctx, Y, L(1)) {
		t.Fatal("Reserve with no escrow must decline")
	}
	eq(k.EscrowOf(ctx, X), L(6), "escrow unchanged after declines")

	// A withdraws its full 5 (escrow 6 >= 5), from the pool
	if err := k.Withdraw(ctx, A, X, L(5)); err != nil {
		t.Fatal(err)
	}
	eq(k.EscrowOf(ctx, X), L(1), "escrow after A withdraw")
	eq(k.ContributionOf(ctx, A, X), math.ZeroInt(), "A contribution drained")
	eq(bget(bank.acc, A.String()), L(100), "A made whole")
	eq(bget(bank.mod, poolMod), L(3), "pool reduced by A withdrawal")

	// B limited to remaining escrow (1), not its full 3 (the reserved 2 left the shared pool)
	if err := k.Withdraw(ctx, B, X, L(3)); err == nil {
		t.Fatal("withdraw beyond remaining escrow must fail")
	}
	if err := k.Withdraw(ctx, B, X, L(1)); err != nil {
		t.Fatal(err)
	}
	eq(k.EscrowOf(ctx, X), math.ZeroInt(), "escrow empty")

	// over-contribution guard
	if err := k.Withdraw(ctx, A, X, L(1)); err == nil {
		t.Fatal("withdraw beyond contribution must fail")
	}
}
