package keeper

import (
	"bytes"
	"context"
	"testing"
	"time"

	coreaddress "cosmossdk.io/core/address"
	"cosmossdk.io/math"

	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/runtime"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	vestingtypes "github.com/cosmos/cosmos-sdk/x/auth/vesting/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/cosmos/evm/x/valgrant/types"
)

const testDenom = "aLIMO"

// ---------------------------------------------------------------------------
// mock keepers (in-memory; deterministic)
// ---------------------------------------------------------------------------

type mockAccountKeeper struct {
	codec   coreaddress.Codec
	accs    map[string]sdk.AccountI
	nextNum uint64
}

func newMockAK() *mockAccountKeeper {
	return &mockAccountKeeper{
		codec: addresscodec.NewBech32Codec(sdk.GetConfig().GetBech32AccountAddrPrefix()),
		accs:  map[string]sdk.AccountI{},
	}
}

func (m *mockAccountKeeper) NewAccount(_ context.Context, acc sdk.AccountI) sdk.AccountI {
	_ = acc.SetAccountNumber(m.nextNum)
	m.nextNum++
	return acc
}
func (m *mockAccountKeeper) GetAccount(_ context.Context, addr sdk.AccAddress) sdk.AccountI {
	return m.accs[string(addr.Bytes())]
}
func (m *mockAccountKeeper) SetAccount(_ context.Context, acc sdk.AccountI) {
	m.accs[string(acc.GetAddress().Bytes())] = acc
}
func (m *mockAccountKeeper) HasAccount(_ context.Context, addr sdk.AccAddress) bool {
	_, ok := m.accs[string(addr.Bytes())]
	return ok
}
func (m *mockAccountKeeper) GetModuleAddress(name string) sdk.AccAddress {
	return authtypes.NewModuleAddress(name)
}
func (m *mockAccountKeeper) AddressCodec() coreaddress.Codec { return m.codec }

type mockBankKeeper struct {
	bal map[string]sdk.Coins
}

func newMockBank() *mockBankKeeper { return &mockBankKeeper{bal: map[string]sdk.Coins{}} }

func (m *mockBankKeeper) add(addr sdk.AccAddress, amt sdk.Coins) {
	m.bal[string(addr.Bytes())] = m.bal[string(addr.Bytes())].Add(amt...)
}
func (m *mockBankKeeper) sub(addr sdk.AccAddress, amt sdk.Coins) error {
	cur := m.bal[string(addr.Bytes())]
	newBal, neg := cur.SafeSub(amt...)
	if neg {
		return sdkerrors.ErrInsufficientFunds.Wrapf("%s < %s", cur, amt)
	}
	m.bal[string(addr.Bytes())] = newBal
	return nil
}
func (m *mockBankKeeper) SendCoinsFromModuleToAccount(_ context.Context, module string, addr sdk.AccAddress, amt sdk.Coins) error {
	maddr := authtypes.NewModuleAddress(module)
	if err := m.sub(maddr, amt); err != nil {
		return err
	}
	m.add(addr, amt)
	return nil
}
func (m *mockBankKeeper) SendCoinsFromAccountToModule(_ context.Context, addr sdk.AccAddress, module string, amt sdk.Coins) error {
	if err := m.sub(addr, amt); err != nil {
		return err
	}
	m.add(authtypes.NewModuleAddress(module), amt)
	return nil
}
func (m *mockBankKeeper) GetBalance(_ context.Context, addr sdk.AccAddress, denom string) sdk.Coin {
	return sdk.NewCoin(denom, m.bal[string(addr.Bytes())].AmountOf(denom))
}
func (m *mockBankKeeper) GetAllBalances(_ context.Context, addr sdk.AccAddress) sdk.Coins {
	return m.bal[string(addr.Bytes())]
}
func (m *mockBankKeeper) BlockedAddr(_ sdk.AccAddress) bool { return false }
func (m *mockBankKeeper) BurnCoins(_ context.Context, module string, amt sdk.Coins) error {
	return m.sub(authtypes.NewModuleAddress(module), amt)
}

// mockDel models a single delegation with shares and tokens tracked SEPARATELY
// so a slash can be represented faithfully: a slash reduces `tokens` (the
// validator's token pool backing this delegation) while leaving `shares`
// untouched, so the tokens:shares exchange rate falls below 1. A fresh
// delegation is created at rate 1 (shares == tokens), matching x/staking's
// genesis exchange rate for the first self-delegation.
type mockDel struct {
	shares math.LegacyDec
	tokens math.Int
}

// mockUBDEntry models a single x/staking UnbondingDelegationEntry: identified by
// (creationHeight, completion) and carrying BOTH InitialBalance and Balance, tracked
// SEPARATELY exactly as x/staking does — a same-block AddEntry merge SUMS both, while a
// re-slash (SlashUnbondingDelegation) DECREMENTS only Balance (leaving the
// slash-invariant InitialBalance) — so the deferred clawback sweep's per-block capture
// reads the real re-slash-aware Balance and the real merged InitialBalance.
type mockUBDEntry struct {
	creationHeight int64
	completion     time.Time
	initialBalance math.Int
	balance        math.Int
}

type mockStakingKeeper struct {
	valCodec coreaddress.Codec
	// dels[delAddrBytes][valAddrBech32] = the (shares, tokens) delegation record.
	dels map[string]map[string]*mockDel
	// ubds[delAddrBytes][valAddrBech32] = the delegator's live unbonding entries at
	// that validator. Appended by Undelegate, mutated by reslashUBD, drained by
	// completeMaturedUBD — modelling the real UnbondingDelegation lifecycle so
	// GetUnbondingDelegation returns authentic, re-slash-aware entries.
	ubds map[string]map[string][]*mockUBDEntry
	// vals[valBech32] = a registered (existing) validator; GetValidator/Delegate
	// only succeed for these. Populated by addValidator.
	vals map[string]bool
	// hooks is the x/valgrant staking hooks (set by newFixture). The hook-firing
	// helpers below invoke it exactly as x/staking would, so the granted-share
	// ledger is exercised by the REAL reconcile code.
	hooks stakingtypes.StakingHooks
}

func newMockSK() *mockStakingKeeper {
	return &mockStakingKeeper{
		valCodec: addresscodec.NewBech32Codec(sdk.GetConfig().GetBech32ValidatorAddrPrefix()),
		dels:     map[string]map[string]*mockDel{},
		ubds:     map[string]map[string][]*mockUBDEntry{},
		vals:     map[string]bool{},
	}
}

func (m *mockStakingKeeper) addValidator(valBech string) { m.vals[valBech] = true }

// delegate creates/overwrites a delegation of `tokens` at exchange rate 1
// (shares == tokens). Tests build a merged commingled delegation by passing the
// SUM (grant + own self-bond) and then applying slash().
func (m *mockStakingKeeper) delegate(del sdk.AccAddress, valBech string, tokens math.Int) {
	k := string(del.Bytes())
	if m.dels[k] == nil {
		m.dels[k] = map[string]*mockDel{}
	}
	m.dels[k][valBech] = &mockDel{shares: math.LegacyNewDecFromInt(tokens), tokens: tokens}
}

// slash reduces a delegation's token pool to `remainingTokens`, leaving the
// share count unchanged (exactly how x/staking slashing works). Models jail /
// tombstone / double-sign / downtime slashes of any severity.
func (m *mockStakingKeeper) slash(del sdk.AccAddress, valBech string, remainingTokens math.Int) {
	if d := m.get(del, valBech); d != nil {
		d.tokens = remainingTokens
	}
}
func (m *mockStakingKeeper) get(del sdk.AccAddress, valBech string) *mockDel {
	if m.dels[string(del.Bytes())] == nil {
		return nil
	}
	return m.dels[string(del.Bytes())][valBech]
}
func (m *mockStakingKeeper) tokensOf(del sdk.AccAddress, valBech string) math.Int {
	if d := m.get(del, valBech); d != nil {
		return d.tokens
	}
	return math.ZeroInt()
}
func (m *mockStakingKeeper) sharesOf(del sdk.AccAddress, valBech string) math.LegacyDec {
	if d := m.get(del, valBech); d != nil {
		return d.shares
	}
	return math.LegacyZeroDec()
}
func (m *mockStakingKeeper) BondDenom(_ context.Context) (string, error) { return testDenom, nil }
func (m *mockStakingKeeper) ValidatorAddressCodec() coreaddress.Codec    { return m.valCodec }
func (m *mockStakingKeeper) GetDelegatorDelegations(_ context.Context, del sdk.AccAddress, _ uint16) ([]stakingtypes.Delegation, error) {
	var out []stakingtypes.Delegation
	// deterministic order: bech32 strings are sorted
	m2 := m.dels[string(del.Bytes())]
	keys := make([]string, 0, len(m2))
	for vk := range m2 {
		keys = append(keys, vk)
	}
	// simple insertion sort (avoid importing sort just for this)
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	for _, vk := range keys {
		out = append(out, stakingtypes.Delegation{
			ValidatorAddress: vk,
			Shares:           m2[vk].shares,
		})
	}
	return out, nil
}
func (m *mockStakingKeeper) ValidateUnbondAmount(_ context.Context, del sdk.AccAddress, val sdk.ValAddress, amt math.Int) (math.LegacyDec, error) {
	valBech, err := m.valCodec.BytesToString(val.Bytes())
	if err != nil {
		return math.LegacyDec{}, err
	}
	d := m.get(del, valBech)
	if d == nil || amt.GT(d.tokens) {
		return math.LegacyDec{}, sdkerrors.ErrInvalidRequest.Wrap("invalid shares amount")
	}
	if d.tokens.IsZero() {
		return math.LegacyZeroDec(), nil
	}
	// shares representing `amt` tokens at the current exchange rate:
	//   shares = amt * totalShares / totalTokens
	return d.shares.MulInt(amt).QuoInt(d.tokens), nil
}
func (m *mockStakingKeeper) Undelegate(ctx context.Context, del sdk.AccAddress, val sdk.ValAddress, shares math.LegacyDec) (time.Time, math.Int, error) {
	valBech, err := m.valCodec.BytesToString(val.Bytes())
	if err != nil {
		return time.Time{}, math.ZeroInt(), err
	}
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	completion := sdkCtx.BlockTime().Add(21 * 24 * time.Hour)
	d := m.get(del, valBech)
	if d == nil {
		return completion, math.ZeroInt(), nil
	}
	var amt math.Int
	// Cap at the delegation's shares; undelegating all shares returns all tokens.
	if shares.GTE(d.shares) {
		amt = d.tokens
		delete(m.dels[string(del.Bytes())], valBech)
	} else {
		// tokens returned for `shares` at the current exchange rate:
		//   amt = shares * totalTokens / totalShares   (truncated, like x/staking)
		amt = shares.MulInt(d.tokens).Quo(d.shares).TruncateInt()
		d.shares = d.shares.Sub(shares)
		d.tokens = d.tokens.Sub(amt)
	}
	// Record the created UnbondingDelegationEntry (as x/staking does) so the deferred
	// sweep can identify it and read its live, re-slash-aware Balance.
	if amt.IsPositive() {
		m.appendUBD(del, valBech, sdkCtx.BlockHeight(), completion, amt)
	}
	return completion, amt, nil
}
func (m *mockStakingKeeper) CompleteUnbonding(_ context.Context, _ sdk.AccAddress, _ sdk.ValAddress) (sdk.Coins, error) {
	return sdk.NewCoins(), nil
}

// --- unbonding-delegation modelling (re-slash-aware deferred sweep, HIGH-C) ---

// appendUBD models x/staking UnbondingDelegation.AddEntry: an undelegation with the
// SAME (creationHeight, completion) as an existing entry MERGES into it, SUMMING both
// InitialBalance and Balance (the same-block merge that co-locates a clawback reclaim
// with the grantee's own same-block self-undelegation); otherwise it appends a fresh
// entry with InitialBalance == Balance == balance.
func (m *mockStakingKeeper) appendUBD(del sdk.AccAddress, valBech string, height int64, completion time.Time, balance math.Int) {
	k := string(del.Bytes())
	if m.ubds[k] == nil {
		m.ubds[k] = map[string][]*mockUBDEntry{}
	}
	for _, e := range m.ubds[k][valBech] {
		if e.creationHeight == height && e.completion.Equal(completion) {
			e.initialBalance = e.initialBalance.Add(balance)
			e.balance = e.balance.Add(balance)
			return
		}
	}
	m.ubds[k][valBech] = append(m.ubds[k][valBech], &mockUBDEntry{
		creationHeight: height, completion: completion, initialBalance: balance, balance: balance,
	})
}

// GetUnbondingDelegation returns the delegator's live unbonding entries at valBech,
// mirroring x/staking (ErrNoUnbondingDelegation when none). The entries carry the
// current Balance, which reslashUBD may have decremented.
func (m *mockStakingKeeper) GetUnbondingDelegation(_ context.Context, del sdk.AccAddress, val sdk.ValAddress) (stakingtypes.UnbondingDelegation, error) {
	valBech, err := m.valCodec.BytesToString(val.Bytes())
	if err != nil {
		return stakingtypes.UnbondingDelegation{}, err
	}
	entries := m.ubds[string(del.Bytes())][valBech]
	if len(entries) == 0 {
		return stakingtypes.UnbondingDelegation{}, stakingtypes.ErrNoUnbondingDelegation
	}
	ubd := stakingtypes.UnbondingDelegation{DelegatorAddress: del.String(), ValidatorAddress: valBech}
	for _, e := range entries {
		ubd.Entries = append(ubd.Entries, stakingtypes.UnbondingDelegationEntry{
			CreationHeight: e.creationHeight,
			CompletionTime: e.completion,
			InitialBalance: e.initialBalance,
			Balance:        e.balance,
		})
	}
	return ubd, nil
}

// reslashUBD models SlashUnbondingDelegation DECREMENTING the unbonding entry's
// Balance in place during the unbonding window — evidence of an old infraction that
// surfaced after the clawback. It sets Balance to newBalance (the amount that will be
// returned at CompleteUnbonding) and LEAVES InitialBalance untouched (slash-invariant),
// exactly as x/staking does.
func (m *mockStakingKeeper) reslashUBD(del sdk.AccAddress, valBech string, newBalance math.Int) {
	for _, e := range m.ubds[string(del.Bytes())][valBech] {
		e.balance = newBalance
	}
}

// slashUBDByFactor models SlashUnbondingDelegation FAITHFULLY: for each unbonding entry
// it slashes  slashAmount = truncate(factor * InitialBalance)  and decrements Balance by
// min(slashAmount, Balance), leaving the slash-invariant InitialBalance. Because the
// slash base is the (possibly-merged) InitialBalance, the grant and grantee portions of
// a merged entry shrink by the same proportional factor — the exact on-chain behavior
// the proportional pool credit must track.
func (m *mockStakingKeeper) slashUBDByFactor(del sdk.AccAddress, valBech string, factor math.LegacyDec) {
	for _, e := range m.ubds[string(del.Bytes())][valBech] {
		slashAmount := factor.MulInt(e.initialBalance).TruncateInt()
		if slashAmount.GT(e.balance) {
			slashAmount = e.balance
		}
		e.balance = e.balance.Sub(slashAmount)
	}
}

// completeMaturedUBD models x/staking's EndBlock CompleteUnbonding: it removes every
// matured entry (completion <= now) and returns the TOTAL matured Balance (the coins
// the caller then credits to the account). A fully-slashed entry (Balance 0) returns
// 0 but is still removed.
func (m *mockStakingKeeper) completeMaturedUBD(del sdk.AccAddress, valBech string, now time.Time) math.Int {
	total := math.ZeroInt()
	entries := m.ubds[string(del.Bytes())][valBech]
	kept := entries[:0]
	for _, e := range entries {
		if !e.completion.After(now) { // matured
			total = total.Add(e.balance)
			continue
		}
		kept = append(kept, e)
	}
	m.ubds[string(del.Bytes())][valBech] = kept
	return total
}

// GetValidator succeeds only for validators registered via addValidator (models
// "the validator exists"). Used by IssueLocked's module-performed delegation.
func (m *mockStakingKeeper) GetValidator(_ context.Context, val sdk.ValAddress) (stakingtypes.Validator, error) {
	valBech, err := m.valCodec.BytesToString(val.Bytes())
	if err != nil {
		return stakingtypes.Validator{}, err
	}
	if !m.vals[valBech] {
		return stakingtypes.Validator{}, stakingtypes.ErrNoValidatorFound
	}
	return stakingtypes.Validator{OperatorAddress: valBech, Status: stakingtypes.Bonded}, nil
}

func (m *mockStakingKeeper) GetDelegation(_ context.Context, del sdk.AccAddress, val sdk.ValAddress) (stakingtypes.Delegation, error) {
	valBech, err := m.valCodec.BytesToString(val.Bytes())
	if err != nil {
		return stakingtypes.Delegation{}, err
	}
	d := m.get(del, valBech)
	if d == nil {
		return stakingtypes.Delegation{}, stakingtypes.ErrNoDelegation
	}
	return stakingtypes.Delegation{ValidatorAddress: valBech, Shares: d.shares}, nil
}

// Delegate mints shares for (del, validator): rate 1 for a fresh delegation, at
// the current exchange rate otherwise. Fires AfterDelegationModified exactly as
// x/staking does. Models the MODULE's locked delegation at issuance.
func (m *mockStakingKeeper) Delegate(ctx context.Context, del sdk.AccAddress, bondAmt math.Int, _ stakingtypes.BondStatus, validator stakingtypes.Validator, _ bool) (math.LegacyDec, error) {
	valBech := validator.GetOperator()
	k := string(del.Bytes())
	if m.dels[k] == nil {
		m.dels[k] = map[string]*mockDel{}
	}
	var newShares math.LegacyDec
	if d := m.dels[k][valBech]; d == nil {
		newShares = math.LegacyNewDecFromInt(bondAmt)
		m.dels[k][valBech] = &mockDel{shares: newShares, tokens: bondAmt}
	} else {
		newShares = d.shares.MulInt(bondAmt).QuoInt(d.tokens)
		d.shares = d.shares.Add(newShares)
		d.tokens = d.tokens.Add(bondAmt)
	}
	m.fireAfterModified(ctx, del, valBech)
	return newShares, nil
}

// --- hook-firing helpers (invoke the REAL x/valgrant granted-share reconcile) ---

func (m *mockStakingKeeper) fireAfterModified(ctx context.Context, del sdk.AccAddress, valBech string) {
	if m.hooks == nil {
		return
	}
	if valBz, err := m.valCodec.StringToBytes(valBech); err == nil {
		_ = m.hooks.AfterDelegationModified(ctx, del, sdk.ValAddress(valBz))
	}
}

func (m *mockStakingKeeper) fireBeforeRemoved(ctx context.Context, del sdk.AccAddress, valBech string) {
	if m.hooks == nil {
		return
	}
	if valBz, err := m.valCodec.StringToBytes(valBech); err == nil {
		_ = m.hooks.BeforeDelegationRemoved(ctx, del, sdk.ValAddress(valBz))
	}
}

// addDelegationHook adds `tokens` of self-bond to (del,val) (rate 1 fresh, else at
// the current rate) and fires the modify hook — models the grantee delegating
// additional OWN funds at a validator (commingle).
func (m *mockStakingKeeper) addDelegationHook(ctx context.Context, del sdk.AccAddress, valBech string, tokens math.Int) {
	k := string(del.Bytes())
	if m.dels[k] == nil {
		m.dels[k] = map[string]*mockDel{}
	}
	if d := m.dels[k][valBech]; d == nil {
		m.dels[k][valBech] = &mockDel{shares: math.LegacyNewDecFromInt(tokens), tokens: tokens}
	} else {
		newSh := d.shares.MulInt(tokens).QuoInt(d.tokens)
		d.shares = d.shares.Add(newSh)
		d.tokens = d.tokens.Add(tokens)
	}
	m.fireAfterModified(ctx, del, valBech)
}

// redelegateHook moves `shares` from (del, fromBech) to (del, toBech)
// bonded->bonded (tokens follow at the source's current rate, truncated like
// staking) and fires the source + destination hooks exactly as BeginRedelegation
// does. Returns the tokens moved.
func (m *mockStakingKeeper) redelegateHook(ctx context.Context, del sdk.AccAddress, fromBech, toBech string, shares math.LegacyDec) math.Int {
	src := m.get(del, fromBech)
	moved := shares.MulInt(src.tokens).Quo(src.shares).TruncateInt()
	src.shares = src.shares.Sub(shares)
	src.tokens = src.tokens.Sub(moved)
	if src.shares.IsZero() {
		m.fireBeforeRemoved(ctx, del, fromBech)
		delete(m.dels[string(del.Bytes())], fromBech)
	} else {
		m.fireAfterModified(ctx, del, fromBech)
	}
	k := string(del.Bytes())
	if m.dels[k] == nil {
		m.dels[k] = map[string]*mockDel{}
	}
	if d := m.dels[k][toBech]; d == nil {
		m.dels[k][toBech] = &mockDel{shares: math.LegacyNewDecFromInt(moved), tokens: moved}
	} else {
		d.shares = d.shares.Add(math.LegacyNewDecFromInt(moved))
		d.tokens = d.tokens.Add(moved)
	}
	m.fireAfterModified(ctx, del, toBech)
	return moved
}
func (m *mockStakingKeeper) PowerReduction(_ context.Context) math.Int { return math.NewInt(1_000_000) }
func (m *mockStakingKeeper) GetBondedValidatorsByPower(_ context.Context) ([]stakingtypes.Validator, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

type fixture struct {
	k          Keeper
	ctx        sdk.Context
	ak         *mockAccountKeeper
	bank       *mockBankKeeper
	sk         *mockStakingKeeper
	granteeBz  sdk.AccAddress
	granteeStr string
	valBz      sdk.ValAddress
	valStr     string
	poolAddr   sdk.AccAddress
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key := storetypes.NewKVStoreKey(types.StoreKey)
	tkey := storetypes.NewTransientStoreKey("transient_valgrant")
	testCtx := testutil.DefaultContextWithDB(t, key, tkey)

	ak := newMockAK()
	bank := newMockBank()
	sk := newMockSK()
	k := NewKeeper(runtime.NewKVStoreService(key), ak, bank, sk)
	sk.hooks = k.Hooks() // wire the granted-share reconcile so redelegate/undelegate track
	ctx := testCtx.Ctx.WithBlockHeight(100).
		WithBlockTime(time.Unix(1_700_000_000, 0)).
		WithEventManager(sdk.NewEventManager())

	granteeBz := sdk.AccAddress(bytes.Repeat([]byte{0x11}, 20))
	valBz := sdk.ValAddress(bytes.Repeat([]byte{0x22}, 20))
	granteeStr := granteeBz.String()
	valStr := valBz.String()

	return &fixture{
		k: k, ctx: ctx, ak: ak, bank: bank, sk: sk,
		granteeBz: granteeBz, granteeStr: granteeStr,
		valBz: valBz, valStr: valStr,
		poolAddr: authtypes.NewModuleAddress(types.ModuleName),
	}
}

func (f *fixture) setGrant(g types.Grant) {
	if err := f.k.SetGrant(f.ctx, g); err != nil {
		panic(err)
	}
}

func (f *fixture) govAuthority() string {
	return authtypes.NewModuleAddress(govtypes.ModuleName).String()
}

func (f *fixture) hasEvent(typ string) (sdk.Event, bool) {
	for _, e := range f.ctx.EventManager().Events() {
		if e.Type == typ {
			return e, true
		}
	}
	return sdk.Event{}, false
}

func eventAttr(e sdk.Event, key string) string {
	for _, a := range e.Attributes {
		if a.Key == key {
			return a.Value
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// Authority gating: a non-gov signer is rejected (code 4 / unauthorized) and the
// grant is left untouched. A malformed authority is rejected by ValidateBasic.
func TestClawbackGrant_AuthorityGating(t *testing.T) {
	f := newFixture(t)
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: f.valStr, Status: "active"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1000))

	srv := NewMsgServerImpl(f.k)

	// non-gov but well-formed authority -> unauthorized
	notGov := sdk.AccAddress(bytes.Repeat([]byte{0x33}, 20)).String()
	_, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: notGov, Grantee: f.granteeStr, Reason: "x"})
	if err == nil {
		t.Fatal("expected unauthorized error for non-gov authority")
	}
	// grant must be untouched
	g, _ := f.k.GetGrant(f.ctx, f.granteeStr)
	if g.Status != "active" {
		t.Fatalf("grant status changed on rejected clawback: %q", g.Status)
	}
	if !f.sk.tokensOf(f.granteeBz, f.valStr).Equal(math.NewInt(1000)) {
		t.Fatal("delegation changed on rejected clawback")
	}

	// malformed authority -> ValidateBasic rejects
	_, err = srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: "not-bech32", Grantee: f.granteeStr})
	if err == nil {
		t.Fatal("expected ValidateBasic error for malformed authority")
	}
}

// Successful clawback of a fully-bonded grant: returns the locked principal
// (deferred, since it is bonded), revokes the grant, records the pending sweep,
// and emits the loud valgrant_clawback event.
func TestClawbackGrant_SuccessBondedPrincipal(t *testing.T) {
	f := newFixture(t)
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1000))

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalPending != "1000" || resp.PrincipalReturned != "0" {
		t.Fatalf("resp principal returned/pending = %q/%q want 0/1000", resp.PrincipalReturned, resp.PrincipalPending)
	}
	// grant revoked
	g, _ := f.k.GetGrant(f.ctx, f.granteeStr)
	if g.Status != "revoked" {
		t.Fatalf("grant not revoked: %q", g.Status)
	}
	// pending clawback recorded
	var pendingSeen int
	var sweep string
	f.k.IteratePendingClawbacks(f.ctx, func(pc types.PendingClawback) {
		pendingSeen++
		sweep = pc.SweepAmount
	})
	if pendingSeen != 1 || sweep != "1000" {
		t.Fatalf("pending clawback = %d sweep=%q want 1 / 1000", pendingSeen, sweep)
	}
	// delegation fully undelegated
	if !f.sk.tokensOf(f.granteeBz, f.valStr).IsZero() {
		t.Fatalf("delegation not undelegated: %s", f.sk.tokensOf(f.granteeBz, f.valStr))
	}
	// loud event
	e, ok := f.hasEvent("valgrant_clawback")
	if !ok {
		t.Fatal("no valgrant_clawback event")
	}
	if eventAttr(e, "grantee") != f.granteeStr || eventAttr(e, "valoper") != f.valStr {
		t.Fatal("event grantee/valoper mismatch")
	}
	if eventAttr(e, "reason") != "sybil" || eventAttr(e, "principal_pending") != "1000" {
		t.Fatalf("event attrs wrong: reason=%q pending=%q", eventAttr(e, "reason"), eventAttr(e, "principal_pending"))
	}
}

// In-account (never-bonded) locked principal is swept to the foundation pool
// immediately; the grantee's gas allowance is left behind, and the PLVA is
// unlocked (converted to a BaseAccount).
func TestClawbackGrant_InAccountPrincipalSwept(t *testing.T) {
	f := newFixture(t)
	// grantee holds 1000 locked principal + 50 gas in-account, nothing bonded.
	base := authtypes.NewBaseAccountWithAddress(f.granteeBz)
	plva, err := vestingtypes.NewPermanentLockedAccount(base, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1000))))
	if err != nil {
		t.Fatal(err)
	}
	f.ak.SetAccount(f.ctx, plva)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1050))))
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "50", ValidatorOp: f.valStr, Status: "active"})

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "abandoned"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalReturned != "1000" || resp.PrincipalPending != "0" {
		t.Fatalf("resp returned/pending = %q/%q want 1000/0", resp.PrincipalReturned, resp.PrincipalPending)
	}
	// pool received the principal
	if !f.bank.GetBalance(f.ctx, f.poolAddr, testDenom).Amount.Equal(math.NewInt(1000)) {
		t.Fatalf("pool balance = %s want 1000", f.bank.GetBalance(f.ctx, f.poolAddr, testDenom).Amount)
	}
	// grantee keeps the 50 gas
	if !f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount.Equal(math.NewInt(50)) {
		t.Fatalf("grantee balance = %s want 50 (gas kept)", f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount)
	}
	// PLVA unlocked -> plain BaseAccount
	acc := f.ak.GetAccount(f.ctx, f.granteeBz)
	if _, isVesting := acc.(*vestingtypes.PermanentLockedAccount); isVesting {
		t.Fatal("account still a PermanentLockedAccount after clawback")
	}
}

// SAFETY BOUNDARY #1: a validator with NO grant (its stake is entirely its own
// self-bond) cannot be clawed back — clean rejection, no state change.
func TestClawbackGrant_NoGrantRejected(t *testing.T) {
	f := newFixture(t)
	// no grant set; the account has a self-bond of its own.
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(5000))

	srv := NewMsgServerImpl(f.k)
	_, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "x"})
	if err == nil {
		t.Fatal("expected rejection clawing back a non-granted validator")
	}
	// self-bond untouched
	if !f.sk.tokensOf(f.granteeBz, f.valStr).Equal(math.NewInt(5000)) {
		t.Fatalf("self-bond changed: %s", f.sk.tokensOf(f.granteeBz, f.valStr))
	}
}

// SAFETY BOUNDARY #2: when the grantee delegated MORE than the granted principal
// (locked principal + their own self-bond), only the granted locked principal is
// undelegated; the self-bond stays bonded and is never swept.
func TestClawbackGrant_SelfBondUntouched(t *testing.T) {
	f := newFixture(t)
	// grant = 1000 locked principal; grantee delegated 1500 (1000 grant + 500 own).
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "1500"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1500))

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	// only 1000 reclaimed (pending), NOT the 500 self-bond
	if resp.PrincipalPending != "1000" {
		t.Fatalf("pending = %q want 1000 (only granted principal)", resp.PrincipalPending)
	}
	// 500 self-bond MUST remain bonded
	if !f.sk.tokensOf(f.granteeBz, f.valStr).Equal(math.NewInt(500)) {
		t.Fatalf("self-bond not preserved: remaining bonded = %s want 500", f.sk.tokensOf(f.granteeBz, f.valStr))
	}
	// recorded sweep is exactly the granted principal
	var sweep string
	f.k.IteratePendingClawbacks(f.ctx, func(pc types.PendingClawback) { sweep = pc.SweepAmount })
	if sweep != "1000" {
		t.Fatalf("pending sweep = %q want 1000", sweep)
	}
}

// LOW-fix honesty: rewards_cancelled is 0 (no on-chain reward escrow backs it —
// rewards are liquid by design), while an on-chain escrowed deposit
// (DepositEscrowed=true) is honestly forfeited. Both grant fields are voided.
func TestClawbackGrant_RewardsCancelledAndDepositForfeited(t *testing.T) {
	f := newFixture(t)
	f.setGrant(types.Grant{
		Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: f.valStr,
		Status: "active", UnvestedRewards: "200", Deposit: "300", DepositEscrowed: true,
	})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1000))

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	// rewards_cancelled is an honest 0 (no on-chain escrow); deposit is backed
	// (DepositEscrowed=true) so it is forfeited.
	if resp.RewardsCancelled != "0" || resp.DepositForfeited != "300" {
		t.Fatalf("rewards/deposit = %q/%q want 0/300", resp.RewardsCancelled, resp.DepositForfeited)
	}
	g, _ := f.k.GetGrant(f.ctx, f.granteeStr)
	if g.UnvestedRewards != "0" || g.Deposit != "0" || g.DepositEscrowed {
		t.Fatalf("escrow fields not voided: rewards=%q deposit=%q escrowed=%v", g.UnvestedRewards, g.Deposit, g.DepositEscrowed)
	}
}

// An off-chain deposit (DepositEscrowed=false) is a documented no-op: forfeited
// amount is 0 and the event records deposit_on_chain=false.
func TestClawbackGrant_OffChainDepositNoOp(t *testing.T) {
	f := newFixture(t)
	f.setGrant(types.Grant{
		Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: f.valStr,
		Status: "active", Deposit: "300", DepositEscrowed: false,
	})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1000))

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "x"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.DepositForfeited != "0" {
		t.Fatalf("off-chain deposit forfeited = %q want 0", resp.DepositForfeited)
	}
	e, _ := f.hasEvent("valgrant_clawback")
	if eventAttr(e, "deposit_on_chain") != "false" {
		t.Fatalf("deposit_on_chain = %q want false", eventAttr(e, "deposit_on_chain"))
	}
}

// Idempotency: an already-revoked grant cannot be clawed back again.
func TestClawbackGrant_AlreadyRevokedRejected(t *testing.T) {
	f := newFixture(t)
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: f.valStr, Status: "revoked"})

	srv := NewMsgServerImpl(f.k)
	_, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "x"})
	if err == nil {
		t.Fatal("expected rejection re-clawing an already-revoked grant")
	}
}

// Determinism: two independent runs from identical state produce identical
// outputs, grant state, and event attributes.
func TestClawbackGrant_Deterministic(t *testing.T) {
	run := func() (pr, pp, rc, df, status, evReason, evTotal string) {
		f := newFixture(t)
		f.setGrant(types.Grant{
			Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: f.valStr,
			Status: "active", UnvestedRewards: "100", Deposit: "50", DepositEscrowed: true,
			GrantedShares: "1000", TrackedShares: "1500",
		})
		f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1500))
		p1, p2, r, d, _, err := f.k.ClawbackGrantGov(f.ctx, f.granteeStr, "why")
		if err != nil {
			t.Fatalf("clawback failed: %v", err)
		}
		g, _ := f.k.GetGrant(f.ctx, f.granteeStr)
		e, _ := f.hasEvent("valgrant_clawback")
		return p1.String(), p2.String(), r.String(), d.String(), g.Status, eventAttr(e, "reason"), eventAttr(e, "principal_total")
	}
	a := [7]string{}
	b := [7]string{}
	a[0], a[1], a[2], a[3], a[4], a[5], a[6] = run()
	b[0], b[1], b[2], b[3], b[4], b[5], b[6] = run()
	if a != b {
		t.Fatalf("nondeterministic clawback:\n a=%v\n b=%v", a, b)
	}
}

// ---------------------------------------------------------------------------
// HIGH-1 scoped-reclaim regression tests (audit fixes)
// ---------------------------------------------------------------------------

// HIGH-1 (self-bond at a DIFFERENT validator that sorts EARLIER): the grant is
// delegated to grant.ValidatorOp (V2) and the grantee self-bonds their OWN funds
// to a different validator V1 that iterates FIRST. Only V1... i.e. only the
// GRANTED delegation at V2 may be touched; the earlier-sorting self-bond at V1 is
// left fully bonded. (Old code drained V1 first — the core self-bond seizure.)
func TestClawbackGrant_OnlyGrantedValidatorTouched(t *testing.T) {
	f := newFixture(t)
	vSelf := valoper(0x55)  // OWN self-bond validator, sorts FIRST (bech32)
	vGrant := valoper(0x22) // grant-funded validator (grant.ValidatorOp), sorts LAST
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: vGrant, Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	f.sk.delegate(f.granteeBz, vGrant, math.NewInt(1000)) // granted principal
	f.sk.delegate(f.granteeBz, vSelf, math.NewInt(500))   // OWN self-bond, earlier sort

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	// self-bond at the OTHER validator is fully preserved
	if !f.sk.tokensOf(f.granteeBz, vSelf).Equal(math.NewInt(500)) {
		t.Fatalf("self-bond at unrelated validator seized: %s want 500", f.sk.tokensOf(f.granteeBz, vSelf))
	}
	// the granted delegation is fully reclaimed
	if !f.sk.tokensOf(f.granteeBz, vGrant).IsZero() {
		t.Fatalf("granted delegation not reclaimed: %s want 0", f.sk.tokensOf(f.granteeBz, vGrant))
	}
	if resp.PrincipalPending != "1000" {
		t.Fatalf("pending = %q want 1000", resp.PrincipalPending)
	}
	// the ONLY pending entry is the granted validator
	var entries []types.PendingClawbackEntry
	f.k.IteratePendingClawbacks(f.ctx, func(pc types.PendingClawback) { entries = pc.Entries })
	if len(entries) != 1 || entries[0].Validator != vGrant {
		t.Fatalf("pending entries = %+v want single entry for %s", entries, vGrant)
	}
}

// HIGH-1 + HIGH-2 (SLASHED granted delegation): the granted delegation was
// slashed below nominal (1000 -> 400 recoverable), the grantee holds an unrelated
// self-bond and liquid gas/own funds. Reclaim is capped at the recoverable 400
// (UNDER-reclaim); the self-bond and ALL liquid funds are untouched — no spill to
// cover the slash shortfall. (Old code filled the full 1000 from other sources.)
func TestClawbackGrant_SlashedGrantedDelegationUnderReclaims(t *testing.T) {
	f := newFixture(t)
	vSelf := valoper(0x55)
	vGrant := valoper(0x22)
	// GrantedShares=1000 (nominal grant shares); the live delegation is slashed to
	// 400 tokens, so min(1000, del.Shares=400) reclaims the recoverable 400 only.
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "50", ValidatorOp: vGrant, Status: "active", GrantedShares: "1000", TrackedShares: "400"})
	f.sk.delegate(f.granteeBz, vGrant, math.NewInt(400)) // granted principal, SLASHED to 400
	f.sk.delegate(f.granteeBz, vSelf, math.NewInt(700))  // OWN self-bond
	// plain BaseAccount + liquid gas(50) + own(500) = 550 spendable
	base := authtypes.NewBaseAccountWithAddress(f.granteeBz)
	f.ak.SetAccount(f.ctx, base)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(550))))

	liquidBefore := f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount
	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "abandoned-slashed"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	// reclaim is capped at the 400 recoverable at the granted validator
	if resp.PrincipalPending != "400" || resp.PrincipalReturned != "0" {
		t.Fatalf("returned/pending = %q/%q want 0/400 (under-reclaim)", resp.PrincipalReturned, resp.PrincipalPending)
	}
	if !f.sk.tokensOf(f.granteeBz, vGrant).IsZero() {
		t.Fatalf("granted delegation not fully taken: %s", f.sk.tokensOf(f.granteeBz, vGrant))
	}
	// self-bond preserved
	if !f.sk.tokensOf(f.granteeBz, vSelf).Equal(math.NewInt(700)) {
		t.Fatalf("self-bond seized under slash: %s want 700", f.sk.tokensOf(f.granteeBz, vSelf))
	}
	// liquid gas + own funds UNTOUCHED (no shortfall spill)
	liquidAfter := f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount
	if !liquidAfter.Equal(liquidBefore) {
		t.Fatalf("liquid funds seized: before=%s after=%s (must be untouched)", liquidBefore, liquidAfter)
	}
}

// HIGH-1 (granted delegation REDELEGATED AWAY / gone): grant.ValidatorOp has no
// delegation (the grantee moved it to a different validator). Reclaim from staking
// is 0 — NEVER substituted from the delegation that now exists elsewhere or from
// liquid funds. The grant is still revoked, no pending sweep is recorded, and the
// event reports 0 principal.
func TestClawbackGrant_RedelegatedAwayReclaimsZero(t *testing.T) {
	f := newFixture(t)
	vGrant := valoper(0x22) // grant.ValidatorOp — but NO delegation here anymore
	vOther := valoper(0x55) // where the grantee redelegated to
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: vGrant, Status: "active"})
	f.sk.delegate(f.granteeBz, vOther, math.NewInt(1000)) // moved away from vGrant
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(300))))

	liquidBefore := f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount
	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalReturned != "0" || resp.PrincipalPending != "0" {
		t.Fatalf("returned/pending = %q/%q want 0/0 (no substitution)", resp.PrincipalReturned, resp.PrincipalPending)
	}
	// the delegation that DOES exist elsewhere is NOT touched
	if !f.sk.tokensOf(f.granteeBz, vOther).Equal(math.NewInt(1000)) {
		t.Fatalf("unrelated delegation substituted: %s want 1000", f.sk.tokensOf(f.granteeBz, vOther))
	}
	// liquid untouched
	if !f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount.Equal(liquidBefore) {
		t.Fatalf("liquid substituted: %s want %s", f.bank.GetBalance(f.ctx, f.granteeBz, testDenom).Amount, liquidBefore)
	}
	// grant revoked, no pending sweep recorded
	g, _ := f.k.GetGrant(f.ctx, f.granteeStr)
	if g.Status != "revoked" {
		t.Fatalf("grant not revoked: %q", g.Status)
	}
	var pendingSeen int
	f.k.IteratePendingClawbacks(f.ctx, func(pc types.PendingClawback) { pendingSeen++ })
	if pendingSeen != 0 {
		t.Fatalf("pending clawback recorded for a zero reclaim: %d", pendingSeen)
	}
	e, _ := f.hasEvent("valgrant_clawback")
	if eventAttr(e, "principal_total") != "0" {
		t.Fatalf("event principal_total = %q want 0", eventAttr(e, "principal_total"))
	}
}

// MED (PLVA): when the granted delegation is redelegated away (reclaim 0) and the
// grantee still holds a PLVA, the permanent lock is LEFT INTACT — we do not
// blanket-unlock it to a BaseAccount on a no-reclaim clawback.
func TestClawbackGrant_PLVALockKeptWhenNothingReclaimed(t *testing.T) {
	f := newFixture(t)
	vGrant := valoper(0x22)
	vOther := valoper(0x55)
	base := authtypes.NewBaseAccountWithAddress(f.granteeBz)
	// PLVA models a grant whose principal was delegated then redelegated to vOther;
	// nothing is recoverable at vGrant and nothing is locked in-account.
	plva, err := vestingtypes.NewPermanentLockedAccount(base, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1000))))
	if err != nil {
		t.Fatal(err)
	}
	// mark the full principal as delegated so LockedCoins (in-account) == 0
	plva.DelegatedVesting = sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(1000)))
	f.ak.SetAccount(f.ctx, plva)
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: vGrant, Status: "active"})
	f.sk.delegate(f.granteeBz, vOther, math.NewInt(1000))

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalReturned != "0" || resp.PrincipalPending != "0" {
		t.Fatalf("returned/pending = %q/%q want 0/0", resp.PrincipalReturned, resp.PrincipalPending)
	}
	// PLVA lock left intact (still a PermanentLockedAccount)
	acc := f.ak.GetAccount(f.ctx, f.granteeBz)
	if _, isVesting := acc.(*vestingtypes.PermanentLockedAccount); !isVesting {
		t.Fatal("PLVA was blanket-unlocked on a zero-reclaim clawback")
	}
}

// ---------------------------------------------------------------------------
// HIGH-2 locked-share reclaim tests (commingled self-bond safety, DelegatedVesting)
// ---------------------------------------------------------------------------

// DV path, PURE slashed grant (no self-bond): PLVA with DelegatedVesting=1000, all
// bonded, delegation slashed 1000->400. The locked shares == the whole delegation,
// so the reclaim takes its fair slashed value (400) — an honest UNDER-reclaim of
// the 1000 nominal, never dipping into other funds.
func TestClawbackGrant_PLVA_SlashedSingleGrant_FairValue(t *testing.T) {
	f := newFixture(t)
	makeGrantPLVA(t, f, 1000, 1000)
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "1000"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1000))
	f.sk.slash(f.granteeBz, f.valStr, math.NewInt(400)) // 60% slash, no self-bond

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "abandoned-slashed"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalPending != "400" || resp.PrincipalReturned != "0" {
		t.Fatalf("returned/pending = %q/%q want 0/400 (fair slashed value)", resp.PrincipalReturned, resp.PrincipalPending)
	}
	if !f.sk.tokensOf(f.granteeBz, f.valStr).IsZero() {
		t.Fatalf("granted delegation not fully taken: %s", f.sk.tokensOf(f.granteeBz, f.valStr))
	}
}

// DV path, TOMBSTONE (near-total slash) with commingled self-bond: merged 2000
// shares slashed 99% -> 20 tokens. Reclaim only the 1000 locked shares (fair value
// 10); the 1000 own self-bond shares (10 tokens) survive; no error/halt.
func TestClawbackGrant_PLVA_TombstonedValidator_LockedOnly(t *testing.T) {
	f := newFixture(t)
	makeGrantPLVA(t, f, 1000, 1000)
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "2000"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(2000)) // 1000 grant + 1000 own
	f.sk.slash(f.granteeBz, f.valStr, math.NewInt(20))      // tombstone-grade 99% slash

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "double-sign-tombstone"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	reclaimed := math.LegacyMustNewDecFromStr(resp.PrincipalPending).TruncateInt()
	if !reclaimed.Equal(math.NewInt(10)) {
		t.Fatalf("reclaimed=%s want 10 (fair value of 1000 locked shares at 1%% survival)", reclaimed)
	}
	if !f.sk.tokensOf(f.granteeBz, f.valStr).Equal(math.NewInt(10)) {
		t.Fatalf("self-bond seized under tombstone: remaining=%s want 10", f.sk.tokensOf(f.granteeBz, f.valStr))
	}
	if !f.sk.sharesOf(f.granteeBz, f.valStr).Equal(math.LegacyNewDec(1000)) {
		t.Fatalf("self-bond shares changed: %s want 1000", f.sk.sharesOf(f.granteeBz, f.valStr))
	}
}

// DV path, commingled self-bond with NO slash: PLVA DelegatedVesting=1000, merged
// delegation 1500 (1000 grant + 500 own). Reclaim EXACTLY the 1000 locked; the 500
// own stays. Proves the split is driven by DelegatedVesting, not the delegation size.
func TestClawbackGrant_PLVA_CommingledNoSlash_LockedOnly(t *testing.T) {
	f := newFixture(t)
	makeGrantPLVA(t, f, 1000, 1000)
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: f.valStr, Status: "active", GrantedShares: "1000", TrackedShares: "1500"})
	f.sk.delegate(f.granteeBz, f.valStr, math.NewInt(1500)) // 1000 grant + 500 own

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalPending != "1000" {
		t.Fatalf("pending=%q want 1000 (locked only)", resp.PrincipalPending)
	}
	if !f.sk.tokensOf(f.granteeBz, f.valStr).Equal(math.NewInt(500)) {
		t.Fatalf("self-bond not preserved: remaining=%s want 500", f.sk.tokensOf(f.granteeBz, f.valStr))
	}
}

// DV path, granted delegation REDELEGATED AWAY: PLVA still reports DelegatedVesting
// (redelegation does not touch it), but grant.ValidatorOp holds NO delegation.
// Reclaim from staking is 0 — never chased to the destination validator, never
// substituted from other funds; the PLVA lock is kept intact (nothing swept).
func TestClawbackGrant_PLVA_RedelegatedAwayReclaimsZero(t *testing.T) {
	f := newFixture(t)
	vGrant := valoper(0x22)
	vOther := valoper(0x55)
	makeGrantPLVA(t, f, 1000, 1000) // DelegatedVesting=1000, in-account locked 0
	f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "0", ValidatorOp: vGrant, Status: "active"})
	f.sk.delegate(f.granteeBz, vOther, math.NewInt(1000)) // grant redelegated to vOther

	srv := NewMsgServerImpl(f.k)
	resp, err := srv.ClawbackGrant(f.ctx, &types.MsgClawbackGrant{Authority: f.govAuthority(), Grantee: f.granteeStr, Reason: "sybil"})
	if err != nil {
		t.Fatalf("clawback failed: %v", err)
	}
	if resp.PrincipalReturned != "0" || resp.PrincipalPending != "0" {
		t.Fatalf("returned/pending = %q/%q want 0/0 (no substitution)", resp.PrincipalReturned, resp.PrincipalPending)
	}
	if !f.sk.tokensOf(f.granteeBz, vOther).Equal(math.NewInt(1000)) {
		t.Fatalf("destination delegation touched: %s want 1000", f.sk.tokensOf(f.granteeBz, vOther))
	}
	acc := f.ak.GetAccount(f.ctx, f.granteeBz)
	if _, isVesting := acc.(*vestingtypes.PermanentLockedAccount); !isVesting {
		t.Fatal("PLVA blanket-unlocked on a zero-reclaim clawback")
	}
}

// Determinism of the scoped reclaim under the hard combo: slashed granted
// delegation + earlier-sorting self-bond + liquid funds. Two runs from identical
// state produce identical outputs, grant state, and event attributes.
func TestClawbackGrant_ScopedReclaimDeterministic(t *testing.T) {
	run := func() (pr, pp, status, evTotal, selfBond string) {
		f := newFixture(t)
		vSelf := valoper(0x55)
		vGrant := valoper(0x22)
		f.setGrant(types.Grant{Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "50", ValidatorOp: vGrant, Status: "active", GrantedShares: "1000", TrackedShares: "400"})
		f.sk.delegate(f.granteeBz, vGrant, math.NewInt(400))
		f.sk.delegate(f.granteeBz, vSelf, math.NewInt(700))
		base := authtypes.NewBaseAccountWithAddress(f.granteeBz)
		f.ak.SetAccount(f.ctx, base)
		f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(testDenom, math.NewInt(550))))
		p1, p2, _, _, _, err := f.k.ClawbackGrantGov(f.ctx, f.granteeStr, "why")
		if err != nil {
			t.Fatalf("clawback failed: %v", err)
		}
		g, _ := f.k.GetGrant(f.ctx, f.granteeStr)
		e, _ := f.hasEvent("valgrant_clawback")
		return p1.String(), p2.String(), g.Status, eventAttr(e, "principal_total"), f.sk.tokensOf(f.granteeBz, vSelf).String()
	}
	var a, b [5]string
	a[0], a[1], a[2], a[3], a[4] = run()
	b[0], b[1], b[2], b[3], b[4] = run()
	if a != b {
		t.Fatalf("nondeterministic scoped reclaim:\n a=%v\n b=%v", a, b)
	}
}
