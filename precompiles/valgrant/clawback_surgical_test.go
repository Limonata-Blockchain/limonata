package valgrant

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"

	coreaddress "cosmossdk.io/core/address"
	"cosmossdk.io/math"

	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/runtime"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	valgrantkeeper "github.com/cosmos/evm/x/valgrant/keeper"
	valgranttypes "github.com/cosmos/evm/x/valgrant/types"
)

// ===========================================================================
// HIGH-D — the EVM precompile clawback(address) is the SECOND non-governance
// clawback surface (it routes through the same msgServer.Clawback as the
// admin-gated MsgClawback). These probes drive the precompile handler itself —
// ABI method + vm.Contract caller + stateDB — end-to-end into the keeper, and
// assert the cycle-7 surgical guarantee at the ABI boundary:
//
//   - ONLY the locked grant shares at grant.ValidatorOp are force-undelegated;
//     the grantee's own self-bond at ANY other validator is never touched, and
//     at maturity the pool receives EXACTLY the locked principal while the
//     grantee's gas / own stake stay byte-exact (the retired blunt k.Clawback
//     force-undelegated everything and — uncapped — swept it all to the pool).
//   - Admin gating (Params.admin) is enforced for the EVM caller's derived
//     cosmos address; non-admin callers are rejected with no state change.
//   - Contract callers (non-EOA, non-EIP-7702) are rejected, closing the
//     precompile reentrancy/wrapper surface.
//
// The deeper sweep mechanics (merge + re-slash proration, PLVA bucketing,
// SweepAmount cap) are proven by the keeper-level probes in
// x/valgrant/keeper/audit_nongov_clawback_probe_test.go; this file proves the
// precompile surface reaches the SAME surgical path.
// ===========================================================================

const pTestDenom = "aLIMO"

// --- lean deterministic mocks (subset of the keeper test fixture) ---

type pMockAccountKeeper struct {
	codec   coreaddress.Codec
	accs    map[string]sdk.AccountI
	nextNum uint64
}

func (m *pMockAccountKeeper) NewAccount(_ context.Context, acc sdk.AccountI) sdk.AccountI {
	_ = acc.SetAccountNumber(m.nextNum)
	m.nextNum++
	return acc
}
func (m *pMockAccountKeeper) GetAccount(_ context.Context, addr sdk.AccAddress) sdk.AccountI {
	return m.accs[string(addr.Bytes())]
}
func (m *pMockAccountKeeper) SetAccount(_ context.Context, acc sdk.AccountI) {
	m.accs[string(acc.GetAddress().Bytes())] = acc
}
func (m *pMockAccountKeeper) HasAccount(_ context.Context, addr sdk.AccAddress) bool {
	_, ok := m.accs[string(addr.Bytes())]
	return ok
}
func (m *pMockAccountKeeper) GetModuleAddress(name string) sdk.AccAddress {
	return authtypes.NewModuleAddress(name)
}
func (m *pMockAccountKeeper) AddressCodec() coreaddress.Codec { return m.codec }

type pMockBankKeeper struct{ bal map[string]sdk.Coins }

func (m *pMockBankKeeper) add(addr sdk.AccAddress, amt sdk.Coins) {
	m.bal[string(addr.Bytes())] = m.bal[string(addr.Bytes())].Add(amt...)
}
func (m *pMockBankKeeper) sub(addr sdk.AccAddress, amt sdk.Coins) error {
	nb, neg := m.bal[string(addr.Bytes())].SafeSub(amt...)
	if neg {
		return sdkerrors.ErrInsufficientFunds
	}
	m.bal[string(addr.Bytes())] = nb
	return nil
}
func (m *pMockBankKeeper) SendCoinsFromModuleToAccount(_ context.Context, module string, addr sdk.AccAddress, amt sdk.Coins) error {
	if err := m.sub(authtypes.NewModuleAddress(module), amt); err != nil {
		return err
	}
	m.add(addr, amt)
	return nil
}
func (m *pMockBankKeeper) SendCoinsFromAccountToModule(_ context.Context, addr sdk.AccAddress, module string, amt sdk.Coins) error {
	if err := m.sub(addr, amt); err != nil {
		return err
	}
	m.add(authtypes.NewModuleAddress(module), amt)
	return nil
}
func (m *pMockBankKeeper) GetBalance(_ context.Context, addr sdk.AccAddress, denom string) sdk.Coin {
	return sdk.NewCoin(denom, m.bal[string(addr.Bytes())].AmountOf(denom))
}
func (m *pMockBankKeeper) GetAllBalances(_ context.Context, addr sdk.AccAddress) sdk.Coins {
	return m.bal[string(addr.Bytes())]
}
func (m *pMockBankKeeper) BlockedAddr(_ sdk.AccAddress) bool { return false }
func (m *pMockBankKeeper) BurnCoins(_ context.Context, module string, amt sdk.Coins) error {
	return m.sub(authtypes.NewModuleAddress(module), amt)
}

// pMockDel / pMockUBD: minimal staking model — delegations at exchange rate 1,
// Undelegate records a real UnbondingDelegationEntry (Initial == Balance), no
// merge/slash modelling here (proven at the keeper layer).
type pMockDel struct {
	shares math.LegacyDec
	tokens math.Int
}
type pMockUBD struct {
	height     int64
	completion time.Time
	initial    math.Int
	balance    math.Int
}

type pMockStakingKeeper struct {
	valCodec coreaddress.Codec
	dels     map[string]map[string]*pMockDel
	ubds     map[string]map[string][]*pMockUBD
}

func (m *pMockStakingKeeper) delegate(del sdk.AccAddress, valBech string, tokens math.Int) {
	k := string(del.Bytes())
	if m.dels[k] == nil {
		m.dels[k] = map[string]*pMockDel{}
	}
	m.dels[k][valBech] = &pMockDel{shares: math.LegacyNewDecFromInt(tokens), tokens: tokens}
}
func (m *pMockStakingKeeper) tokensOf(del sdk.AccAddress, valBech string) math.Int {
	if d := m.dels[string(del.Bytes())][valBech]; d != nil {
		return d.tokens
	}
	return math.ZeroInt()
}
func (m *pMockStakingKeeper) BondDenom(_ context.Context) (string, error) { return pTestDenom, nil }
func (m *pMockStakingKeeper) ValidatorAddressCodec() coreaddress.Codec    { return m.valCodec }
func (m *pMockStakingKeeper) GetDelegatorDelegations(_ context.Context, del sdk.AccAddress, _ uint16) ([]stakingtypes.Delegation, error) {
	var out []stakingtypes.Delegation
	m2 := m.dels[string(del.Bytes())]
	keys := make([]string, 0, len(m2))
	for vk := range m2 {
		keys = append(keys, vk)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	for _, vk := range keys {
		out = append(out, stakingtypes.Delegation{ValidatorAddress: vk, Shares: m2[vk].shares})
	}
	return out, nil
}
func (m *pMockStakingKeeper) Undelegate(ctx context.Context, del sdk.AccAddress, val sdk.ValAddress, shares math.LegacyDec) (time.Time, math.Int, error) {
	valBech, err := m.valCodec.BytesToString(val.Bytes())
	if err != nil {
		return time.Time{}, math.ZeroInt(), err
	}
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	completion := sdkCtx.BlockTime().Add(21 * 24 * time.Hour)
	d := m.dels[string(del.Bytes())][valBech]
	if d == nil {
		return completion, math.ZeroInt(), nil
	}
	var amt math.Int
	if shares.GTE(d.shares) {
		amt = d.tokens
		delete(m.dels[string(del.Bytes())], valBech)
	} else {
		amt = shares.MulInt(d.tokens).Quo(d.shares).TruncateInt()
		d.shares = d.shares.Sub(shares)
		d.tokens = d.tokens.Sub(amt)
	}
	if amt.IsPositive() {
		k := string(del.Bytes())
		if m.ubds[k] == nil {
			m.ubds[k] = map[string][]*pMockUBD{}
		}
		m.ubds[k][valBech] = append(m.ubds[k][valBech], &pMockUBD{
			height: sdkCtx.BlockHeight(), completion: completion, initial: amt, balance: amt,
		})
	}
	return completion, amt, nil
}
func (m *pMockStakingKeeper) CompleteUnbonding(_ context.Context, _ sdk.AccAddress, _ sdk.ValAddress) (sdk.Coins, error) {
	return sdk.NewCoins(), nil
}
func (m *pMockStakingKeeper) GetUnbondingDelegation(_ context.Context, del sdk.AccAddress, val sdk.ValAddress) (stakingtypes.UnbondingDelegation, error) {
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
			CreationHeight: e.height, CompletionTime: e.completion, InitialBalance: e.initial, Balance: e.balance,
		})
	}
	return ubd, nil
}
func (m *pMockStakingKeeper) completeMaturedUBD(del sdk.AccAddress, valBech string, now time.Time) math.Int {
	total := math.ZeroInt()
	entries := m.ubds[string(del.Bytes())][valBech]
	kept := entries[:0]
	for _, e := range entries {
		if !e.completion.After(now) {
			total = total.Add(e.balance)
			continue
		}
		kept = append(kept, e)
	}
	m.ubds[string(del.Bytes())][valBech] = kept
	return total
}
func (m *pMockStakingKeeper) GetValidator(_ context.Context, val sdk.ValAddress) (stakingtypes.Validator, error) {
	valBech, err := m.valCodec.BytesToString(val.Bytes())
	if err != nil {
		return stakingtypes.Validator{}, err
	}
	return stakingtypes.Validator{OperatorAddress: valBech, Status: stakingtypes.Bonded}, nil
}
func (m *pMockStakingKeeper) GetDelegation(_ context.Context, del sdk.AccAddress, val sdk.ValAddress) (stakingtypes.Delegation, error) {
	valBech, err := m.valCodec.BytesToString(val.Bytes())
	if err != nil {
		return stakingtypes.Delegation{}, err
	}
	d := m.dels[string(del.Bytes())][valBech]
	if d == nil {
		return stakingtypes.Delegation{}, stakingtypes.ErrNoDelegation
	}
	return stakingtypes.Delegation{ValidatorAddress: valBech, Shares: d.shares}, nil
}
func (m *pMockStakingKeeper) Delegate(_ context.Context, _ sdk.AccAddress, _ math.Int, _ stakingtypes.BondStatus, _ stakingtypes.Validator, _ bool) (math.LegacyDec, error) {
	return math.LegacyZeroDec(), nil
}
func (m *pMockStakingKeeper) ValidateUnbondAmount(_ context.Context, _ sdk.AccAddress, _ sdk.ValAddress, _ math.Int) (math.LegacyDec, error) {
	return math.LegacyZeroDec(), nil
}
func (m *pMockStakingKeeper) PowerReduction(_ context.Context) math.Int {
	return math.NewInt(1_000_000)
}
func (m *pMockStakingKeeper) GetBondedValidatorsByPower(_ context.Context) ([]stakingtypes.Validator, error) {
	return nil, nil
}

// stubStateDB implements ONLY what the clawback precompile touches (GetCode for
// the EOA check, AddLog for the event). Any other vm.StateDB call panics via
// the embedded nil interface — a loud failure, never a silent fake.
type stubStateDB struct {
	vm.StateDB
	code map[common.Address][]byte
	logs []*ethtypes.Log
}

func (s *stubStateDB) GetCode(addr common.Address) []byte { return s.code[addr] }
func (s *stubStateDB) AddLog(l *ethtypes.Log)             { s.logs = append(s.logs, l) }

// --- fixture ---

type pFixture struct {
	p          *Precompile
	k          valgrantkeeper.Keeper
	ctx        sdk.Context
	ak         *pMockAccountKeeper
	bank       *pMockBankKeeper
	sk         *pMockStakingKeeper
	stateDB    *stubStateDB
	adminEth   common.Address
	adminBech  string
	granteeEth common.Address
	granteeBz  sdk.AccAddress
	granteeStr string
	vGrant     string
	vOther     string
	poolAddr   sdk.AccAddress
}

func newPFixture(t *testing.T) *pFixture {
	t.Helper()
	key := storetypes.NewKVStoreKey(valgranttypes.StoreKey)
	tkey := storetypes.NewTransientStoreKey("transient_valgrant_p")
	testCtx := testutil.DefaultContextWithDB(t, key, tkey)

	ak := &pMockAccountKeeper{
		codec: addresscodec.NewBech32Codec(sdk.GetConfig().GetBech32AccountAddrPrefix()),
		accs:  map[string]sdk.AccountI{},
	}
	bank := &pMockBankKeeper{bal: map[string]sdk.Coins{}}
	sk := &pMockStakingKeeper{
		valCodec: addresscodec.NewBech32Codec(sdk.GetConfig().GetBech32ValidatorAddrPrefix()),
		dels:     map[string]map[string]*pMockDel{},
		ubds:     map[string]map[string][]*pMockUBD{},
	}
	k := valgrantkeeper.NewKeeper(runtime.NewKVStoreService(key), ak, bank, sk)
	ctx := testCtx.Ctx.WithBlockHeight(100).
		WithBlockTime(time.Unix(1_700_000_000, 0)).
		WithEventManager(sdk.NewEventManager())

	adminEth := common.BytesToAddress(bytes.Repeat([]byte{0x44}, 20))
	granteeEth := common.BytesToAddress(bytes.Repeat([]byte{0x11}, 20))
	granteeBz := sdk.AccAddress(granteeEth.Bytes())
	adminBech := sdk.AccAddress(adminEth.Bytes()).String()
	if err := k.SetParams(ctx, valgranttypes.Params{Admin: adminBech}); err != nil {
		t.Fatal(err)
	}

	return &pFixture{
		p:          NewPrecompile(k, nil),
		k:          k,
		ctx:        ctx,
		ak:         ak,
		bank:       bank,
		sk:         sk,
		stateDB:    &stubStateDB{code: map[common.Address][]byte{}},
		adminEth:   adminEth,
		adminBech:  adminBech,
		granteeEth: granteeEth,
		granteeBz:  granteeBz,
		granteeStr: granteeBz.String(),
		vGrant:     sdk.ValAddress(bytes.Repeat([]byte{0x22}, 20)).String(),
		vOther:     sdk.ValAddress(bytes.Repeat([]byte{0x66}, 20)).String(),
		poolAddr:   authtypes.NewModuleAddress(valgranttypes.ModuleName),
	}
}

// callClawback invokes the precompile's Clawback handler exactly as Execute
// dispatches it: ABI method, vm.Contract carrying the caller, live stateDB.
func (f *pFixture) callClawback(caller common.Address) ([]byte, error) {
	method := f.p.Methods[ClawbackMethod]
	contract := vm.NewContract(caller, f.p.Address(), uint256.NewInt(0), 200_000, nil)
	return f.p.Clawback(f.ctx, contract, f.stateDB, &method, []interface{}{f.granteeEth})
}

// seedBondedGrant: locked 1000 bonded at vGrant (GrantedShares ledger 1000),
// the grantee's OWN 500 self-bond at vOther, 10 liquid gas. BaseAccount grantee
// (the PLVA bucketing mechanics are proven at the keeper layer).
func (f *pFixture) seedBondedGrant(t *testing.T) {
	t.Helper()
	f.ak.SetAccount(f.ctx, authtypes.NewBaseAccountWithAddress(f.granteeBz))
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(pTestDenom, math.NewInt(10))))
	if err := f.k.SetGrant(f.ctx, valgranttypes.Grant{
		Grantee: f.granteeStr, LockedAmount: "1000", GasAllowance: "10",
		ValidatorOp: f.vGrant, Status: "active", GrantedShares: "1000", TrackedShares: "1000",
	}); err != nil {
		t.Fatal(err)
	}
	f.sk.delegate(f.granteeBz, f.vGrant, math.NewInt(1000))
	f.sk.delegate(f.granteeBz, f.vOther, math.NewInt(500))
}

// (i) END-TO-END through the ABI surface: admin EOA calls clawback(grantee).
// The reclaim must be SURGICAL (only the locked shares at vGrant; the vOther
// self-bond untouched) and at maturity the pool receives EXACTLY the locked
// 1000 while the grantee's 10 gas + 500 own self-bond stay byte-exact. The
// GrantClawedBack log must report (undelegated=1000, sweptNow=0, pending=1000).
func TestPrecompile_Clawback_SurgicalLockedOnly(t *testing.T) {
	f := newPFixture(t)
	f.seedBondedGrant(t)

	ret, err := f.callClawback(f.adminEth)
	if err != nil {
		t.Fatalf("precompile clawback failed: %v", err)
	}
	if len(ret) == 0 {
		t.Fatal("no return data (want ABI-packed true)")
	}

	// SURGICAL at the staking layer.
	if got := f.sk.tokensOf(f.granteeBz, f.vOther); !got.Equal(math.NewInt(500)) {
		t.Fatalf("vOther self-bond=%s want 500 UNTOUCHED (blunt path force-undelegated it)", got)
	}
	if got := f.sk.tokensOf(f.granteeBz, f.vGrant); !got.IsZero() {
		t.Fatalf("vGrant residual=%s want 0", got)
	}
	// Grant revoked; pending is pure locked principal.
	if g, _ := f.k.GetGrant(f.ctx, f.granteeStr); g.Status != "revoked" {
		t.Fatalf("grant status=%s want revoked", g.Status)
	}
	var pcs []valgranttypes.PendingClawback
	f.k.IteratePendingClawbacks(f.ctx, func(pc valgranttypes.PendingClawback) { pcs = append(pcs, pc) })
	if len(pcs) != 1 || len(pcs[0].Entries) != 1 || pcs[0].Entries[0].Validator != f.vGrant || pcs[0].SweepAmount != "1000" {
		t.Fatalf("pending=%+v want single pure-locked entry at vGrant, SweepAmount 1000", pcs)
	}

	// The EVM event reports the surgical amounts.
	if len(f.stateDB.logs) != 1 {
		t.Fatalf("logs=%d want 1 GrantClawedBack", len(f.stateDB.logs))
	}
	ev := f.p.Events[EventTypeGrantClawedBack]
	if f.stateDB.logs[0].Topics[0] != ev.ID {
		t.Fatalf("log topic0=%s want GrantClawedBack id", f.stateDB.logs[0].Topics[0])
	}
	vals, err := ev.Inputs.NonIndexed().Unpack(f.stateDB.logs[0].Data)
	if err != nil {
		t.Fatalf("unpack log: %v", err)
	}
	if len(vals) != 3 || vals[0].(interface{ String() string }).String() != "1000" ||
		vals[1].(interface{ String() string }).String() != "0" ||
		vals[2].(interface{ String() string }).String() != "1000" {
		t.Fatalf("log (undelegated,sweptNow,pending)=%v want (1000,0,1000)", vals)
	}

	// Capture block, maturity return, deferred sweep.
	if err := f.k.SweepMaturedClawbacks(f.ctx.WithBlockTime(f.ctx.BlockTime().Add(24 * time.Hour))); err != nil {
		t.Fatalf("capture sweep errored: %v", err)
	}
	at := f.ctx.BlockTime().Add(22 * 24 * time.Hour)
	f.bank.add(f.granteeBz, sdk.NewCoins(sdk.NewCoin(pTestDenom, f.sk.completeMaturedUBD(f.granteeBz, f.vGrant, at))))
	afterCtx := f.ctx.WithBlockTime(at)
	if err := f.k.SweepMaturedClawbacks(afterCtx); err != nil {
		t.Fatalf("deferred sweep errored: %v", err)
	}

	if pool := f.bank.GetBalance(afterCtx, f.poolAddr, pTestDenom).Amount; !pool.Equal(math.NewInt(1000)) {
		t.Fatalf("pool=%s want EXACTLY 1000 (locked principal only)", pool)
	}
	if liquid := f.bank.GetBalance(afterCtx, f.granteeBz, pTestDenom).Amount; !liquid.Equal(math.NewInt(10)) {
		t.Fatalf("grantee liquid=%s want 10 byte-exact (gas untouched)", liquid)
	}
	if got := f.sk.tokensOf(f.granteeBz, f.vOther); !got.Equal(math.NewInt(500)) {
		t.Fatalf("vOther self-bond=%s want 500 byte-exact after sweep", got)
	}
}

// (ii) ADMIN GATING at the ABI boundary: a non-admin EOA (here: the grantee
// themselves) is rejected by the msg server's Params.admin check and NOTHING
// changes — no undelegation, no pending, grant stays active, no log.
func TestPrecompile_Clawback_NonAdminRejected(t *testing.T) {
	f := newPFixture(t)
	f.seedBondedGrant(t)

	if _, err := f.callClawback(f.granteeEth); err == nil || !strings.Contains(err.Error(), "not the valgrant admin") {
		t.Fatalf("non-admin precompile clawback must be rejected, got err=%v", err)
	}
	if got := f.sk.tokensOf(f.granteeBz, f.vGrant); !got.Equal(math.NewInt(1000)) {
		t.Fatalf("vGrant=%s want 1000 untouched", got)
	}
	if g, _ := f.k.GetGrant(f.ctx, f.granteeStr); g.Status != "active" {
		t.Fatalf("grant status=%s want active", g.Status)
	}
	if len(f.stateDB.logs) != 0 {
		t.Fatalf("logs=%d want 0 after rejection", len(f.stateDB.logs))
	}
}

// (iii) CONTRACT callers are rejected (EOA-only surface; EIP-7702 delegation
// designators are the sole exception). A wrapper contract cannot proxy or
// re-enter the clawback even if the admin key were tricked into calling it.
func TestPrecompile_Clawback_ContractCallerRejected(t *testing.T) {
	f := newPFixture(t)
	f.seedBondedGrant(t)

	f.stateDB.code[f.adminEth] = []byte{0x60, 0x00, 0x60, 0x00} // plain bytecode, not a 7702 delegation
	if _, err := f.callClawback(f.adminEth); err == nil || !strings.Contains(err.Error(), ErrCannotCallFromContract) {
		t.Fatalf("contract-caller clawback must be rejected, got err=%v", err)
	}
	if got := f.sk.tokensOf(f.granteeBz, f.vGrant); !got.Equal(math.NewInt(1000)) {
		t.Fatalf("vGrant=%s want 1000 untouched", got)
	}
}
