package types

import squeezetypes "github.com/cosmos/evm/x/squeeze/types"

const (
	// ModuleName is the gassponsor module name and its (minter) module account.
	ModuleName = "gassponsor"
	// StoreKey is the gassponsor store key.
	StoreKey = ModuleName
	// ConsensusVersion of the module.
	ConsensusVersion = 1
)

// Reuse the existing protocol gas pool + fee denom from x/squeeze. Do NOT define a
// second pool account: gassponsor mints into the SAME paymaster_gas_pool that squeeze
// recycles into and that pays users' EVM fees.
const (
	GasPoolName = squeezetypes.GasPoolName // "paymaster_gas_pool"
	FeeDenom    = squeezetypes.FeeDenom    // "aLIMO"
)

// Store layout (single-byte key prefixes).
var (
	ParamsKey         = []byte{0x01} // -> JSON Params
	AllowancePrefix   = []byte{0x02} // 0x02 | day(8) | sender -> used aLIMO (math.Int as decimal string)
	MintedTodayPrefix = []byte{0x03} // 0x03 | day(8) -> cumulative refill-minted aLIMO today (math.Int as decimal string)
	// OnboardingPrefix keys the one-shot LIFETIME onboarding grant counter (NOT per-day):
	// 0x05 | sender -> cumulative aLIMO ever granted to that account via the onboarding
	// path (math.Int as decimal string). A 0-balance never-seen account draws down its
	// OnboardingGrant here so its first tx works with no faucet; once exhausted it must
	// hold LIMO to earn the daily budget. (0x04 is intentionally skipped to avoid any
	// collision with reserved/legacy layouts.)
	OnboardingPrefix = []byte{0x05}
	// GrantedTodayPrefix keys the GLOBAL per-UTC-day onboarding-grant budget counter
	// (mirrors MintedTodayPrefix): 0x06 | day(8) -> cumulative aLIMO handed out via the
	// onboarding path during that day (math.Int as decimal string). Enforces
	// OnboardingDailyCap (sybil-flood gate); a new day has no key so it resets to zero.
	GrantedTodayPrefix = []byte{0x06}
	// DappSpentPrefix keys the per-(UTC-day, contract) approved-dApp sponsorship counter:
	// 0x07 | day(8) | contractAddr(20) -> cumulative aLIMO sponsored via the approved-dApp
	// path for that contract during that day (math.Int as decimal string). Enforces
	// DappDailyCap (per-contract pool-drain gate); a new day has no key so it resets to zero.
	DappSpentPrefix = []byte{0x07}
)
