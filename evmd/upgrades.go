package evmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"slices"

	"github.com/cosmos/cosmos-sdk/baseapp"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"

	"github.com/ethereum/go-ethereum/common"

	valgranttypes "github.com/cosmos/evm/x/valgrant/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
	vpcaptypes "github.com/cosmos/evm/x/vpcap/types"
)

// UpgradeName defines the on-chain upgrade name for the sample EVMD upgrade
// from v0.6.0 to v0.7.0.
//
// NOTE: This upgrade defines a reference implementation of what an upgrade
// could look like when an application is migrating from EVMD version
// v0.6.x to v0.7.0.
const UpgradeName = "v0.6.0-to-v0.7.0"

// ValGrantUpgradeName is the Limonata in-place upgrade that introduces the
// x/valgrant module + its EVM precompile (0x...0900) WITHOUT wiping state.
// On live (limonata_10777-1) the binary is swapped at the upgrade height; the
// handler below runs module migrations (which creates the valgrant store via
// the store loader added in RegisterUpgradeHandlers), sets the valgrant admin,
// ensures the valgrant module account exists, and activates the 0x900
// precompile. It NEVER moves user funds: the grant pool is funded separately
// by the admin AFTER the upgrade.
const ValGrantUpgradeName = "valgrant-v1"

// ValGrantAdmin is the bech32 admin authorized to issue/clawback grants on
// live (= 0x88A2256a982Ed09228EA9fc4C9740765E62188E9). The upgrade handler
// writes this into x/valgrant Params if it is not already set, so the live
// chain ends the upgrade with a working admin without needing a genesis edit.
const ValGrantAdmin = "cosmos13z3z265c9mgfy282nlzvjaq8vhnzrz8ftvzuam"

// ValGrantForceUpgradeEnv, when set to "1", enables the fast NON-GOV operator
// upgrade path: the binary is swapped on a single-validator chain and, on the
// first block after the swap, it (a) adds the valgrant KV store at the next
// height via a force StoreLoader and (b) runs the SAME valgrant init the gov
// handler runs. No on-chain gov plan is required. A normal start (env unset)
// is completely unaffected; both paths share applyValGrantInit so they cannot
// drift.
const ValGrantForceUpgradeEnv = "VALGRANT_FORCE_UPGRADE"

// valGrantForceUpgrade reports whether the fast operator path is enabled.
func valGrantForceUpgrade() bool { return os.Getenv(ValGrantForceUpgradeEnv) == "1" }

// valGrantAdmin returns the admin bech32 to write into x/valgrant Params.
// VALGRANT_ADMIN_OVERRIDE lets a dry-run point the admin at a key it controls;
// live leaves it unset so the constant is used.
func valGrantAdmin() string {
	if ov := os.Getenv("VALGRANT_ADMIN_OVERRIDE"); ov != "" {
		return ov
	}
	return ValGrantAdmin
}

// applyValGrantInit is the SHARED, deterministic init body for x/valgrant. It is
// called by BOTH the gov upgrade handler and the fast operator one-shot, so the
// two paths can never diverge. It assumes the valgrant KV store already exists
// (created by a StoreLoader) and that module migrations have already registered
// the module. It:
//   - sets x/valgrant Params.Admin (if empty),
//   - ensures the valgrant module account exists (perm nil; creates if missing),
//   - activates the 0x900 valgrant precompile in the EVM params (idempotent).
//
// It NEVER mints or moves user funds; the grant pool is funded by the admin
// AFTER the upgrade. It is fully idempotent: re-running it is a no-op.
func (app *EVMD) applyValGrantInit(ctx sdk.Context) error {
	logger := ctx.Logger().With("upgrade", ValGrantUpgradeName)

	// 1) Ensure the valgrant Params.Admin is set.
	vgParams := app.ValGrantKeeper.GetParams(ctx)
	if vgParams.Admin == "" {
		vgParams.Admin = valGrantAdmin()
		if err := app.ValGrantKeeper.SetParams(ctx, vgParams); err != nil {
			return err
		}
		logger.Info("valgrant admin set", "admin", vgParams.Admin)
	} else {
		logger.Info("valgrant admin already set", "admin", vgParams.Admin)
	}

	// 2) Ensure the valgrant module account exists. GetModuleAccount creates +
	//    persists it (perm nil) if missing. Does NOT mint or move any funds.
	macc := app.AccountKeeper.GetModuleAccount(ctx, valgranttypes.ModuleName)
	logger.Info("valgrant module account ensured", "address", macc.GetAddress().String())

	// 3) Activate the 0x900 valgrant precompile by adding it to the EVM module's
	//    active_static_precompiles (kept sorted by SetParams). Idempotent.
	pcAddr := common.HexToAddress(evmtypes.ValGrantPrecompileAddress)
	evmParams := app.EVMKeeper.GetParams(ctx)
	if !slices.Contains(evmParams.ActiveStaticPrecompiles, pcAddr.Hex()) {
		if err := app.EVMKeeper.EnableStaticPrecompiles(ctx, pcAddr); err != nil {
			return err
		}
		logger.Info("valgrant precompile activated", "address", pcAddr.Hex())
	} else {
		logger.Info("valgrant precompile already active", "address", pcAddr.Hex())
	}

	return nil
}

// --- Limonata: encrypted-mempool (threshold) + x/vpcap in-place upgrade ---
//
// This upgrade adds the x/vpcap KV store (the ONLY new store; encmempool's new
// threshold keys live under the existing encmempool store, valgrant's KPI under
// the existing valgrant store, contest's change is msg-only) and optionally
// activates the threshold-encrypted mempool. x/vpcap stays DISABLED (Enabled=
// false, default) — its store is added only so the new binary loads; the cap is
// a separate mainnet decision. The dry-run proved a plain binary swap FAILS with
// "version of store vpcap mismatch ... new stores should be added using
// StoreUpgrades", which this wiring fixes.
const EncMempoolUpgradeName = "encmempool-threshold-vpcap-v1"

// EncMempoolForceUpgradeEnv enables the fast NON-GOV single-operator path (same
// shape as valgrant's): swap the binary with the env set, the vpcap store is
// added at the next height and the one-shot below runs migrations + activation.
const EncMempoolForceUpgradeEnv = "ENCMEMPOOL_FORCE_UPGRADE"

// EncMempoolActivationEnv carries activation params as JSON on the FORCE path
// ONLY: {"threshold_pub":"<base64>","threshold":2,"keypers":["addr",...],"decrypt_delay":15}.
// The multi-validator GOV path MUST NOT read env (validators could differ ->
// state divergence): it uses bakedEncActivation(), baked into the release binary.
const EncMempoolActivationEnv = "ENCMEMPOOL_ACTIVATION"

// encMempoolForceUpgrade / envEncActivation / maybeRunEncMempoolForceInit (the env-driven,
// single-operator FORCE path) live in upgrades_encforce.go behind the `encmempoolforce` build tag
// (round-12 #1 CRITICAL). A production/default binary compiles the no-op stubs in
// upgrades_encforce_stub.go, so NO environment variable can add a store, run migrations, or mutate
// consensus params - eliminating the app-hash divergence a per-validator env would cause. The
// deterministic GOV path (bakedEncActivation via the registered upgrade handler) is unaffected.

// encActivation holds the parameters that turn the encrypted mempool ON.
type encActivation struct {
	ThresholdPub []byte
	Threshold    uint32
	Keypers      []string
	DecryptDelay uint64
}

// bakedEncActivation returns the activation compiled into THIS binary for the GOV
// path (deterministic: every validator runs the same binary). The threshold key
// + keyper set below are baked for the Limonata testnet (10777) encrypted-mempool
// activation; the threshold public key was produced by a trusted `keyper setup
// --n 3 --t 2` whose secret shares Jason holds (never shared). keypers are ordered
// so keypers[i] holds share-(i+1).
func bakedEncActivation() (encActivation, bool) {
	const thresholdPubB64 = "Aw2DNwiH87yToy7Q+HC3Bv4hBiihRYlqnqp5nKsTIfwN"
	pub, err := base64.StdEncoding.DecodeString(thresholdPubB64)
	if err != nil || len(pub) != 33 {
		return encActivation{}, false
	}
	return encActivation{
		ThresholdPub: pub,
		Threshold:    2, // need 2 of 3 keypers to decrypt
		Keypers: []string{
			"cosmos1p7jf6dgs9fwyl353hs8l8qjw83l5z0vdj5hv2a", // keyper1 <- share-1
			"cosmos1vvxdr3np5ke3tu6scu4945z6j4zlnwf3khjz4d", // keyper2 <- share-2
			"cosmos1g5kykywdmu90fkcxkqmq0hegumsvuyly6ugn7e", // keyper3 <- share-3
		},
		DecryptDelay: 15, // ~30s at 2s blocks: time for keypers to post shares
	}, true
}

// applyEncMempoolInit activates the encrypted mempool deterministically from act,
// preserving the existing reveal-path params (reveal_delay, max_reveal_window).
// Idempotent (no-op if already enabled). If not configured it does nothing — the
// upgrade then only added the vpcap store. NEVER touches user funds.
func (app *EVMD) applyEncMempoolInit(ctx sdk.Context, act encActivation, configured bool) error {
	logger := ctx.Logger().With("upgrade", EncMempoolUpgradeName)
	if !configured {
		logger.Info("encrypted mempool activation not configured; vpcap store added, mempool left disabled")
		return nil
	}
	p := app.EncMempoolKeeper.GetParams(ctx)
	if p.EncEnabled {
		logger.Info("encrypted mempool already enabled; no-op")
		return nil
	}
	p.EncEnabled = true
	p.ThresholdPub = act.ThresholdPub
	p.Threshold = act.Threshold
	p.Keypers = act.Keypers
	p.DecryptDelay = act.DecryptDelay
	// round-12 #1 (CRITICAL): NEVER write params that fail validation. An upgrade activating the
	// encrypted path with an invalid config (bad threshold/keyper split, zero decrypt delay, ...)
	// must HALT the upgrade loudly, not silently install a broken live path.
	if err := p.Validate(); err != nil {
		return fmt.Errorf("encmempool activation params invalid, refusing to write: %w", err)
	}
	if err := app.EncMempoolKeeper.SetParams(ctx, p); err != nil {
		return err
	}
	logger.Info("encrypted mempool ACTIVATED", "threshold", act.Threshold, "keypers", len(act.Keypers), "decrypt_delay", act.DecryptDelay)
	return nil
}

// --- Limonata: gassponsor security caps in-place upgrade (v0.3.0) ---
//
// SecurityCapsUpgradeName is the LATER Limonata gov upgrade that HARDENS x/gassponsor
// on the LIVE chain by installing the two anti-drain caps the re-genesis proof baked
// into genesis:
//   - Params.DappPerTxFeeCap    = 1 LIMO/tx        (bounds the unlimited approved-dApp path)
//   - Params.RefillDailyMintCap = 10,000 LIMO/day  (global daily mint circuit breaker)
//
// CRITICAL: on a live chain the gassponsor Params were written by an OLDER binary that
// had NEITHER field, so at upgrade time they unmarshal to "" — which keeper.withinDappCap
// and the abci refill both treat as UNLIMITED. A plain binary swap would therefore leave
// the caps OFF. This upgrade's handler runs a deterministic param migration
// (applySecurityCaps) that reads the existing params, sets the two cap fields to the
// hardened values, and writes them back. NO new store keys are added: the caps live in
// x/gassponsor Params (0x01) and the daily-mint counter under MintedTodayPrefix (0x03),
// BOTH in the EXISTING gassponsor store — so NO StoreUpgrades/StoreLoader is needed.
// NEVER mints or moves user funds.
const SecurityCapsUpgradeName = "gassponsor-security-caps-v1"

// Hardened live cap values installed by the SecurityCapsUpgradeName migration. They
// match the re-genesis genesis-script values so fresh-genesis and in-place-upgrade
// chains converge on identical hardened params.
const (
	securityCapsDappPerTxFeeCap    = "1000000000000000000"     // 1 LIMO/tx
	securityCapsRefillDailyMintCap = "10000000000000000000000" // 10,000 LIMO/day

	// v0.3.0 UNIFORM gasless budget (settled design). On a live chain the gassponsor
	// Params were written by an OLDER binary WITHOUT these three fields, so at upgrade
	// time they unmarshal to "" — which the keeper treats as "fall back to the legacy
	// history-scaled formula" (daily_budget "") / "onboarding disabled" (onboarding_grant "").
	// The migration below writes these hardened values so an in-place-upgraded chain
	// converges on the SAME uniform model a fresh-genesis chain runs.
	securityCapsDailyBudget     = "1000000000000000000" // 1 LIMO/day flat, holders only
	securityCapsHoldMinimum     = "1000000000000000000" // must hold >= 1 LIMO to earn the daily budget
	securityCapsOnboardingGrant = "50000000000000000"   // 0.05 LIMO one-shot cold-wallet grant

	// squeeze fee split installed on the live chain by the same handler (20% burn /
	// 20% gas-pool recycle / 60% distribution). On a live chain the squeeze Params were
	// written by an OLDER binary as compile-time consts (no governable Params blob yet),
	// so this migration writes the canonical split so gov can later tune it.
	securityCapsSqueezeBurnBps  uint32 = 2000 // 20% burned
	securityCapsSqueezeGrantBps uint32 = 2000 // 20% recycled into the gas pool
)

// applySecurityCaps is the SHARED, deterministic init body for the gassponsor
// security-caps upgrade. It reads the existing x/gassponsor Params, installs the
// hardened DappPerTxFeeCap (1 LIMO/tx) and RefillDailyMintCap (10,000 LIMO/day), AND
// the v0.3.0 uniform gasless budget (DailyBudget 1 LIMO/day, HoldMinimum 1 LIMO,
// OnboardingGrant 0.05 LIMO), then writes them back — preserving every other param. It
// is fully idempotent: it always writes the same hardened values, so re-running it is a
// no-op. It NEVER mints or moves user funds. Mirrors the shape of applyValGrantInit /
// applyEncMempoolInit.
func (app *EVMD) applySecurityCaps(ctx sdk.Context) error {
	logger := ctx.Logger().With("upgrade", SecurityCapsUpgradeName)

	// Read the existing (live) params. On a live chain these were written by an older
	// binary WITHOUT the cap / uniform-budget fields, so they unmarshal here as "" —
	// which the keeper treats as "unlimited" (caps) / "legacy formula" (daily_budget) /
	// "onboarding disabled" (onboarding_grant).
	p := app.GasSponsorKeeper.GetParams(ctx)
	logger.Info("gassponsor security caps: before",
		"dapp_per_tx_fee_cap", p.DappPerTxFeeCap,
		"refill_daily_mint_cap", p.RefillDailyMintCap,
		"daily_budget", p.DailyBudget,
		"hold_minimum", p.HoldMinimum,
		"onboarding_grant", p.OnboardingGrant,
	)

	p.DappPerTxFeeCap = securityCapsDappPerTxFeeCap
	p.RefillDailyMintCap = securityCapsRefillDailyMintCap
	// v0.3.0 uniform gasless budget: switch the live chain onto the flat holders-only
	// DailyBudget + one-shot OnboardingGrant model (matches the fresh-genesis values).
	p.DailyBudget = securityCapsDailyBudget
	p.HoldMinimum = securityCapsHoldMinimum
	p.OnboardingGrant = securityCapsOnboardingGrant
	if err := app.GasSponsorKeeper.SetParams(ctx, p); err != nil {
		return err
	}

	logger.Info("gassponsor security caps: after",
		"dapp_per_tx_fee_cap", p.DappPerTxFeeCap,
		"refill_daily_mint_cap", p.RefillDailyMintCap,
		"daily_budget", p.DailyBudget,
		"hold_minimum", p.HoldMinimum,
		"onboarding_grant", p.OnboardingGrant,
	)
	return nil
}

// applySqueezeSplitParams is the SHARED, deterministic init body that installs the
// governable x/squeeze fee split on the live chain: BurnBps=2000 (20% burn) /
// GrantBps=2000 (20% gas-pool recycle) / 60% remainder left in fee_collector for
// x/distribution. It reads the existing squeeze Params, sets the two fields, and
// writes them back. Fully idempotent (always writes the same values). It NEVER mints
// or moves user funds. Called from the SecurityCapsUpgradeName handler alongside
// applySecurityCaps so a fresh-genesis chain and an in-place-upgraded chain converge
// on identical split params.
func (app *EVMD) applySqueezeSplitParams(ctx sdk.Context) error {
	logger := ctx.Logger().With("upgrade", SecurityCapsUpgradeName)

	sp := app.SqueezeKeeper.GetParams(ctx)
	logger.Info("squeeze split params: before",
		"burn_bps", sp.BurnBps,
		"grant_bps", sp.GrantBps,
	)

	sp.BurnBps = securityCapsSqueezeBurnBps
	sp.GrantBps = securityCapsSqueezeGrantBps
	if err := app.SqueezeKeeper.SetParams(ctx, sp); err != nil {
		return err
	}

	logger.Info("squeeze split params: after",
		"burn_bps", sp.BurnBps,
		"grant_bps", sp.GrantBps,
	)
	return nil
}

func (app *EVMD) RegisterUpgradeHandlers() {
	app.UpgradeKeeper.SetUpgradeHandler(
		UpgradeName,
		func(ctx context.Context, _ upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
			sdkCtx := sdk.UnwrapSDKContext(ctx)
			sdkCtx.Logger().Debug("this is a debug level message to test that verbose logging mode has properly been enabled during a chain upgrade")
			return app.ModuleManager.RunMigrations(ctx, app.Configurator(), fromVM)
		},
	)

	// Limonata: valgrant-v1 GOV upgrade handler (the 48h on-chain path).
	app.UpgradeKeeper.SetUpgradeHandler(
		ValGrantUpgradeName,
		func(ctx context.Context, _ upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
			sdkCtx := sdk.UnwrapSDKContext(ctx)

			// Run module migrations. x/valgrant is a brand-new module (not in
			// fromVM), so RunMigrations registers it + runs its InitGenesis. The
			// valgrant KV store itself is created by the store loader wired below.
			newVM, err := app.ModuleManager.RunMigrations(ctx, app.Configurator(), fromVM)
			if err != nil {
				return nil, err
			}

			// Shared deterministic init (admin + module account + 0x900).
			if err := app.applyValGrantInit(sdkCtx); err != nil {
				return nil, err
			}

			return newVM, nil
		},
	)

	// Limonata: encmempool-threshold + vpcap GOV upgrade handler. x/vpcap is a
	// brand-new module (not in fromVM) so RunMigrations registers it + runs its
	// InitGenesis (default Enabled=false); the vpcap KV store is created by the
	// store loader wired below. Then optionally activate the encrypted mempool
	// from the binary-baked params (deterministic across all validators).
	app.UpgradeKeeper.SetUpgradeHandler(
		EncMempoolUpgradeName,
		func(ctx context.Context, _ upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
			sdkCtx := sdk.UnwrapSDKContext(ctx)
			newVM, err := app.ModuleManager.RunMigrations(ctx, app.Configurator(), fromVM)
			if err != nil {
				return nil, err
			}
			act, configured := bakedEncActivation()
			if err := app.applyEncMempoolInit(sdkCtx, act, configured); err != nil {
				return nil, err
			}
			return newVM, nil
		},
	)

	// Limonata: gassponsor-security-caps GOV upgrade handler (v0.3.0). It adds NO new
	// modules or stores — it only runs module migrations, then installs the hardened
	// gassponsor caps via applySecurityCaps (the LIVE params were written without the
	// new cap fields, so they unmarshal to "" == unlimited; this migration turns the
	// caps ON). Because the caps + daily-mint counter both live in the EXISTING
	// gassponsor store, NO StoreUpgrades/StoreLoader is wired below for this name.
	app.UpgradeKeeper.SetUpgradeHandler(
		SecurityCapsUpgradeName,
		func(ctx context.Context, _ upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
			sdkCtx := sdk.UnwrapSDKContext(ctx)
			newVM, err := app.ModuleManager.RunMigrations(ctx, app.Configurator(), fromVM)
			if err != nil {
				return nil, err
			}
			if err := app.applySecurityCaps(sdkCtx); err != nil {
				return nil, err
			}
			if err := app.applySqueezeSplitParams(sdkCtx); err != nil {
				return nil, err
			}
			return newVM, nil
		},
	)

	upgradeInfo, err := app.UpgradeKeeper.ReadUpgradeInfoFromDisk()
	if err != nil {
		panic(err)
	}

	// Limonata: fast NON-GOV path for the encmempool/vpcap upgrade. Adds the vpcap
	// store at the next height after the swap; the PreBlocker one-shot then runs
	// migrations + activation. Single-operator/dry-run only.
	if encMempoolForceUpgrade() {
		app.SetStoreLoader(forceAddStoreLoader(vpcaptypes.StoreKey))
		return
	}

	// Fast NON-GOV operator path: when VALGRANT_FORCE_UPGRADE=1, install a
	// StoreLoader that adds the valgrant store at the NEXT height after the swap,
	// read dynamically inside the loader (operator need not compute a height).
	// Idempotent: if the valgrant store already exists in state, fall back to the
	// default loader so a re-start with the env still set does not error.
	if valGrantForceUpgrade() {
		app.SetStoreLoader(forceAddStoreLoader(valgranttypes.StoreKey))
		return
	}

	if app.UpgradeKeeper.IsSkipHeight(upgradeInfo.Height) {
		return
	}

	switch upgradeInfo.Name {
	case UpgradeName:
		storeUpgrades := storetypes.StoreUpgrades{
			Added: []string{},
		}
		// configure store loader that checks if version == upgradeHeight and applies store upgrades
		app.SetStoreLoader(upgradetypes.UpgradeStoreLoader(upgradeInfo.Height, &storeUpgrades))
	case ValGrantUpgradeName:
		// Limonata: create the new x/valgrant KV store at the upgrade height.
		storeUpgrades := storetypes.StoreUpgrades{
			Added: []string{valgranttypes.StoreKey},
		}
		app.SetStoreLoader(upgradetypes.UpgradeStoreLoader(upgradeInfo.Height, &storeUpgrades))
	case EncMempoolUpgradeName:
		// Limonata: create the new x/vpcap KV store at the upgrade height (the only
		// new store this upgrade introduces).
		storeUpgrades := storetypes.StoreUpgrades{
			Added: []string{vpcaptypes.StoreKey},
		}
		app.SetStoreLoader(upgradetypes.UpgradeStoreLoader(upgradeInfo.Height, &storeUpgrades))
	}
}

// forceAddStoreLoader returns a StoreLoader that unconditionally adds the named
// store(s) at the NEXT commit version, with no on-chain upgrade plan. It reads
// the last commit version dynamically so the operator does not pass a height.
// Idempotent: if the store already loads under the default loader (i.e. it is
// already present in state from a prior run), it falls back to DefaultStoreLoader
// so a re-start with VALGRANT_FORCE_UPGRADE still set will not error.
func forceAddStoreLoader(storeKeys ...string) baseapp.StoreLoader {
	return func(ms storetypes.CommitMultiStore) error {
		// If the store(s) already exist in the committed state, LoadLatestVersion
		// succeeds and the upgrade has already been applied -> idempotent re-start.
		// If a registered store key is missing from committed state (the first
		// start after the binary swap), LoadLatestVersion returns a
		// "version mismatch ... new stores should be added using StoreUpgrades"
		// error; we then add the store(s) at LastCommitID().Version+1.
		if err := baseapp.DefaultStoreLoader(ms); err == nil {
			return nil
		}

		storeUpgrades := &storetypes.StoreUpgrades{Added: storeKeys}
		return ms.LoadLatestVersionAndUpgrade(storeUpgrades)
	}
}

// maybeRunValGrantForceInit is the fast NON-GOV operator one-shot. It runs from
// PreBlocker on EVERY block but is a strict no-op unless ALL of these hold:
//   - VALGRANT_FORCE_UPGRADE=1 (operator opted in), and
//   - the valgrant KV store exists (added by forceAddStoreLoader at G+1), and
//   - x/valgrant Params.Admin is still empty (i.e. init has not run yet).
//
// On the single block where they all hold (the first block after the swap), it
// runs module migrations (registering x/valgrant in the on-chain version map +
// running its InitGenesis) and then the SAME applyValGrantInit the gov handler
// uses. After it sets Params.Admin, the empty-admin guard makes every later
// block a no-op, so it runs exactly once. It NEVER touches user funds.
func (app *EVMD) maybeRunValGrantForceInit(ctx sdk.Context) error {
	if !valGrantForceUpgrade() {
		return nil
	}

	// The valgrant store must exist before we can read its params; otherwise the
	// force loader has not added it yet (should not happen post-swap, but guard).
	if app.GetKey(valgranttypes.StoreKey) == nil {
		return nil
	}

	// Run-once guard: empty admin means the init has not been applied yet.
	if app.ValGrantKeeper.GetParams(ctx).Admin != "" {
		return nil
	}

	logger := ctx.Logger().With("upgrade", ValGrantUpgradeName, "path", "force-operator")
	logger.Info("running valgrant force (non-gov) one-shot init")

	// Register x/valgrant in the on-chain module version map + run its InitGenesis
	// (sets empty default params), exactly like the gov handler does.
	fromVM, err := app.UpgradeKeeper.GetModuleVersionMap(ctx)
	if err != nil {
		return err
	}
	newVM, err := app.ModuleManager.RunMigrations(ctx, app.Configurator(), fromVM)
	if err != nil {
		return err
	}
	if err := app.UpgradeKeeper.SetModuleVersionMap(ctx, newVM); err != nil {
		return err
	}

	// Shared deterministic init (admin + module account + 0x900) — identical to
	// the gov path so the two cannot drift.
	if err := app.applyValGrantInit(ctx); err != nil {
		return err
	}

	logger.Info("valgrant force one-shot init complete")
	return nil
}

// maybeRunEncMempoolForceInit is the fast NON-GOV one-shot for the encmempool/
// vpcap upgrade. No-op unless ENCMEMPOOL_FORCE_UPGRADE=1 and migrations have not
// run yet (detected by x/vpcap being absent from the on-chain version map). On
// the first block after the binary swap it registers x/vpcap (RunMigrations runs
// its InitGenesis) and activates the encrypted mempool from ENCMEMPOOL_ACTIVATION.
// Runs exactly once. NEVER touches user funds.
// maybeRunEncMempoolForceInit is defined in upgrades_encforce.go (real, `encmempoolforce` build) and
// upgrades_encforce_stub.go (no-op, default build) - round-12 #1.
