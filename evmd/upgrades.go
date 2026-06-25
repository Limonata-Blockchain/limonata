package evmd

import (
	"context"
	"os"
	"slices"

	"github.com/cosmos/cosmos-sdk/baseapp"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"

	"github.com/ethereum/go-ethereum/common"

	evmtypes "github.com/cosmos/evm/x/vm/types"
	valgranttypes "github.com/cosmos/evm/x/valgrant/types"
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

func (app EVMD) RegisterUpgradeHandlers() {
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

	upgradeInfo, err := app.UpgradeKeeper.ReadUpgradeInfoFromDisk()
	if err != nil {
		panic(err)
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
