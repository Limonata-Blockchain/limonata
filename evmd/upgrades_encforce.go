//go:build encmempoolforce

package evmd

import (
	"encoding/base64"
	"encoding/json"
	"os"

	sdk "github.com/cosmos/cosmos-sdk/types"

	vpcaptypes "github.com/cosmos/evm/x/vpcap/types"
)

// ============================================================================
// ENV-DRIVEN, SINGLE-OPERATOR FORCE PATH - throwaway / dry-run builds ONLY.
//
// This file is compiled ONLY with `go build -tags encmempoolforce`. A production/default binary
// gets the no-op stubs in upgrades_encforce_stub.go, so NO environment variable can add a store, run
// migrations, or mutate consensus params - which on a multi-validator chain (env set on some nodes,
// not others) would be an app-hash divergence / fork (round-12 #1 CRITICAL). The deterministic GOV
// path (bakedEncActivation via the registered upgrade handler) is the only production activation.
// ============================================================================

func encMempoolForceUpgrade() bool { return os.Getenv(EncMempoolForceUpgradeEnv) == "1" }

// envEncActivation parses ENCMEMPOOL_ACTIVATION for the FORCE / dry-run path.
func envEncActivation() (encActivation, bool) {
	raw := os.Getenv(EncMempoolActivationEnv)
	if raw == "" {
		return encActivation{}, false
	}
	var j struct {
		ThresholdPub string   `json:"threshold_pub"`
		Threshold    uint32   `json:"threshold"`
		Keypers      []string `json:"keypers"`
		DecryptDelay uint64   `json:"decrypt_delay"`
	}
	if err := json.Unmarshal([]byte(raw), &j); err != nil {
		return encActivation{}, false
	}
	pub, err := base64.StdEncoding.DecodeString(j.ThresholdPub)
	if err != nil || len(pub) == 0 || j.Threshold == 0 || len(j.Keypers) == 0 {
		return encActivation{}, false
	}
	return encActivation{ThresholdPub: pub, Threshold: j.Threshold, Keypers: j.Keypers, DecryptDelay: j.DecryptDelay}, true
}

// maybeRunEncMempoolForceInit runs the encmempool/vpcap migrations + activation ONCE on the first
// block after a binary swap, when ENCMEMPOOL_FORCE_UPGRADE=1. Only ever present in a force build.
func (app *EVMD) maybeRunEncMempoolForceInit(ctx sdk.Context) error {
	if !encMempoolForceUpgrade() {
		return nil
	}
	vm, err := app.UpgradeKeeper.GetModuleVersionMap(ctx)
	if err != nil {
		return err
	}
	if _, registered := vm[vpcaptypes.ModuleName]; registered {
		return nil // migrations already ran -> done
	}
	logger := ctx.Logger().With("upgrade", EncMempoolUpgradeName, "path", "force-operator")
	logger.Info("running encmempool/vpcap force (non-gov) one-shot")

	newVM, err := app.ModuleManager.RunMigrations(ctx, app.Configurator(), vm)
	if err != nil {
		return err
	}
	if err := app.UpgradeKeeper.SetModuleVersionMap(ctx, newVM); err != nil {
		return err
	}
	act, configured := envEncActivation()
	if err := app.applyEncMempoolInit(ctx, act, configured); err != nil {
		return err
	}
	logger.Info("encmempool/vpcap force one-shot complete")
	return nil
}
