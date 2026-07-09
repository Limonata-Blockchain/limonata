//go:build !encmempoolforce

package evmd

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Default/production build: the env-driven encmempool FORCE path is COMPILED OUT (round-12 #1
// CRITICAL). No env var can add a store, run migrations, or mutate consensus params, so a validator
// fleet can never diverge on whether/how the encrypted mempool activates - only the deterministic
// GOV path (bakedEncActivation via the registered upgrade handler) can. Build the force path
// explicitly with `-tags encmempoolforce` for a single-operator dry-run.
func encMempoolForceUpgrade() bool { return false }

func (app *EVMD) maybeRunEncMempoolForceInit(_ sdk.Context) error { return nil }
