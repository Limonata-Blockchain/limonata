package evmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// round-12 #1 (CRITICAL): in the DEFAULT (production) build the env-driven encmempool FORCE path is
// compiled out, so setting the env cannot flip it on - the only way a validator could diverge on
// consensus state. This test runs in the default build (no -tags encmempoolforce), so it pins that
// the env is IGNORED. (A force build would compile upgrades_encforce.go instead; that binary is for
// single-operator dry-runs only.)
func TestEncMempoolForcePathCompiledOutByDefault(t *testing.T) {
	t.Setenv(EncMempoolForceUpgradeEnv, "1")
	t.Setenv(EncMempoolActivationEnv, `{"threshold_pub":"AAAA","threshold":2,"keypers":["a"],"decrypt_delay":15}`)
	require.False(t, encMempoolForceUpgrade(),
		"the env-driven force path MUST be inert in the default binary (no per-validator consensus divergence)")
}
