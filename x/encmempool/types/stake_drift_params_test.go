package types

import "testing"

// TestValidate_StakeDriftParams locks the bounds on the cycle-5 stake-drift rekey params:
// both default 0 (OFF) and accepted; a cadence above the window ceiling and a drift threshold
// above 100% (10000 bps, above which the trigger could never fire) are rejected. Validation runs
// only under DkgEnabled, so a valid transparent DKG base is used.
func TestValidate_StakeDriftParams(t *testing.T) {
	base := func() Params {
		return Params{
			RevealDelay: 1, MaxRevealWindow: 100,
			DkgEnabled: true, DkgTransparent: true,
			DkgDealWindow: 20, DkgComplaintWindow: 10, DkgRetryBackoff: 5,
		}
	}
	// Default (both 0 = OFF) must validate.
	if err := base().Validate(); err != nil {
		t.Fatalf("default (triggers off) must validate, got %v", err)
	}
	// Enabled-but-in-bounds must validate.
	ok := base()
	ok.DkgMaxEpochBlocks = maxDkgWindowBlocks
	ok.DkgRekeyOnStakeDriftBps = maxDriftBps
	if err := ok.Validate(); err != nil {
		t.Fatalf("in-bounds triggers must validate, got %v", err)
	}
	// Cadence above the window ceiling is rejected.
	bad := base()
	bad.DkgMaxEpochBlocks = maxDkgWindowBlocks + 1
	if err := bad.Validate(); err == nil {
		t.Fatal("dkg_max_epoch_blocks above the ceiling must be rejected")
	}
	// Drift threshold above 100% (never-fires misconfig) is rejected.
	bad = base()
	bad.DkgRekeyOnStakeDriftBps = maxDriftBps + 1
	if err := bad.Validate(); err == nil {
		t.Fatal("dkg_rekey_on_stake_drift_bps above 10000 must be rejected")
	}
}
