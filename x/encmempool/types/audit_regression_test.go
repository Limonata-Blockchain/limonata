package types

import "testing"

// TestRegression_ValidateRejectsBrokenThresholdParams regresses the threshold-param
// state-leak footgun: GenesisState.Validate() previously ignored every
// threshold-encryption param, so a genesis/upgrade that set EncEnabled=true with
// DecryptDelay=0 or Threshold=0 (both a permanent, per-user, unbounded EncTx state
// leak) passed validation. The fix must reject those while still accepting (a) the
// launch/default disabled config and (b) a well-formed enabled config, and while
// staying inert (no-op) when the path is disabled.
func TestRegression_ValidateRejectsBrokenThresholdParams(t *testing.T) {
	base := func() Params {
		return Params{
			RevealDelay: 1, MaxRevealWindow: 100,
			EncEnabled: true, ThresholdPub: []byte{0x02, 0x01},
			Threshold: 2, Keypers: []string{"k1", "k2", "k3"}, DecryptDelay: 1,
			MaxInFlightEncTx: 32768, // finding 4: a live path needs a finite global admission cap
		}
	}

	// well-formed enabled config: accepted.
	if err := (GenesisState{Params: base()}).Validate(); err != nil {
		t.Fatalf("well-formed enabled params must validate, got %v", err)
	}
	// launch/default (disabled) config: accepted.
	if err := DefaultGenesisState().Validate(); err != nil {
		t.Fatalf("default genesis must validate, got %v", err)
	}

	cases := []struct {
		name string
		mut  func(*Params)
	}{
		{"decrypt_delay_zero", func(p *Params) { p.DecryptDelay = 0 }},
		{"threshold_zero", func(p *Params) { p.Threshold = 0 }},
		{"threshold_exceeds_keypers", func(p *Params) { p.Threshold = 4 }},
		{"empty_pub", func(p *Params) { p.ThresholdPub = nil }},
		{"duplicate_keypers", func(p *Params) { p.Keypers = []string{"k1", "k1", "k2"} }},
		// finding 4: a live enc path must not run with the global admission cap disabled.
		{"max_in_flight_zero", func(p *Params) { p.MaxInFlightEncTx = 0 }},
	}
	for _, c := range cases {
		p := base()
		c.mut(&p)
		if err := (GenesisState{Params: p}).Validate(); err == nil {
			t.Fatalf("%s: expected Validate to REJECT, got nil", c.name)
		}
	}

	// disabled path: threshold params are inert, so even broken values validate.
	dp := base()
	dp.EncEnabled = false
	dp.DecryptDelay = 0
	dp.Threshold = 0
	dp.Keypers = nil
	if err := (GenesisState{Params: dp}).Validate(); err != nil {
		t.Fatalf("disabled path must ignore threshold params, got %v", err)
	}
}
