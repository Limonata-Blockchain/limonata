package types

import (
	"encoding/json"
	"testing"
)

// LIVE-GENESIS INCOMPATIBILITY - measured, not assumed.
//
// This binary CANNOT resynchronise limonata_10777-1 from block 1. The live
// chain's genesis file carries app_state.contest with passkey_enabled=true and
// NO passkey_rp_id / passkey_allowed_origins (those params did not exist when
// 10777 was born; the passkey ante was bound to its RP later, in state). The
// fail-closed GenesisState.Validate() added to this build REJECTS that document,
// keeper.InitGenesis turns the error into a returned error, and
// x/contest/module.go:78 turns THAT into a panic inside InitChain - so a node
// replaying 10777 from height 0 with this binary dies before block 1.
//
// The fragment below is copied VERBATIM from the app_state.contest of the live
// limonata_10777-1 genesis.json. If this test ever starts passing, the
// incompatibility has changed and LIGNE-DE-BUILD.md must be updated.
func TestLiveChain10777Genesis_IsRejectedByThisBinary(t *testing.T) {
	const liveContestGenesis = `{
  "params": {
    "snapshot_unix": 1794355200,
    "dev_track_budget": "150000000000000000000000000",
    "tester_track_budget": "100000000000000000000000000",
    "weight_tx_volume": 1,
    "weight_gas_sponsored_per": 1,
    "gas_sponsored_divisor": "1000000000000000000",
    "weight_uaw": 10,
    "admin": "cosmos13z3z265c9mgfy282nlzvjaq8vhnzrz8ftvzuam",
    "passkey_enabled": true
  },
  "showcase": []
}`

	var gs GenesisState
	if err := json.Unmarshal([]byte(liveContestGenesis), &gs); err != nil {
		t.Fatalf("the live app_state.contest no longer unmarshals: %v", err)
	}
	if !gs.Params.PasskeyEnabled {
		t.Fatal("fixture drift: the live genesis has passkey_enabled=true")
	}
	if gs.Params.PasskeyRPID != "" || len(gs.Params.PasskeyAllowedOrigins) != 0 {
		t.Fatal("fixture drift: the live genesis has NO passkey_rp_id / passkey_allowed_origins")
	}

	err := gs.Validate()
	if err == nil {
		t.Fatal("Validate() accepted the live 10777 genesis: the documented resync " +
			"incompatibility has changed - update LIGNE-DE-BUILD.md")
	}
	t.Logf("this binary rejects the live 10777 genesis (as designed): %v", err)
}
