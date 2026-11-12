package types

import "testing"

// Fail-closed at genesis: a genesis that enables passkeys without RP binding
// config must be rejected.
func TestGenesisPasskeyFailClosed(t *testing.T) {
	gs := DefaultGenesisState()
	if err := gs.Validate(); err != nil {
		t.Fatalf("default genesis must be valid: %v", err)
	}

	gs.Params.PasskeyEnabled = true
	if err := gs.Validate(); err == nil {
		t.Fatal("passkey_enabled without rp_id/origins must be rejected")
	}

	gs.Params.PasskeyRPID = "limonata.xyz"
	if err := gs.Validate(); err == nil {
		t.Fatal("passkey_enabled without origins must be rejected")
	}

	gs.Params.PasskeyAllowedOrigins = []string{"https://limonata.xyz"}
	if err := gs.Validate(); err != nil {
		t.Fatalf("fully-configured passkey genesis must be valid: %v", err)
	}
}
