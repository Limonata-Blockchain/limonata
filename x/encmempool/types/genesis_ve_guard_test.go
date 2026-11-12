package types

import (
	"encoding/json"
	"strings"
	"testing"
)

// veGenesis builds the smallest genesis fragment that arms the transparent DKG.
func veGenesis(t *testing.T, transparent bool) json.RawMessage {
	t.Helper()
	p := DefaultParams()
	p.EncEnabled = true
	p.DkgEnabled = true
	p.DkgTransparent = transparent
	gs := GenesisState{Params: p}
	if transparent {
		// The transparent fragment must be a genesis this build would otherwise ACCEPT, so
		// the VE guard is provably the thing that rejects it and not some unrelated params
		// error. (The opaque variant is skipped here: an opaque dkg_enabled genesis also
		// needs a declared dkg_members list, which is irrelevant to this guard.)
		if err := gs.Validate(); err != nil {
			t.Fatalf("fixture is not a valid genesis on its own: %v", err)
		}
	}
	bz, err := json.Marshal(gs)
	if err != nil {
		t.Fatal(err)
	}
	return bz
}

// The LIVE limonata_10777-1 app_state.encmempool, copied verbatim. Its consensus section
// carries vote_extensions_enable_height = 0. The guard must be a NO-OP on it: the DKG was
// activated by governance long after genesis, so the genesis document never armed it.
const live10777EncMempool = `{"params":{"reveal_delay":2,"max_reveal_window":200},"commits":[],"pending":[]}`

func TestGenesisVoteExtensions_Live10777IsUnaffected(t *testing.T) {
	if err := ValidateGenesisVoteExtensions(json.RawMessage(live10777EncMempool), 0, 22020096); err != nil {
		t.Fatalf("the live 10777 genesis must still pass the VE guard, got: %v", err)
	}
}

func TestGenesisVoteExtensions_AbsentModuleIsNoop(t *testing.T) {
	if err := ValidateGenesisVoteExtensions(nil, 0, 0); err != nil {
		t.Fatalf("absent module must be a no-op, got: %v", err)
	}
	if err := ValidateGenesisVoteExtensions(json.RawMessage{}, 0, 0); err != nil {
		t.Fatalf("empty fragment must be a no-op, got: %v", err)
	}
}

func TestGenesisVoteExtensions_TransparentWithoutScheduledVEIsRejected(t *testing.T) {
	err := ValidateGenesisVoteExtensions(veGenesis(t, true), 0, 22020096)
	if err == nil {
		t.Fatal("dkg_transparent at genesis with vote_extensions_enable_height=0 must be rejected")
	}
	if !strings.Contains(err.Error(), "vote_extensions_enable_height") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenesisVoteExtensions_OpaqueDkgWithoutVEIsAccepted(t *testing.T) {
	// The OPAQUE (off-chain keyper) DKG does not ride vote extensions; it must not be
	// caught by this guard.
	if err := ValidateGenesisVoteExtensions(veGenesis(t, false), 0, 22020096); err != nil {
		t.Fatalf("opaque DKG must not require vote extensions, got: %v", err)
	}
}

func TestGenesisVoteExtensions_ScheduledVEIsAccepted(t *testing.T) {
	if err := ValidateGenesisVoteExtensions(veGenesis(t, true), 1, 22020096); err != nil {
		t.Fatalf("scheduled vote extensions must be accepted, got: %v", err)
	}
}

func TestGenesisVoteExtensions_TooSmallMaxBytesIsRejected(t *testing.T) {
	p := DefaultParams()
	p.DkgEnabled = true
	p.DkgTransparent = true
	gs := GenesisState{Params: p}
	// A block max_bytes far below the estimated injected-commit aggregate.
	small := gs.Params.DkgInjectedCommitBytesUpperBound() / 2
	if small <= 0 {
		t.Fatal("bad fixture: upper bound is not positive")
	}
	err := gs.ValidateVoteExtensions(1, small)
	if err == nil {
		t.Fatalf("an injected commit of ~%d bytes must not be accepted under max_bytes %d",
			gs.Params.DkgInjectedCommitBytesUpperBound(), small)
	}
	if !strings.Contains(err.Error(), "max_tx_bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
	// max_bytes unknown (0) skips the size clause, exactly as MsgUpdateParams does.
	if err := gs.ValidateVoteExtensions(1, 0); err != nil {
		t.Fatalf("unknown max_bytes must skip the size clause, got: %v", err)
	}
}

func TestGenesisVoteExtensions_RejectsMalformedFragment(t *testing.T) {
	if err := ValidateGenesisVoteExtensions(json.RawMessage(`{`), 1, 0); err == nil {
		t.Fatal("a malformed encmempool genesis fragment must be reported, not ignored")
	}
}
