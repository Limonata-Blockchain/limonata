// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

package types_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cosmos/evm/x/encmempool/types"
)

// TestParamsWireCompat_GateOffEmitsNothingNew is a CONSENSUS regression guard, not a style test.
//
// Params are persisted as a raw json.Marshal of the Go struct (keeper.SetParams writes the result
// straight to types.ParamsKey). There is no proto schema and no field whitelist, so the wire bytes
// are whatever the struct tags say. That makes any new field a potential app-hash change: a field
// tagged WITHOUT omitempty emits its zero value, so a node running the new binary writes a longer
// blob than the old binary wrote for the identical logical params.
//
// The consequences are not theoretical. Params are written at InitGenesis, at every gov
// MsgUpdateParams, and by the upgrade handlers (applyEncMempoolInit, applyDkgActivation). A blob
// that differs by even one byte means:
//   - sync-from-genesis fails at block 1 with "wrong Block.Header.AppHash";
//   - state sync fails whenever the snapshot-to-tip replay window contains a params write;
//   - a node that installed the new binary BEFORE its gov plan height FORKS from its peers the
//     moment any encmempool params update executes.
//
// So: every field added to Params from now on must be omitempty AND appended LAST, so that a blob
// written by an older binary re-marshals byte-identically. This test pins that rule.
func TestParamsWireCompat_GateOffEmitsNothingNew(t *testing.T) {
	// Shaped like a blob an older binary wrote: no key for any post-v0.3.4 field.
	const legacyBlob = `{"reveal_delay":1,"max_reveal_window":100,"enc_enabled":true,` +
		`"dkg_enabled":true,"dkg_transparent":true,"dkg_deal_window":20,` +
		`"dkg_complaint_window":10,"dkg_min_rekey_gap":30,"dkg_rekey_on_stake_drift_bps":500}`

	var p types.Params
	if err := json.Unmarshal([]byte(legacyBlob), &p); err != nil {
		t.Fatalf("a legacy params blob must still unmarshal: %v", err)
	}
	if p.DkgRetainActiveDealings {
		t.Fatal("an absent dkg_retain_active_dealings key must read as FALSE (the legacy rule), " +
			"otherwise historical blocks replay under the new behaviour and diverge")
	}
	if p.DkgStrictConcentration {
		t.Fatal("an absent dkg_strict_concentration key must read as FALSE (the legacy formula t=floor(2S/3)+1), " +
			"otherwise historical DKG finalizations replay under the +n threshold and diverge on app hash")
	}

	reMarshalled, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(reMarshalled), "dkg_retain_active_dealings") {
		t.Fatalf("CONSENSUS BREAK: re-marshalling a legacy params blob now EMITS the gate key.\n"+
			"Every params write would then differ from what the previous binary wrote, breaking\n"+
			"sync-from-genesis and state sync, and forking any node that runs ahead of its plan height.\n"+
			"Fix: tag the field `json:\"...,omitempty\"` and keep it LAST in the struct.\ngot: %s",
			reMarshalled)
	}
	if strings.Contains(string(reMarshalled), "dkg_strict_concentration") {
		t.Fatalf("CONSENSUS BREAK: re-marshalling a legacy params blob now EMITS dkg_strict_concentration.\n"+
			"Every params write would then differ from what the previous binary wrote, breaking\n"+
			"sync-from-genesis and state sync, and forking any node ahead of its plan height.\n"+
			"Fix: tag the field `json:\"...,omitempty\"` and keep it LAST in the struct.\ngot: %s",
			reMarshalled)
	}

	// The flags must still be expressible when genuinely on, or the upgrade handlers are no-ops.
	p.DkgRetainActiveDealings = true
	p.DkgStrictConcentration = true
	on, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(on), `"dkg_retain_active_dealings":true`) {
		t.Fatalf("the retain gate must serialise when true, got: %s", on)
	}
	if !strings.Contains(string(on), `"dkg_strict_concentration":true`) {
		t.Fatalf("the strict-concentration gate must serialise when true, got: %s", on)
	}

	// A fresh genesis (mainnet) must be born with the fixed rules - it has no legacy history to match.
	if !types.DefaultParams().DkgRetainActiveDealings {
		t.Fatal("DefaultParams must enable the retain gate so a fresh chain never runs the legacy purge rule")
	}
	if !types.DefaultParams().DkgStrictConcentration {
		t.Fatal("DefaultParams must enable the strict-concentration gate so a fresh chain is born with the two-clause guard")
	}
}
