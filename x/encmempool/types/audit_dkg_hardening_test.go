package types

import (
	"bytes"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"testing"
)

// Finding 2: the stake-drift / epoch-cadence rekey triggers must ship ON by default so
// decryption power cannot follow a stale stake snapshot indefinitely. Both were 0
// (disabled) before; assert non-zero, sane, and within their validation bounds.
func TestDefaultParamsShipRekeyTriggers(t *testing.T) {
	p := DefaultParams()
	if p.DkgRekeyOnStakeDriftBps == 0 {
		t.Fatal("dkg_rekey_on_stake_drift_bps defaults to 0 (stale-stake rekey disabled)")
	}
	if p.DkgMaxEpochBlocks == 0 {
		t.Fatal("dkg_max_epoch_blocks defaults to 0 (epoch-cadence rekey disabled)")
	}
	if p.DkgRekeyOnStakeDriftBps > maxDriftBps {
		t.Fatalf("drift bps default %d exceeds max %d", p.DkgRekeyOnStakeDriftBps, maxDriftBps)
	}
	if p.DkgMaxEpochBlocks > maxDkgWindowBlocks {
		t.Fatalf("epoch-blocks default %d exceeds max %d", p.DkgMaxEpochBlocks, maxDkgWindowBlocks)
	}
	// The default genesis (DKG off) must still validate.
	if err := DefaultGenesisState().Validate(); err != nil {
		t.Fatalf("default genesis must validate: %v", err)
	}
}

// Finding 2 (fail-closed): a LIVE transparent encrypted path must not validate with both
// staleness-rekey triggers disabled — else governance could silently re-open the stale-
// stake hole the non-zero defaults close. One trigger armed is enough; the legacy
// (non-transparent) DKG path is unaffected.
func TestTransparentRequiresRekeyTrigger(t *testing.T) {
	base := func() Params {
		return Params{
			RevealDelay: 1, MaxRevealWindow: 100, EncEnabled: true, DecryptDelay: 2,
			MaxInFlightEncTx: 32768,
			DkgEnabled:       true, DkgTransparent: true, DkgStartHeight: 1,
			DkgDealWindow: 2, DkgComplaintWindow: 2, DkgThreshold: 2, DkgMaxMembers: 16,
			DkgRetryBackoff: 5, DkgMaxAttempts: 8, DkgShareBudget: 128,
		}
	}
	// both triggers 0 on a live transparent path: rejected.
	if err := base().Validate(); err == nil {
		t.Fatal("transparent+enc path with both rekey triggers 0 must be rejected")
	}
	// drift trigger armed: accepted.
	p := base()
	p.DkgRekeyOnStakeDriftBps = 500
	if err := p.Validate(); err != nil {
		t.Fatalf("drift trigger armed must validate: %v", err)
	}
	// epoch cadence armed: accepted.
	p = base()
	p.DkgMaxEpochBlocks = 43200
	if err := p.Validate(); err != nil {
		t.Fatalf("epoch cadence armed must validate: %v", err)
	}
	// legacy (non-transparent) DKG path is not subject to the trigger requirement.
	p = base()
	p.DkgTransparent = false
	// a REAL compressed secp256k1 point (the generator G) - a non-point is now rejected (round-8 #6).
	genG := secp256k1.PrivKeyFromBytes([]byte{0x01}).PubKey().SerializeCompressed()
	p.DkgMembers = []DkgMember{{OperatorAddr: "op1", AccountAddr: "acc1", EncPubKey: genG}}
	p.DkgThreshold = 1
	if err := p.Validate(); err != nil {
		t.Fatalf("legacy declared DKG path must not require a rekey trigger: %v", err)
	}
}

// round-8 #3: a valid-but-huge (committee, share-budget) whose >2/3 injected-commit aggregate would
// exceed the assumed MaxTxBytes floor must be REJECTED (else DKG injection can never fit -> stall).
// The default committee/budget is well within budget.
func TestCommitteeShareBudgetCoupledToMaxTxBytes(t *testing.T) {
	base := func() Params {
		return Params{
			RevealDelay: 1, MaxRevealWindow: 100, EncEnabled: true, DecryptDelay: 2, MaxInFlightEncTx: 32768,
			DkgEnabled: true, DkgTransparent: true, DkgStartHeight: 1,
			DkgDealWindow: 2, DkgComplaintWindow: 2, DkgRetryBackoff: 5, DkgMaxAttempts: 8,
			DkgRekeyOnStakeDriftBps: 500,
		}
	}
	// default committee (16) + a moderate S: fits.
	p := base()
	p.DkgMaxMembers = 16
	p.DkgShareBudget = 256
	if err := p.Validate(); err != nil {
		t.Fatalf("default-ish committee/budget must fit MaxTxBytes: %v", err)
	}
	// max committee (128) + max S (1024): a >2/3 aggregate ~79 MB >> 20 MB floor -> rejected.
	p = base()
	p.DkgMaxMembers = 128
	p.DkgShareBudget = 1024
	if err := p.Validate(); err == nil {
		t.Fatal("a committee*share-budget whose 2/3 aggregate exceeds MaxTxBytes must be rejected")
	}
}

// Finding 6: the pre-decode object-count bound in VerifyVoteExtension rests on the
// invariant that a '{' byte in a marshalled VoteExtension can ONLY open a real JSON
// object — because every field value is a uint64 or a Go-base64 []byte (whose alphabet
// excludes '{') and there are no free-form string fields. If that ever breaks (e.g. a
// string field is added), the byte count would under-count objects and the bound could
// be bypassed. This test pins the invariant: count('{') == exact object count.
func TestVoteExtObjectCountInvariant(t *testing.T) {
	// Build a VE exercising every object-bearing array: a dealing (wrapper + enc_shares),
	// decryption shares, and complaints. Fill the []byte fields with values whose RAW bytes
	// contain '{' (0x7b) to prove the base64 encoding neutralizes them.
	brace := []byte{0x7b, 0x7b, 0x7b, 0x7b} // '{{{{' as raw bytes -> base64, never literal '{'
	ve := VoteExtension{
		EncPubKey:    brace,
		EncPubKeyPoP: brace,
		Dealing: &VoteExtDealing{
			Epoch:       1,
			Commitments: [][]byte{brace, brace},
			EncShares: []DkgStoredEncShare{
				{MemberIndex: 1, A: brace, Nonce: brace, Body: brace},
				{MemberIndex: 2, A: brace, Nonce: brace, Body: brace},
			},
		},
		Shares: []VoteExtShare{
			{Epoch: 1, DecryptHeight: 8, Seq: 0, Index: 1, D: brace, Proof: brace},
			{Epoch: 1, DecryptHeight: 8, Seq: 1, Index: 2, D: brace, Proof: brace},
			{Epoch: 1, DecryptHeight: 9, Seq: 0, Index: 3, D: brace, Proof: brace},
		},
		Complaints: []VoteExtComplaint{
			{Epoch: 1, Against: 2, EvalPoint: 5, SharedPoint: brace, DleqProof: brace},
		},
	}

	// Exact object count: 1 top-level + 1 dealing wrapper + 2 enc_shares + 3 shares + 1 complaint = 8.
	const wantObjects = 1 + 1 + 2 + 3 + 1

	blob := MarshalVoteExtension(ve)
	// MarshalVoteExtension prefixes a version byte; the '{' count is over the JSON body.
	got := bytes.Count(blob, []byte{'{'})
	if got != wantObjects {
		t.Fatalf("'{' count %d != exact object count %d — the object-count bound's safety invariant is broken "+
			"(a value must have introduced a literal '{'; check for a new string field)", got, wantObjects)
	}

	// And the payload must round-trip (the base64-encoded braces decode back to raw bytes).
	back, ok := UnmarshalVoteExtension(blob)
	if !ok {
		t.Fatal("marshalled VE failed to round-trip")
	}
	if !bytes.Equal(back.EncPubKey, brace) || len(back.Shares) != 3 || len(back.Complaints) != 1 {
		t.Fatal("round-trip lost payload")
	}
}
