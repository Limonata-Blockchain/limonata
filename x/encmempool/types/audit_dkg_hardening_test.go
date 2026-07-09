package types

import (
	"bytes"
	"testing"

	sdkmath "cosmossdk.io/math"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/cosmos/evm/x/encmempool/threshold"
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
	p.DkgMaxMembers = 64
	p.DkgShareBudget = 512
	if err := p.Validate(); err == nil {
		t.Fatal("a committee*share-budget that fits raw MaxTxBytes but exceeds the proposer trim budget must be rejected")
	}
	// max committee (128) + max S (1024): a >2/3 aggregate ~79 MB >> 20 MB floor -> rejected.
	p = base()
	p.DkgMaxMembers = 128
	p.DkgShareBudget = 1024
	if err := p.Validate(); err == nil {
		t.Fatal("a committee*share-budget whose 2/3 aggregate exceeds MaxTxBytes must be rejected")
	}
}

func TestGenesisValidatesImportedDKGState(t *testing.T) {
	pt := func(x byte) []byte {
		return secp256k1.PrivKeyFromBytes([]byte{x}).PubKey().SerializeCompressed()
	}
	valid := func() GenesisState {
		nonce := make([]byte, threshold.NonceSize)
		round := DkgRound{
			Epoch: 1, OpenHeight: 10, DealDeadline: 12, ComplaintDeadline: 14,
			Threshold: 3, Status: DkgStatusActive, Attempt: 1,
			Members: []RoundMember{
				{Index: 1, OperatorAddr: "op1", EncPubKey: pt(1), Weight: sdkmath.NewInt(2), Weighted: true, EvalPoints: []uint64{1, 2}},
				{Index: 2, OperatorAddr: "op2", EncPubKey: pt(2), Weight: sdkmath.NewInt(2), Weighted: true, EvalPoints: []uint64{3, 4}},
			},
		}
		return GenesisState{
			Params:       DefaultParams(),
			DkgRounds:    []DkgRound{round},
			ActiveKeys:   []ActiveThresholdKey{{Epoch: 1, Pub: pt(3), PublicCommitments: [][]byte{pt(4), pt(5), pt(6)}, Threshold: 3, Qual: []uint64{1, 2}}},
			CurrentEpoch: 1,
			ActiveEpoch:  1,
			Dealings: []Dealing{{
				Epoch: 1, DealerIndex: 1, Dealer: "op1",
				Commitments: [][]byte{pt(7), pt(8), pt(9)},
				EncShares: []DkgStoredEncShare{
					{MemberIndex: 1, A: pt(10), Nonce: nonce, Body: []byte{1}},
					{MemberIndex: 2, A: pt(11), Nonce: nonce, Body: []byte{1}},
					{MemberIndex: 3, A: pt(12), Nonce: nonce, Body: []byte{1}},
					{MemberIndex: 4, A: pt(13), Nonce: nonce, Body: []byte{1}},
				},
			}},
			EncKeys: []EncKeyReg{{Operator: "op1", Key: pt(1)}, {Operator: "op2", Key: pt(2)}},
		}
	}

	if err := valid().Validate(); err != nil {
		t.Fatalf("coherent imported DKG state must validate: %v", err)
	}

	gs := valid()
	gs.DkgRounds[0].Members[1].EvalPoints = []uint64{2, 4}
	if err := gs.Validate(); err == nil {
		t.Fatal("duplicate imported eval points must be rejected")
	}

	gs = valid()
	gs.Dealings[0].EncShares = gs.Dealings[0].EncShares[:3]
	if err := gs.Validate(); err == nil {
		t.Fatal("dealing missing an eval-point share must be rejected")
	}

	gs = valid()
	gs.ActiveKeys[0].Pub = []byte("not-a-point")
	if err := gs.Validate(); err == nil {
		t.Fatal("active key with malformed pubkey must be rejected")
	}

	gs = valid()
	gs.ActiveEpoch = 2
	if err := gs.Validate(); err == nil {
		t.Fatal("active_epoch without a matching round/key must be rejected")
	}

	gs = valid()
	gs.DkgRounds[0].Threshold = 2
	gs.ActiveKeys[0].Threshold = 2
	gs.ActiveKeys[0].PublicCommitments = [][]byte{pt(4), pt(5)}
	if err := gs.Validate(); err == nil {
		t.Fatal("weighted imported round with threshold below strict >2/3 must be rejected")
	}

	gs = valid()
	gs.DkgRounds[0].Members[0].Weight = sdkmath.ZeroInt()
	if err := gs.Validate(); err == nil {
		t.Fatal("weighted imported round with eval points but non-positive weight must be rejected")
	}

	gs = valid()
	gs.EncKeys = append(gs.EncKeys, EncKeyReg{Operator: "op1", Key: pt(14)})
	if err := gs.Validate(); err == nil {
		t.Fatal("duplicate imported enc-key operators must be rejected")
	}

	gs = valid()
	gs.EncKeys = append(gs.EncKeys, EncKeyReg{Operator: "op3", Key: pt(1)})
	if err := gs.Validate(); err == nil {
		t.Fatal("duplicate imported enc-key material must be rejected")
	}

	gs = valid()
	nonce := make([]byte, threshold.NonceSize)
	gs.EncSeq = 2
	gs.EncTxs = []EncTx{{DecryptHeight: 20, Seq: 1, Submitter: "alice", A: pt(14), Nonce: nonce, Body: []byte{1}, Epoch: 1}}
	gs.EncShares = []EncShare{
		{Keyper: "op1", DecryptHeight: 20, Seq: 1, Index: 1, D: pt(15)},
		{Keyper: "op2", DecryptHeight: 20, Seq: 1, Index: 1, D: pt(16)},
	}
	if err := gs.Validate(); err == nil {
		t.Fatal("duplicate imported decrypt-share slots must be rejected")
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
