package types

import "fmt"

// Params govern the commit-reveal timing. RevealDelay is the minimum number of
// blocks between a commit and its reveal; MaxRevealWindow bounds how long an
// unrevealed commit lingers in state before it is garbage-collected.
type Params struct {
	RevealDelay     uint64 `json:"reveal_delay"`
	MaxRevealWindow uint64 `json:"max_reveal_window"`

	// --- threshold encryption (OPT-IN; OFF by default so the binary is inert
	// until governance activates it — the same safety pattern as x/vpcap) ---
	EncEnabled   bool     `json:"enc_enabled"`   // master switch for the encrypted path
	ThresholdPub []byte   `json:"threshold_pub"` // compressed threshold public key Y = x*G (LEGACY trusted-setup path)
	Threshold    uint32   `json:"threshold"`     // t: decryption shares required (LEGACY path)
	Keypers      []string `json:"keypers"`       // authorized keyper addrs (bech32); share index = position+1 (LEGACY path)
	DecryptDelay uint64   `json:"decrypt_delay"` // blocks between submit and decrypt-execute

	// --- on-chain validator DKG (OPT-IN; supersedes the LEGACY trusted setup
	// above when enabled). The active threshold key is then produced by the
	// validators' DKG (stored per-epoch), not by params.ThresholdPub. ---
	DkgEnabled         bool        `json:"dkg_enabled"`          // run the validator DKG + use its key
	DkgStartHeight     uint64      `json:"dkg_start_height"`     // open epoch 1 at/after this height
	DkgDealWindow      uint64      `json:"dkg_deal_window"`      // blocks a dealer has to post its dealing
	DkgComplaintWindow uint64      `json:"dkg_complaint_window"` // blocks for complaints after the deal window
	DkgThreshold       uint32      `json:"dkg_threshold"`        // t for the DKG; 0 => majority floor(n/2)+1
	DkgMembers         []DkgMember `json:"dkg_members"`          // genesis-declared member set (operator+account+enc key)

	// --- auto-retry / self-heal (a failed or timed-out round must NEVER leave the
	// chain permanently keyless; the EndBlocker reopens a fresh round automatically). ---
	DkgRetryBackoff uint64 `json:"dkg_retry_backoff"` // blocks to wait after a failed round before auto-reopening (>=1 enforced)
	DkgMaxAttempts  uint64 `json:"dkg_max_attempts"`  // consecutive-failure attempts before emitting a dkg_stalled ALERT (0 = never). NOT a hard stop: retries continue so the chain always converges once >= t members return.

	// DkgMinRekeyGap is the minimum number of blocks between successive MEMBER-CHANGE
	// re-genesis rounds. It DAMPENS an induced membership FLAP (a validator toggling
	// its bond to force endless rekeys / reset the retry backoff): a change arriving
	// within this many blocks of the last rekey is coalesced, so re-genesis happens at
	// most once per gap. A genuine SETTLED change is never delayed — it is preceded by
	// a stable period, so the gap has already elapsed and it rekeys immediately. 0
	// disables the dampener (rekey on every change). (HIGH-2 variant fix.)
	DkgMinRekeyGap uint64 `json:"dkg_min_rekey_gap"`
}

// DkgMember is a genesis-declared DKG participant. For this PoC the member set is
// declared (rather than derived from validator keys) so the chain need not wait for
// x/auth to have seen a pubkey; the ACTIVE member set each round is this list
// INTERSECTED with the currently-bonded validators (matched by OperatorAddr), which
// is what drives the Shutter/Penumbra-style re-run when the validator set changes.
//
// REMAINING GAP (deferred): deriving EncPubKey from a validator key instead of
// declaring it. The consensus key is ed25519 (wrong curve for the secp256k1 ECIES
// used to seal shares), so derivation would key off the operator ACCOUNT's
// eth_secp256k1 pubkey — which requires (a) wiring an AccountKeeper into this module,
// (b) a valoper->account lookup, and (c) handling accounts whose pubkey x/auth has
// not yet seen (never-signed). That is a non-trivial integration with real edge
// cases, so genesis-declared enc keys are retained here; the auto-derive is left as
// documented future work rather than destabilize the multi-node hardening.
type DkgMember struct {
	OperatorAddr string `json:"operator_addr"` // validator operator address (valoper bech32)
	AccountAddr  string `json:"account_addr"`  // the member's fee/signer account (bech32) = MsgDkgDeal.dealer
	EncPubKey    []byte `json:"enc_pubkey"`    // compressed secp256k1 encryption key (shares are sealed to this)
}

// RoundMember is a DkgMember with its assigned 1-based index for a specific round
// (rank by OperatorAddr among the active members at round-open).
type RoundMember struct {
	Index        uint64 `json:"index"`
	OperatorAddr string `json:"operator_addr"`
	AccountAddr  string `json:"account_addr"`
	EncPubKey    []byte `json:"enc_pubkey"`
}

// DKG round status values.
const (
	DkgStatusOpen   = "open"   // dealing/complaint windows are in progress
	DkgStatusActive = "active" // finalized successfully; an ActiveThresholdKey was installed
	DkgStatusFailed = "failed" // |QUAL| < t (or timed out); the EndBlocker auto-reopens a fresh round
)

// DkgRound is one DKG epoch's on-chain record.
type DkgRound struct {
	Epoch             uint64        `json:"epoch"`
	OpenHeight        uint64        `json:"open_height"`
	DealDeadline      uint64        `json:"deal_deadline"`      // deals accepted while height <= this
	ComplaintDeadline uint64        `json:"complaint_deadline"` // finalize runs at height >= this
	Members           []RoundMember `json:"members"`
	Threshold         uint32        `json:"threshold"`
	MembersHash       []byte        `json:"members_hash"` // hash of the active operator set (re-run trigger)
	Status            string        `json:"status"`
	// Attempt is the 1-based try count within the CURRENT convergence campaign: it is
	// 1 for a first run or a fresh campaign after a membership change, and increments
	// on every auto-retry of a failed round. It resets to 1 once a key is installed.
	Attempt uint64 `json:"attempt"`
}

// DkgStoredEncShare is one encrypted point-to-point share as stored on chain.
type DkgStoredEncShare struct {
	MemberIndex uint64 `json:"member_index"`
	A           []byte `json:"a"`
	Nonce       []byte `json:"nonce"`
	Body        []byte `json:"body"`
}

// Dealing is a dealer's stored on-chain contribution for an epoch.
type Dealing struct {
	Epoch       uint64              `json:"epoch"`
	DealerIndex uint64              `json:"dealer_index"`
	Dealer      string              `json:"dealer"` // account addr
	Commitments [][]byte            `json:"commitments"`
	EncShares   []DkgStoredEncShare `json:"enc_shares"`
}

// DkgComplaintRec is a stored, already-verified justified complaint. Its presence
// disqualifies the accused dealer at finalize.
type DkgComplaintRec struct {
	Epoch        uint64 `json:"epoch"`
	Against      uint64 `json:"against"`
	AccuserIndex uint64 `json:"accuser_index"`
}

// ActiveThresholdKey is the DKG output installed as the active encryption key for
// an epoch. It REPLACES the trusted params.ThresholdPub while DKG is enabled.
type ActiveThresholdKey struct {
	Epoch             uint64   `json:"epoch"`
	Pub               []byte   `json:"pub"`                // compressed msk*G
	PublicCommitments [][]byte `json:"public_commitments"` // aggregate V_j (for RecoverVerified)
	Threshold         uint32   `json:"threshold"`
	Qual              []uint64 `json:"qual"`
}

// Commit is a recorded hash-commitment to a future transaction.
type Commit struct {
	Sender     string `json:"sender"`
	CommitHash []byte `json:"commit_hash"` // sha256(reveal_tx || salt)
	Height     uint64 `json:"height"`      // block height the commit was recorded at
	Seq        uint64 `json:"seq"`
}

// PendingReveal is a validated reveal queued for deterministic execution in BeginBlock.
type PendingReveal struct {
	Sender       string `json:"sender"`
	CommitHeight uint64 `json:"commit_height"`
	Seq          uint64 `json:"seq"`
	RevealTx     []byte `json:"reveal_tx"`
	Salt         []byte `json:"salt"`
}

// EncTx is an encrypted transaction (threshold ciphertext) submitted for a future
// decrypt height. Stored ORDERED by (decryptHeight, seq) — the order is fixed
// before anyone can read the body, which is the anti-MEV property.
type EncTx struct {
	Submitter     string `json:"submitter"`
	SubmitHeight  uint64 `json:"submit_height"`
	DecryptHeight uint64 `json:"decrypt_height"` // submit_height + DecryptDelay
	Seq           uint64 `json:"seq"`
	A             []byte `json:"a"`     // ciphertext component r*G (compressed)
	Nonce         []byte `json:"nonce"` // AES-GCM nonce
	Body          []byte `json:"body"`  // AES-256-GCM ciphertext
	Epoch         uint64 `json:"epoch"` // DKG epoch whose key this was encrypted to (0 = legacy)
}

// EncShare is a keyper's threshold decryption share (x_i * A) for one EncTx.
type EncShare struct {
	Keyper        string `json:"keyper"`
	DecryptHeight uint64 `json:"decrypt_height"`
	Seq           uint64 `json:"seq"`   // the EncTx this share is for
	Index         uint64 `json:"index"` // keyper share index (1..n)
	D             []byte `json:"d"`     // compressed x_i * A
	Proof         []byte `json:"proof"` // DLEQ proof (C||Z, 64 bytes) binding D to Y_index; empty on legacy path
}

// GenesisState is the x/encmempool genesis (plain JSON, no proto).
type GenesisState struct {
	Params  Params          `json:"params"`
	Commits []Commit        `json:"commits"`
	Pending []PendingReveal `json:"pending"`
}

func DefaultParams() Params {
	return Params{
		RevealDelay: 1, MaxRevealWindow: 100, EncEnabled: false, DecryptDelay: 1,
		// DKG is OFF by default. When enabled, these windows are sized for a REAL
		// multi-node network (independent validators over p2p + a daemon that must
		// observe the open, build a dealing, and land the tx) rather than the tiny
		// single-node smoke-test windows. At ~2s blocks: deal ~40s, complaint ~20s,
		// retry backoff ~10s. All are governance-tunable per deployment.
		DkgEnabled: false, DkgDealWindow: 20, DkgComplaintWindow: 10,
		DkgRetryBackoff: 5, DkgMaxAttempts: 8,
		// Dampen a membership FLAP: never re-genesis on member change more than once per
		// ~30 blocks (~60s at 2s blocks — roughly one deal+complaint window). Governance
		// tunable; 0 disables. A genuine settled change is not delayed (see field doc).
		DkgMinRekeyGap: 30,
	}
}

func DefaultGenesisState() *GenesisState {
	return &GenesisState{Params: DefaultParams(), Commits: []Commit{}, Pending: []PendingReveal{}}
}

func (gs GenesisState) Validate() error {
	if gs.Params.RevealDelay == 0 {
		return fmt.Errorf("reveal_delay must be >= 1")
	}
	if gs.Params.MaxRevealWindow < gs.Params.RevealDelay {
		return fmt.Errorf("max_reveal_window (%d) must be >= reveal_delay (%d)", gs.Params.MaxRevealWindow, gs.Params.RevealDelay)
	}
	if gs.Params.DkgEnabled {
		if len(gs.Params.DkgMembers) == 0 {
			return fmt.Errorf("dkg_enabled requires a non-empty dkg_members set")
		}
		seenOp, seenAcc := map[string]bool{}, map[string]bool{}
		for i, m := range gs.Params.DkgMembers {
			if m.OperatorAddr == "" || m.AccountAddr == "" {
				return fmt.Errorf("dkg_members[%d]: operator_addr and account_addr are required", i)
			}
			if len(m.EncPubKey) != 33 {
				return fmt.Errorf("dkg_members[%d]: enc_pubkey must be a 33-byte compressed key, got %d", i, len(m.EncPubKey))
			}
			if seenOp[m.OperatorAddr] || seenAcc[m.AccountAddr] {
				return fmt.Errorf("dkg_members[%d]: duplicate operator/account address", i)
			}
			seenOp[m.OperatorAddr], seenAcc[m.AccountAddr] = true, true
		}
		if n := len(gs.Params.DkgMembers); gs.Params.DkgThreshold != 0 && int(gs.Params.DkgThreshold) > n {
			return fmt.Errorf("dkg_threshold (%d) must be <= number of members (%d)", gs.Params.DkgThreshold, n)
		}
		if err := gs.Params.ValidateDkgWindows(); err != nil {
			return err
		}
	}
	return nil
}

// DKG window bounds. MEDIUM FIX: without these, governance (or a hand-built genesis)
// could set a nonsensical window that degenerates or wedges the round machine — a
// zero deal/complaint window (finalize would run before anyone can deal/complain, or
// a bad dealer could finalize uncontestable) or a zero retry backoff (a failed round
// would busy-reopen every block). The upper cap keeps every deadline far below the
// uint64 saturation point so a mis-set window can never approach an overflow. These
// mirror the runtime floors openRound already applies (max(window,1)), promoted to an
// up-front validation so a bad param is rejected at ingress instead of silently
// clamped. DkgMaxAttempts=0 is intentionally allowed (it means "never alert").
const (
	minDkgWindowBlocks uint64 = 1
	maxDkgWindowBlocks uint64 = 10_000_000
)

// ValidateDkgWindows bounds the DKG timing params. Only meaningful when DkgEnabled.
func (p Params) ValidateDkgWindows() error {
	for _, f := range []struct {
		name string
		v    uint64
	}{
		{"dkg_deal_window", p.DkgDealWindow},
		{"dkg_complaint_window", p.DkgComplaintWindow},
		{"dkg_retry_backoff", p.DkgRetryBackoff},
	} {
		if f.v < minDkgWindowBlocks || f.v > maxDkgWindowBlocks {
			return fmt.Errorf("%s (%d) must be in [%d, %d]", f.name, f.v, minDkgWindowBlocks, maxDkgWindowBlocks)
		}
	}
	// DkgMinRekeyGap may be 0 (disabled) but not absurdly large.
	if p.DkgMinRekeyGap > maxDkgWindowBlocks {
		return fmt.Errorf("dkg_min_rekey_gap (%d) must be <= %d", p.DkgMinRekeyGap, maxDkgWindowBlocks)
	}
	// DkgMaxAttempts=0 means "never alert" (retries continue regardless); only guard
	// against an absurd upper bound.
	if p.DkgMaxAttempts > maxDkgWindowBlocks {
		return fmt.Errorf("dkg_max_attempts (%d) must be <= %d", p.DkgMaxAttempts, maxDkgWindowBlocks)
	}
	return nil
}
