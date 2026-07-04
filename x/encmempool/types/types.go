package types

import (
	"fmt"

	sdkmath "cosmossdk.io/math"
)

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

	// --- ADMISSION CONTROL: bound the in-flight EncTx state a flooder can create.
	// A SubmitEncrypted whose acceptance would exceed either ceiling is REJECTED at
	// ingress, so a flood cannot grow EncTx state (or the per-block decrypt scan) without
	// bound or starve honest ciphertexts. 0 disables the check (the always-on absolute
	// constant ceiling in the keeper still guarantees bounded state as a last resort). ---
	MaxInFlightEncTx        uint64 `json:"max_in_flight_enc_tx"`        // global ceiling on un-matured EncTx (0 = disabled)
	MaxInFlightPerSubmitter uint64 `json:"max_in_flight_per_submitter"` // per-submitter ceiling on un-matured EncTx (0 = disabled)

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

	// --- TRANSPARENT in-node DKG (ABCI++ vote extensions) ---
	//
	// DkgTransparent switches the member set from the genesis-DECLARED DkgMembers list to
	// the set of BONDED VALIDATORS that have auto-announced a DKG enc key via a vote
	// extension — i.e. any validator that simply RUNS THE BINARY becomes a member, with
	// no declared list, no account/fee setup, and no separate daemon. When true, DkgMembers
	// may be empty (members are derived on-chain). When false, the legacy declared-member
	// path (with the off-chain `evmd dkg start` daemon) is used unchanged. It is a distinct
	// switch from DkgEnabled so the transparent path can be validated/staged independently;
	// BOTH must be on (plus a consensus-param VoteExtensionsEnableHeight) for the in-node
	// DKG to run — keeping the module dormant by default.
	DkgTransparent bool `json:"dkg_transparent"`

	// DkgMaxMembers caps the DKG COMMITTEE to the top-N bonded validators by stake weight
	// (0 => the built-in DefaultDkgMaxMembers cap). Bounding the committee bounds the
	// vote-extension / injected-block-data size on a large validator set. Only meaningful
	// on the transparent path.
	DkgMaxMembers uint32 `json:"dkg_max_members"`

	// DkgShareBudget is the FIXED total number of Shamir evaluation points S the transparent
	// committee's stake is apportioned across (HIGH-3 stake-weighted secret sharing). Each
	// member gets ~round(stake_fraction * S) distinct points, and the reconstruction
	// threshold is t = floor(2S/3)+1 of them, so gathering t points requires a stake
	// supermajority. It is a FIXED cap (0 => DefaultDkgShareBudget=256) so the per-dealing /
	// vote-extension size stays O(S) regardless of raw stake magnitude. Only meaningful on
	// the transparent path.
	DkgShareBudget uint32 `json:"dkg_share_budget"`
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
	// Weight is the member's committee STAKE weight, snapshotted at round-open (the
	// transparent path records the validator's tokens; the legacy declared path leaves it
	// zero). It is NOT part of MembersHash, so a validator's stake drifting does not churn
	// the member set / trigger a rekey. HIGH-3 uses it to allocate EvalPoints proportional
	// to stake (see below), so a stake-minority Sybil that grabbed a seat-majority still
	// cannot reconstruct the epoch secret. Zero/absent on the legacy path.
	Weight sdkmath.Int `json:"weight"`

	// EvalPoints are the Shamir EVALUATION POINTS (share indices) this member owns for the
	// round, allocated PROPORTIONAL to its stake Weight within a bounded total budget S
	// (HIGH-3). A member with stake fraction w owns ~round(w*S) distinct points; the whole
	// committee's points are the contiguous domain 1..S. Because the reconstruction
	// threshold t is a fraction of S (t = floor(2S/3)+1), assembling t points requires a
	// stake supermajority — so a stake-MINORITY seat-MAJORITY holds < t points and CANNOT
	// reconstruct the secret even off-chain. It is a deterministic pure function of the
	// snapshotted Weight (see keeper.AllocateEvalPoints) so every node allocates identically.
	//
	// EMPTY on the legacy/declared path (and on hand-built rounds): the member then owns the
	// single point equal to its Index — see OwnedEvalPoints — which preserves the original
	// unweighted (one-share-per-member, count-threshold) behaviour byte-for-byte.
	EvalPoints []uint64 `json:"eval_points,omitempty"`
}

// OwnedEvalPoints returns the Shamir evaluation points this member holds a share at.
//
//   - Stake-weighted transparent path: its allocated EvalPoints. A member allocated ZERO points
//     (negligible stake) owns NOTHING — the empty result is correct, NOT a fallback to its index.
//     Such a member is identified by carrying a positive stake Weight while having no EvalPoints.
//   - Unweighted legacy/declared/hand-built round: no stake Weight is recorded, so the member
//     falls back to the single point equal to its Index (one share per member), preserving the
//     original scheme byte-for-byte.
func (m RoundMember) OwnedEvalPoints() []uint64 {
	if len(m.EvalPoints) > 0 {
		return m.EvalPoints
	}
	if !m.Weight.IsNil() && m.Weight.IsPositive() {
		return nil // weighted member allocated zero points: owns no shares
	}
	return []uint64{m.Index}
}

// OwnsEvalPoint reports whether this member holds a share at Shamir evaluation point p.
func (m RoundMember) OwnsEvalPoint(p uint64) bool {
	for _, q := range m.OwnedEvalPoints() {
		if q == p {
			return true
		}
	}
	return false
}

// TotalEvalPoints is the size of the round's Shamir evaluation-point domain S' = Σ|EvalPoints|
// over all members (the bounded budget S on the weighted path; the member count n on the
// unweighted path). It is what the reconstruction threshold is a fraction of.
func TotalEvalPoints(members []RoundMember) int {
	total := 0
	for _, m := range members {
		total += len(m.OwnedEvalPoints())
	}
	return total
}

// EvalPointOwner returns the member index that owns Shamir evaluation point p in the round,
// or 0 if p is not owned by any member. Used to authorize a decryption share carried on a
// vote extension (the share's index must be a point its operator actually owns).
func EvalPointOwner(members []RoundMember, p uint64) uint64 {
	for _, m := range members {
		if m.OwnsEvalPoint(p) {
			return m.Index
		}
	}
	return 0
}

// MemberIndexByOperator returns the 1-based DKG member index for `operator` in `members`,
// or 0 if the operator is not a member. This is the OPERATOR-keyed self-identifier that
// replaces the enc-key first-match: the operator is the validator's real consensus
// identity (resolved from its consensus address), so it cannot be spoofed by a colliding
// enc key. HIGH-4.
func MemberIndexByOperator(members []RoundMember, operator string) uint64 {
	if operator == "" {
		return 0
	}
	for _, m := range members {
		if m.OperatorAddr == operator {
			return m.Index
		}
	}
	return 0
}

// VoteExtEnabledAt reports whether CometBFT vote extensions are ACTIVE at blockHeight,
// given the consensus-param enable height. It mirrors baseapp.ValidateVoteExtensions'
// own gate EXACTLY (enableHeight != 0 AND blockHeight > enableHeight), so the transparent
// DKG's handlers act if and only if ValidateVoteExtensions would accept the extensions.
// HIGH-1: this is the coupling that stops enabling DkgTransparent (a module param) while
// vote extensions (a SEPARATE consensus param) are not active from halting the chain.
func VoteExtEnabledAt(enableHeight, blockHeight int64) bool {
	return enableHeight != 0 && blockHeight > enableHeight
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
//
// MemberIndex is the Shamir EVALUATION POINT (share index) this sealed share f_dealer(p) is
// for; the ciphertext is ECIES-sealed to the enc key of the member that OWNS that point. On
// the stake-weighted transparent path a dealing carries one entry per evaluation point in the
// budget domain 1..S (a member owning k points receives k entries, all under its own key). On
// the unweighted legacy path there is exactly one entry per member and the point equals the
// member's index — so the field name still reads naturally there.
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
		// Admission ceilings sized far above any legitimate per-block volume (the encrypted
		// path is gas-bounded per block) but low enough to bound worst-case in-flight state.
		// Governance-tunable per deployment; the keeper's absolute constant ceiling is the
		// always-on backstop below these.
		MaxInFlightEncTx: 32768, MaxInFlightPerSubmitter: 2048,
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
	return gs.Params.Validate()
}

// Validate checks the commit-reveal timing params and, when the OPT-IN threshold
// path is enabled, the threshold params the decrypt path relies on.
//
// AUDIT FIX (state-leak footgun): the previous Validate only checked
// RevealDelay/MaxRevealWindow and ignored every threshold param. A genesis or upgrade
// that flipped EncEnabled=true with DecryptDelay=0 or Threshold=0 passed validation
// yet produced EncTx that are NEVER decrypted AND never garbage-collected (a
// permanent, per-user, unbounded state leak — decryptMatured only ever runs for
// height==cur, and is skipped entirely when Threshold==0). The threshold checks are a
// no-op while the path is disabled (the launch/default config), so this only ever
// rejects a config that could not work.
func (p Params) Validate() error {
	if p.RevealDelay == 0 {
		return fmt.Errorf("reveal_delay must be >= 1")
	}
	if p.MaxRevealWindow < p.RevealDelay {
		return fmt.Errorf("max_reveal_window (%d) must be >= reveal_delay (%d)", p.MaxRevealWindow, p.RevealDelay)
	}
	// MEDIUM FIX: bound DecryptDelay. It is the submit->decrypt gap and therefore the window
	// a ciphertext (and, on the DKG path, its stamped epoch's DkgRound + ActiveThresholdKey)
	// is retained in state; an unbounded governance-set value would let one cheap ciphertext
	// per rekeyed epoch pin that epoch's key for an arbitrarily long time. Capping it (together
	// with the global in-flight ceiling, which bounds the COUNT of pinned epochs) keeps the
	// key-retention window finite. This is a sanity bound and applies regardless of which
	// decrypt path is active.
	if p.DecryptDelay > maxDkgWindowBlocks {
		return fmt.Errorf("decrypt_delay (%d) must be <= %d (it drives the key-retention window)", p.DecryptDelay, maxDkgWindowBlocks)
	}
	// Admission ceilings: a per-submitter ceiling above the global one is meaningless (the
	// global one binds first), so reject that misconfig; also cap both far below overflow.
	if p.MaxInFlightEncTx > maxInFlightCeiling || p.MaxInFlightPerSubmitter > maxInFlightCeiling {
		return fmt.Errorf("max_in_flight ceilings must be <= %d", maxInFlightCeiling)
	}
	if p.MaxInFlightEncTx > 0 && p.MaxInFlightPerSubmitter > p.MaxInFlightEncTx {
		return fmt.Errorf("max_in_flight_per_submitter (%d) must be <= max_in_flight_enc_tx (%d)", p.MaxInFlightPerSubmitter, p.MaxInFlightEncTx)
	}
	// DKG params are gated by their own switch, independent of EncEnabled: a DKG can be
	// configured/validated even before the encrypted path is flipped on.
	if p.DkgEnabled {
		// TRANSPARENT path: members are derived on-chain from the bonded validators that
		// auto-announced an enc key (no declared list), so DkgMembers is NOT required and
		// its per-entry checks below are skipped. The declared-member checks only apply to
		// the legacy declared path.
		if !p.DkgTransparent {
			if len(p.DkgMembers) == 0 {
				return fmt.Errorf("dkg_enabled requires a non-empty dkg_members set (unless dkg_transparent)")
			}
			seenOp, seenAcc := map[string]bool{}, map[string]bool{}
			for i, m := range p.DkgMembers {
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
			if n := len(p.DkgMembers); p.DkgThreshold != 0 && int(p.DkgThreshold) > n {
				return fmt.Errorf("dkg_threshold (%d) must be <= number of members (%d)", p.DkgThreshold, n)
			}
		}
		if err := p.ValidateDkgWindows(); err != nil {
			return err
		}
	}
	// Trusted-setup / threshold path validation below is only meaningful when the encrypted
	// path is enabled.
	if !p.EncEnabled {
		return nil // threshold path inert; its params are unused.
	}
	// AUDIT FIX (state-leak footgun): a positive decrypt delay is required on either key
	// path, otherwise EncTx are never decrypted AND never garbage-collected.
	if p.DecryptDelay == 0 {
		return fmt.Errorf("decrypt_delay must be >= 1 when enc_enabled (else EncTx are never decrypted and never GC'd)")
	}
	// When the DKG supplies the active key, the trusted-setup params.ThresholdPub/Threshold/
	// Keypers are the epoch-0 fallback and need not be populated; the DKG member set was
	// already validated above.
	if p.DkgEnabled {
		return nil
	}
	if p.Threshold == 0 {
		return fmt.Errorf("threshold must be >= 1 when enc_enabled")
	}
	if int(p.Threshold) > len(p.Keypers) {
		return fmt.Errorf("threshold (%d) exceeds keyper count (%d)", p.Threshold, len(p.Keypers))
	}
	if len(p.ThresholdPub) == 0 {
		return fmt.Errorf("threshold_pub must be set when enc_enabled")
	}
	seen := make(map[string]bool, len(p.Keypers))
	for _, kp := range p.Keypers {
		if kp == "" {
			return fmt.Errorf("keyper address must not be empty")
		}
		if seen[kp] {
			return fmt.Errorf("duplicate keyper address %q (breaks the 1-based index scheme)", kp)
		}
		seen[kp] = true
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
	// maxInFlightCeiling bounds the admission ceilings so a governance-set value cannot
	// approach a uint64 overflow in the keeper's ref-count arithmetic.
	maxInFlightCeiling uint64 = 1 << 40
)

// Committee-size bounds for the TRANSPARENT path. DefaultDkgMaxMembers caps the
// committee when DkgMaxMembers==0; maxDkgCommittee is the absolute upper bound a
// governance-set DkgMaxMembers may not exceed (bounds vote-extension / injected
// block-data size, and the O(committee^2) dealing bulk, on a large validator set).
const (
	DefaultDkgMaxMembers uint32 = 16
	maxDkgCommittee      uint32 = 128
	// DefaultDkgShareBudget is the fixed stake-apportionment budget S used when
	// DkgShareBudget==0. 256 gives ~0.4%/point stake resolution and keeps the worst-case
	// largest-remainder rounding slop (<= committee_size/2 <= 64) well below the S/3 margin
	// that separates a 1/3-stake adversary's points from the t=floor(2S/3)+1 threshold, so a
	// within-BFT (<=1/3 stake) adversary can never assemble t points. See keeper.stakeThreshold.
	DefaultDkgShareBudget uint32 = 256
	// maxDkgShareBudget bounds a governance-set budget so per-dealing / vote-extension size
	// (O(S) sealed shares + O(t) commitments) cannot be blown up without bound.
	maxDkgShareBudget uint32 = 4096
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
	// DkgMaxMembers=0 means "use DefaultDkgMaxMembers"; a positive value must not exceed
	// the absolute committee ceiling (bounds VE / injected-block-data size).
	if p.DkgMaxMembers > maxDkgCommittee {
		return fmt.Errorf("dkg_max_members (%d) must be <= %d", p.DkgMaxMembers, maxDkgCommittee)
	}
	// DkgShareBudget=0 means "use DefaultDkgShareBudget"; a positive value must not exceed the
	// absolute budget ceiling (bounds per-dealing / vote-extension size).
	if p.DkgShareBudget > maxDkgShareBudget {
		return fmt.Errorf("dkg_share_budget (%d) must be <= %d", p.DkgShareBudget, maxDkgShareBudget)
	}
	return nil
}

// EffectiveShareBudget returns the stake-apportionment budget S actually applied:
// DkgShareBudget, or DefaultDkgShareBudget when it is 0. Always <= maxDkgShareBudget
// (enforced by Validate).
func (p Params) EffectiveShareBudget() int {
	if p.DkgShareBudget == 0 {
		return int(DefaultDkgShareBudget)
	}
	return int(p.DkgShareBudget)
}

// EffectiveMaxMembers returns the committee cap actually applied: DkgMaxMembers, or
// DefaultDkgMaxMembers when it is 0. Always <= maxDkgCommittee (enforced by Validate).
func (p Params) EffectiveMaxMembers() int {
	if p.DkgMaxMembers == 0 {
		return int(DefaultDkgMaxMembers)
	}
	return int(p.DkgMaxMembers)
}
