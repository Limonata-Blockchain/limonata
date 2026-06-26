package types

// x/sponsorpool: permissionless, per-contract gas-sponsorship escrow. A developer deposits
// LIMO earmarked for THEIR contract; transactions targeting that contract draw gas from the
// deposit (paid from this module's own account, so it is dev-funded and NOT mint-backed),
// until the deposit runs dry. Depositors can withdraw their unspent contribution.
const (
	ModuleName = "sponsorpool"
	StoreKey   = ModuleName
	// FeeDenom is the gas/fee coin (aLIMO), matching x/squeeze and x/gassponsor.
	FeeDenom = "aLIMO"
	// ConsensusVersion is the x/sponsorpool module consensus version.
	ConsensusVersion = 1
)

var (
	// ParamsKey -> JSON Params.
	ParamsKey = []byte{0x00}
	// EscrowPrefix | lower-hex-contract -> total escrow funding that contract (aLIMO, math.Int string).
	EscrowPrefix = []byte{0x01}
	// ContribPrefix | sponsor.Bytes() | lower-hex-contract -> that sponsor's withdrawable contribution.
	ContribPrefix = []byte{0x02}
)
