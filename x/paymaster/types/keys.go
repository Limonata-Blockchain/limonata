package types

// x/paymaster: protocol-level gas abstraction. A sponsor (developer) registers
// policies that cause matching user transactions to be paid by the sponsor's
// account instead of the user — a fully gasless UX for end-users (incl. passkey
// accounts). Sponsored fees still flow to fee_collector and feed the Squeeze split.
const (
	ModuleName       = "paymaster"
	StoreKey         = ModuleName
	ConsensusVersion = 1
)

// PoliciesKey stores the JSON-encoded []Policy.
var PoliciesKey = []byte{0x01}
