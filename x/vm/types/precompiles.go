package types

const (
	P256PrecompileAddress   = "0x0000000000000000000000000000000000000100"
	Bech32PrecompileAddress = "0x0000000000000000000000000000000000000400"
)

const (
	StakingPrecompileAddress      = "0x0000000000000000000000000000000000000800"
	DistributionPrecompileAddress = "0x0000000000000000000000000000000000000801"
	ICS20PrecompileAddress        = "0x0000000000000000000000000000000000000802"
	VestingPrecompileAddress      = "0x0000000000000000000000000000000000000803"
	BankPrecompileAddress         = "0x0000000000000000000000000000000000000804"
	GovPrecompileAddress          = "0x0000000000000000000000000000000000000805"
	SlashingPrecompileAddress     = "0x0000000000000000000000000000000000000806"
	ICS02PrecompileAddress        = "0x0000000000000000000000000000000000000807"
	// ValGrantPrecompileAddress is the Limonata x/valgrant admin precompile.
	// Fresh slot 0x900 (does not collide with any existing static precompile).
	ValGrantPrecompileAddress = "0x0000000000000000000000000000000000000900"
)

// AvailableStaticPrecompiles defines the full list of all available EVM extension addresses.
//
// NOTE: To be explicit, this list does not include the dynamically registered EVM extensions
// like the ERC-20 extensions.
var AvailableStaticPrecompiles = []string{
	P256PrecompileAddress,
	Bech32PrecompileAddress,
	StakingPrecompileAddress,
	DistributionPrecompileAddress,
	ICS20PrecompileAddress,
	VestingPrecompileAddress,
	BankPrecompileAddress,
	GovPrecompileAddress,
	SlashingPrecompileAddress,
	ICS02PrecompileAddress,
	ValGrantPrecompileAddress,
}
