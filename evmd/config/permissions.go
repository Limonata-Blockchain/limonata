package config

import (
	"maps"
	"sort"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	cosmosevmutils "github.com/cosmos/evm/utils"
	encmempooltypes "github.com/cosmos/evm/x/encmempool/types"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	feemarkettypes "github.com/cosmos/evm/x/feemarket/types"
	gassponsortypes "github.com/cosmos/evm/x/gassponsor/types"
	squeezetypes "github.com/cosmos/evm/x/squeeze/types"
	valgranttypes "github.com/cosmos/evm/x/valgrant/types"
	vmtypes "github.com/cosmos/evm/x/vm/types"
	transfertypes "github.com/cosmos/ibc-go/v11/modules/apps/transfer/types"
	corevm "github.com/ethereum/go-ethereum/core/vm"
)

// BlockedAddresses returns all the app's blocked account addresses.
//
// Note, this includes:
//   - module accounts
//   - Ethereum's native precompiled smart contracts
//   - Cosmos EVM' available static precompiled contracts
func BlockedAddresses() map[string]bool {
	blockedAddrs := make(map[string]bool)

	maccPerms := GetMaccPerms()
	accs := make([]string, 0, len(maccPerms))
	for acc := range maccPerms {
		accs = append(accs, acc)
	}
	sort.Strings(accs)

	for _, acc := range accs {
		// Limonata valgrant: the grant reserve pool MUST be fundable by the admin
		// (it is seeded by a direct transfer of LIMO after the valgrant-v1 upgrade).
		// Keep it OUT of the blocked set so SendCoins to it succeeds; it stays a
		// module account (perm nil) and only x/valgrant moves funds out of it.
		if acc == valgranttypes.ModuleName {
			continue
		}
		blockedAddrs[authtypes.NewModuleAddress(acc).String()] = true
	}

	blockedPrecompilesHex := vmtypes.AvailableStaticPrecompiles
	for _, addr := range corevm.PrecompiledAddressesPrague {
		blockedPrecompilesHex = append(blockedPrecompilesHex, addr.Hex())
	}

	for _, precompile := range blockedPrecompilesHex {
		blockedAddrs[cosmosevmutils.Bech32StringFromHexAddress(precompile)] = true
	}

	return blockedAddrs
}

// module account permissions
var maccPerms = map[string][]string{
	authtypes.FeeCollectorName:     nil,
	distrtypes.ModuleName:          nil,
	transfertypes.ModuleName:       {authtypes.Minter, authtypes.Burner},
	minttypes.ModuleName:           {authtypes.Minter},
	stakingtypes.BondedPoolName:    {authtypes.Burner, authtypes.Staking},
	stakingtypes.NotBondedPoolName: {authtypes.Burner, authtypes.Staking},
	govtypes.ModuleName:            {authtypes.Burner},

	// Cosmos EVM modules
	vmtypes.ModuleName:        {authtypes.Minter, authtypes.Burner},
	feemarkettypes.ModuleName: nil,
	erc20types.ModuleName:     {authtypes.Minter, authtypes.Burner},

	// Limonata Squeeze fee module + protocol gas pool
	squeezetypes.ModuleName:  {authtypes.Burner},
	squeezetypes.GasPoolName: nil,
	// Limonata gas sponsor: mints the refill into the pool (the pool itself stays
	// permissionless so only gassponsor can replenish it).
	gassponsortypes.ModuleName: {authtypes.Minter},

	// Limonata valgrant: the grant reserve pool. Burner — it is seeded at genesis,
	// grants are funded from / clawed back into it, AND the admin can permanently
	// DESTROY pool LIMO (BurnPool: removes it from the module account + total supply)
	// to prove reclaimed bootstrap capital never returns to anyone. It never mints.
	valgranttypes.ModuleName: {authtypes.Burner},

	// Limonata encrypted mempool: escrows the anti-sybil submit bond while a ciphertext is in flight
	// (round-9 #1). Burner so it can DESTROY the non-refundable burn fraction on release (round-10 #1);
	// it never mints. The remainder of each bond is refunded to the submitter.
	encmempooltypes.ModuleName: {authtypes.Burner},
}

// GetMaccPerms returns a copy of the module account permissions
func GetMaccPerms() map[string][]string {
	return maps.Clone(maccPerms)
}
