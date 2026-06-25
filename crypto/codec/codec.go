package codec

import (
	"github.com/cosmos/evm/crypto/ethsecp256k1"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256r1"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

// RegisterInterfaces register the Cosmos EVM key concrete types.
func RegisterInterfaces(registry codectypes.InterfaceRegistry) {
	registry.RegisterImplementations((*cryptotypes.PubKey)(nil), &ethsecp256k1.PubKey{})
	registry.RegisterImplementations((*cryptotypes.PrivKey)(nil), &ethsecp256k1.PrivKey{})
	// Limonata: register secp256r1 / P-256 so WebAuthn passkey accounts can be
	// unpacked from AuthInfo (gas-abstraction prerequisite; sigverify already
	// supports the curve, only the codec registration was missing).
	secp256r1.RegisterInterfaces(registry)
}
