package server

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"

	serverconfig "github.com/cosmos/evm/server/config"
)

// Only List is used by the startup guard; no signing keys are created.
type startupGuardKeyring struct {
	keyring.Keyring
	records []*keyring.Record
	err     error
}

func (k startupGuardKeyring) List() ([]*keyring.Record, error) {
	return k.records, k.err
}

func TestGuardExposedKeyring(t *testing.T) {
	t.Setenv("LIMONATA_ALLOW_EXPOSED_KEYRING", "")
	withKey := startupGuardKeyring{records: []*keyring.Record{{Name: "synthetic-record"}}}
	for _, listener := range []string{
		"0.0.0.0:8545", "127.0.0.1:8545", "localhost:8545", "[::1]:8545",
	} {
		for _, namespace := range []string{"eth", "personal"} {
			t.Run(listener+"/"+namespace, func(t *testing.T) {
				config := serverconfig.DefaultConfig()
				config.JSONRPC.Address = listener
				config.JSONRPC.WsAddress = "127.0.0.1:8546"
				config.JSONRPC.API = []string{namespace}
				err := guardExposedKeyring(config, client.Context{Keyring: withKey})
				require.ErrorContains(t, err, "refusing to start JSON-RPC")
			})
		}
	}

	config := serverconfig.DefaultConfig()
	config.JSONRPC.API = []string{"eth"}
	require.NoError(t, guardExposedKeyring(config, client.Context{}))
	require.NoError(t, guardExposedKeyring(config, client.Context{Keyring: startupGuardKeyring{}}))

	listErr := errors.New("cannot inspect keyring")
	require.ErrorIs(t, guardExposedKeyring(config, client.Context{
		Keyring: startupGuardKeyring{err: listErr},
	}), listErr)

	config.JSONRPC.API = []string{"net", "web3"}
	require.NoError(t, guardExposedKeyring(config, client.Context{Keyring: withKey}))

	config.JSONRPC.API = []string{"eth"}
	t.Setenv("LIMONATA_ALLOW_EXPOSED_KEYRING", "1")
	require.NoError(t, guardExposedKeyring(config, client.Context{Keyring: withKey}))
}
