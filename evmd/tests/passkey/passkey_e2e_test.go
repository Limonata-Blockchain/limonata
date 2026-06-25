package passkey_test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"cosmossdk.io/math"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256r1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	cosmosante "github.com/cosmos/evm/ante/cosmos"
	evmd "github.com/cosmos/evm/evmd"
	testconstants "github.com/cosmos/evm/testutil/constants"
	"github.com/cosmos/evm/x/paymaster/webauthn"
)

// These tests drive the REAL WebAuthnSigVerificationDecorator over a REAL app-encoded
// transaction: the app's own SignModeHandler derives the sign-bytes, a simulated
// authenticator (the reference client signer) produces the assertion, and the
// decorator verifies it against the account's secp256r1 pubkey held in the real
// AccountKeeper. They live in their own test binary (like the ledger suite) to keep
// the EVM global-config singleton clean.

// newPasskeyAccount builds a fresh controlled context (over the shared app) plus a
// secp256r1 account whose key is held by a simulated WebAuthn authenticator. The
// account's pubkey is pre-set, simulating that SetPubKeyDecorator (earlier in the
// ante chain) has already populated it from the tx auth_info.
//
// The app is created ONCE per process (the EVM global config can only be configured
// once), so all subtests share it; each gets its own context and account.
func newPasskeyAccount(t *testing.T, app *evmd.EVMD) (sdk.Context, *webauthn.SimulatedAuthenticator, *secp256r1.PubKey, sdk.AccAddress, uint64) {
	t.Helper()
	ctx := app.NewContext(false).WithBlockHeight(2).WithChainID(testconstants.ExampleChainID.ChainID)

	auth, err := webauthn.NewSimulatedAuthenticator("limonata.xyz")
	require.NoError(t, err)

	pk, err := secp256r1.NewPubKeyFromBytes(auth.CompressedPubKey())
	require.NoError(t, err)
	require.Equal(t, auth.CompressedPubKey(), pk.Bytes(), "authenticator key must match the on-chain secp256r1 pubkey bytes")

	addr := sdk.AccAddress(pk.Address())
	acc := app.AccountKeeper.NewAccountWithAddress(ctx, addr)
	require.NoError(t, acc.SetPubKey(pk))
	require.NoError(t, acc.SetSequence(0))
	app.AccountKeeper.SetAccount(ctx, acc)

	return ctx, auth, pk, addr, acc.GetAccountNumber()
}

// buildPasskeyTx assembles a real bank MsgSend tx, computes its canonical
// SIGN_MODE_DIRECT sign-bytes via the app's own SignModeHandler, lets the simulated
// authenticator sign challengeOverride (or the real sign-bytes hash when nil), and
// packs the resulting assertion into the tx signature blob exactly as a passkey
// client would.
func buildPasskeyTx(t *testing.T, app *evmd.EVMD, ctx sdk.Context, auth *webauthn.SimulatedAuthenticator, pk *secp256r1.PubKey, addr sdk.AccAddress, accNum uint64, challengeOverride []byte) sdk.Tx {
	t.Helper()
	txConfig := app.GetTxConfig()
	txb := txConfig.NewTxBuilder()

	recipient := sdk.AccAddress([]byte("recipient-addr-01234"))
	msg := banktypes.NewMsgSend(addr, recipient, sdk.NewCoins(sdk.NewCoin("uatom", math.NewInt(1))))
	require.NoError(t, txb.SetMsgs(msg))
	txb.SetGasLimit(200000)
	txb.SetFeeAmount(sdk.NewCoins(sdk.NewCoin("uatom", math.NewInt(0))))

	// Empty signature first, to fix the SignerInfo (pubkey + sign mode + sequence)
	// inside AuthInfo before deriving the sign-bytes.
	empty := signing.SignatureV2{
		PubKey:   pk,
		Data:     &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT, Signature: nil},
		Sequence: 0,
	}
	require.NoError(t, txb.SetSignatures(empty))

	signerData := authsigning.SignerData{
		Address:       addr.String(),
		ChainID:       ctx.ChainID(),
		AccountNumber: accNum,
		Sequence:      0,
		PubKey:        pk,
	}
	signBytes, err := authsigning.GetSignBytesAdapter(ctx, txConfig.SignModeHandler(), signing.SignMode_SIGN_MODE_DIRECT, signerData, txb.GetTx())
	require.NoError(t, err)

	realChallenge := sha256.Sum256(signBytes)
	challenge := realChallenge[:]
	if challengeOverride != nil {
		challenge = challengeOverride
	}
	assertion, err := auth.Sign(challenge, "https://limonata.xyz", true)
	require.NoError(t, err)

	packed := assertion.Marshal()
	require.True(t, webauthn.IsWebAuthnSig(packed))
	signed := signing.SignatureV2{
		PubKey:   pk,
		Data:     &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT, Signature: packed},
		Sequence: 0,
	}
	require.NoError(t, txb.SetSignatures(signed))
	return txb.GetTx()
}

func terminalAnte(ctx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) { return ctx, nil }

func newDecorator(app *evmd.EVMD, enabled bool) cosmosante.WebAuthnSigVerificationDecorator {
	return cosmosante.NewWebAuthnSigVerificationDecorator(
		app.AccountKeeper, app.GetTxConfig().SignModeHandler(),
		func(sdk.Context) bool { return enabled },
	)
}

// TestPasskeyAnte exercises the real decorator end-to-end. The app is built once and
// shared across subtests because the EVM global config can only be configured once
// per process.
func TestPasskeyAnte(t *testing.T) {
	chainID := testconstants.ExampleChainID
	app := evmd.Setup(t, chainID.ChainID, chainID.EVMChainID)

	// With the param ON, a tx signed by the simulated passkey over the tx's own
	// DIRECT sign-bytes is accepted by the real decorator.
	t.Run("happy path accepted when enabled", func(t *testing.T) {
		ctx, auth, pk, addr, accNum := newPasskeyAccount(t, app)
		tx := buildPasskeyTx(t, app, ctx, auth, pk, addr, accNum, nil)
		_, err := newDecorator(app, true).AnteHandle(ctx, tx, false, terminalAnte)
		require.NoError(t, err, "valid passkey tx must be accepted when the param is on")
	})

	// An assertion bound to a DIFFERENT challenge (a replay / substituted-tx attack)
	// is rejected, proving the challenge is bound to this exact tx's sign-bytes.
	t.Run("replay or substituted challenge rejected", func(t *testing.T) {
		ctx, auth, pk, addr, accNum := newPasskeyAccount(t, app)
		wrong := sha256.Sum256([]byte("a challenge from some other transaction"))
		tx := buildPasskeyTx(t, app, ctx, auth, pk, addr, accNum, wrong[:])
		_, err := newDecorator(app, true).AnteHandle(ctx, tx, false, terminalAnte)
		require.Error(t, err, "an assertion bound to the wrong challenge must be rejected")
	})

	// With the param OFF (the production default), a passkey-signed tx falls through
	// to the standard decorator, which cannot validate the packed blob as a raw
	// secp256r1 signature and rejects it. The feature is inert until governance
	// explicitly enables it.
	t.Run("rejected when param disabled", func(t *testing.T) {
		ctx, auth, pk, addr, accNum := newPasskeyAccount(t, app)
		tx := buildPasskeyTx(t, app, ctx, auth, pk, addr, accNum, nil)
		_, err := newDecorator(app, false).AnteHandle(ctx, tx, false, terminalAnte)
		require.Error(t, err, "passkey tx must be rejected when the param is off")
	})
}
