package passkey_test

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"cosmossdk.io/math"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256r1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	cosmosante "github.com/cosmos/evm/ante/cosmos"
	evmd "github.com/cosmos/evm/evmd"
	testconstants "github.com/cosmos/evm/testutil/constants"
	contestkeeper "github.com/cosmos/evm/x/contest/keeper"
	contesttypes "github.com/cosmos/evm/x/contest/types"
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
	return newDecoratorRP(app, enabled, "limonata.xyz", []string{"https://limonata.xyz"})
}

func newDecoratorRP(app *evmd.EVMD, enabled bool, rpID string, origins []string) cosmosante.WebAuthnSigVerificationDecorator {
	return cosmosante.NewWebAuthnSigVerificationDecorator(
		app.AccountKeeper, app.GetTxConfig().SignModeHandler(),
		func(sdk.Context) bool { return enabled },
		func(sdk.Context) (string, []string) { return rpID, origins },
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

	// RP binding: an assertion whose signed rpIdHash is for a different relying
	// party must be rejected when the chain pins an RP id.
	t.Run("wrong rpId rejected", func(t *testing.T) {
		ctx, auth, pk, addr, accNum := newPasskeyAccount(t, app)
		tx := buildPasskeyTx(t, app, ctx, auth, pk, addr, accNum, nil)
		_, err := newDecoratorRP(app, true, "some-other-rp.example", []string{"https://limonata.xyz"}).AnteHandle(ctx, tx, false, terminalAnte)
		require.ErrorContains(t, err, "rpIdHash", "assertion for a different RP must be rejected")
	})

	// Origin binding: a clientData.origin outside the on-chain allowlist must be
	// rejected when the chain pins an origin allowlist.
	t.Run("wrong origin rejected", func(t *testing.T) {
		ctx, auth, pk, addr, accNum := newPasskeyAccount(t, app)
		tx := buildPasskeyTx(t, app, ctx, auth, pk, addr, accNum, nil)
		_, err := newDecoratorRP(app, true, "limonata.xyz", []string{"https://only-this.example"}).AnteHandle(ctx, tx, false, terminalAnte)
		require.ErrorContains(t, err, "origin", "assertion from a non-allowlisted origin must be rejected")
	})

	// Legacy-state fail-closed: a chain whose stored params say enabled=true but
	// carry NO RP config (pre-RP-binding state, as on live 10777) must treat the
	// passkey path as disabled — the tx falls through to the standard decorator
	// and is rejected, instead of verifying with RP binding skipped.
	t.Run("enabled without RP config is inert", func(t *testing.T) {
		ctx, auth, pk, addr, accNum := newPasskeyAccount(t, app)
		tx := buildPasskeyTx(t, app, ctx, auth, pk, addr, accNum, nil)
		_, err := newDecoratorRP(app, true, "", nil).AnteHandle(ctx, tx, false, terminalAnte)
		require.Error(t, err, "stale enabled=true state without RP config must not verify passkey txs")
	})

	// Fail-closed activation: MsgSetPasskeyEnabled must refuse to enable the
	// feature until an RP id and at least one allowed origin are configured, and
	// must accept + persist the config when the msg carries it.
	t.Run("enable refused without RP config", func(t *testing.T) {
		ctx, _, _, _, _ := newPasskeyAccount(t, app)
		admin := sdk.AccAddress([]byte("contest-admin-000001")).String()
		p := app.ContestKeeper.GetParams(ctx)
		p.Admin = admin
		p.PasskeyRPID = ""
		p.PasskeyAllowedOrigins = nil
		require.NoError(t, app.ContestKeeper.SetParams(ctx, p))
		ms := contestkeeper.NewMsgServerImpl(app.ContestKeeper)

		_, err := ms.SetPasskeyEnabled(ctx, &contesttypes.MsgSetPasskeyEnabled{Admin: admin, Enabled: true})
		require.ErrorContains(t, err, "rp_id", "enable without RP config must fail closed")
		require.False(t, app.ContestKeeper.GetParams(ctx).PasskeyEnabled)

		_, err = ms.SetPasskeyEnabled(ctx, &contesttypes.MsgSetPasskeyEnabled{
			Admin: admin, Enabled: true, RpId: "limonata.xyz", AllowedOrigins: []string{"https://limonata.xyz"},
		})
		require.NoError(t, err, "enable with RP config in the msg must succeed")
		got := app.ContestKeeper.GetParams(ctx)
		require.True(t, got.PasskeyEnabled)
		require.Equal(t, "limonata.xyz", got.PasskeyRPID)
		require.Equal(t, []string{"https://limonata.xyz"}, got.PasskeyAllowedOrigins)
	})

	// A WebAuthn-packed signature on an account whose pubkey is NOT secp256r1 must
	// fail with a clear invalid-pubkey error (explicit type assertion), not fall
	// through to point parsing.
	t.Run("non-r1 account pubkey rejected", func(t *testing.T) {
		ctx, auth, pk, addr, accNum := newPasskeyAccount(t, app)
		tx := buildPasskeyTx(t, app, ctx, auth, pk, addr, accNum, nil)

		// Swap the ACCOUNT's key material for a secp256k1 key; the decorator reads
		// the pubkey from the account keeper, not from the tx.
		k1 := secp256k1.GenPrivKey()
		acc := app.AccountKeeper.GetAccount(ctx, addr)
		require.NoError(t, acc.SetPubKey(k1.PubKey()))
		app.AccountKeeper.SetAccount(ctx, acc)

		_, err := newDecorator(app, true).AnteHandle(ctx, tx, false, terminalAnte)
		require.ErrorContains(t, err, "must be secp256r1", "non-P-256 account pubkey must be rejected explicitly")
	})
}
