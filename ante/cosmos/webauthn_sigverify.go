package cosmos

import (
	"crypto/sha256"

	apitxsigning "cosmossdk.io/api/cosmos/tx/signing/v1beta1"
	errorsmod "cosmossdk.io/errors"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256r1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	txsigning "github.com/cosmos/cosmos-sdk/x/tx/signing"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cosmos/evm/x/paymaster/webauthn"
)

// WebAuthnSigVerificationDecorator is an EXPERIMENTAL, audit-gated drop-in wrapper
// around the standard SigVerificationDecorator that adds a passkey (WebAuthn / P-256)
// authorization path.
//
// Safety model:
//   - If the passkey param is OFF (the default), OR the tx carries no WebAuthn-packed
//     signature, the tx is handled ENTIRELY by the standard decorator. Normal txs and
//     the production chain are therefore completely unaffected.
//   - Only when the param is ON and a signature is a packed WebAuthn assertion does it
//     take the passkey path: it recomputes the tx's SIGN_MODE_DIRECT sign bytes, hashes
//     them to the WebAuthn challenge, and verifies the P-256 assertion against the
//     account's secp256r1 public key (challenge-bound, replay-safe per account/sequence).
//
// Scope of the experiment (documented for the audit): single-signer, SIGN_MODE_DIRECT,
// ordered transactions. Multi-sig / unordered / amino webauthn txs are not supported and
// fall through to the standard decorator (which will reject the non-standard signature).
type WebAuthnSigVerificationDecorator struct {
	std                 ante.SigVerificationDecorator
	ak                  ante.AccountKeeper
	handler             *txsigning.HandlerMap
	enabled             func(sdk.Context) bool
	rpConfig            func(sdk.Context) (rpID string, allowedOrigins []string)
	requireUserVerified bool
}

// NewWebAuthnSigVerificationDecorator wraps the standard sig-verification decorator.
// enabled may be nil (treated as always-off). rpConfig is REQUIRED for the passkey
// path to activate: a nil rpConfig, an empty rp id, or an empty origin allowlist
// all keep the path disabled (see rpConfigured — fail-closed).
func NewWebAuthnSigVerificationDecorator(ak ante.AccountKeeper, h *txsigning.HandlerMap, enabled func(sdk.Context) bool, rpConfig func(sdk.Context) (string, []string)) WebAuthnSigVerificationDecorator {
	return WebAuthnSigVerificationDecorator{
		std:                 ante.NewSigVerificationDecorator(ak, h),
		ak:                  ak,
		handler:             h,
		enabled:             enabled,
		rpConfig:            rpConfig,
		requireUserVerified: true,
	}
}

func (d WebAuthnSigVerificationDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	if simulate || d.enabled == nil || !d.enabled(ctx) || !d.rpConfigured(ctx) || !txHasWebAuthnSig(tx) {
		return d.std.AnteHandle(ctx, tx, simulate, next)
	}
	if err := d.verifyWebAuthnTx(ctx, tx); err != nil {
		return ctx, err
	}
	return next(ctx, tx, simulate)
}

// rpConfigured reports whether the on-chain RP binding config is complete. The
// passkey path is treated as DISABLED without it (fail-closed): this covers
// states the MsgSetPasskeyEnabled activation guard cannot, e.g. a chain whose
// params were written by a pre-RP-binding binary with passkey_enabled already
// true — after the upgrade the feature stays inert until the admin sets the
// RP config, instead of running with RP binding silently skipped.
func (d WebAuthnSigVerificationDecorator) rpConfigured(ctx sdk.Context) bool {
	if d.rpConfig == nil {
		return false
	}
	rpID, origins := d.rpConfig(ctx)
	return rpID != "" && len(origins) > 0
}

func txHasWebAuthnSig(tx sdk.Tx) bool {
	sigTx, ok := tx.(authsigning.Tx)
	if !ok {
		return false
	}
	sigs, err := sigTx.GetSignaturesV2()
	if err != nil {
		return false
	}
	for _, s := range sigs {
		if single, ok := s.Data.(*signing.SingleSignatureData); ok && webauthn.IsWebAuthnSig(single.Signature) {
			return true
		}
	}
	return false
}

func (d WebAuthnSigVerificationDecorator) verifyWebAuthnTx(ctx sdk.Context, tx sdk.Tx) error {
	sigTx, ok := tx.(authsigning.Tx)
	if !ok {
		return errorsmod.Wrap(sdkerrors.ErrTxDecode, "invalid transaction type")
	}
	adaptableTx, ok := tx.(authsigning.V2AdaptableTx)
	if !ok {
		return errorsmod.Wrap(sdkerrors.ErrTxDecode, "tx does not implement V2AdaptableTx")
	}
	txData := adaptableTx.GetSigningTxData()

	sigs, err := sigTx.GetSignaturesV2()
	if err != nil {
		return err
	}
	signers, err := sigTx.GetSigners()
	if err != nil {
		return err
	}
	if len(sigs) != len(signers) {
		return errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "invalid number of signers; expected %d got %d", len(signers), len(sigs))
	}

	chainID := ctx.ChainID()
	genesis := ctx.BlockHeight() == 0

	// RP binding config from on-chain params. rpConfigured (checked in AnteHandle)
	// guarantees both values are non-empty here, so both checks are always armed.
	rpID, origins := d.rpConfig(ctx)
	rpHash := sha256.Sum256([]byte(rpID))
	opts := webauthn.VerifyOptions{
		RequireUserVerified: d.requireUserVerified,
		ExpectedRPIDHash:    rpHash[:],
		AllowedOrigins:      origins,
	}

	for i, sig := range sigs {
		acc, err := ante.GetSignerAcc(ctx, d.ak, sdk.AccAddress(signers[i]))
		if err != nil {
			return err
		}
		pubKey := acc.GetPubKey()
		if pubKey == nil {
			return errorsmod.Wrap(sdkerrors.ErrInvalidPubKey, "pubkey not set on account")
		}
		// WebAuthn assertions are only meaningful against a P-256 account key.
		// parseP256 would reject other key material anyway, but assert the type
		// explicitly so the property is auditable and fails with a clear error.
		if _, ok := pubKey.(*secp256r1.PubKey); !ok {
			return errorsmod.Wrapf(sdkerrors.ErrInvalidPubKey,
				"webauthn ante: account pubkey must be secp256r1, got %T", pubKey)
		}
		if sig.Sequence != acc.GetSequence() {
			return errorsmod.Wrapf(sdkerrors.ErrWrongSequence, "account sequence mismatch, expected %d got %d", acc.GetSequence(), sig.Sequence)
		}
		single, ok := sig.Data.(*signing.SingleSignatureData)
		if !ok || !webauthn.IsWebAuthnSig(single.Signature) {
			return errorsmod.Wrap(sdkerrors.ErrUnauthorized, "webauthn ante: every signature must be a WebAuthn assertion")
		}

		var accNum uint64
		if !genesis {
			accNum = acc.GetAccountNumber()
		}
		anyPk, err := codectypes.NewAnyWithValue(pubKey)
		if err != nil {
			return err
		}
		signerData := txsigning.SignerData{
			Address:       acc.GetAddress().String(),
			ChainID:       chainID,
			AccountNumber: accNum,
			Sequence:      sig.Sequence,
			PubKey:        &anypb.Any{TypeUrl: anyPk.TypeUrl, Value: anyPk.Value},
		}
		// The WebAuthn challenge is bound to the SIGN_MODE_DIRECT sign bytes of THIS tx
		// (which include chain-id, account number, and sequence), so an assertion cannot
		// be replayed against a different tx, chain, account, or sequence.
		signBytes, err := d.handler.GetSignBytes(ctx, apitxsigning.SignMode_SIGN_MODE_DIRECT, signerData, txData)
		if err != nil {
			return err
		}
		challenge := sha256.Sum256(signBytes)

		assertion, err := webauthn.UnmarshalAssertion(single.Signature)
		if err != nil {
			return errorsmod.Wrap(sdkerrors.ErrUnauthorized, err.Error())
		}
		if err := webauthn.VerifyAssertion(pubKey.Bytes(), assertion.Signature, assertion.AuthenticatorData, assertion.ClientDataJSON, challenge[:], opts); err != nil {
			return errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "webauthn assertion verification failed: %s", err.Error())
		}
	}
	return nil
}
