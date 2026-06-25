package cosmos

import (
	"crypto/sha256"

	apitxsigning "cosmossdk.io/api/cosmos/tx/signing/v1beta1"
	errorsmod "cosmossdk.io/errors"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
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
	requireUserVerified bool
}

// NewWebAuthnSigVerificationDecorator wraps the standard sig-verification decorator.
// enabled may be nil (treated as always-off).
func NewWebAuthnSigVerificationDecorator(ak ante.AccountKeeper, h *txsigning.HandlerMap, enabled func(sdk.Context) bool) WebAuthnSigVerificationDecorator {
	return WebAuthnSigVerificationDecorator{
		std:                 ante.NewSigVerificationDecorator(ak, h),
		ak:                  ak,
		handler:             h,
		enabled:             enabled,
		requireUserVerified: true,
	}
}

func (d WebAuthnSigVerificationDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	if simulate || d.enabled == nil || !d.enabled(ctx) || !txHasWebAuthnSig(tx) {
		return d.std.AnteHandle(ctx, tx, simulate, next)
	}
	if err := d.verifyWebAuthnTx(ctx, tx); err != nil {
		return ctx, err
	}
	return next(ctx, tx, simulate)
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
	for i, sig := range sigs {
		acc, err := ante.GetSignerAcc(ctx, d.ak, sdk.AccAddress(signers[i]))
		if err != nil {
			return err
		}
		pubKey := acc.GetPubKey()
		if pubKey == nil {
			return errorsmod.Wrap(sdkerrors.ErrInvalidPubKey, "pubkey not set on account")
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
		if err := webauthn.VerifyAssertion(pubKey.Bytes(), assertion.Signature, assertion.AuthenticatorData, assertion.ClientDataJSON, challenge[:], d.requireUserVerified); err != nil {
			return errorsmod.Wrapf(sdkerrors.ErrUnauthorized, "webauthn assertion verification failed: %s", err.Error())
		}
	}
	return nil
}
