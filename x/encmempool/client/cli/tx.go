package cli

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	ethtypes "github.com/ethereum/go-ethereum/core/types"

	"github.com/cosmos/evm/x/encmempool/dkg"
	"github.com/cosmos/evm/x/encmempool/threshold"
	"github.com/cosmos/evm/x/encmempool/types"
)

// GetTxCmd returns the encmempool transaction commands.
func GetTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "encmempool transaction subcommands",
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}
	cmd.AddCommand(NewSubmitEncryptedCmd())
	return cmd
}

// NewSubmitEncryptedCmd builds, signs and threshold-encrypts an inner EVM transaction to the active
// DKG threshold key, then submits it as a MsgSubmitEncrypted. The --from account is the on-chain
// submitter (it posts the anti-MEV bond and signs the cosmos tx); the inner EVM tx is signed
// separately with --eth-key and only revealed once the validator committee decrypts it in a block.
func NewSubmitEncryptedCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "submit-encrypted",
		Short: "Encrypt a signed EVM transfer to the DKG threshold key and submit it to the encrypted mempool",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			pubHex, _ := cmd.Flags().GetString("threshold-pub")
			ethKeyHex, _ := cmd.Flags().GetString("eth-key")
			toHex, _ := cmd.Flags().GetString("to")
			valueStr, _ := cmd.Flags().GetString("value")
			nonce, _ := cmd.Flags().GetUint64("nonce")
			gas, _ := cmd.Flags().GetUint64("gas-limit")
			gasPriceStr, _ := cmd.Flags().GetString("gas-price")
			evmChainID, _ := cmd.Flags().GetInt64("evm-chain-id")

			pub, err := hex.DecodeString(trim0x(pubHex))
			if err != nil {
				return fmt.Errorf("bad --threshold-pub hex: %w", err)
			}
			ethKey, err := ethcrypto.HexToECDSA(trim0x(ethKeyHex))
			if err != nil {
				return fmt.Errorf("bad --eth-key hex: %w", err)
			}
			value, ok := new(big.Int).SetString(valueStr, 10)
			if !ok {
				return fmt.Errorf("bad --value: %q", valueStr)
			}
			gasPrice, ok := new(big.Int).SetString(gasPriceStr, 10)
			if !ok {
				return fmt.Errorf("bad --gas-price: %q", gasPriceStr)
			}
			to := ethcommon.HexToAddress(toHex)

			// 1. Build + sign the inner EVM transaction.
			signer := ethtypes.LatestSignerForChainID(big.NewInt(evmChainID))
			ethTx, err := ethtypes.SignTx(ethtypes.NewTx(&ethtypes.LegacyTx{
				Nonce: nonce, To: &to, Value: value, Gas: gas, GasPrice: gasPrice,
			}), signer, ethKey)
			if err != nil {
				return fmt.Errorf("sign inner evm tx: %w", err)
			}
			rlp, err := ethTx.MarshalBinary()
			if err != nil {
				return err
			}

			// 2. Threshold-encrypt the signed inner tx to the DKG key.
			ct, r, err := threshold.EncryptWithR(pub, rlp)
			if err != nil {
				return fmt.Errorf("encrypt to threshold key: %w", err)
			}

			// 3. Wrap in MsgSubmitEncrypted with a PoK binding A to this submitter + ciphertext.
			submitter := clientCtx.GetFromAddress().String()
			pok := dkg.ProveEncKeyPoK(r, clientCtx.ChainID, submitter, ct.A, ct.Nonce, ct.Body).Marshal()
			msg := &types.MsgSubmitEncrypted{
				Submitter: submitter, A: ct.A, Nonce: ct.Nonce, Body: ct.Body, Pok: pok,
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	cmd.Flags().String("threshold-pub", "", "active DKG threshold public key (compressed secp256k1, hex)")
	cmd.Flags().String("eth-key", "", "private key of the inner EVM sender (hex, unprefixed)")
	cmd.Flags().String("to", "", "inner EVM recipient (0x address)")
	cmd.Flags().String("value", "0", "inner EVM transfer value in wei")
	cmd.Flags().Uint64("nonce", 0, "inner EVM sender nonce")
	cmd.Flags().Uint64("gas-limit", 21000, "inner EVM gas limit")
	cmd.Flags().String("gas-price", "1000000000", "inner EVM gas price in wei")
	cmd.Flags().Int64("evm-chain-id", 0, "EVM chain id used to sign the inner tx")
	_ = cmd.MarkFlagRequired("threshold-pub")
	_ = cmd.MarkFlagRequired("eth-key")
	_ = cmd.MarkFlagRequired("to")
	_ = cmd.MarkFlagRequired("evm-chain-id")
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func trim0x(s string) string {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return s[2:]
	}
	return s
}
