package keeper

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/sponsorpool/types"
)

// contractKeyLen is the fixed byte length of the lower-hex contract address that
// terminates every 0x02 contribution key. Every write path goes through the
// precompile, which builds the string as strings.ToLower(common.Address.Hex()) =
// "0x" + 40 hex chars. It is the ONLY variable-length-looking part of the key that
// can be pinned, which is what makes a contribution key splittable at all: the
// sponsor prefix is raw address bytes with no length marker.
const contractKeyLen = 42

// InitGenesis sets the module params and RESTORES the escrow accounting.
//
// The escrow ledger is not derived state: the coins themselves live in the shared
// gas-pool module account (exported by x/bank), and this module is the only place
// that records whose money it is and which contract it funds. See types.GenesisState.
func (k Keeper) InitGenesis(ctx context.Context, gs types.GenesisState) error {
	// Un genesis incoherent doit REFUSER de demarrer, pas demarrer en silence:
	// ces params sont IRREVERSIBLES apres le bloc 1 (aucun MsgUpdateParams sur
	// ce module).
	if err := gs.Validate(); err != nil {
		return fmt.Errorf("%s: invalid genesis: %w", types.ModuleName, err)
	}
	if err := k.SetParams(ctx, gs.Params); err != nil {
		return err
	}
	for i, e := range gs.Escrows {
		amt, ok := math.NewIntFromString(e.Amount)
		if !ok {
			return fmt.Errorf("%s: escrows[%d]: invalid amount %q", types.ModuleName, i, e.Amount)
		}
		k.setInt(ctx, escrowKey(e.Contract), amt)
	}
	for i, c := range gs.Contributions {
		sponsor, err := sdk.AccAddressFromBech32(c.Sponsor)
		if err != nil {
			return fmt.Errorf("%s: contributions[%d]: invalid sponsor %q: %w", types.ModuleName, i, c.Sponsor, err)
		}
		amt, ok := math.NewIntFromString(c.Amount)
		if !ok {
			return fmt.Errorf("%s: contributions[%d]: invalid amount %q", types.ModuleName, i, c.Amount)
		}
		k.setInt(ctx, contribKey(sponsor, c.Contract), amt)
	}
	return nil
}

// ExportGenesis returns the module params AND the full escrow accounting.
func (k Keeper) ExportGenesis(ctx context.Context) *types.GenesisState {
	gs := &types.GenesisState{Params: k.GetParams(ctx)}

	st := k.store(ctx)
	if it, err := st.Iterator(types.EscrowPrefix, prefixEnd(types.EscrowPrefix)); err == nil {
		for ; it.Valid(); it.Next() {
			gs.Escrows = append(gs.Escrows, types.EscrowEntry{
				Contract: string(it.Key()[len(types.EscrowPrefix):]),
				Amount:   string(it.Value()),
			})
		}
		it.Close()
	} else {
		panic(fmt.Errorf("%s: cannot export escrows: %w", types.ModuleName, err))
	}

	if it, err := st.Iterator(types.ContribPrefix, prefixEnd(types.ContribPrefix)); err == nil {
		for ; it.Valid(); it.Next() {
			key := it.Key()[len(types.ContribPrefix):]
			// key = sponsor.Bytes() || lower-hex contract (fixed contractKeyLen bytes).
			if len(key) <= contractKeyLen {
				panic(fmt.Errorf("%s: contribution key is too short to split (%d bytes)", types.ModuleName, len(key)))
			}
			sponsorBz := key[:len(key)-contractKeyLen]
			contract := string(key[len(key)-contractKeyLen:])
			// Refuse to guess: if the tail is not the "0x"+40-hex shape every write
			// path produces, the split is wrong and the export would silently
			// misattribute someone's money.
			if !strings.HasPrefix(contract, "0x") {
				panic(fmt.Errorf("%s: contribution key does not end in a 0x-prefixed contract address (got %q)", types.ModuleName, contract))
			}
			gs.Contributions = append(gs.Contributions, types.ContributionEntry{
				Sponsor:  sdk.AccAddress(sponsorBz).String(),
				Contract: contract,
				Amount:   string(it.Value()),
			})
		}
		it.Close()
	} else {
		panic(fmt.Errorf("%s: cannot export contributions: %w", types.ModuleName, err))
	}

	// Store iteration is already key-ordered, so both lists are deterministic; sort
	// anyway so the export order is defined by the exported FIELDS rather than by the
	// raw key encoding (which would change if the key layout ever did).
	sort.Slice(gs.Escrows, func(i, j int) bool { return gs.Escrows[i].Contract < gs.Escrows[j].Contract })
	sort.Slice(gs.Contributions, func(i, j int) bool {
		if gs.Contributions[i].Sponsor != gs.Contributions[j].Sponsor {
			return gs.Contributions[i].Sponsor < gs.Contributions[j].Sponsor
		}
		return gs.Contributions[i].Contract < gs.Contributions[j].Contract
	})
	return gs
}

func prefixEnd(p []byte) []byte {
	end := make([]byte, len(p))
	copy(end, p)
	for i := len(end) - 1; i >= 0; i-- {
		if end[i] != 0xFF {
			end[i]++
			return end[:i+1]
		}
	}
	return nil // all 0xFF -> open-ended
}
