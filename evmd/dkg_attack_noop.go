// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Limonata. Source-available under the Business Source License 1.1
// (see LICENSE.dkg at the repository root). NOT licensed under Apache-2.0 - this file is a
// separately-licensed part of the Limonata transparent-DKG / encrypted-mempool work.

//go:build !dkgattack

package evmd

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	encmempooltypes "github.com/cosmos/evm/x/encmempool/types"
)

// dkgAttackShares is a NO-OP in production builds (round-9 #6): the ExtendVote adversary lives in
// dkg_attack.go behind the `dkgattack` build tag and is compiled ONLY into throwaway/audit binaries.
// Here it returns the honest shares untouched, so no runtime env var can make a production validator
// misbehave. This is the default build.
func (app *EVMD) dkgAttackShares(_ sdk.Context, _ string, honest []encmempooltypes.VoteExtShare) []encmempooltypes.VoteExtShare {
	return honest
}
