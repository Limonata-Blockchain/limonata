package types

import "cosmossdk.io/errors"

var (
	ErrBadAmount                = errors.Register(ModuleName, 2, "amount must be positive")
	ErrInsufficientContribution = errors.Register(ModuleName, 3, "withdraw exceeds your contribution")
	ErrInsufficientEscrow       = errors.Register(ModuleName, 4, "escrow has already been spent on gas")
)
