package valgrant

const (
	// ErrCannotCallFromContract is raised when the precompile is invoked from a
	// smart contract rather than directly (admin-gated EOA only).
	ErrCannotCallFromContract = "this method can only be called directly to the precompile, not from a smart contract"
	// ErrInvalidGrantee is raised when the grantee address argument is invalid.
	ErrInvalidGrantee = "invalid grantee address: %v"
)
