package types

import errorsmod "cosmossdk.io/errors"

// ErrNetCapExceeded is returned when a restricted address would exceed its
// rolling-window net-seller cap.
var ErrNetCapExceeded = errorsmod.Register(ModuleName, 2, "net-seller cap exceeded")
