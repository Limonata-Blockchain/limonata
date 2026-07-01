package types

import codectypes "github.com/cosmos/cosmos-sdk/codec/types"

// RegisterInterfaces is a no-op for v1: x/vpcap has no Msg types (params are set
// at genesis; a gov MsgUpdateParams can be added in v2). Present so the module's
// AppModuleBasic can call it uniformly with the other modules.
func RegisterInterfaces(_ codectypes.InterfaceRegistry) {}
