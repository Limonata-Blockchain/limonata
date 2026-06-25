package squeeze

import (
	"context"
	"encoding/json"

	"github.com/gorilla/mux"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/spf13/cobra"

	"cosmossdk.io/core/appmodule"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"

	"github.com/cosmos/evm/x/squeeze/keeper"
	"github.com/cosmos/evm/x/squeeze/types"
)

// type checks
var (
	_ module.AppModule          = AppModule{}
	_ module.AppModuleBasic     = AppModuleBasic{}
	_ appmodule.AppModule       = AppModule{}
	_ appmodule.HasBeginBlocker = AppModule{}
)

// AppModuleBasic for the squeeze module (no proto, no genesis state).
type AppModuleBasic struct{}

func (AppModuleBasic) Name() string                                      { return types.ModuleName }
func (AppModuleBasic) RegisterLegacyAminoCodec(_ *codec.LegacyAmino)     {}
func (AppModuleBasic) RegisterInterfaces(_ codectypes.InterfaceRegistry) {}
func (AppModuleBasic) ConsensusVersion() uint64                          { return types.ConsensusVersion }

func (AppModuleBasic) DefaultGenesis(_ codec.JSONCodec) json.RawMessage { return json.RawMessage("{}") }
func (AppModuleBasic) ValidateGenesis(_ codec.JSONCodec, _ client.TxEncodingConfig, _ json.RawMessage) error {
	return nil
}
func (AppModuleBasic) RegisterRESTRoutes(_ client.Context, _ *mux.Router)              {}
func (AppModuleBasic) RegisterGRPCGatewayRoutes(_ client.Context, _ *runtime.ServeMux) {}
func (AppModuleBasic) GetTxCmd() *cobra.Command                                        { return nil }
func (AppModuleBasic) GetQueryCmd() *cobra.Command                                     { return nil }

// AppModule implements a BeginBlock-only module.
type AppModule struct {
	AppModuleBasic
	keeper keeper.Keeper
}

func NewAppModule(k keeper.Keeper) AppModule {
	return AppModule{keeper: k}
}

func (AppModule) Name() string                          { return types.ModuleName }
func (am AppModule) RegisterServices(_ module.Configurator) {}

// BeginBlock performs the 50/40/10 fee split before x/distribution.
func (am AppModule) BeginBlock(ctx context.Context) error {
	return am.keeper.BeginBlock(sdk.UnwrapSDKContext(ctx))
}

// IsAppModule / IsOnePerModuleType implement appmodule.AppModule.
func (am AppModule) IsAppModule()        {}
func (am AppModule) IsOnePerModuleType() {}
