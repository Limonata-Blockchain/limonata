package vpcap

import (
	"encoding/json"
	"fmt"

	"github.com/gorilla/mux"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/spf13/cobra"

	abci "github.com/cometbft/cometbft/abci/types"

	"cosmossdk.io/core/appmodule"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"

	"github.com/cosmos/evm/x/vpcap/keeper"
	"github.com/cosmos/evm/x/vpcap/types"
)

var (
	_ module.AppModule      = AppModule{}
	_ module.AppModuleBasic = AppModule{}
	_ module.HasABCIGenesis = AppModule{}
	_ appmodule.AppModule   = AppModule{}
)

// AppModule for x/vpcap. Genesis-only: the per-validator cap is applied at the
// APP-LEVEL EndBlocker (app.go), NOT via a module EndBlock returning updates
// (the module manager forbids a second module returning validator updates).
type AppModuleBasic struct{}

func (AppModuleBasic) Name() string                                  { return types.ModuleName }
func (AppModuleBasic) RegisterLegacyAminoCodec(_ *codec.LegacyAmino) {}
func (AppModuleBasic) RegisterInterfaces(registry codectypes.InterfaceRegistry) {
	types.RegisterInterfaces(registry)
}
func (AppModuleBasic) ConsensusVersion() uint64 { return types.ConsensusVersion }

func (AppModuleBasic) DefaultGenesis(_ codec.JSONCodec) json.RawMessage {
	bz, _ := json.Marshal(types.DefaultGenesisState())
	return bz
}
func (AppModuleBasic) ValidateGenesis(_ codec.JSONCodec, _ client.TxEncodingConfig, bz json.RawMessage) error {
	var gs types.GenesisState
	if err := json.Unmarshal(bz, &gs); err != nil {
		return fmt.Errorf("failed to unmarshal %s genesis: %w", types.ModuleName, err)
	}
	return gs.Validate()
}
func (AppModuleBasic) RegisterRESTRoutes(_ client.Context, _ *mux.Router)              {}
func (AppModuleBasic) RegisterGRPCGatewayRoutes(_ client.Context, _ *runtime.ServeMux) {}
func (AppModuleBasic) GetTxCmd() *cobra.Command                                        { return nil }
func (AppModuleBasic) GetQueryCmd() *cobra.Command                                     { return nil }

type AppModule struct {
	AppModuleBasic
	keeper keeper.Keeper
}

func NewAppModule(k keeper.Keeper) AppModule { return AppModule{keeper: k} }

func (AppModule) Name() string                          { return types.ModuleName }
func (am AppModule) RegisterServices(_ module.Configurator) {}

func (am AppModule) InitGenesis(ctx sdk.Context, _ codec.JSONCodec, data json.RawMessage) []abci.ValidatorUpdate {
	var gs types.GenesisState
	if err := json.Unmarshal(data, &gs); err != nil {
		panic(err)
	}
	if err := am.keeper.InitGenesis(ctx, gs); err != nil {
		panic(err)
	}
	return []abci.ValidatorUpdate{}
}

func (am AppModule) ExportGenesis(ctx sdk.Context, _ codec.JSONCodec) json.RawMessage {
	bz, _ := json.Marshal(am.keeper.ExportGenesis(ctx))
	return bz
}

func (am AppModule) IsAppModule()        {}
func (am AppModule) IsOnePerModuleType() {}
