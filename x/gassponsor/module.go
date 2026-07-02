package gassponsor

import (
	"context"
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

	"github.com/cosmos/evm/x/gassponsor/keeper"
	"github.com/cosmos/evm/x/gassponsor/types"
)

var (
	_ module.AppModule          = AppModule{}
	_ module.AppModuleBasic     = AppModuleBasic{}
	_ module.HasABCIGenesis     = AppModule{}
	_ appmodule.AppModule       = AppModule{}
	_ appmodule.HasBeginBlocker = AppModule{}
)

type AppModuleBasic struct{}

func (AppModuleBasic) Name() string                                             { return types.ModuleName }
func (AppModuleBasic) RegisterLegacyAminoCodec(_ *codec.LegacyAmino)            {}
func (AppModuleBasic) RegisterInterfaces(_ codectypes.InterfaceRegistry)        {}
func (AppModuleBasic) ConsensusVersion() uint64                                 { return types.ConsensusVersion }

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

func (AppModule) Name() string { return types.ModuleName }

// RegisterServices would register the read-only gRPC Query service (Params, MintedToday,
// EffectiveAllowance, AllowanceUsed, PoolBalance). x/gassponsor is a plain-JSON module with
// NO generated proto (no .pb.go, unlike x/contest), and this build environment has neither
// buf nor protoc, so a gRPC ServiceDesc cannot be generated or hand-registered here. The
// modern SDK also dropped the legacy amino querier, so there is no proto-free query route to
// hook into module.Configurator either.
//
// The full read surface is therefore exposed as in-process keeper methods
// (keeper.GetParams / MintedToday / EffectiveAllowance / AllowanceUsed / OnboardingUsed /
// PoolBalance), which are callable from upgrade handlers, tests, and precompiles today. A
// full gRPC/REST Query service is a mechanical follow-up once proto regen (buf/protoc) is
// available: add proto/cosmos/evm/gassponsor/v1/query.proto, regenerate, then register the
// generated QueryServer here.
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

// BeginBlock mints the gas pool back up to its target (see keeper.BeginBlock).
func (am AppModule) BeginBlock(ctx context.Context) error {
	return am.keeper.BeginBlock(sdk.UnwrapSDKContext(ctx))
}

func (am AppModule) IsAppModule()        {}
func (am AppModule) IsOnePerModuleType() {}
