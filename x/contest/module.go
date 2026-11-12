// Package contest is the Proving Grounds scoring module.
//
// AVERTISSEMENT LIGNE DE BUILD - CE BINAIRE NE PEUT PAS RESYNCHRONISER 10777
// DEPUIS LE BLOC 1. Fait MESURE, pas suppose (voir
// types/genesis_live10777_test.go, qui rejoue le fragment app_state.contest
// exact du genesis vivant):
//
//	le genesis de limonata_10777-1 porte app_state.contest.params avec
//	passkey_enabled=true et AUCUN passkey_rp_id ni passkey_allowed_origins
//	(ces champs n'existaient pas a la naissance de 10777; le lien RP a ete
//	pose plus tard, en etat). Le Validate() fail-closed de cette ligne de
//	build refuse ce document -
//	  "passkey_enabled requires passkey_rp_id and at least one
//	   passkey_allowed_origins entry"
//	- keeper.InitGenesis renvoie l erreur, et AppModule.InitGenesis
//	  (plus bas dans ce fichier) fait panic(err) DANS InitChain.
//
// Consequence operationnelle: un noeud qui rejoue 10777 a partir de la hauteur
// 0 avec ce binaire MEURT avant le bloc 1. Pour 10777, il faut soit le binaire
// de la chaine vivante, soit un state sync (voir la recette v0.3.3), soit un
// genesis corrige portant passkey_rp_id + passkey_allowed_origins - ce qui
// CHANGE le hash du genesis et n est donc PAS le meme reseau. Cette ligne de
// build vise le genesis du mainnet, pas le rejeu du testnet.
//
// Voir LIGNE-DE-BUILD.md a la racine du depot.
package contest

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

	"github.com/cosmos/evm/x/contest/keeper"
	"github.com/cosmos/evm/x/contest/types"
)

var (
	_ module.AppModule        = AppModule{}
	_ module.AppModuleBasic   = AppModuleBasic{}
	_ module.HasABCIGenesis   = AppModule{}
	_ appmodule.AppModule     = AppModule{}
	_ appmodule.HasEndBlocker = AppModule{}
)

type AppModuleBasic struct{}

func (AppModuleBasic) Name() string                                      { return types.ModuleName }
func (AppModuleBasic) RegisterLegacyAminoCodec(_ *codec.LegacyAmino)     {}
func (AppModuleBasic) RegisterInterfaces(registry codectypes.InterfaceRegistry) {
	types.RegisterInterfaces(registry)
}
func (AppModuleBasic) ConsensusVersion() uint64                          { return types.ConsensusVersion }

// Genesis is plain JSON (no proto); the passed codec.JSONCodec is intentionally unused.
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
func (am AppModule) RegisterServices(cfg module.Configurator) {
	types.RegisterMsgServer(cfg.MsgServer(), keeper.NewMsgServerImpl(am.keeper))
}

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

// EndBlock rolls up tester activity and triggers the hard snapshot.
func (am AppModule) EndBlock(ctx context.Context) error {
	return am.keeper.EndBlock(sdk.UnwrapSDKContext(ctx))
}

func (am AppModule) IsAppModule()        {}
func (am AppModule) IsOnePerModuleType() {}
