package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethrpc "github.com/ethereum/go-ethereum/rpc"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"golang.org/x/sync/errgroup"

	rpcclient "github.com/cometbft/cometbft/rpc/client"

	"github.com/cosmos/evm/rpc"
	"github.com/cosmos/evm/rpc/backend"
	"github.com/cosmos/evm/rpc/stream"
	serverconfig "github.com/cosmos/evm/server/config"
	"github.com/cosmos/evm/server/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/server"
)

const shutdownTimeout = 200 * time.Millisecond

type AppWithPendingTxStream interface {
	RegisterPendingTxListener(listener func(common.Hash))
}

// StartJSONRPC starts the JSON-RPC server
func StartJSONRPC(
	ctx context.Context,
	srvCtx *server.Context,
	clientCtx client.Context,
	g *errgroup.Group,
	config *serverconfig.Config,
	indexer types.EVMTxIndexer,
	app AppWithPendingTxStream,
	mempool backend.Mempool,
) (*http.Server, error) {
	logger := srvCtx.Logger.With("module", "geth")

	// SECURITY GATE (Limonata): never serve signing-capable JSON-RPC methods
	// (eth_accounts / eth_sendTransaction / eth_sign / personal_*) on a public
	// interface while the node's keyring holds keys. On a public listener the
	// node signs txs and messages for those keys with no authentication, which
	// is remote unauthenticated fund theft plus a signing oracle. Fail closed.
	if err := guardExposedKeyring(config, clientCtx); err != nil {
		return nil, err
	}

	evtClient, ok := clientCtx.Client.(rpcclient.EventsClient)
	if !ok {
		return nil, fmt.Errorf("client %T does not implement EventsClient", clientCtx.Client)
	}

	stream := stream.NewRPCStreams(evtClient, logger, clientCtx.TxConfig.TxDecoder())
	app.RegisterPendingTxListener(stream.ListenPendingTx)

	evmBackend := backend.NewBackend(
		srvCtx,
		clientCtx,
		indexer,
		mempool,
		backend.WithUnprotectedTxs(config.JSONRPC.AllowUnprotectedTxs),
		backend.WithLogger(srvCtx.Logger),
	)

	apis := rpc.BuildRPCs(config.JSONRPC.API, srvCtx, clientCtx, stream, evmBackend)

	rpcServer := ethrpc.NewServer()
	rpcServer.SetBatchLimits(config.JSONRPC.BatchRequestLimit, config.JSONRPC.BatchResponseMaxSize)
	rpcServer.SetHTTPBodyLimit(config.JSONRPC.HTTPBodyLimit)

	for _, api := range apis {
		if err := rpcServer.RegisterName(api.Namespace, api.Service); err != nil {
			logger.Error(
				"failed to register service in JSON RPC namespace",
				"namespace", api.Namespace,
				"service", api.Service,
			)
			return nil, err
		}
	}

	r := mux.NewRouter()
	r.HandleFunc("/", rpcServer.ServeHTTP).Methods("POST")

	handlerWithCors := cors.Default()
	if config.API.EnableUnsafeCORS {
		handlerWithCors = cors.AllowAll()
	}

	httpSrv := &http.Server{
		Addr:              config.JSONRPC.Address,
		Handler:           handlerWithCors.Handler(r),
		ReadHeaderTimeout: config.JSONRPC.HTTPTimeout,
		ReadTimeout:       config.JSONRPC.HTTPTimeout,
		WriteTimeout:      config.JSONRPC.HTTPTimeout,
		IdleTimeout:       config.JSONRPC.HTTPIdleTimeout,
	}
	httpSrvDone := make(chan struct{}, 1)

	ln, err := Listen(httpSrv.Addr, config)
	if err != nil {
		return nil, err
	}

	g.Go(func() error {
		srvCtx.Logger.Info("Starting JSON-RPC server", "address", config.JSONRPC.Address)
		errCh := make(chan error)
		go func() {
			errCh <- httpSrv.Serve(ln)
		}()

		// Start a blocking select to wait for an indication to stop the server or that
		// the server failed to start properly.
		select {
		case <-ctx.Done():
			// The calling process canceled or closed the provided context, so we must
			// gracefully stop the JSON-RPC server.
			logger.Info("stopping JSON-RPC server...", "address", config.JSONRPC.Address, "timeout", shutdownTimeout)
			ctxShutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			if err := httpSrv.Shutdown(ctxShutdown); err != nil {
				logger.Error("failed to shutdown JSON-RPC server", "error", err.Error())
			}
			return nil
		case err := <-errCh:
			if err == http.ErrServerClosed {
				close(httpSrvDone)
				return nil
			}

			srvCtx.Logger.Error("failed to start JSON-RPC server", "error", err.Error())
			return err
		}
	})

	srvCtx.Logger.Info("Starting JSON WebSocket server", "address", config.JSONRPC.WsAddress)

	wsSrv := rpc.NewWebsocketsServer(clientCtx, logger, stream, config)
	wsSrv.Start()
	return httpSrv, nil
}

// isPublicBind reports whether a "host:port" listen address is reachable from
// off-box. An empty or unparsable host, or any non-loopback IP, is treated as
// public (fail safe). "localhost" and loopback IPs are private.
func isPublicBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return true // bind-all
	}
	if host == "localhost" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback()
	}
	return true
}

// guardExposedKeyring refuses to start the JSON-RPC/WS server when it would
// serve signing-capable methods (eth_accounts / eth_sendTransaction / eth_sign
// via the "eth" namespace, or the "personal" namespace) on a public interface
// while the node's keyring holds keys. That combination lets any anonymous
// caller make the node sign and broadcast as those keys. Fail closed; a node on
// a trusted private network can override with LIMONATA_ALLOW_EXPOSED_KEYRING=1.
func guardExposedKeyring(config *serverconfig.Config, clientCtx client.Context) error {
	if os.Getenv("LIMONATA_ALLOW_EXPOSED_KEYRING") == "1" {
		return nil
	}

	public := isPublicBind(config.JSONRPC.Address) || isPublicBind(config.JSONRPC.WsAddress)

	signing := false
	for _, ns := range config.JSONRPC.API {
		if ns == rpc.EthNamespace || ns == rpc.PersonalNamespace {
			signing = true
			break
		}
	}

	if !public || !signing || clientCtx.Keyring == nil {
		return nil
	}

	keys, err := clientCtx.Keyring.List()
	if err != nil {
		return fmt.Errorf("json-rpc keyring safety check failed: %w", err)
	}
	if len(keys) == 0 {
		return nil
	}

	return fmt.Errorf(
		"refusing to start JSON-RPC: %d key(s) in the keyring would be exposed for "+
			"unauthenticated server-side signing (eth_accounts/eth_sendTransaction/eth_sign) "+
			"on public listener http=%q ws=%q with namespaces %v. Remove the keys from this "+
			"node's keyring, bind json-rpc to loopback, or drop the eth/personal namespaces. "+
			"Override only on a trusted private network with LIMONATA_ALLOW_EXPOSED_KEYRING=1",
		len(keys), config.JSONRPC.Address, config.JSONRPC.WsAddress, config.JSONRPC.API,
	)
}
