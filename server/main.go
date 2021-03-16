// Package main provides an STFE server binary
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"os/signal"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/system-transparency/stfe"
	"github.com/system-transparency/stfe/types"
	"google.golang.org/grpc"
)

var (
	httpEndpoint    = flag.String("http_endpoint", "localhost:6965", "host:port specification of where stfe serves clients")
	rpcBackend      = flag.String("log_rpc_server", "localhost:6962", "host:port specification of where Trillian serves clients")
	prefix          = flag.String("prefix", "st/v1", "a prefix that proceeds each endpoint path")
	trillianID      = flag.Int64("trillian_id", 0, "log identifier in the Trillian database")
	deadline        = flag.Duration("deadline", time.Second*10, "deadline for backend requests")
	key             = flag.String("key", "", "base64-encoded Ed25519 signing key")
	submitterPolicy = flag.Bool("submitter_policy", false, "whether there is any submitter namespace policy (default: none, accept unregistered submitter namespaces)")
	witnessPolicy   = flag.Bool("witness_policy", false, "whether there is any witness namespace policy (default: none, accept unregistered witness namespaces)")
	submitters      = flag.String("submitters", "", "comma-separated list of trusted submitter namespaces in base64 (default: none)")
	witnesses       = flag.String("witnesses", "", "comma-separated list of trusted submitter namespaces in base64 (default: none)")
	maxRange        = flag.Int64("max_range", 10, "maximum number of entries that can be retrived in a single request")
	interval        = flag.Duration("interval", time.Minute*10, "interval used to rotate the log's cosigned STH")
)

func main() {
	flag.Parse()
	defer glog.Flush()

	// wait for clean-up before exit
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	glog.V(3).Infof("configuring stfe instance...")
	instance, err := setupInstanceFromFlags()
	if err != nil {
		glog.Errorf("setupInstance: %v", err)
		return
	}

	glog.V(3).Infof("spawning SthSource")
	go func() {
		wg.Add(1)
		defer wg.Done()
		instance.SthSource.Run(ctx)
		glog.Errorf("SthSource shutdown")
		cancel() // must have SthSource running
	}()

	glog.V(3).Infof("spawning await")
	server := http.Server{Addr: *httpEndpoint}
	go await(ctx, func() {
		wg.Add(1)
		defer wg.Done()
		ctxInner, _ := context.WithTimeout(ctx, time.Second*60)
		glog.Infof("Shutting down HTTP server...")
		server.Shutdown(ctxInner)
		glog.V(3).Infof("HTTP server shutdown")
		glog.Infof("Shutting down spawned go routines...")
		cancel()
	})

	glog.Infof("Serving on %v/%v", *httpEndpoint, *prefix)
	if err = server.ListenAndServe(); err != http.ErrServerClosed {
		glog.Errorf("ListenAndServe: %v", err)
	}
}

// SetupInstance sets up a new STFE instance from flags
func setupInstanceFromFlags() (*stfe.Instance, error) {
	// Trillian gRPC connection
	dialOpts := []grpc.DialOption{grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(*deadline)}
	conn, err := grpc.Dial(*rpcBackend, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("Dial: %v", err)
	}
	client := trillian.NewTrillianLogClient(conn)
	// HTTP multiplexer
	mux := http.NewServeMux()
	http.Handle("/", mux)
	// Prometheus metrics
	glog.V(3).Infof("Adding prometheus handler on path: /metrics")
	http.Handle("/metrics", promhttp.Handler())
	// Trusted submitters
	submitters, err := newNamespacePoolFromString(*submitters)
	if err != nil {
		return nil, fmt.Errorf("submitters: newNamespacePoolFromString: %v", err)
	}
	// Trusted witnesses
	witnesses, err := newNamespacePoolFromString(*witnesses)
	if err != nil {
		return nil, fmt.Errorf("witnesses: NewNamespacePool: %v", err)
	}
	// Log identity
	sk, err := base64.StdEncoding.DecodeString(*key)
	if err != nil {
		return nil, fmt.Errorf("sk: DecodeString: %v", err)
	}
	signer := ed25519.PrivateKey(sk)
	logId, err := types.NewNamespaceEd25519V1([]byte(ed25519.PrivateKey(sk).Public().(ed25519.PublicKey)))
	if err != nil {
		return nil, fmt.Errorf("NewNamespaceEd25519V1: %v", err)
	}
	// Setup log parameters
	lp, err := stfe.NewLogParameters(signer, logId, *trillianID, *prefix, submitters, witnesses, *maxRange, *interval, *deadline, *submitterPolicy, *witnessPolicy)
	if err != nil {
		return nil, fmt.Errorf("NewLogParameters: %v", err)
	}
	// Setup STH source
	source, err := stfe.NewActiveSthSource(client, lp)
	if err != nil {
		return nil, fmt.Errorf("NewActiveSthSource: %v", err)
	}
	// Setup log instance
	i := &stfe.Instance{client, lp, source}
	for _, handler := range i.Handlers() {
		glog.V(3).Infof("adding handler: %s", handler.Path())
		mux.Handle(handler.Path(), handler)
	}
	return i, nil
}

// newNamespacePoolFromString creates a new namespace pool from a
// comma-separated list of serialized and base64-encoded namespaces.
func newNamespacePoolFromString(str string) (*types.NamespacePool, error) {
	var namespaces []*types.Namespace
	if len(str) > 0 {
		for _, b64 := range strings.Split(str, ",") {
			b, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return nil, fmt.Errorf("DecodeString: %v", err)
			}
			var namespace types.Namespace
			if err := types.Unmarshal(b, &namespace); err != nil {
				return nil, fmt.Errorf("Unmarshal: %v", err)
			}
			namespaces = append(namespaces, &namespace)
		}
	}
	pool, err := types.NewNamespacePool(namespaces)
	if err != nil {
		return nil, fmt.Errorf("NewNamespacePool: %v", err)
	}
	return pool, nil
}

// await waits for a shutdown signal and then runs a clean-up function
func await(ctx context.Context, done func()) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigs:
	case <-ctx.Done():
	}
	glog.V(3).Info("received shutdown signal")
	done()
}
