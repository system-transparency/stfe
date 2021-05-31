// Package main provides an STFE server binary
package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/system-transparency/stfe"
	"github.com/system-transparency/stfe/types"
	"google.golang.org/grpc"
)

var (
	httpEndpoint = flag.String("http_endpoint", "localhost:6965", "host:port specification of where stfe serves clients")
	rpcBackend   = flag.String("log_rpc_server", "localhost:6962", "host:port specification of where Trillian serves clients")
	prefix       = flag.String("prefix", "st/v0", "a prefix that proceeds each endpoint path")
	trillianID   = flag.Int64("trillian_id", 0, "log identifier in the Trillian database")
	deadline     = flag.Duration("deadline", time.Second*10, "deadline for backend requests")
	key          = flag.String("key", "", "hex-encoded Ed25519 signing key")
	witnesses    = flag.String("witnesses", "", "comma-separated list of trusted witness verification keys in hex")
	maxRange     = flag.Int64("max_range", 10, "maximum number of entries that can be retrived in a single request")
	interval     = flag.Duration("interval", time.Second*30, "interval used to rotate the log's cosigned STH")
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
	// Trusted witnesses
	witnesses, err := newWitnessMap(*witnesses)
	if err != nil {
		return nil, fmt.Errorf("newWitnessMap: %v", err)
	}
	// Secret signing key
	sk, err := hex.DecodeString(*key)
	if err != nil {
		return nil, fmt.Errorf("sk: DecodeString: %v", err)
	}
	// Setup log parameters
	lp := &stfe.LogParameters{
		LogId:     hex.EncodeToString([]byte(ed25519.PrivateKey(sk).Public().(ed25519.PublicKey))),
		TreeId:    *trillianID,
		Prefix:    *prefix,
		MaxRange:  *maxRange,
		Deadline:  *deadline,
		Interval:  *interval,
		HashType:  crypto.SHA256,
		Signer:    ed25519.PrivateKey(sk),
		Witnesses: witnesses,
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

// newWitnessMap creates a new map of trusted witnesses
func newWitnessMap(witnesses string) (map[[types.HashSize]byte][types.VerificationKeySize]byte, error) {
	w := make(map[[types.HashSize]byte][types.VerificationKeySize]byte)
	if len(witnesses) > 0 {
		for _, witness := range strings.Split(witnesses, ",") {
			b, err := hex.DecodeString(witness)
			if err != nil {
				return nil, fmt.Errorf("DecodeString: %v", err)
			}

			var vk [types.VerificationKeySize]byte
			if n := copy(vk[:], b); n != types.VerificationKeySize {
				return nil, fmt.Errorf("Invalid verification key size: %v", n)
			}
			w[*types.Hash(vk[:])] = vk
		}
	}
	return w, nil
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
