// Package main provides an STFE server binary
package main

import (
	"flag"
	"time"

	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/system-transparency/stfe"
	"google.golang.org/grpc"
)

var (
	httpEndpoint = flag.String("http_endpoint", "localhost:6965", "host:port specification of where stfe serves clients")
	rpcBackend   = flag.String("log_rpc_server", "localhost:6962", "host:port specification of where Trillian serves clients")
	prefix       = flag.String("prefix", "/st/v1", "a prefix that proceeds each endpoint path")
	trillianID   = flag.Int64("trillian_id", 5991359069696313945, "log identifier in the Trillian database")
	rpcDeadline  = flag.Duration("rpc_deadline", time.Second*10, "deadline for backend RPC requests")
	anchorPath   = flag.String("anchor_path", "testdata/chain/rgdd-root.pem", "path to a file containing PEM-encoded X.509 root certificates")
	keyPath = flag.String("key_path", "testdata/chain/stfe.key", "path to a PEM-encoded ed25519 signing key")
)

func main() {
	flag.Parse()

	glog.Info("Dialling Trillian gRPC log server")
	dialOpts := []grpc.DialOption{grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(*rpcDeadline)}
	conn, err := grpc.Dial(*rpcBackend, dialOpts...)
	if err != nil {
		glog.Fatal(err)
	}
	client := trillian.NewTrillianLogClient(conn)

	glog.Info("Creating HTTP request multiplexer")
	mux := http.NewServeMux()
	http.Handle("/", mux)

	lp, err := stfe.NewLogParameters(*trillianID, *prefix, *anchorPath, *keyPath)
	if err != nil {
		glog.Fatalf("failed setting up log parameters: %v", err)
	}

	i, err := stfe.NewInstance(lp, client, *rpcDeadline, mux)
	if err != nil {
		glog.Fatalf("failed setting up log instance: %v", err)
	}
	glog.Infof("Configured: %s", i)

	glog.Infof("Serving on %v%v", *httpEndpoint, *prefix)
	srv := http.Server{Addr: *httpEndpoint}
	err = srv.ListenAndServe()
	if err != http.ErrServerClosed {
		glog.Warningf("Server exited: %v", err)
	}

	glog.Flush()
}
