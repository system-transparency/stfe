// Package main provides an STFE server binary
package main

import (
	"flag"
	"strings"
	"time"

	"crypto/ed25519"
	"encoding/base64"
	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/system-transparency/stfe"
	"github.com/system-transparency/stfe/namespace"
	"google.golang.org/grpc"
)

var (
	httpEndpoint = flag.String("http_endpoint", "localhost:6965", "host:port specification of where stfe serves clients")
	rpcBackend   = flag.String("log_rpc_server", "localhost:6962", "host:port specification of where Trillian serves clients")
	prefix       = flag.String("prefix", "st/v1", "a prefix that proceeds each endpoint path")
	trillianID   = flag.Int64("trillian_id", 5991359069696313945, "log identifier in the Trillian database")
	rpcDeadline  = flag.Duration("rpc_deadline", time.Second*10, "deadline for backend RPC requests")
	key          = flag.String("key", "8gzezwrU/2eTrO6tEYyLKsoqn5V54URvKIL9cTE7jUYUqXVX4neJvcBq/zpSAYPsZFG1woh0OGBzQbi9UP9MZw==", "base64-encoded Ed25519 signing key")
	namespaces   = flag.String("namespaces", "AAEgHOQFUkKNWpjYAhNKTyWCzahlI7RDtf5123kHD2LACj0=,AAEgLqrWb9JwQUTk/SwTNDdMH8aRmy3mbmhwEepO5WSgb+A=", "comma-separated list of trusted namespaces in base64 (default: testdata.Ed25519{Vk,Vk2})")
	maxRange     = flag.Int64("max_range", 2, "maximum number of entries that can be retrived in a single request")
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

	glog.Info("Adding prometheus handler on path: /metrics")
	http.Handle("/metrics", promhttp.Handler())

	glog.Infof("Creating namespace pool")
	var anchors []*namespace.Namespace
	for _, b64 := range strings.Split(*namespaces, ",") {
		b, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			glog.Fatalf("invalid namespace: %s: %v", b64, err)
		}
		var namespace namespace.Namespace
		if err := namespace.Unmarshal(b); err != nil {
			glog.Fatalf("invalid namespace: %s: %v", b64, err)
		}
		anchors = append(anchors, &namespace)
	}
	pool, err := namespace.NewNamespacePool(anchors)
	if err != nil {
		glog.Fatalf("invalid namespace pool: %v", err)
	}

	glog.Infof("Creating log signer and identifier")
	sk, err := base64.StdEncoding.DecodeString(*key)
	if err != nil {
		glog.Fatalf("invalid signing key: %v", err)
	}
	signer := ed25519.PrivateKey(sk)
	logId, err := namespace.NewNamespaceEd25519V1([]byte(ed25519.PrivateKey(sk).Public().(ed25519.PublicKey)))
	if err != nil {
		glog.Fatalf("failed creating log id from secret key: %v", err)
	}

	glog.Infof("Initializing log parameters")
	lp, err := stfe.NewLogParameters(signer, logId, *trillianID, *prefix, pool, *maxRange)
	if err != nil {
		glog.Fatalf("failed setting up log parameters: %v", err)
	}

	i := stfe.NewInstance(lp, client, *rpcDeadline)
	for _, handler := range i.Handlers() {
		glog.Infof("adding handler: %s", handler.Path())
		mux.Handle(handler.Path(), handler)
	}
	glog.Infof("Configured: %s", i)

	glog.Infof("Serving on %v/%v", *httpEndpoint, *prefix)
	srv := http.Server{Addr: *httpEndpoint}
	err = srv.ListenAndServe()
	if err != http.ErrServerClosed {
		glog.Warningf("Server exited: %v", err)
	}

	glog.Flush()
}
