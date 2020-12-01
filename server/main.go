// Package main provides an STFE server binary
package main

import (
	"flag"
	"fmt"
	"time"

	"crypto/x509"
	"io/ioutil"
	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/system-transparency/stfe"
	"github.com/system-transparency/stfe/x509util"
	"google.golang.org/grpc"
)

var (
	httpEndpoint = flag.String("http_endpoint", "localhost:6965", "host:port specification of where stfe serves clients")
	rpcBackend   = flag.String("log_rpc_server", "localhost:6962", "host:port specification of where Trillian serves clients")
	prefix       = flag.String("prefix", "st/v1", "a prefix that proceeds each endpoint path")
	trillianID   = flag.Int64("trillian_id", 5991359069696313945, "log identifier in the Trillian database")
	rpcDeadline  = flag.Duration("rpc_deadline", time.Second*10, "deadline for backend RPC requests")
	anchorPath   = flag.String("anchor_path", "../x509util/testdata/anchors.pem", "path to a file containing PEM-encoded X.509 root certificates")
	keyPath      = flag.String("key_path", "../x509util/testdata/log.key", "path to a PEM-encoded ed25519 signing key")
	maxRange     = flag.Int64("max_range", 2, "maximum number of entries that can be retrived in a single request")
	maxChain     = flag.Int64("max_chain", 3, "maximum number of certificates in a chain, including the trust anchor")
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

	glog.Infof("Loading trust anchors from file: %s", *anchorPath)
	anchors, err := loadCertificates(*anchorPath)
	if err != nil {
		glog.Fatalf("no trust anchors: %v", err)
	}

	glog.Infof("Loading Ed25519 signing key from file: %s", *keyPath)
	pem, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		glog.Fatalf("no signing key: %v", err)
	}
	signer, err := x509util.NewEd25519PrivateKey(pem)
	if err != nil {
		glog.Fatalf("no signing key: %v", err)
	}

	lp, err := stfe.NewLogParameters(*trillianID, *prefix, anchors, signer, *maxRange, *maxChain)
	if err != nil {
		glog.Fatalf("failed setting up log parameters: %v", err)
	}

	i := stfe.NewInstance(lp, client, *rpcDeadline, mux)
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

// loadCertificates loads a non-empty list of PEM-encoded certificates from file
func loadCertificates(path string) ([]*x509.Certificate, error) {
	pem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading %s: %v", path, err)
	}
	anchors, err := x509util.NewCertificateList(pem)
	if err != nil {
		return nil, fmt.Errorf("failed parsing: %v", err)
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("no trust anchors")
	}
	return anchors, nil
}
