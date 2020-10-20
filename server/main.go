// Package main provides an STFE binary
package main

import (
	"flag"
	"time"

	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/system-transparency/stfe"
	"google.golang.org/grpc"

	ctutil "github.com/google/certificate-transparency-go/trillian/util"
)

var (
	httpEndpoint = flag.String("http_endpoint", "localhost:6965", "host:port specification of where stfe serves clients")
	rpcBackend   = flag.String("log_rpc_server", "localhost:6962", "host:port specification of where Trillian serves clients")
	prefix       = flag.String("prefix", "/st/v1", "a prefix that proceeds each endpoint path")
	trillianID   = flag.Int64("trillianID", 5991359069696313945, "log identifier in the Trillian database")
	rpcDeadline  = flag.Duration("rpc_deadline", time.Second*10, "deadline for backend RPC requests")
)

func main() {
	flag.Parse()

	glog.Info("Dialling Trillian gRPC log server")
	dialOpts := []grpc.DialOption{grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(*rpcDeadline)}
	conn, err := grpc.Dial(*rpcBackend, dialOpts...)
	if err != nil {
		glog.Fatal(err)
	}

	glog.Info("Creating HTTP request multiplexer")
	mux := http.NewServeMux()
	http.Handle("/", mux)

	glog.Info("Creating STFE server instance")
	stfe_server := stfe.NewInstance(*prefix, *trillianID, trillian.NewTrillianLogClient(conn), *rpcDeadline, new(ctutil.SystemTimeSource))
	stfe_server.AddEndpoints(mux)

	glog.Infof("Serving on %v%v", *httpEndpoint, *prefix)
	srv := http.Server{Addr: *httpEndpoint}
	err = srv.ListenAndServe()
	if err != http.ErrServerClosed {
		glog.Warningf("Server exited: %v", err)
	}

	glog.Flush()
}
