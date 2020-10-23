package stfe

import (
	"time"

	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"

	"github.com/google/certificate-transparency-go/trillian/ctfe"
	ctutil "github.com/google/certificate-transparency-go/trillian/util"
)

// instance groups information about a specific STFE instance.
type instance struct {
	prefix     string
	logID      int64
	client     trillian.TrillianLogClient
	deadline   time.Duration
	anchors    ctfe.CertValidationOpts
	timesource ctutil.TimeSource
}

// NewInstance returns a new STFE instance
func NewInstance(prefix string, id int64, client trillian.TrillianLogClient, deadline time.Duration, timesource ctutil.TimeSource, anchors ctfe.CertValidationOpts) *instance {
	return &instance{
		prefix:     prefix,
		logID:      id,
		client:     client,
		deadline:   deadline,
		timesource: timesource,
		anchors:    anchors,
	}
}

// addEndpoints registers STFE handler functions for the respective HTTP paths
func (i *instance) AddEndpoints(mux *http.ServeMux) {
	for _, endpoint := range []struct {
		path    string
		handler appHandler
	}{
		{i.prefix + "/add-entry", appHandler{instance: i, handler: addEntry, endpoint: "add-entry", method: http.MethodPost}},
		{i.prefix + "/get-entries", appHandler{instance: i, handler: getEntries, endpoint: "get-entries", method: http.MethodGet}},
		{i.prefix + "/get-anchors", appHandler{instance: i, handler: getAnchors, endpoint: "get-anchors", method: http.MethodGet}},
		{i.prefix + "/get-proof-by-hash", appHandler{instance: i, handler: getProofByHash, endpoint: "get-proof-by-hash", method: http.MethodGet}},
		{i.prefix + "/get-consistency-proof", appHandler{instance: i, handler: getConsistencyProof, endpoint: "get-consistency-proof", method: http.MethodGet}},
		{i.prefix + "/get-sth", appHandler{instance: i, handler: getSth, endpoint: "get-sth", method: http.MethodGet}},
	} {
		glog.Infof("adding handler for %v", endpoint.path)
		mux.Handle(endpoint.path, endpoint.handler)
	}
}
