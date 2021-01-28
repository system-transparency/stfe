package stfe

import (
	"crypto"
	"fmt"
	"strings"
	"time"

	"net/http"

	"github.com/google/trillian"
	"github.com/system-transparency/stfe/namespace"
)

// Instance is an instance of a particular log front-end
type Instance struct {
	LogParameters *LogParameters
	Client        trillian.TrillianLogClient
	Deadline      time.Duration
}

// LogParameters is a collection of log parameters
type LogParameters struct {
	LogId      []byte                   // used externally by everyone
	TreeId     int64                    // used internally by Trillian
	Prefix     string                   // e.g., "test" for <base>/test
	MaxRange   int64                    // max entries per get-entries request
	Namespaces *namespace.NamespacePool // trust namespaces
	Signer     crypto.Signer
	HashType   crypto.Hash // hash function used by Trillian
}

// Endpoint is a named HTTP API endpoint
type Endpoint string

const (
	EndpointAddEntry            = Endpoint("add-entry")
	EndpointGetEntries          = Endpoint("get-entries")
	EndpointGetAnchors          = Endpoint("get-anchors")
	EndpointGetProofByHash      = Endpoint("get-proof-by-hash")
	EndpointGetConsistencyProof = Endpoint("get-consistency-proof")
	EndpointGetSth              = Endpoint("get-sth")
)

func (i Instance) String() string {
	return fmt.Sprintf("%s Deadline(%v)\n", i.LogParameters, i.Deadline)
}

func (lp LogParameters) String() string {
	return fmt.Sprintf("LogId(%s) TreeId(%d) Prefix(%s) MaxRange(%d) Namespaces(%d)", lp.id(), lp.TreeId, lp.Prefix, lp.MaxRange, len(lp.Namespaces.List()))
}

func (e Endpoint) String() string {
	return string(e)
}

// NewInstance creates a new STFE instance
func NewInstance(lp *LogParameters, client trillian.TrillianLogClient, deadline time.Duration) *Instance {
	return &Instance{
		LogParameters: lp,
		Client:        client,
		Deadline:      deadline,
	}
}

// NewLogParameters creates new log parameters.  Note that the signer is
// assumed to be an ed25519 signing key.  Could be fixed at some point.
func NewLogParameters(signer crypto.Signer, logId *namespace.Namespace, treeId int64, prefix string, namespaces *namespace.NamespacePool, maxRange int64) (*LogParameters, error) {
	if signer == nil {
		return nil, fmt.Errorf("need a signer but got none")
	}
	if maxRange < 1 {
		return nil, fmt.Errorf("max range must be at least one")
	}
	if len(namespaces.List()) < 1 {
		return nil, fmt.Errorf("need at least one trusted namespace")
	}
	lid, err := logId.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed encoding log identifier: %v", err)
	}
	return &LogParameters{
		LogId:      lid,
		TreeId:     treeId,
		Prefix:     prefix,
		MaxRange:   maxRange,
		Namespaces: namespaces,
		Signer:     signer,
		HashType:   crypto.SHA256, // STFE assumes RFC 6962 hashing
	}, nil
}

// Handlers returns a list of STFE handlers
func (i *Instance) Handlers() []Handler {
	return []Handler{
		Handler{instance: i, handler: addEntry, endpoint: EndpointAddEntry, method: http.MethodPost},
		Handler{instance: i, handler: getEntries, endpoint: EndpointGetEntries, method: http.MethodGet},
		Handler{instance: i, handler: getAnchors, endpoint: EndpointGetAnchors, method: http.MethodGet},
		Handler{instance: i, handler: getProofByHash, endpoint: EndpointGetProofByHash, method: http.MethodGet},
		Handler{instance: i, handler: getConsistencyProof, endpoint: EndpointGetConsistencyProof, method: http.MethodGet},
		Handler{instance: i, handler: getSth, endpoint: EndpointGetSth, method: http.MethodGet},
	}
}

// id formats the log's identifier as base64
func (i *LogParameters) id() string {
	return b64(i.LogId)
}

// Path joins a number of components to form a full endpoint path, e.g., base
// ("example.com"), prefix ("st/v1"), and the endpoint itself ("get-sth").
func (e Endpoint) Path(components ...string) string {
	return strings.Join(append(components, string(e)), "/")
}
