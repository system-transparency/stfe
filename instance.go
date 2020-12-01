package stfe

import (
	"crypto"
	"fmt"
	"strings"
	"time"

	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"

	"github.com/google/trillian"
	"github.com/system-transparency/stfe/x509util"
)

// Instance is an instance of a particular log front-end
type Instance struct {
	LogParameters *LogParameters
	Client        trillian.TrillianLogClient
	Deadline      time.Duration
}

// LogParameters is a collection of log parameters
type LogParameters struct {
	LogId      []byte              // used externally by everyone
	TreeId     int64               // used internally by Trillian
	Prefix     string              // e.g., "test" for <base>/test
	MaxRange   int64               // max entries per get-entries request
	MaxChain   int64               // max submitter certificate chain length
	AnchorPool *x509.CertPool      // for chain verification
	AnchorList []*x509.Certificate // for access to the raw certificates
	KeyUsage   []x509.ExtKeyUsage  // which extended key usages are accepted
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

func (p LogParameters) String() string {
	return fmt.Sprintf("LogId(%s) TreeId(%d) Prefix(%s) NumAnchors(%d)", base64.StdEncoding.EncodeToString(p.LogId), p.TreeId, p.Prefix, len(p.AnchorList))
}

func (e Endpoint) String() string {
	return string(e)
}

// NewInstance creates a new STFE instance
func NewInstance(lp *LogParameters, client trillian.TrillianLogClient, deadline time.Duration, mux *http.ServeMux) *Instance {
	return &Instance{
		LogParameters: lp,
		Client:        client,
		Deadline:      deadline,
	}
}

// NewLogParameters creates new log parameters.  Note that the signer is
// assumed to be an ed25519 signing key.  Could be fixed at some point.
func NewLogParameters(treeId int64, prefix string, anchors []*x509.Certificate, signer crypto.Signer, maxRange, maxChain int64) (*LogParameters, error) {
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed DER encoding SubjectPublicKeyInfo: %v", err)
	}
	if maxRange < 1 {
		return nil, fmt.Errorf("invalid max range: must be at least 1")
	}
	if maxChain < 1 {
		return nil, fmt.Errorf("invalid max chain: must be at least 1")
	}
	hasher := sha256.New()
	hasher.Write(pub)
	return &LogParameters{
		LogId:      hasher.Sum(nil),
		TreeId:     treeId,
		Prefix:     prefix,
		MaxRange:   maxRange,
		MaxChain:   maxChain,
		AnchorPool: x509util.NewCertPool(anchors),
		AnchorList: anchors,
		KeyUsage:   []x509.ExtKeyUsage{}, // placeholder, must be tested if used
		Signer:     signer,
		HashType:   crypto.SHA256, // STFE assumes RFC 6962 hashing
	}, nil
}

// Path joins a number of components to form a full endpoint path, e.g., base
// ("example.com"), prefix ("st/v1"), and the endpoint itself ("get-sth").
func (e Endpoint) Path(components ...string) string {
	return strings.Join(append(components, string(e)), "/")
}

// TODO: id() docdoc
func (i *LogParameters) id() string {
	return base64.StdEncoding.EncodeToString(i.LogId)
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
