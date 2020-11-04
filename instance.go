package stfe

import (
	"crypto"
	"fmt"
	"time"

	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"

	"github.com/golang/glog"
	"github.com/google/trillian"
)

// Instance is an instance of a particular log front-end
type Instance struct {
	LogParameters *LogParameters
	Client        trillian.TrillianLogClient
	Deadline      time.Duration
}

// LogParameters is a collection of log parameters
type LogParameters struct {
	LogId      []byte // used externally by everyone
	TreeId     int64  // used internally by Trillian
	Prefix     string
	MaxRange   int64               // max entries per get-entries request
	MaxChain   int64               // max submitter certificate chain length
	AnchorPool *x509.CertPool      // for chain verification
	AnchorList []*x509.Certificate // for access to the raw certificates
	KeyUsage   []x509.ExtKeyUsage  // which extended key usages are accepted
	Signer     crypto.Signer
	HashType   crypto.Hash // hash function used by Trillian
}

func (i Instance) String() string {
	return fmt.Sprintf("%s Deadline(%v)\n", i.LogParameters, i.Deadline)
}

func (p LogParameters) String() string {
	return fmt.Sprintf("LogId(%s) TreeId(%d) Prefix(%s) NumAnchors(%d)", base64.StdEncoding.EncodeToString(p.LogId), p.TreeId, p.Prefix, len(p.AnchorList))
}

func (i *LogParameters) id() string {
	return base64.StdEncoding.EncodeToString(i.LogId)
}

// NewInstance returns a new STFE Instance
func NewInstance(lp *LogParameters, client trillian.TrillianLogClient, deadline time.Duration, mux *http.ServeMux) (*Instance, error) {
	i := &Instance{
		LogParameters: lp,
		Client:        client,
		Deadline:      deadline,
	}
	i.registerHandlers(mux)
	once.Do(metricSetup)
	return i, nil
}

// NewLogParameters initializes log parameters, assuming ed25519 signatures.
func NewLogParameters(treeId int64, prefix string, anchorPath, keyPath string, maxRange, maxChain int64) (*LogParameters, error) {
	anchorList, anchorPool, err := LoadTrustAnchors(anchorPath)
	if err != nil {
		return nil, err
	}

	key, err := LoadEd25519SigningKey(keyPath)
	if err != nil {
		return nil, err
	}

	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("failed DER encoding SubjectPublicKeyInfo: %v", err)
	}
	hasher := sha256.New()
	hasher.Write(pub)
	logId := hasher.Sum(nil)

	return &LogParameters{
		LogId:      logId,
		TreeId:     treeId,
		Prefix:     prefix,
		MaxRange:   maxRange,
		MaxChain:   maxChain,
		AnchorPool: anchorPool,
		AnchorList: anchorList,
		KeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Signer:     key,
		HashType:   crypto.SHA256,
	}, nil
}

func (i *Instance) registerHandlers(mux *http.ServeMux) {
	for _, endpoint := range []struct {
		path    string
		handler appHandler
	}{
		{i.LogParameters.Prefix + "/add-entry", appHandler{instance: i, handler: addEntry, endpoint: "add-entry", method: http.MethodPost}},
		{i.LogParameters.Prefix + "/get-entries", appHandler{instance: i, handler: getEntries, endpoint: "get-entries", method: http.MethodGet}},
		{i.LogParameters.Prefix + "/get-anchors", appHandler{instance: i, handler: getAnchors, endpoint: "get-anchors", method: http.MethodGet}},
		{i.LogParameters.Prefix + "/get-proof-by-hash", appHandler{instance: i, handler: getProofByHash, endpoint: "get-proof-by-hash", method: http.MethodGet}},
		{i.LogParameters.Prefix + "/get-consistency-proof", appHandler{instance: i, handler: getConsistencyProof, endpoint: "get-consistency-proof", method: http.MethodGet}},
		{i.LogParameters.Prefix + "/get-sth", appHandler{instance: i, handler: getSth, endpoint: "get-sth", method: http.MethodGet}},
	} {
		glog.Infof("adding handler for %v", endpoint.path)
		mux.Handle(endpoint.path, endpoint.handler)
	}
}
