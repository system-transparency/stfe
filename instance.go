package stfe

import (
	"crypto"
	"fmt"
	"time"

	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"net/http"

	"github.com/golang/glog"
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
	return i, nil
}

// NewLogParameters initializes log parameters, assuming ed25519 signatures.
func NewLogParameters(treeId int64, prefix string, anchorPath, keyPath string, maxRange, maxChain int64) (*LogParameters, error) {
	anchorList, anchorPool, err := loadTrustAnchors(anchorPath)
	if err != nil {
		return nil, err
	}

	pem, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed reading %s: %v", keyPath, err)
	}
	key, err := x509util.NewEd25519PrivateKey(pem)
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
		KeyUsage:   []x509.ExtKeyUsage{}, // placeholder, must be tested if used
		Signer:     key,
		HashType:   crypto.SHA256,
	}, nil
}

func (i *Instance) registerHandlers(mux *http.ServeMux) {
	for _, endpoint := range []struct {
		path    string
		handler handler
	}{
		{i.LogParameters.Prefix + "/add-entry", handler{instance: i, handler: addEntry, endpoint: "add-entry", method: http.MethodPost}},
		{i.LogParameters.Prefix + "/get-entries", handler{instance: i, handler: getEntries, endpoint: "get-entries", method: http.MethodGet}},
		{i.LogParameters.Prefix + "/get-anchors", handler{instance: i, handler: getAnchors, endpoint: "get-anchors", method: http.MethodGet}},
		{i.LogParameters.Prefix + "/get-proof-by-hash", handler{instance: i, handler: getProofByHash, endpoint: "get-proof-by-hash", method: http.MethodGet}},
		{i.LogParameters.Prefix + "/get-consistency-proof", handler{instance: i, handler: getConsistencyProof, endpoint: "get-consistency-proof", method: http.MethodGet}},
		{i.LogParameters.Prefix + "/get-sth", handler{instance: i, handler: getSth, endpoint: "get-sth", method: http.MethodGet}},
	} {
		glog.Infof("adding handler for %v", endpoint.path)
		mux.Handle(endpoint.path, endpoint.handler)
	}
}

// loadTrustAnchors loads a list of PEM-encoded certificates from file
func loadTrustAnchors(path string) ([]*x509.Certificate, *x509.CertPool, error) {
	pem, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading trust anchors: %v", err)
	}
	anchorList, err := x509util.NewCertificateList(pem)
	if err != nil || len(anchorList) == 0 {
		return nil, nil, fmt.Errorf("failed parsing trust anchors: %v", err)
	}
	return anchorList, x509util.NewCertPool(anchorList), nil
}
