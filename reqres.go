package stfe

import (
	"fmt"
	"strconv"

	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian"
)

// AddEntryRequest is a collection of add-entry input parameters
type AddEntryRequest struct {
	Item        string `json:"item"`        // base64-encoded StItem
	Signature   string `json:"signature"`   // base64-encoded DigitallySigned
	Certificate string `json:"certificate"` // base64-encoded X.509 certificate
}

// GetEntriesRequest is a collection of get-entry input parameters
type GetEntriesRequest struct {
	Start int64 `json:"start"` // 0-based and inclusive start-index
	End   int64 `json:"end"`   // 0-based and inclusive end-index
}

// GetProofByHashRequest is a collection of get-proof-by-hash input parameters
type GetProofByHashRequest struct {
	Hash     []byte `json:"hash"`      // base64-encoded leaf hash
	TreeSize int64  `json:"tree_size"` // Tree head size to base proof on
}

// GetEntryResponse is an assembled log entry and its associated appendix
type GetEntryResponse struct {
	Leaf      string   `json:"leaf"`      // base64-encoded StItem
	Signature string   `json:"signature"` // base64-encoded DigitallySigned
	Chain     []string `json:"chain"`     // base64-encoded X.509 certificates
}

// GetEntriesResponse is an assembled get-entries responses
type GetEntriesResponse struct {
	Entries []GetEntryResponse `json:"entries"`
}

// GetProofByHashResponse is an assembled inclusion proof response
type GetProofByHashResponse struct {
	InclusionProof string `json:"inclusion_proof"` // base64-encoded StItem
}

// GetAnchorsResponse
type GetAnchorsResponse struct {
	Certificates []string `json:"certificates"`
}

// NewAddEntryRequest parses and sanitizes the JSON-encoded add-entry
// parameters from an incoming HTTP post.  The resulting AddEntryRequest is
// well-formed, but not necessarily trusted (further sanitization is needed).
func NewAddEntryRequest(r *http.Request) (AddEntryRequest, error) {
	var ret AddEntryRequest
	if err := UnpackJsonPost(r, &ret); err != nil {
		return ret, err
	}

	item, err := StItemFromB64(ret.Item)
	if err != nil {
		return ret, fmt.Errorf("failed decoding StItem: %v", err)
	}
	if item.Format != StFormatChecksumV1 {
		return ret, fmt.Errorf("invalid StItem format: %s", item.Format)
	}
	// TODO: verify that we got a checksum length
	// TODO: verify that we got a signature and certificate
	return ret, nil
}

// NewGetEntriesRequest parses and sanitizes the URL-encoded get-entries
// parameters from an incoming HTTP request.
func NewGetEntriesRequest(httpRequest *http.Request) (GetEntriesRequest, error) {
	start, err := strconv.ParseInt(httpRequest.FormValue("start"), 10, 64)
	if err != nil {
		return GetEntriesRequest{}, fmt.Errorf("bad start parameter: %v", err)
	}
	end, err := strconv.ParseInt(httpRequest.FormValue("end"), 10, 64)
	if err != nil {
		return GetEntriesRequest{}, fmt.Errorf("bad end parameter: %v", err)
	}

	if start < 0 {
		return GetEntriesRequest{}, fmt.Errorf("bad parameters: start(%v) must have a non-negative value", start)
	}
	if start > end {
		return GetEntriesRequest{}, fmt.Errorf("bad parameters: start(%v) must be larger than end(%v)", start, end)
	}
	// TODO: check that range is not larger than the max range. Yes -> truncate
	// TODO: check that end is not past the most recent STH. Yes -> truncate
	return GetEntriesRequest{Start: start, End: end}, nil
}

// NewGetProofByHashRequest parses and sanitizes the URL-encoded
// get-proof-by-hash parameters from an incoming HTTP request.
func NewGetProofByHashRequest(httpRequest *http.Request) (GetProofByHashRequest, error) {
	treeSize, err := strconv.ParseInt(httpRequest.FormValue("tree_size"), 10, 64)
	if err != nil {
		return GetProofByHashRequest{}, fmt.Errorf("bad tree_size parameter: %v", err)
	}
	if treeSize < 0 {
		return GetProofByHashRequest{}, fmt.Errorf("bad tree_size parameter: negative value")
	}
	// TODO: check that tree size is not past STH.tree_size

	hash, err := base64.StdEncoding.DecodeString(httpRequest.FormValue("hash"))
	if err != nil {
		return GetProofByHashRequest{}, fmt.Errorf("bad hash parameter: %v", err)
	}
	return GetProofByHashRequest{TreeSize: treeSize, Hash: hash}, nil
}

// NewGetEntryResponse assembles a log entry and its appendix
func NewGetEntryResponse(leaf []byte) GetEntryResponse {
	return GetEntryResponse{
		Leaf: base64.StdEncoding.EncodeToString(leaf),
		// TODO: add signature and chain
	}
}

// NewGetEntriesResponse assembles a get-entries response
func NewGetEntriesResponse(leaves []*trillian.LogLeaf) (GetEntriesResponse, error) {
	entries := make([]GetEntryResponse, 0, len(leaves))
	for _, leaf := range leaves {
		entries = append(entries, NewGetEntryResponse(leaf.GetLeafValue())) // TODO: add signature and chain
	}
	return GetEntriesResponse{entries}, nil
}

// NewGetProofByHashResponse assembles a get-proof-by-hash response
func NewGetProofByHashResponse(treeSize uint64, inclusionProof *trillian.Proof) (*GetProofByHashResponse, error) {
	item := NewInclusionProofV1([]byte("TODO: add log ID"), treeSize, inclusionProof)
	b, err := tls.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("tls marshal failed: %v", err)
	}
	return &GetProofByHashResponse{
		InclusionProof: base64.StdEncoding.EncodeToString(b),
	}, nil
}

func NewGetAnchorsResponse(anchors []*x509.Certificate) GetAnchorsResponse {
	certificates := make([]string, 0, len(anchors))
	for _, certificate := range anchors {
		certificates = append(certificates, base64.StdEncoding.EncodeToString(certificate.Raw))
	}
	return GetAnchorsResponse{Certificates: certificates}
}

// VerifyAddEntryRequest determines whether a well-formed AddEntryRequest should
// be inserted into the log.  If so, the serialized leaf value is returned.
func VerifyAddEntryRequest(a ctfe.CertValidationOpts, r AddEntryRequest) ([]byte, error) {
	item, _ := StItemFromB64(r.Item) // r.Item is a well-formed ChecksumV1
	leaf, _ := tls.Marshal(item)     // again, r.Item is well-formed

	chainBytes, err := base64.StdEncoding.DecodeString(r.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed decoding certificate: %v", err)
	}

	chain := make([][]byte, 0, 1)
	chain = append(chain, chainBytes)
	_, err = ctfe.ValidateChain(chain, a)
	if err != nil {
		return nil, fmt.Errorf("chain verification failed: %v", err)
	}

	// TODO: verify signature
	return leaf, nil
}

// UnpackJsonPost unpacks a json-encoded HTTP POST request into `unpack`
func UnpackJsonPost(r *http.Request, unpack interface{}) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed reading request body: %v", err)
	}
	if err := json.Unmarshal(body, &unpack); err != nil {
		return fmt.Errorf("failed parsing json body: %v", err)
	}
	return nil
}
