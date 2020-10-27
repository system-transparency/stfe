package stfe

import (
	"fmt"
	"strconv"

	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/google/certificate-transparency-go/tls"
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
	Signature string   `json:"signature"` // base64-encoded signature
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
func NewGetEntryResponse(leaf, appendix []byte) (GetEntryResponse, error) {
	var app Appendix
	extra, err := tls.Unmarshal(appendix, &app)
	if err != nil {
		return GetEntryResponse{}, fmt.Errorf("failed tls unmarshaling appendix: %v (%v)", err, extra)
	} else if len(extra) > 0 {
		return GetEntryResponse{}, fmt.Errorf("tls umarshal found extra data for appendix: %v", extra)
	}

	chain := make([]string, 0, len(app.Chain))
	for _, c := range app.Chain {
		chain = append(chain, base64.StdEncoding.EncodeToString(c.Data))
	}

	return GetEntryResponse{
		Leaf:      base64.StdEncoding.EncodeToString(leaf),
		Signature: base64.StdEncoding.EncodeToString(app.Signature),
		Chain:     chain,
	}, nil
}

// NewGetEntriesResponse assembles a get-entries response
func NewGetEntriesResponse(leaves []*trillian.LogLeaf) (GetEntriesResponse, error) {
	entries := make([]GetEntryResponse, 0, len(leaves))
	for _, leaf := range leaves {
		entry, err := NewGetEntryResponse(leaf.GetLeafValue(), leaf.GetExtraData())
		if err != nil {
			return GetEntriesResponse{}, err
		}
		entries = append(entries, entry)
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
// be inserted into the log.  The corresponding leaf and appendix is returned.
func VerifyAddEntryRequest(ld *LogParameters, r AddEntryRequest) ([]byte, []byte, error) {
	item, err := StItemFromB64(r.Item)
	if err != nil {
		return nil, nil, fmt.Errorf("failed decoding StItem: %v", err)
	}

	leaf, err := tls.Marshal(item)
	if err != nil {
		return nil, nil, fmt.Errorf("failed tls marshaling StItem: %v", err)
	} // leaf is the serialized data that should be added to the tree

	c, err := base64.StdEncoding.DecodeString(r.Certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("failed decoding certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(c)
	if err != nil {
		return nil, nil, fmt.Errorf("failed decoding certificate: %v", err)
	} // certificate is the end-entity certificate that signed leaf

	chain, err := VerifyChain(ld, certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("chain verification failed: %v", err)
	} // chain is a valid path to some trust anchor

	signature, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("failed decoding signature: %v", err)
	}
	if err := VerifySignature(leaf, signature, certificate); err != nil {
		return nil, nil, fmt.Errorf("signature verification failed: %v", err)
	} // signature is valid for certificate

	// TODO: update doc of what signature "is", i.e., w/e x509 does
	// TODO: doc in markdown/api.md what signature schemes we expect
	appendix, err := tls.Marshal(NewAppendix(chain, signature))
	if err != nil {
		return nil, nil, fmt.Errorf("failed tls marshaling appendix: %v", err)
	}

	return leaf, appendix, nil
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

func WriteJsonResponse(response interface{}, w http.ResponseWriter) error {
	json, err := json.Marshal(&response)
	if err != nil {
		return fmt.Errorf("json-encoding failed: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(json)
	if err != nil {
		return fmt.Errorf("failed writing json response: %v", err)
	}
	return nil
}
