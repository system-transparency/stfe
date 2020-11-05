package stfe

import (
	"fmt"
	"strconv"

	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/google/trillian"
)

// AddEntryRequest is a collection of add-entry input parameters
type AddEntryRequest struct {
	Item            []byte   `json:"item"`             // tls-serialized StItem
	Signature       []byte   `json:"signature"`        // serialized signature using the signature scheme below
	SignatureScheme uint16   `json:"signature_scheme"` // rfc 8446, §4.2.3
	Chain           [][]byte `json:"chain"`            // der-encoded X.509 certificates
}

// GetEntriesRequest is a collection of get-entry input parameters
type GetEntriesRequest struct {
	Start int64 `json:"start"` // 0-based and inclusive start-index
	End   int64 `json:"end"`   // 0-based and inclusive end-index
}

// GetProofByHashRequest is a collection of get-proof-by-hash input parameters
type GetProofByHashRequest struct {
	Hash     []byte `json:"hash"`      // leaf hash
	TreeSize int64  `json:"tree_size"` // tree head size to base proof on
}

// GetConsistencyProofRequest is a collection of get-consistency-proof input
// parameters
type GetConsistencyProofRequest struct {
	First  int64 `json:"first"`  // size of the older Merkle tree
	Second int64 `json:"second"` // size of the newer Merkle tree
}

// GetEntryResponse is an assembled log entry and its associated appendix
type GetEntryResponse struct {
	Leaf      []byte   `json:"leaf"`      // tls-serialized StItem
	Signature []byte   `json:"signature"` // Serialized signature using the log's signature scheme
	Chain     [][]byte `json:"chain"`     // der-encoded certificates
}

// newAddEntryRequest parses and sanitizes the JSON-encoded add-entry
// parameters from an incoming HTTP post.  The serialized leaf value and
// associated appendix is returned if the submitted data is valid: well-formed,
// signed using a supported scheme, and chains back to a valid trust anchor.
func (lp *LogParameters) newAddEntryRequest(r *http.Request) ([]byte, []byte, error) {
	var entry AddEntryRequest
	if err := unpackJsonPost(r, &entry); err != nil {
		return nil, nil, err
	}

	// Try decoding as ChecksumV1 StItem
	var item StItem
	if err := item.Unmarshal(entry.Item); err != nil {
		return nil, nil, fmt.Errorf("StItem(%s): %v", item.Format, err)
	}
	if item.Format != StFormatChecksumV1 {
		return nil, nil, fmt.Errorf("invalid StItem format: %s", item.Format)
	}

	// Check that there is a valid trust anchor
	chain, err := buildChainFromDerList(lp, entry.Chain)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid certificate chain: %v", err)
	}

	// Check that there is a valid signature
	if err := verifySignature(lp, chain[0], tls.SignatureScheme(entry.SignatureScheme), entry.Item, entry.Signature); err != nil {
		return nil, nil, fmt.Errorf("invalid signature: %v", err)
	}

	extra, err := NewAppendix(chain, entry.Signature, entry.SignatureScheme).Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("failed marshaling appendix: %v", err)
	}
	return entry.Item, extra, nil
}

// newGetEntriesRequest parses and sanitizes the URL-encoded get-entries
// parameters from an incoming HTTP request.  Too large ranges are truncated
// based on the log's configured max range, but without taking the log's
// current tree size into consideration (because it is not know at this point).
func (lp *LogParameters) newGetEntriesRequest(httpRequest *http.Request) (*GetEntriesRequest, error) {
	start, err := strconv.ParseInt(httpRequest.FormValue("start"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad start parameter: %v", err)
	}
	end, err := strconv.ParseInt(httpRequest.FormValue("end"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad end parameter: %v", err)
	}

	if start < 0 {
		return nil, fmt.Errorf("bad parameters: start(%v) must have a non-negative value", start)
	}
	if start > end {
		return nil, fmt.Errorf("bad parameters: start(%v) must be less than or equal to end(%v)", start, end)
	}
	if end-start+1 > lp.MaxRange {
		end = start + lp.MaxRange - 1
	}
	return &GetEntriesRequest{Start: start, End: end}, nil
}

// newGetProofByHashRequest parses and sanitizes the URL-encoded
// get-proof-by-hash parameters from an incoming HTTP request.
func (lp *LogParameters) newGetProofByHashRequest(httpRequest *http.Request) (*GetProofByHashRequest, error) {
	size, err := strconv.ParseInt(httpRequest.FormValue("tree_size"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad tree_size parameter: %v", err)
	}
	if size < 0 {
		return nil, fmt.Errorf("bad tree_size parameter: negative value")
	}
	hash, err := deb64(httpRequest.FormValue("hash"))
	if err != nil {
		return nil, fmt.Errorf("bad hash parameter: %v", err)
	}
	return &GetProofByHashRequest{TreeSize: size, Hash: hash}, nil
}

// newGetConsistencyProofRequest parses and sanitizes the URL-encoded
// get-consistency-proof-request parameters from an incoming HTTP request
func (lp *LogParameters) newGetConsistencyProofRequest(httpRequest *http.Request) (*GetConsistencyProofRequest, error) {
	first, err := strconv.ParseInt(httpRequest.FormValue("first"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad first parameter: %v", err)
	}
	second, err := strconv.ParseInt(httpRequest.FormValue("second"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad second parameter: %v", err)
	}

	if first < 1 {
		return nil, fmt.Errorf("bad parameters: first(%d) must be a natural number", first)
	}
	if first >= second {
		return nil, fmt.Errorf("bad parameters: second(%d) must be larger than first(%d)", first, second)
	}
	return &GetConsistencyProofRequest{First: first, Second: second}, nil
}

// newGetEntryResponse assembles a log entry and its appendix
func (lp *LogParameters) newGetEntryResponse(leaf, appendix []byte) (*GetEntryResponse, error) {
	var app Appendix
	if err := app.Unmarshal(appendix); err != nil {
		return nil, err
	}
	chain := make([][]byte, 0, len(app.Chain))
	for _, c := range app.Chain {
		chain = append(chain, c.Data)
	}
	return &GetEntryResponse{leaf, app.Signature, chain}, nil
}

// newGetEntriesResponse assembles a get-entries response
func (lp *LogParameters) newGetEntriesResponse(leaves []*trillian.LogLeaf) ([]*GetEntryResponse, error) {
	entries := make([]*GetEntryResponse, 0, len(leaves))
	for _, leaf := range leaves {
		entry, err := lp.newGetEntryResponse(leaf.GetLeafValue(), leaf.GetExtraData())
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// newGetAnchorsResponse assembles a get-anchors response
func (lp *LogParameters) newGetAnchorsResponse() [][]byte {
	certificates := make([][]byte, 0, len(lp.AnchorList))
	for _, certificate := range lp.AnchorList {
		certificates = append(certificates, certificate.Raw)
	}
	return certificates
}

// unpackJsonPost unpacks a json-encoded HTTP POST request into `unpack`
func unpackJsonPost(r *http.Request, unpack interface{}) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed reading request body: %v", err)
	}
	if err := json.Unmarshal(body, &unpack); err != nil {
		return fmt.Errorf("failed parsing json body: %v", err)
	}
	return nil
}

// writeJsonBody writes a json-body HTTP response
func writeJsonResponse(response interface{}, w http.ResponseWriter) error {
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
