package stfe

import (
	"fmt"
	"strconv"

	"encoding/base64"
	"net/http"

	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/trillian"
)

// StFormat defines a particular StItem type that is versioned
type StFormat tls.Enum

const (
	StFormatReserved           StFormat = 0
	StFormatSignedTreeHeadV1   StFormat = 1
	StFormatSignedDebugInfoV1  StFormat = 2
	StFormatConsistencyProofV1 StFormat = 3
	StFormatInclusionProofV1   StFormat = 4
	StFormatChecksumV1                  = 5
)

func (f StFormat) String() string {
	switch f {
	case StFormatReserved:
		return "reserved"
	case StFormatSignedTreeHeadV1:
		return "signed_tree_head_v1"
	case StFormatSignedDebugInfoV1:
		return "signed_debug_info_v1"
	case StFormatConsistencyProofV1:
		return "consistency_proof_v1"
	case StFormatInclusionProofV1:
		return "inclusion_proof_v1"
	case StFormatChecksumV1:
		return "checksum_v1"
	default:
		return fmt.Sprintf("Unknown StFormat: %d", f)
	}
}

// StItem references a versioned item based on a given format specifier.
type StItem struct {
	Format     StFormat    `tls:"maxval:65535"`
	ChecksumV1 *ChecksumV1 `tls:"selector:Format,val:5"`
	// TODO: add more items
}

func (i StItem) String() string {
	switch i.Format {
	case StFormatChecksumV1:
		return fmt.Sprintf("%s %s", i.Format, *i.ChecksumV1)
	default:
		return fmt.Sprintf("unknown StItem: %s", i.Format)
	}
}

func StItemFromB64(s string) (*StItem, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decoding failed: %v", err)
	}

	var item StItem
	extra, err := tls.Unmarshal(b, &item)
	if err != nil {
		return nil, fmt.Errorf("tls unmarshal failed: %v", err)
	} else if len(extra) > 0 {
		return nil, fmt.Errorf("tls unmarshal found extra data: %v", extra)
	}
	return &item, nil
}

// ChecksumV1 associates a package name with an arbitrary checksum value
type ChecksumV1 struct {
	Package  []byte `tls:"minlen:0,maxlen:255"`
	Checksum []byte `tls:"minlen:32,maxlen:255"`
}

// NewChecksumV1 creates a new StItem of type checksum_v1
func NewChecksumV1(name string, checksum []byte) (StItem, error) {
	return StItem{
		Format: StFormatChecksumV1,
		ChecksumV1: &ChecksumV1{
			Package:  []byte(name),
			Checksum: checksum,
		},
	}, nil // TODO: error handling
}

func (i ChecksumV1) String() string {
	return fmt.Sprintf("%v %v", string(i.Package), base64.StdEncoding.EncodeToString(i.Checksum))
}

type NodeHash struct {
	Data []byte `tls:"minlen:32,maxlen:255"`
}

type InclusionProofV1 struct {
	LogID         []byte `tls:"minlen:2,maxlen:127"`
	TreeSize      uint64
	LeafIndex     uint64
	InclusionPath []NodeHash `tls:"minlen:1,maxlen:65535"`
}

func NewInclusionProofV1(logID []byte, treeSize uint64, proof *trillian.Proof) InclusionProofV1 {
	inclusionPath := make([]NodeHash, 0, len(proof.Hashes))
	for _, hash := range proof.Hashes {
		inclusionPath = append(inclusionPath, NodeHash{Data: hash})
	}

	return InclusionProofV1{
		LogID:         logID,
		TreeSize:      treeSize,
		LeafIndex:     uint64(proof.LeafIndex),
		InclusionPath: inclusionPath,
	}
}

// AddEntryRequest is a collection of add-entry input parameters
type AddEntryRequest struct {
	Item        string `json:"item"`
	Signature   string `json:"signature"`
	Certificate string `json:"certificate"`
}

// GetEntriesRequest is a collection of get-entry input parameters
type GetEntriesRequest struct {
	Start int64
	End   int64
}

func (r *GetEntriesRequest) Unpack(httpRequest *http.Request) error {
	var err error

	r.Start, err = strconv.ParseInt(httpRequest.FormValue("start"), 10, 64)
	if err != nil {
		return fmt.Errorf("bad start parameter: %v", err)
	}
	r.End, err = strconv.ParseInt(httpRequest.FormValue("end"), 10, 64)
	if err != nil {
		return fmt.Errorf("bad end parameter: %v", err)
	}

	if r.Start < 0 {
		return fmt.Errorf("bad parameters: start(%v) must have a non-negative value", r.Start)
	}
	if r.Start > r.End {
		return fmt.Errorf("bad parameters: start(%v) must be larger than end(%v)", r.Start, r.End)
	}
	// TODO: check that range is not larger than the max range. Yes -> truncate
	// TODO: check that end is not past the most recent STH. Yes -> truncate
	return nil
}

type GetEntryResponse struct {
	Leaf      string   `json:"leaf"`
	Signature string   `json:"signature"`
	Chain     []string `json:chain`
}

func NewGetEntryResponse(leaf []byte) GetEntryResponse {
	return GetEntryResponse{
		Leaf: base64.StdEncoding.EncodeToString(leaf),
		// TODO: add signature and chain
	}
}

type GetEntriesResponse struct {
	Entries []GetEntryResponse `json:"entries"`
}

func NewGetEntriesResponse(leaves []*trillian.LogLeaf) (GetEntriesResponse, error) {
	entries := make([]GetEntryResponse, 0, len(leaves))
	for _, leaf := range leaves {
		entries = append(entries, NewGetEntryResponse(leaf.GetLeafValue())) // TODO: add signature and chain
	}
	return GetEntriesResponse{entries}, nil
}

type GetProofByHashRequest struct {
	Hash     []byte
	TreeSize int64
}

func NewGetProofByHashRequest(httpRequest *http.Request) (*GetProofByHashRequest, error) {
	var r GetProofByHashRequest
	var err error

	r.TreeSize, err = strconv.ParseInt(httpRequest.FormValue("tree_size"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad tree_size parameter: %v", err)
	}
	if r.TreeSize < 0 {
		return nil, fmt.Errorf("bad tree_size parameter: negative value")
	}
	// TODO: check that tree size is not past STH.tree_size

	r.Hash, err = base64.StdEncoding.DecodeString(httpRequest.FormValue("hash"))
	if err != nil {
		return nil, fmt.Errorf("bad hash parameter: %v", err)
	}
	return &r, nil
}

type GetProofByHashResponse struct {
	InclusionProof string `json:"inclusion_proof"`
}

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
