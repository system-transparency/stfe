package stfe

import (
	"fmt"
	"time"

	"encoding/base64"

	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/trillian/types"
	"github.com/system-transparency/stfe/namespace"
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
	StFormatCosignedTreeHeadV1          = 6
)

// StItem references a versioned item based on a given format specifier
type StItem struct {
	Format             StFormat            `tls:"maxval:65535"`
	SignedTreeHeadV1   *SignedTreeHeadV1   `tls:"selector:Format,val:1"`
	SignedDebugInfoV1  *SignedDebugInfoV1  `tls:"selector:Format,val:2"`
	ConsistencyProofV1 *ConsistencyProofV1 `tls:"selector:Format,val:3"`
	InclusionProofV1   *InclusionProofV1   `tls:"selector:Format,val:4"`
	ChecksumV1         *ChecksumV1         `tls:"selector:Format,val:5"`
	CosignedTreeHeadV1 *CosignedTreeHeadV1 `tls:"selector:Format,val:6"`
}

// SignedTreeHeadV1 is a signed tree head as defined by RFC 6962/bis, §4.10
type SignedTreeHeadV1 struct {
	LogId     []byte `tls:"minlen:35,maxlen:35"`
	TreeHead  TreeHeadV1
	Signature []byte `tls:"minlen:1,maxlen:65535"`
}

// SignedDebugInfoV1 is a signed statement that we intend (but do not promise)
// to insert an entry into the log as defined by markdown/api.md
type SignedDebugInfoV1 struct {
	LogId     []byte `tls:"minlen:35,maxlen:35"`
	Message   []byte `tls:"minlen:0,maxlen:65535"`
	Signature []byte `tls:"minlen:1,maxlen:65535"`
}

// ConsistencyProofV1 is a consistency proof as defined by RFC 6962/bis, §4.11
type ConsistencyProofV1 struct {
	LogId           []byte `tls:"minlen:35,maxlen:35"`
	TreeSize1       uint64
	TreeSize2       uint64
	ConsistencyPath []NodeHash `tls:"minlen:0,maxlen:65535"`
}

// InclusionProofV1 is an inclusion proof as defined by RFC 6962/bis, §4.12
type InclusionProofV1 struct {
	LogId         []byte `tls:"minlen:35,maxlen:35"`
	TreeSize      uint64
	LeafIndex     uint64
	InclusionPath []NodeHash `tls:"minlen:0,maxlen:65535"`
}

// ChecksumV1 associates a leaf type as defined by markdown/api.md
type ChecksumV1 struct {
	Package   []byte `tls:"minlen:1,maxlen:255"`
	Checksum  []byte `tls:"minlen:1,maxlen:64"`
	Namespace namespace.Namespace
}

// TreeHeadV1 is a tree head as defined by RFC 6962/bis, §4.10
type TreeHeadV1 struct {
	Timestamp uint64
	TreeSize  uint64
	RootHash  NodeHash
	Extension []byte `tls:"minlen:0,maxlen:65535"`
}

// CosignedTreeheadV1 is a cosigned STH
type CosignedTreeHeadV1 struct {
	SignedTreeHeadV1 SignedTreeHeadV1
	SignatureV1      []SignatureV1 `tls:"minlen:0,maxlen:4294967295"`
}

// SignatureV1 is a detached signature that was produced by a namespace
type SignatureV1 struct {
	Namespace namespace.Namespace
	Signature []byte `tls:"minlen:1,maxlen:65535"`
}

// NodeHash is a Merkle tree hash as defined by RFC 6962/bis, §4.9
type NodeHash struct {
	Data []byte `tls:"minlen:32,maxlen:255"`
}

// RawCertificate is a serialized X.509 certificate
type RawCertificate struct {
	Data []byte `tls:"minlen:0,maxlen:65535"`
}

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
	case StFormatCosignedTreeHeadV1:
		return "cosigned_tree_head_v1"
	default:
		return fmt.Sprintf("Unknown StFormat: %d", f)
	}
}

func (i StItem) String() string {
	switch i.Format {
	case StFormatChecksumV1:
		return fmt.Sprintf("Format(%s): %s", i.Format, i.ChecksumV1)
	case StFormatConsistencyProofV1:
		return fmt.Sprintf("Format(%s): %s", i.Format, i.ConsistencyProofV1)
	case StFormatInclusionProofV1:
		return fmt.Sprintf("Format(%s): %s", i.Format, i.InclusionProofV1)
	case StFormatSignedDebugInfoV1:
		return fmt.Sprintf("Format(%s): %s", i.Format, i.SignedDebugInfoV1)
	case StFormatSignedTreeHeadV1:
		return fmt.Sprintf("Format(%s): %s", i.Format, i.SignedTreeHeadV1)
	case StFormatCosignedTreeHeadV1:
		return fmt.Sprintf("Format(%s): %s", i.Format, i.CosignedTreeHeadV1)
	default:
		return fmt.Sprintf("unknown StItem: %s", i.Format)
	}
}

func (i SignedTreeHeadV1) String() string {
	return fmt.Sprintf("LogId(%s) TreeHead(%s) Signature(%s)", b64(i.LogId), i.TreeHead, b64(i.Signature))
}

func (i SignedDebugInfoV1) String() string {
	return fmt.Sprintf("LogId(%s) Message(%s) Signature(%s)", b64(i.LogId), string(i.Message), b64(i.Signature))
}

func (i ConsistencyProofV1) String() string {
	return fmt.Sprintf("LogID(%s) TreeSize1(%d) TreeSize2(%d) ConsistencyPath(%v)", b64(i.LogId), i.TreeSize1, i.TreeSize2, B64EncodePath(i.ConsistencyPath))
}

func (i InclusionProofV1) String() string {
	return fmt.Sprintf("LogID(%s) TreeSize(%d) LeafIndex(%d) AuditPath(%v)", b64(i.LogId), i.TreeSize, i.LeafIndex, B64EncodePath(i.InclusionPath))
}

func (i ChecksumV1) String() string {
	return fmt.Sprintf("Package(%s) Checksum(%s) Namespace(%s)", string(i.Package), string(i.Checksum), i.Namespace.String())
}

func (th TreeHeadV1) String() string {
	return fmt.Sprintf("Timestamp(%s) TreeSize(%d) RootHash(%s)", time.Unix(int64(th.Timestamp/1000), 0), th.TreeSize, b64(th.RootHash.Data))
}

func (i CosignedTreeHeadV1) String() string {
	return fmt.Sprintf("SignedTreeHead(%s) #Cosignatures(%d)", i.SignedTreeHeadV1.String(), len(i.SignatureV1))
}

// Marshal serializes an Stitem as defined by RFC 5246
func (i *StItem) Marshal() ([]byte, error) {
	serialized, err := tls.Marshal(*i)
	if err != nil {
		return nil, fmt.Errorf("marshal failed for StItem(%s): %v", i.Format, err)
	}
	return serialized, nil
}

// MarshalB64 base64-encodes a serialized StItem
func (i *StItem) MarshalB64() (string, error) {
	serialized, err := i.Marshal()
	if err != nil {
		return "", err
	}
	return b64(serialized), nil
}

// Unmarshal unpacks a serialized StItem
func (i *StItem) Unmarshal(serialized []byte) error {
	extra, err := tls.Unmarshal(serialized, i)
	if err != nil {
		return fmt.Errorf("unmarshal failed for StItem(%s): %v", i.Format, err)
	} else if len(extra) > 0 {
		return fmt.Errorf("unmarshal found extra data for StItem(%s): %v", i.Format, extra)
	}
	return nil
}

// UnmarshalB64 unpacks a base64-encoded serialized StItem
func (i *StItem) UnmarshalB64(s string) error {
	serialized, err := deb64(s)
	if err != nil {
		return fmt.Errorf("base64 decoding failed for StItem(%s): %v", i.Format, err)
	}
	return i.Unmarshal(serialized)
}

// Marshal serializes a TreeHeadV1 as defined by RFC 5246
func (th *TreeHeadV1) Marshal() ([]byte, error) {
	serialized, err := tls.Marshal(*th)
	if err != nil {
		return nil, fmt.Errorf("marshal failed for TreeHeadV1: %v", err)
	}
	return serialized, nil
}

// B64EncodePath encodes a path of node hashes as a list of base64 strings
func B64EncodePath(path []NodeHash) []string {
	p := make([]string, 0, len(path))
	for _, hash := range path {
		p = append(p, b64(hash.Data))
	}
	return p
}

// NewSignedTreeHead creates a new StItem of type signed_tree_head_v1
func NewSignedTreeHeadV1(th *TreeHeadV1, logId, signature []byte) *StItem {
	return &StItem{
		Format:           StFormatSignedTreeHeadV1,
		SignedTreeHeadV1: &SignedTreeHeadV1{logId, *th, signature},
	}
}

// NewSignedDebugInfoV1 creates a new StItem of type inclusion_proof_v1
func NewSignedDebugInfoV1(logId, message, signature []byte) *StItem {
	return &StItem{
		Format:            StFormatSignedDebugInfoV1,
		SignedDebugInfoV1: &SignedDebugInfoV1{logId, message, signature},
	}
}

// NewInclusionProofV1 creates a new StItem of type inclusion_proof_v1
func NewInclusionProofV1(logID []byte, treeSize, index uint64, proof [][]byte) *StItem {
	path := make([]NodeHash, 0, len(proof))
	for _, hash := range proof {
		path = append(path, NodeHash{Data: hash})
	}
	return &StItem{
		Format:           StFormatInclusionProofV1,
		InclusionProofV1: &InclusionProofV1{logID, treeSize, index, path},
	}
}

// NewConsistencyProofV1 creates a new StItem of type consistency_proof_v1
func NewConsistencyProofV1(logId []byte, first, second uint64, proof [][]byte) *StItem {
	path := make([]NodeHash, 0, len(proof))
	for _, hash := range proof {
		path = append(path, NodeHash{Data: hash})
	}
	return &StItem{
		Format:             StFormatConsistencyProofV1,
		ConsistencyProofV1: &ConsistencyProofV1{logId, uint64(first), uint64(second), path},
	}
}

// NewChecksumV1 creates a new StItem of type checksum_v1
func NewChecksumV1(identifier, checksum []byte, namespace *namespace.Namespace) *StItem {
	return &StItem{
		Format:     StFormatChecksumV1,
		ChecksumV1: &ChecksumV1{identifier, checksum, *namespace},
	}
}

// NewTreeHead creates a new TreeHeadV1 from a Trillian-signed log root without
// verifying any signature.  In other words, Trillian <-> STFE must be trusted.
func NewTreeHeadV1(lr *types.LogRootV1) *TreeHeadV1 {
	return &TreeHeadV1{
		uint64(lr.TimestampNanos / 1000 / 1000),
		uint64(lr.TreeSize),
		NodeHash{lr.RootHash},
		nil,
	}
}

// NewCosignedTreeHeadV1 creates a new StItem of type cosigned_tree_head_v1
func NewCosignedTreeHeadV1(sth *SignedTreeHeadV1, sigs []SignatureV1) *StItem {
	return &StItem{
		Format: StFormatCosignedTreeHeadV1,
		CosignedTreeHeadV1: &CosignedTreeHeadV1{
			SignedTreeHeadV1: *sth,
			SignatureV1:      sigs,
		},
	}
}

func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func deb64(str string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(str)
}
