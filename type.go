package stfe

import (
	"fmt"
	"time"

	"crypto/x509"
	"encoding/base64"

	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
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

// StItem references a versioned item based on a given format specifier
type StItem struct {
	Format             StFormat            `tls:"maxval:65535"`
	SignedTreeHeadV1   *SignedTreeHeadV1   `tls:"selector:Format,val:1"`
	SignedDebugInfoV1  *SignedDebugInfoV1  `tls:"selector:Format,val:2"`
	ConsistencyProofV1 *ConsistencyProofV1 `tls:"selector:Format,val:3"`
	InclusionProofV1   *InclusionProofV1   `tls:"selector:Format,val:4"`
	ChecksumV1         *ChecksumV1         `tls:"selector:Format,val:5"`
}

// SignedTreeHeadV1 is a signed tree head as defined by RFC 6962/bis, §4.10
type SignedTreeHeadV1 struct {
	LogId     []byte `tls:"minlen:32,maxlen:32"`
	TreeHead  TreeHeadV1
	Signature []byte `tls:"minlen:1,maxlen:65535"`
}

// SignedDebugInfoV1 is a signed statement that we intend (but do not promise)
// to insert an entry into the log as defined by markdown/api.md
type SignedDebugInfoV1 struct {
	LogId     []byte `tls:"minlen:32,maxlen:32"`
	Message   []byte `tls:"minlen:0,maxlen:65535"`
	Signature []byte `tls:"minlen:1,maxlen:65535"`
}

// ConsistencyProofV1 is a consistency proof as defined by RFC 6962/bis, §4.11
type ConsistencyProofV1 struct {
	LogId           []byte `tls:"minlen:32,maxlen:32"`
	TreeSize1       uint64
	TreeSize2       uint64
	ConsistencyPath []NodeHash `tls:"minlen:1,maxlen:65535"`
}

// InclusionProofV1 is an inclusion proof as defined by RFC 6962/bis, §4.12
type InclusionProofV1 struct {
	LogId         []byte `tls:"minlen:32,maxlen:32"`
	TreeSize      uint64
	LeafIndex     uint64
	InclusionPath []NodeHash `tls:"minlen:1,maxlen:65535"`
}

// ChecksumV1 associates a leaf type as defined by markdown/api.md
type ChecksumV1 struct {
	Package  []byte `tls:"minlen:1,maxlen:255"`
	Checksum []byte `tls:"minlen:1,maxlen:64"`
}

// TreeHeadV1 is a tree head as defined by RFC 6962/bis, §4.10
type TreeHeadV1 struct {
	Timestamp uint64
	TreeSize  uint64
	RootHash  NodeHash
	Extension []byte `tls:"minlen:0,maxlen:65535"`
}

// NodeHash is a Merkle tree hash as defined by RFC 6962/bis, §4.9
type NodeHash struct {
	Data []byte `tls:"minlen:32,maxlen:255"`
}

// RawCertificate is a serialized X.509 certificate
type RawCertificate struct {
	Data []byte `tls:"minlen:0,maxlen:65535"`
}

// Appendix is extra leaf data that is not stored in the log's Merkle tree
type Appendix struct {
	Signature       []byte `tls:"minlen:0,maxlen:16383"`
	SignatureScheme uint16
	Chain           []RawCertificate `tls:"minlen:0,maxlen:65535"`
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
	return fmt.Sprintf("Package(%s) Checksum(%s)", string(i.Package), b64(i.Checksum))
}

func (th TreeHeadV1) String() string {
	return fmt.Sprintf("Timestamp(%s) TreeSize(%d) RootHash(%s)", time.Unix(int64(th.Timestamp/1000), 0), th.TreeSize, b64(th.RootHash.Data))
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

// Marshal serializes an Appendix as defined by RFC 5246
func (a *Appendix) Marshal() ([]byte, error) {
	serialized, err := tls.Marshal(*a)
	if err != nil {
		return nil, fmt.Errorf("marshal failed for Appendix(%v): %v", a, err)
	}
	return serialized, nil
}

// Unmarshal unpacks a serialized Appendix
func (a *Appendix) Unmarshal(serialized []byte) error {
	extra, err := tls.Unmarshal(serialized, a)
	if err != nil {
		return fmt.Errorf("unmarshal failed for Appendix(%v): %v", a, err)
	} else if len(extra) > 0 {
		return fmt.Errorf("unmarshal found extra data for Appendix(%v): %v", a, extra)
	}
	return nil
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
func NewInclusionProofV1(logID []byte, treeSize uint64, proof *trillian.Proof) *StItem {
	inclusionPath := make([]NodeHash, 0, len(proof.Hashes))
	for _, hash := range proof.Hashes {
		inclusionPath = append(inclusionPath, NodeHash{Data: hash})
	}
	return &StItem{
		Format:           StFormatInclusionProofV1,
		InclusionProofV1: &InclusionProofV1{logID, treeSize, uint64(proof.LeafIndex), inclusionPath},
	}
}

// NewConsistencyProofV1 creates a new StItem of type consistency_proof_v1
func NewConsistencyProofV1(logId []byte, first, second int64, proof *trillian.Proof) *StItem {
	path := make([]NodeHash, 0, len(proof.Hashes))
	for _, hash := range proof.Hashes {
		path = append(path, NodeHash{Data: hash})
	}
	return &StItem{
		Format:             StFormatConsistencyProofV1,
		ConsistencyProofV1: &ConsistencyProofV1{logId, uint64(first), uint64(second), path},
	}
}

// NewChecksumV1 creates a new StItem of type checksum_v1
func NewChecksumV1(identifier []byte, checksum []byte) *StItem {
	return &StItem{
		Format:     StFormatChecksumV1,
		ChecksumV1: &ChecksumV1{identifier, checksum},
	}
}

// NewTreeHead creates a new TreeHeadV1 from a Trillian-signed log root without
// verifying any signature.  In other words, Trillian <-> STFE must be trusted.
func NewTreeHeadV1(lp *LogParameters, slr *trillian.SignedLogRoot) (*TreeHeadV1, error) {
	var lr types.LogRootV1
	if err := lr.UnmarshalBinary(slr.GetLogRoot()); err != nil {
		return nil, fmt.Errorf("failed unmarshaling Trillian slr: %v", err)
	}
	if lp.HashType.Size() != len(lr.RootHash) {
		return nil, fmt.Errorf("invalid Trillian root hash: %v", lr.RootHash)
	}
	return &TreeHeadV1{uint64(lr.TimestampNanos / 1000 / 1000), uint64(lr.TreeSize), NodeHash{lr.RootHash}, nil}, nil
}

// NewAppendix creates a new leaf Appendix for an X.509 chain and signature
func NewAppendix(x509Chain []*x509.Certificate, signature []byte, signatureScheme uint16) *Appendix {
	chain := make([]RawCertificate, 0, len(x509Chain))
	for _, c := range x509Chain {
		chain = append(chain, RawCertificate{c.Raw})
	}
	return &Appendix{signature, signatureScheme, chain}
}

func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func deb64(str string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(str)
}
