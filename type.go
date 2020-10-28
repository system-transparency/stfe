package stfe

import (
	"fmt"

	"crypto/x509"
	"encoding/base64"
	"time"

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

// StItem references a versioned item based on a given format specifier.
type StItem struct {
	Format           StFormat          `tls:"maxval:65535"`
	SignedTreeHeadV1 *SignedTreeHeadV1 `tls:"selector:Format,val:1"`
	SignedDebugInfoV1 *SignedDebugInfoV1 `tls:"selector:Format,val:2"`
	// TODO: add consistency proof
	InclusionProofV1 *InclusionProofV1 `tls:"selector:Format,val:4"`
	ChecksumV1       *ChecksumV1       `tls:"selector:Format,val:5"`
}

type SignedTreeHeadV1 struct {
	LogId []byte `tls:"minlen:2,maxlen:127"`
	TreeHead TreeHeadV1 `tls:minlen:0, maxlen:65535` // what should maxlen be?
	Signature []byte `tls:"minlen:0,maxlen:65535"`
}

type TreeHeadV1 struct {
	Timestamp uint64
	TreeSize uint64
	RootHash NodeHash `tls:minlen:32,maxlen:255`
	Extension []byte `tls:"minlen:0,maxlen:65535"`
}

// ChecksumV1 associates a package name with an arbitrary checksum value
type ChecksumV1 struct {
	Package  []byte `tls:"minlen:0,maxlen:255"`
	Checksum []byte `tls:"minlen:32,maxlen:255"`
}

// InclusionProofV1 is a Merkle tree inclusion proof, see RFC 6962/bis (§4.12)
type InclusionProofV1 struct {
	LogID         []byte `tls:"minlen:2,maxlen:127"`
	TreeSize      uint64
	LeafIndex     uint64
	InclusionPath []NodeHash `tls:"minlen:1,maxlen:65535"`
}

// SignedDebugInfoV1 is a signed statement that we intend (but do not promise)
// to insert an entry into the log.  Only Ed25519 signatures are supported.
// TODO: double-check that crypto/ed25519 encodes signature as in RFC 8032
// TODO: need to think about signature format, then update markdown/api.md
type SignedDebugInfoV1 struct {
	LogId []byte `tls:"minlen:32,maxlen:127"`
	Message []byte `tls:"minlen:0,maxlen:65535"`
	Signature []byte `tls:"minlen:0,maxlen:65535"` // defined in RFC 8032
}

// NodeHash is a hashed Merkle tree node, see RFC 6962/bis (§4.9)
type NodeHash struct {
	Data []byte `tls:"minlen:32,maxlen:255"`
}

func NewSignedTreeHeadV1(th TreeHeadV1, logId, signature []byte) StItem {
	return StItem{
		Format: StFormatSignedTreeHeadV1,
		SignedTreeHeadV1: &SignedTreeHeadV1{
			LogId: logId,
			TreeHead: th,
			Signature: signature,
		},
	}
}

func NewTreeHeadV1(timestamp, treeSize uint64, rootHash []byte) TreeHeadV1 {
	return TreeHeadV1{
		Timestamp: timestamp,
		TreeSize: treeSize,
		RootHash: NodeHash{
			Data: rootHash,
		},
		Extension: nil,
	}
}

func NewSignedDebugInfoV1(logId, message, signature []byte) StItem {
	return StItem{
		Format: StFormatSignedDebugInfoV1,
		SignedDebugInfoV1: &SignedDebugInfoV1{
			LogId: logId,
			Message: message,
			Signature: signature,
		},
	}
}

// NewChecksumV1 creates a new StItem of type checksum_v1
func NewChecksumV1(identifier []byte, checksum []byte) StItem {
	return StItem{
		Format: StFormatChecksumV1,
		ChecksumV1: &ChecksumV1{
			Package:  identifier,
			Checksum: checksum,
		},
	}
}

// NewInclusionProofV1 creates a new StItem of type inclusion_proof_v1
func NewInclusionProofV1(logID []byte, treeSize uint64, proof *trillian.Proof) StItem {
	inclusionPath := make([]NodeHash, 0, len(proof.Hashes))
	for _, hash := range proof.Hashes {
		inclusionPath = append(inclusionPath, NodeHash{Data: hash})
	}

	return StItem{
		Format: StFormatInclusionProofV1,
		InclusionProofV1: &InclusionProofV1{
			LogID:         logID,
			TreeSize:      treeSize,
			LeafIndex:     uint64(proof.LeafIndex),
			InclusionPath: inclusionPath,
		},
	}
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
		return fmt.Sprintf("Format(%s): %s", i.Format, *i.ChecksumV1)
	case StFormatInclusionProofV1:
		return fmt.Sprintf("Format(%s): %s", i.Format, *i.InclusionProofV1)
	case StFormatSignedDebugInfoV1:
		return fmt.Sprintf("Format(%s): %s", i.Format, *i.SignedDebugInfoV1)
	case StFormatSignedTreeHeadV1:
		return fmt.Sprintf("Format(%s): %s", i.Format, *i.SignedTreeHeadV1)
	default:
		return fmt.Sprintf("unknown StItem: %s", i.Format)
	}
}

func (th TreeHeadV1) String() string {
	return fmt.Sprintf("Timestamp(%s) TreeSize(%d) RootHash(%s)", time.Unix(int64(th.Timestamp/1000), 0), th.TreeSize, base64.StdEncoding.EncodeToString(th.RootHash.Data))
}

func (i SignedTreeHeadV1) String() string {
	return fmt.Sprintf("LogId(%s) TreeHead(%s) Signature(%s)", base64.StdEncoding.EncodeToString(i.LogId), i.TreeHead, base64.StdEncoding.EncodeToString(i.Signature))
}

func (i SignedDebugInfoV1) String() string {
	return fmt.Sprintf("LogId(%s) Message(%s) Signature(%s)", base64.StdEncoding.EncodeToString(i.LogId), string(i.Message), base64.StdEncoding.EncodeToString(i.Signature))
}

func (i ChecksumV1) String() string {
	return fmt.Sprintf("Package(%v) Checksum(%v)", string(i.Package), base64.StdEncoding.EncodeToString(i.Checksum))
}

func (i InclusionProofV1) String() string {
	path := make([]string, 0, len(i.InclusionPath))
	for _, hash := range i.InclusionPath {
		path = append(path, base64.StdEncoding.EncodeToString(hash.Data))
	}

	return fmt.Sprintf("LogID(%s) TreeSize(%d) LeafIndex(%d) AuditPath(%v)", base64.StdEncoding.EncodeToString(i.LogID), i.TreeSize, i.LeafIndex, path)
}

// StItemFromB64 creates an StItem from a serialized and base64-encoded string
func StItemFromB64(s string) (StItem, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return StItem{}, fmt.Errorf("base64 decoding failed: %v", err)
	}

	var item StItem
	extra, err := tls.Unmarshal(b, &item)
	if err != nil {
		return StItem{}, fmt.Errorf("tls unmarshal failed: %v", err)
	} else if len(extra) > 0 {
		return StItem{}, fmt.Errorf("tls unmarshal found extra data: %v", extra)
	}
	return item, nil
}

// Appendix is extra data that Trillian can store about a leaf
type Appendix struct {
	Signature []byte           `tls:"minlen:0,maxlen:16383"`
	Chain     []RawCertificate `tls:"minlen:0,maxlen:65535"`
}

// RawCertificate is a serialized X.509 certificate
type RawCertificate struct {
	Data []byte `tls:"minlen:0,maxlen:65535"`
}

// NewAppendix creates a new leaf Appendix for an X.509 chain and signature
func NewAppendix(x509Chain []*x509.Certificate, signature []byte) Appendix {
	chain := make([]RawCertificate, 0, 2) // TODO: base length on config param
	for _, c := range x509Chain {
		chain = append(chain, RawCertificate{c.Raw})
	}
	return Appendix{Signature: signature, Chain: chain}
}
