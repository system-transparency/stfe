package types

import (
	"fmt"

	"github.com/google/certificate-transparency-go/tls"
)

// StFormat defines a particular StItem type that is versioned
type StFormat tls.Enum

const (
	StFormatReserved           StFormat = 0
	StFormatSignedTreeHeadV1   StFormat = 1
	StFormatCosignedTreeHeadV1 StFormat = 2
	StFormatConsistencyProofV1 StFormat = 3
	StFormatInclusionProofV1   StFormat = 4
	StFormatSignedChecksumV1   StFormat = 5
)

// StItem references a versioned item based on a given format specifier
type StItem struct {
	Format             StFormat            `tls:"maxval:65535"`
	SignedTreeHeadV1   *SignedTreeHeadV1   `tls:"selector:Format,val:1"`
	CosignedTreeHeadV1 *CosignedTreeHeadV1 `tls:"selector:Format,val:2"`
	ConsistencyProofV1 *ConsistencyProofV1 `tls:"selector:Format,val:3"`
	InclusionProofV1   *InclusionProofV1   `tls:"selector:Format,val:4"`
	SignedChecksumV1   *SignedChecksumV1   `tls:"selector:Format,val:5"`
}

// StItemList is an StItem List that is at most 2^32-1 bytes when serialized.
type StItemList struct {
	Items []StItem `tls:"minlen:0,maxlen:4294967295"`
}

type SignedTreeHeadV1 struct {
	TreeHead  TreeHeadV1
	Signature SignatureV1
}

type CosignedTreeHeadV1 struct {
	SignedTreeHead SignedTreeHeadV1
	Cosignatures   []SignatureV1 `tls:"minlen:0,maxlen:4294967295"`
}

type ConsistencyProofV1 struct {
	LogId           Namespace
	TreeSize1       uint64
	TreeSize2       uint64
	ConsistencyPath []NodeHash `tls:"minlen:0,maxlen:65535"`
}

type InclusionProofV1 struct {
	LogId         Namespace
	TreeSize      uint64
	LeafIndex     uint64
	InclusionPath []NodeHash `tls:"minlen:0,maxlen:65535"`
}

type SignedChecksumV1 struct {
	Data      ChecksumV1
	Signature SignatureV1
}

type ChecksumV1 struct {
	Identifier []byte `tls:"minlen:1,maxlen:128"`
	Checksum   []byte `tls:"minlen:1,maxlen:64"`
}

type TreeHeadV1 struct {
	Timestamp uint64
	TreeSize  uint64
	RootHash  NodeHash
	Extension []byte `tls:"minlen:0,maxlen:65535"`
}

type NodeHash struct {
	Data []byte `tls:"minlen:32,maxlen:255"`
}

type SignatureV1 struct {
	Namespace Namespace
	Signature []byte `tls:"minlen:1,maxlen:65535"`
}

func (f StFormat) String() string {
	switch f {
	case StFormatReserved:
		return "reserved"
	case StFormatSignedTreeHeadV1:
		return "signed_tree_head_v1"
	case StFormatCosignedTreeHeadV1:
		return "cosigned_tree_head_v1"
	case StFormatConsistencyProofV1:
		return "consistency_proof_v1"
	case StFormatInclusionProofV1:
		return "inclusion_proof_v1"
	case StFormatSignedChecksumV1:
		return "signed_checksum_v1"
	default:
		return fmt.Sprintf("unknown StFormat: %d", f)
	}
}

func (i StItem) String() string {
	switch i.Format {
	case StFormatReserved:
		return fmt.Sprintf("Format(%s)", i.Format)
	case StFormatSignedTreeHeadV1:
		return fmt.Sprintf("Format(%s): %+v", i.Format, i.SignedTreeHeadV1)
	case StFormatCosignedTreeHeadV1:
		return fmt.Sprintf("Format(%s): %+v", i.Format, i.CosignedTreeHeadV1)
	case StFormatConsistencyProofV1:
		return fmt.Sprintf("Format(%s): %+v", i.Format, i.ConsistencyProofV1)
	case StFormatInclusionProofV1:
		return fmt.Sprintf("Format(%s): %+v", i.Format, i.InclusionProofV1)
	case StFormatSignedChecksumV1:
		return fmt.Sprintf("Format(%s): %+v", i.Format, i.SignedChecksumV1)
	default:
		return fmt.Sprintf("unknown StItem: %v", i.Format)
	}
}

// Marshal marshals a TLS-encodable item
func Marshal(item interface{}) ([]byte, error) {
	serialized, err := tls.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("tls.Marshal: %v", err)
	}
	return serialized, nil
}

// Unmarshal unmarshals a TLS-encoded item
func Unmarshal(serialized []byte, out interface{}) error {
	extra, err := tls.Unmarshal(serialized, out)
	if err != nil {
		return fmt.Errorf("tls.Unmarshal: %v", err)
	}
	if len(extra) > 0 {
		return fmt.Errorf("tls.Unmarshal: extra data: %X", extra)
	}
	return nil
}
