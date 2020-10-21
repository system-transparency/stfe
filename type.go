package stfe

import (
	"fmt"

	"encoding/base64"

	"github.com/google/certificate-transparency-go/tls"
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
