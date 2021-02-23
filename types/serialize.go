package types

import (
	"fmt"

	"github.com/google/certificate-transparency-go/tls"
)

const (
	HashSizeV1 = 32
)

// GetProofByHashV1 is a serializable get-proof-by-hash request
type GetProofByHashV1 struct {
	Hash     [HashSizeV1]byte
	TreeSize uint64
}

// GetConsistencyProofV1 is a serializable get-consistency-proof request
type GetConsistencyProofV1 struct {
	First  uint64
	Second uint64
}

// GetEntriesV1 is a serializable get-entries request
type GetEntriesV1 struct {
	Start uint64
	End   uint64
}

// Marshal marshals a TLS-encodable structure
func Marshal(item interface{}) ([]byte, error) {
	serialized, err := tls.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("tls.Marshal: %v", err)
	}
	return serialized, nil
}

// Unmarshal unmarshals a TLS-encoded structure
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
